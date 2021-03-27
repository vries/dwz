/* Copyright (C) 2001-2021 Red Hat, Inc.
   Copyright (C) 2003 Free Software Foundation, Inc.
   Copyright (C) 2019-2021 SUSE LLC.
   Written by Jakub Jelinek <jakub@redhat.com>, 2012.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <setjmp.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/times.h>
#include <sys/wait.h>

#include <obstack.h>

#include <gelf.h>
#include "dwarf2.h"
#include "hashtab.h"
#include "sha1.h"
#include "args.h"

#ifndef SHF_COMPRESSED
 /* Glibc elf.h contains SHF_COMPRESSED starting v2.22.  Libelf libelf.h has
    a fallback definition starting v0.166.  Define a fallback definition here
    for the case of both pre-v2.22 glibc and pre-v0.166 libelf.  */
# define SHF_COMPRESSED (1 << 11)  /* Section with compressed data.  */
#endif

/* Theory of operation:
   The DWZ tool can either optimize debug sections of a single
   executable or shared library at a time, or, when -m option
   is used, optimize debug sections even in between different
   executables or shared libraries by constructing a new ET_REL
   ELF object containing debug sections to which the individual
   debug sections in the various executables or shared libraries
   can refer.  As debug info can be pretty large, the multifile
   optimization is done in several phases in order to decrease
   memory usage of the tool, which can still be quite high.

   The dwz () function optimizes a single file, and at the end,
   after processing that single file, it frees all allocated memory.
   Without -m, the dwz () function is called once on each argument.

   When -m has been passed, the dwz () function is first called on
   each argument, and during it in addition to performing the same
   optimizations as dwz tool does without -m it also may append
   data to several temporary files (one for each .debug_* section
   that is needed for the multifile optimization).  During
   preparation of the additions to the temporary files (write_multifile
   function), wr_multifile flag is true.

   Next phase (optimize_multifile) is that all these temporary files
   are mmapped, it is determined what DIEs, strings, .debug_macro
   sequences etc. might be beneficial to have in the common debug
   sections and finally a new ET_REL ELF object is written.  During
   this phase the op_multifile flag is true.  This is often very
   memory consuming phase, so extra hacks are used to decrease
   the memory usage during it.

   Next phase (read_multifile) is where the previously written ET_REL
   ELF object is parsed again and needed hash tables and other data
   structures filled in.  The rd_multifile flag is set during this
   phase.  The reason why this phase is separate from the previous one,
   as opposed to just populating the hash tables right away in
   optimize_multifile, is that the memory consumption during that phase
   can be very big and keeping malloced data around would mean the address
   space would be unnecessarily fragmented.  read_multifile usually needs
   to allocate only small fragment of the memory optimize_multifile
   needs, on the other side that memory needs to be kept around until
   the end of the last phase.

   During the last phase, the dwz () function is called second
   time on each argument, with fi_multifile flag set.  During this
   phase duplicates in the common debug sections are referenced
   from the local debug sections where possible.

   If some executable or shared library has too large debug information
   (number of DIEs in .debug_info section) that there would be
   risk of too high memory consumption, that file isn't multifile
   optimized, instead it is processed by dwz () in a low-memory mode
   with low_mem flag set.  This can decrease memory consumption to
   half in some very large cases.  */

#ifndef NT_GNU_BUILD_ID
# define NT_GNU_BUILD_ID 3
#endif

#if defined __GNUC__ && __GNUC__ >= 3
# define likely(x) __builtin_expect (!!(x), 1)
# define unlikely(x) __builtin_expect (!!(x), 0)
#else
# define likely(x) (x)
# define unlikely(x) (x)
#endif

#if defined __GNUC__
# define FORCE_INLINE __attribute__((always_inline))
# define UNUSED __attribute__((unused))
# define USED __attribute__((used))
#else
# define FORCE_INLINE
# define UNUSED
# define USED
#endif

/* Utility macro.  */
#define IMPLIES(A, B) (!((A) && !(B)))
#define MAX(A, B) ((A) > (B) ? (A) : (B))
#define MIN(A, B) ((A) < (B) ? (A) : (B))

/* Print memory amount M (in kb) in both exact and human readable, like so:
   1382508 (1.3G).  */
static void
print_mem (long m)
{
  float h = m;
  int level = 0;
  const char *unit[] = { "K", "M", "G"};
  while (h > 1024 && level <= 2)
    {
      h = h / 1024;
      level++;
    }
  fprintf (stderr, "%ld (%.1f%s)\n", m, h, unit[level]);
}

static void
report_progress (void)
{
  static struct tms current;
  static struct tms prev;
  static bool first = true;
  static long ticks_per_second = 0;

  if (!first)
    prev = current;

  times (&current);

  if (first)
    {
      ticks_per_second = sysconf (_SC_CLK_TCK);
      first = false;
      return;
    }

  clock_t user = current.tms_utime - prev.tms_utime;
  clock_t sys = current.tms_stime - prev.tms_stime;
  fprintf (stderr, "user: %.2f\n", (float)user / (float)ticks_per_second);
  fprintf (stderr, "sys : %.2f\n", (float)sys / (float)ticks_per_second);

  if (progress_mem_p)
    {
      FILE *s = fopen ("/proc/self/status", "r");
      char *p;
      bool print_next = false;
      for (p = NULL; fscanf (s, "%ms", &p) && p != NULL; free (p))
	{
	  if (print_next)
	    {
	      long mem = strtol (p, NULL, 10);
	      print_mem (mem);
	      print_next = false;
	      continue;
	    }

	  if (!(p[0] == 'V' && p[1] == 'm'))
	    continue;

	  if (strcmp (&p[2], "Peak:") == 0)
	    fprintf (stderr, "VM Peak: ");
	  else if (strcmp (&p[2], "Size:") == 0)
	    fprintf (stderr, "VM Current: ");
	  else if (strcmp (&p[2], "HWM:") == 0)
	    fprintf (stderr, "RSS Peak: ");
	  else if (strcmp (&p[2], "RSS:") == 0)
	    fprintf (stderr, "RSS Current: ");
	  else
	    continue;

	  print_next = true;
	}
      fclose (s);
    }
}

#define obstack_chunk_alloc     malloc
#define obstack_chunk_free      free

/* Where to longjmp on OOM.  */
static jmp_buf oom_buf;

/* Handle OOM situation.  If handling more than one file, we might
   just fail to handle some large file due to OOM, but could very well
   handle other smaller files after it.  */
static void
dwz_oom (void)
{
  longjmp (oom_buf, 1);
}

/* General obstack for struct dw_cu, dw_die, also used for temporary
   vectors.  */
static struct obstack ob;
/* Short lived obstack, global only to free it on allocation failures.  */
static struct obstack ob2;

/* After read_multifile ob and ob2 are moved over to these variables
   and restored during final cleanup.  */
static struct obstack alt_ob, alt_ob2;

static bool odr_active_p = false;

/* Struct to gather statistics.  */
struct stats
{
  const char *file;
  unsigned int root_cnt;
  unsigned int namespace_cnt;
  unsigned int lower_toplevel;
  unsigned int die_count;
  unsigned int lower_toplevel_with_checksum;
  unsigned int dup_cnt;
  unsigned int dup_chain_cnt;
  unsigned int dup_chain_max_length;
  unsigned int part_cnt;
  unsigned int pu_ph1_cnt;
  unsigned int pu_ph2_cnt;
  unsigned int pu_toplevel_die_cnt;
};
static struct stats *stats;

/* Initialize stats struct.  */
static void
init_stats (const char *file)
{
  if (stats == NULL)
    stats = (struct stats *)malloc (sizeof (*stats));
  memset (stats, 0, sizeof (*stats));
  stats->file = file;
}

/* Print stats struct, parsing statistics.  */
static void
print_parse_stats (void)
{
  if (stats == NULL || stats->file == NULL)
    return;

  fprintf (stderr, "Parse statistics for %s\n", stats->file);

  fprintf (stderr, "root_count                     : %10u\n",
	   stats->root_cnt);
  fprintf (stderr, "namespace_count                : %10u\n",
	   stats->namespace_cnt);
  unsigned int upper_toplevel = stats->root_cnt + stats->namespace_cnt;
  fprintf (stderr, "upper_toplevel                 : %10u\n",
	   upper_toplevel);
  unsigned lower_toplevel
    = stats->lower_toplevel + stats->lower_toplevel_with_checksum;
  fprintf (stderr, "lower_toplevel                 : %10u\n",
	   lower_toplevel);
  unsigned int toplevel = upper_toplevel + lower_toplevel;
  fprintf (stderr, "toplevel                       : %10u\n",
	   toplevel);
  unsigned non_toplevel = stats->die_count - toplevel;
  fprintf (stderr, "non_toplevel                   : %10u\n",
	   non_toplevel);
  fprintf (stderr, "die_count                      : %10u\n",
	   stats->die_count);
}

/* Print stats struct, dups statistics.  */
static void
print_dups_stats (void)
{
  if (stats == NULL || stats->file == NULL)
    return;

  fprintf (stderr, "Duplicate statistics for %s\n", stats->file);

  fprintf (stderr, "lower_toplevel with checksum   : %10u\n",
	   stats->lower_toplevel_with_checksum);
  fprintf (stderr, "dup_cnt                        : %10u\n",
	   stats->dup_cnt);
  fprintf (stderr, "dup_chain_cnt                  : %10u\n",
	   stats->dup_chain_cnt);
  fprintf (stderr, "average dup_chain length       : %10.2f\n",
	   (double)stats->dup_cnt / (double)stats->dup_chain_cnt);
  fprintf (stderr, "max dup_chain length           : %10u\n",
	   stats->dup_chain_max_length);
}

static void
print_part_stats (void)
{
  if (stats == NULL || stats->file == NULL)
    return;

  fprintf (stderr, "Partition statistics for %s\n", stats->file);

  fprintf (stderr, "part_cnt                       : %10u\n", stats->part_cnt);
  fprintf (stderr, "pu_ph1_cnt                     : %10u\n",
	   stats->pu_ph1_cnt);
  fprintf (stderr, "pu_ph2_cnt                     : %10u\n",
	   stats->pu_ph2_cnt);
  fprintf (stderr, "pu_cnt                         : %10u\n",
	   stats->pu_ph1_cnt + stats->pu_ph2_cnt);
  fprintf (stderr, "pu_toplevel_die_cnt            : %10u\n",
	   stats->pu_toplevel_die_cnt);
}

typedef struct
{
  Elf *elf;
  GElf_Ehdr ehdr;
  Elf_Scn **scn;
  const char *filename;
  int lastscn;
  GElf_Shdr shdr[0];
} DSO;

/* Macro to parse an uleb128 number, return it and
   update ptr to the end of the uleb128 at the same time.  */
#define read_uleb128(ptr) ({		\
  uint64_t ret = 0;			\
  uint64_t c;				\
  int shift = 0;			\
  do					\
    {					\
      c = *ptr++;			\
      ret |= (c & 0x7f) << shift;	\
      shift += 7;			\
    } while (c & 0x80);			\
					\
  if (shift >= 70)			\
    ret = ~(uint64_t) 0;		\
  ret;					\
})

/* Macro to parse a sleb128 number, return it and
   update ptr to the end of the sleb128 at the same time.  */
#define read_sleb128(ptr) ({		\
  uint64_t ret = 0;			\
  uint64_t c;				\
  int shift = 0;			\
  do					\
    {					\
      c = *ptr++;			\
      ret |= (c & 0x7f) << shift;	\
      shift += 7;			\
    } while (c & 0x80);			\
					\
  if (shift >= 70)			\
    ret = ~(uint64_t) 0;		\
  else if (c & 0x40)			\
    ret |= (-(uint64_t) 1) << shift;	\
  ret;					\
})

/* Macro to store an uleb128 number to ptr and update
   ptr to point after it.  */
#define write_uleb128(ptr, val)		\
  do					\
    {					\
      uint64_t valv = (val);		\
      do				\
	{				\
	  unsigned char c = valv & 0x7f;\
	  valv >>= 7;			\
	  if (valv)			\
	    c |= 0x80;			\
	  *ptr++ = c;			\
	}				\
      while (valv);			\
    }					\
  while (0)

#define write_sleb128(ptr, val)					\
  do								\
    {								\
      int64_t valv = (val);					\
      bool more;						\
      do							\
	{							\
	  unsigned char c = valv & 0x7f;			\
	  valv >>= 7;						\
	  more = ((valv != 0 || (c & 0x40) != 0)                \
		  && (valv != -1 || (c & 0x40) == 0));          \
	  if (more)						\
	    c |= 0x80;						\
	  *ptr++ = c;						\
	}							\
      while (more);						\
    }								\
  while (0)

/* Macro to skip a uleb128 or sleb128 number and update ptr to the end of the
   number.  */
#define skip_leb128(ptr) \
  do {} while ((*ptr++) & 0x80)

/* Macro to parse a uint16_t value represented using form, return it and
   update ptr to the end of the value at the same time.  If the value doesn't
   fit, assign true to error_p.  */
#define read_u16(ptr, form, error_p)			\
  ({							\
    uint16_t ret = 0;					\
    switch (form)					\
      {							\
      case DW_FORM_data1:				\
	ret = read_8 (ptr);				\
	break;						\
      case DW_FORM_data2:				\
	ret = read_16 (ptr);				\
	break;						\
      case DW_FORM_data4:				\
	{						\
	  uint32_t res = read_32 (ptr);			\
	  ret = (uint16_t)res;				\
	  if ((uint32_t)ret != res)			\
	    error_p = true;				\
	  break;					\
	}						\
      case DW_FORM_data8:				\
	{						\
	  uint64_t res = read_64 (ptr);			\
	  ret = (uint16_t)res;				\
	  if ((uint64_t)ret != res)			\
	    error_p = true;				\
	  break;					\
	}						\
      case DW_FORM_udata:				\
	{						\
	  uint64_t res = read_uleb128 (ptr);		\
	  ret = (uint16_t)res;				\
	  if ((uint64_t)ret != res)			\
	    error_p = true;				\
	  break;					\
	}						\
      case DW_FORM_sdata:				\
	{						\
	  union {					\
	    uint64_t u;					\
	    int64_t i;					\
	  } res;					\
	  res.u = read_sleb128 (ptr);			\
	  ret = (uint16_t)res.u;			\
	  if (res.i < 0 || (uint64_t)ret != res.u)	\
	    error_p = true;				\
	  break;					\
	}						\
      default:						\
	error_p = true;					\
	break;						\
      }							\
    ret;						\
  })

/* Pointer size in the debug info, in bytes.  Only debug info
   with a single pointer size are handled.  */
static int ptr_size;

/* Lowest debug_line version we have seen.  When writing out the multi
   file .debug_line we'll only use a DWARF5 version when there is no
   lower line table seen (since the debug_line dir and file table is
   shared between all CUs).  */
static unsigned int lowest_line_version = 5;

/* Utility functions and macros for reading/writing values in
   given ELF endianity, which might be different from host endianity.
   No specific alignment is expected.  */
static uint16_t (*do_read_16) (unsigned char *ptr);
static uint32_t (*do_read_32) (unsigned char *ptr);
static uint64_t (*do_read_64) (unsigned char *ptr);
static void (*do_write_16) (unsigned char *ptr, unsigned short val);
static void (*do_write_32) (unsigned char *ptr, unsigned int val);
static void (*do_write_64) (unsigned char *ptr, uint64_t val);

static inline uint16_t
buf_read_ule16 (unsigned char *data)
{
  return data[0] | (data[1] << 8);
}

static inline uint16_t
buf_read_ube16 (unsigned char *data)
{
  return data[1] | (data[0] << 8);
}

static inline uint32_t
buf_read_ule32 (unsigned char *data)
{
  return (data[0] | (data[1] << 8) | (data[2] << 16)
	  | ((unsigned int)data[3] << 24));
}

static inline uint32_t
buf_read_ube32 (unsigned char *data)
{
  return (data[3] | (data[2] << 8) | (data[1] << 16)
	  | ((unsigned int)data[0] << 24));
}

static inline uint64_t
buf_read_ule64 (unsigned char *data)
{
  return buf_read_ule32 (data)
	 | (((uint64_t) buf_read_ule32 (data + 4)) << 32);
}

static inline uint64_t
buf_read_ube64 (unsigned char *data)
{
  return (((uint64_t) buf_read_ube32 (data)) << 32)
	 | buf_read_ube32 (data + 4);
}

#define read_8(ptr) *ptr++

#define read_16(ptr) ({					\
  uint16_t ret = do_read_16 (ptr);			\
  ptr += 2;						\
  ret;							\
})

#define read_32(ptr) ({					\
  uint32_t ret = do_read_32 (ptr);			\
  ptr += 4;						\
  ret;							\
})

#define read_64(ptr) ({					\
  uint64_t ret = do_read_64 (ptr);			\
  ptr += 8;						\
  ret;							\
})

#define write_8(ptr, val)				\
  do							\
    *ptr++ = (val);					\
  while (0)

#define write_16(ptr, val)				\
  do							\
    {							\
      do_write_16 (ptr, val);				\
      ptr += 2;						\
    }							\
  while (0)

#define write_32(ptr, val)				\
  do							\
    {							\
      do_write_32 (ptr, val);				\
      ptr += 4;						\
    }							\
  while (0)

#define write_64(ptr, val)				\
  do							\
    {							\
      do_write_64 (ptr, val);				\
      ptr += 8;						\
    }							\
  while (0)

static uint64_t
read_size (unsigned char *p, int size)
{
  switch (size)
    {
    case 1: return read_8 (p);
    case 2: return read_16 (p);
    case 4: return read_32 (p);
    case 8: return read_64 (p);
    default: abort ();
    }
}

static void
write_size (unsigned char *p, int size, uint64_t val)
{
  switch (size)
    {
    case 1: write_8 (p, val); break;
    case 2: write_16 (p, val); break;
    case 4: write_32 (p, val); break;
    case 8: write_64 (p, val); break;
    default: abort ();
    }
}

static void
buf_write_le16 (unsigned char *p, unsigned short v)
{
  p[0] = v;
  p[1] = v >> 8;
}

static void
buf_write_be16 (unsigned char *p, unsigned short v)
{
  p[1] = v;
  p[0] = v >> 8;
}

static void
buf_write_le32 (unsigned char *p, unsigned int v)
{
  p[0] = v;
  p[1] = v >> 8;
  p[2] = v >> 16;
  p[3] = v >> 24;
}

static void
buf_write_be32 (unsigned char *p, unsigned int v)
{
  p[3] = v;
  p[2] = v >> 8;
  p[1] = v >> 16;
  p[0] = v >> 24;
}

static void
buf_write_le64 (unsigned char *data, uint64_t v)
{
  buf_write_le32 (data, v);
  buf_write_le32 (data + 4, v >> 32);
}

static void
buf_write_be64 (unsigned char *data, uint64_t v)
{
  buf_write_be32 (data, v >> 32);
  buf_write_be32 (data + 4, v);
}

/* Return a DW_FORM_* name.  */
static const char *
get_DW_FORM_str (unsigned int form)
{
  const char *name = get_DW_FORM_name (form);
  static char buf[9 + 3 * sizeof (int)];
  if (name)
    return name;
  sprintf (buf, "DW_FORM_%u", form);
  return buf;
}

/* Return a DW_OP_* name.  */
static const char *
get_DW_OP_str (unsigned int op)
{
  const char *name = get_DW_OP_name (op);
  static char buf[7 + 3 * sizeof (int)];
  if (name)
    return name;
  sprintf (buf, "DW_OP_%u", op);
  return buf;
}

/* Return a DW_AT_* name.  */
static const char *
get_DW_AT_str (unsigned int at)
{
  const char *name = get_DW_AT_name (at);
  static char buf[7 + 3 * sizeof (int)];
  if (name)
    return name;
  sprintf (buf, "DW_AT_%u", at);
  return buf;
}

/* Return a DW_UT_* name.  */
static const char *
get_DW_UT_str (unsigned int ut)
{
  const char *name = get_DW_UT_name (ut);
  static char buf[7 + 3 * sizeof (int)];
  if (name)
    return name;
  sprintf (buf, "DW_UT_%u", ut);
  return buf;
}

/* Retrun a DW_LNCT_* name.  */
static const char *
get_DW_LNCT_str (unsigned int lnct)
{
  const char *name;
  static char buf[9 + 3 * sizeof (int)];
  switch (lnct)
    {
    case DW_LNCT_path: name = "DW_LNCT_path"; break;
    case DW_LNCT_directory_index: name = "DW_LNCT_directory_index"; break;
    case DW_LNCT_timestamp: name = "DW_LNCT_timestamp"; break;
    case DW_LNCT_size: name = "DW_LNCT_size"; break;
    case DW_LNCT_MD5: name = "DW_LNCT_MD5"; break;

    default: name = 0; break;
    }
  if (name)
    return name;
  sprintf (buf, "DW_LNCT_%u", lnct);
  return buf;
}

/* This must match the debug_sections array content
   below.  */
enum debug_section_kind
{
  DEBUG_INFO,
  DEBUG_ABBREV,
  DEBUG_LINE,
  DEBUG_STR,
  DEBUG_MACRO,
  DEBUG_TYPES,
  DEBUG_ARANGES,
  DEBUG_PUBNAMES,
  DEBUG_PUBTYPES,
  DEBUG_GNU_PUBNAMES,
  DEBUG_GNU_PUBTYPES,
  DEBUG_MACINFO,
  DEBUG_LOC,
  DEBUG_LOCLISTS,
  DEBUG_FRAME,
  DEBUG_RANGES,
  DEBUG_RNGLISTS,
  DEBUG_LINE_STR,
  DEBUG_SUP,
  DEBUG_GDB_SCRIPTS,
  GDB_INDEX,
  GNU_DEBUGALTLINK,
  SECTION_COUNT,
  SAVED_SECTIONS = DEBUG_TYPES + 1
};

/* Details about standard DWARF sections.  */
static struct
{
  const char *name;
  unsigned char *data;
  unsigned char *new_data;
  size_t size;
  size_t new_size;
  int sec;
} debug_sections[] =
  {
    { ".debug_info", NULL, NULL, 0, 0, 0 },
    { ".debug_abbrev", NULL, NULL, 0, 0, 0 },
    { ".debug_line", NULL, NULL, 0, 0, 0 },
    { ".debug_str", NULL, NULL, 0, 0, 0 },
    { ".debug_macro", NULL, NULL, 0, 0, 0 },
    { ".debug_types", NULL, NULL, 0, 0, 0 },
    { ".debug_aranges", NULL, NULL, 0, 0, 0 },
    { ".debug_pubnames", NULL, NULL, 0, 0, 0 },
    { ".debug_pubtypes", NULL, NULL, 0, 0, 0 },
    { ".debug_gnu_pubnames", NULL, NULL, 0, 0, 0 },
    { ".debug_gnu_pubtypes", NULL, NULL, 0, 0, 0 },
    { ".debug_macinfo", NULL, NULL, 0, 0, 0 },
    { ".debug_loc", NULL, NULL, 0, 0, 0 },
    { ".debug_loclists", NULL, NULL, 0, 0, 0 },
    { ".debug_frame", NULL, NULL, 0, 0, 0 },
    { ".debug_ranges", NULL, NULL, 0, 0, 0 },
    { ".debug_rnglists", NULL, NULL, 0, 0, 0 },
    { ".debug_line_str", NULL, NULL, 0, 0, 0 },
    { ".debug_sup", NULL, NULL, 0, 0, 0 },
    { ".debug_gdb_scripts", NULL, NULL, 0, 0, 0 },
    { ".gdb_index", NULL, NULL, 0, 0, 0 },
    { ".gnu_debugaltlink", NULL, NULL, 0, 0, 0 },
    { NULL, NULL, NULL, 0, 0, 0 }
  };

/* Copies of .new_data fields during write_multifile.  */
static unsigned char *saved_new_data[SAVED_SECTIONS];
/* Copies of .new_size fields during write_multifile.  */
static size_t saved_new_size[SAVED_SECTIONS];

/* Copies of .data fields after read_multifile.  */
static unsigned char *alt_data[SAVED_SECTIONS];
/* Copies of .size fields after read_multifile.  */
static size_t alt_size[SAVED_SECTIONS];

/* How many bytes of each of /tmp/dwz.debug_*.XXXXXX have we written
   already.  */
static unsigned int multi_info_off, multi_abbrev_off;
static unsigned int multi_line_off, multi_str_off;
static unsigned int multi_macro_off;
/* And corresponding file descriptors.  */
static int multi_info_fd = -1, multi_abbrev_fd = -1;
static int multi_line_fd = -1, multi_str_fd = -1;
static int multi_macro_fd = -1;

/* Copy of one of the input file's ehdr.  */
static GElf_Ehdr multi_ehdr;

/* Pointer size of all debug info sources accumulated during
   write_multifile.  */
static int multi_ptr_size;
/* And their endianity.  */
static int multi_endian;
/* Highest .gdb_index version seen.  */
static unsigned int multi_gdb_index_ver;

enum multifile_mode_kind
{
  MULTIFILE_MODE_WR = 1,
  MULTIFILE_MODE_OP = 2,
  MULTIFILE_MODE_RD = 4,
  MULTIFILE_MODE_FI = 8,
  MULTIFILE_MODE_LOW_MEM = 16
};

/* True while in write_multifile.  */
#define wr_multifile (multifile_mode & MULTIFILE_MODE_WR)

/* True while in optimize_multifile.  */
#define op_multifile (multifile_mode & MULTIFILE_MODE_OP)

/* True while in read_multifile.  */
#define rd_multifile (multifile_mode & MULTIFILE_MODE_RD)

/* True while in finalize_multifile.  */
#define fi_multifile (multifile_mode & MULTIFILE_MODE_FI)

/* True if running in low_mem mode.  */
#define low_mem (multifile_mode & MULTIFILE_MODE_LOW_MEM)

/* SHA1 checksum (build-id) of the common file.  */
static unsigned char multifile_sha1[0x14];

/* A single attribute in abbreviations.  */
struct abbrev_attr
{
  /* DW_AT_* attribute code.  */
  unsigned int attr;
  /* DW_FORM_* form code.  */
  unsigned int form;
};

/* Internal structure for .debug_abbrev entries.  */
struct abbrev_tag
{
  /* Abbreviation number.  */
  unsigned int entry;
  /* Hash value, in first abbrev hash tables it is
     the same as entry, in cu->cu_new_abbrev hash tables
     iterative hash of all the relevant values.  */
  hashval_t hash;
  /* DW_TAG_* code.  */
  unsigned int tag;
  /* Number of attributes.  */
  unsigned int nattr;
  /* How many DIEs refer to this abbreviation (unused
     in first abbrev hash tables).  */
  unsigned int nusers;
  /* True if DIEs with this abbreviation have children.  */
  bool children;
  /* True if any typed DWARF opcodes refer to this.  */
  bool op_type_referenced;
  /* The values of DW_FORM_implicit_const attribute forms.  */
  int64_t *values;
  /* Attribute/form pairs.  */
  struct abbrev_attr attr[0];
};

typedef struct dw_die *dw_die_ref;
typedef struct dw_cu *dw_cu_ref;
struct import_cu;

/* An entry from .debug_line file table.  */
struct dw_file
{
  char *dir;
  char *file;
  uint64_t time, size;
  unsigned int file_angle_brackets_encapsulated_no_slash : 1;
};

/* Internal representation of a compilation (or partial)
   unit.  */
struct dw_cu
{
  /* Cached entries from .debug_line file table.  */
  struct dw_file *cu_files;
  unsigned int cu_nfiles;
  /* Kind of CU, normal (present in .debug_info), newly created
     partial unit, .debug_types unit or .debug_info partial unit
     from the common file.  */
  enum { CU_NORMAL, CU_PU, CU_TYPES, CU_ALT } cu_kind;
  /* CUs linked from first_cu through this chain.  */
  dw_cu_ref cu_next;
  /* Offset in original .debug_info if CU_NORMAL or .debug_types
     if CU_TYPES, otherwise a unique index of the newly created
     partial CU.  */
  unsigned int cu_offset;
  /* DWARF version of the CU.  */
  unsigned int cu_version;
  /* Cached DW_AT_comp_dir value from DW_TAG_*_unit cu_die,
     or NULL if that attribute is not present.  */
  char *cu_comp_dir;
  /* Pointer to the DW_TAG_*_unit inside of the .debug_info
     chunk.  */
  dw_die_ref cu_die;
  /* The original abbreviation hash table.  */
  htab_t cu_abbrev;
  /* New abbreviation hash table.  */
  htab_t cu_new_abbrev;
  union dw_cu_u1
    {
      /* Pointer to another struct dw_cu that owns
	 cu_new_abbrev for this CU.  */
      dw_cu_ref cu_new_abbrev_owner;
      /* Pointer used during create_import_tree.  */
      struct import_cu *cu_icu;
    } u1;
  union dw_cu_u2
    {
      /* Offset into the new .debug_abbrev section.  */
      unsigned int cu_new_abbrev_offset;
      /* Highest ->entry value in the new abbrev table
	 For abbrevs computed by this tool it is always
	 equal to the number of abbreviations, but if
	 abbrevs are read for .debug_types section which
	 is not rewritten, there might be holes.  */
      unsigned int cu_largest_entry;
    } u2;
  /* Offset into the new .debug_info section.  */
  unsigned int cu_new_offset;
  /* When op_multifile, record which object this came from here,
     otherwise it is the index of the CU.  */
  unsigned int cu_chunk;
  /* Form chosen for intra-cu references.  */
  enum dwarf_form cu_intracu_form;
  /* Intracusize argument to init_new_die_offsets.  Set in compute_abbrevs,
     used in recompute_abbrevs.  */
  unsigned int initial_intracusize;
  enum dwarf_source_language lang;
};

/* Internal representation of a debugging information entry (DIE).
   This structure should be kept as small as possible,
   there are .debug_info sections with tens of millions of DIEs
   in them and this structure is allocated for each of them.  */
struct dw_die
{
  /* Offset in old .debug_info from the start of the .debug_info section,
     -1U for newly created DIEs.  */
  unsigned int die_offset;
  /* Cached copy of die_abbrev->tag.  */
  enum dwarf_tag die_tag : 16;
  /* State of checksum computation.  Not computed yet, computed and
     suitable for moving into partial units, currently being computed
     and finally determined unsuitable for moving into partial units.  */
  enum { CK_UNKNOWN, CK_KNOWN, CK_BEING_COMPUTED, CK_BAD } die_ck_state : 2;
  /* Set if any DW_OP_call2 opcode refers to this DIE.  */
  unsigned int die_op_call2_referenced : 1;
  /* Set if any DW_OP_GNU_{{regval,deref,const}_type,convert,reinterpret}
     opcode refers to this DIE.  Only DW_TAG_base_type DIEs should be
     referenced.  As those opcodes refer to them using uleb128, we need to try
     hard to have those DIEs with low enough offsets that the uleb128 will
     fit.  */
  unsigned int die_op_type_referenced : 1;
  /* Set in DW_TAG_namespace or DW_TAG_module with DW_AT_name that is
     either a child of DW_TAG_*_unit, or a child of another
     die_named_namespace DIE.  */
  unsigned int die_named_namespace : 1;
  /* Set if u.p1.die_ref_hash is valid.  */
  unsigned int die_ref_hash_computed : 1;
  /* Set if die_dup and die_nextdup fields are after this structure.
     True for DW_TAG_*_unit DIEs, die_named_namespace DIEs and their
     immediate children.  */
  unsigned int die_toplevel : 1;
  /* Set if we want to remove this DIE from its containing CU.  */
  unsigned int die_remove : 1;
  /* Set if DIE is unsuitable for moving into alternate .debug_info.  */
  unsigned int die_no_multifile : 1;
  /* Set if DIE is referenced using DW_FORM_ref*.  So far only used during
     optimize_multifile and low_mem.  */
  unsigned int die_referenced : 1;
  /* Set if DIE is referenced using DW_FORM_ref_addr.  So far used only
     during low_mem.  */
  unsigned int die_intercu_referenced : 1;
  /* Set if DIE has its children collapsed.  Only used during
     optimize_multifile.  */
  unsigned int die_collapsed_children : 1;
  /* Set on collapsed child DIE that is referenced.  In that case, die_tag
     is reused for die_enter difference from parent and no fields after
     die_parent are allocated.  */
  unsigned int die_collapsed_child : 1;
  /* Set if die_parent field is reused for struct dw_cu pointer.  */
  unsigned int die_root : 1;
  /* State for ODR optimization.  */
  enum { ODR_UNKNOWN, ODR_NONE, ODR_DEF, ODR_DECL } die_odr_state : 2;
  /* Tree pointer to parent.  */
  dw_die_ref die_parent;

  /* The remaining fields are present only if die_collapsed_child is
     0.  */

  /* Tree pointers, to first child and pointer to next sibling.  */
  dw_die_ref die_child, die_sib;
  /* Pointer to the old .debug_abbrev entry's internal representation.  */
  struct abbrev_tag *die_abbrev;
  /* Size of the DIE (abbrev number + attributes), not including children.
     In later phases this holds the new size as opposed to the old one.  */
  unsigned int die_size;
  /* Index into the dw_die_ref vector used in checksum_ref_die function.
     While this is only phase 1 field, we get better packing by having it
     here instead of u.p1.  */
  unsigned int die_ref_seen;
  union dw_die_phase
    {
      /* Fields used in the first phase (read_debug_info and partition_dups
	 and functions they call).  */
      struct dw_die_p1
	{
	  /* Iterative hash value of the tag, attributes other than
	     references or DW_FORM_ref_addr references or references
	     within the subtree of ultimate parent's die_toplevel DIE's
	     children.  Computed by checksum_die function.  */
	  hashval_t die_hash;
	  /* Iterative hash of other references.  Computed by
	     checksum_ref_die function.  */
	  hashval_t die_ref_hash;
	  /* For ODR phase 1, we change die_hash for ODR_DEF and ODR_DECL DIEs
	     to only hash in the tag and the name, to be able to construct
	     maximal duplicate chains.  But during ODR phase 2, we want to
	     compare ODR_DEF DIEs in the normal way, for which we need the
	     unchanged die_hash, which we store here in die_hash2.  */
	  hashval_t die_hash2;
	  /* Tick count of entering and leaving a DIE during depth first
	     traversal of the CU, used to quickly find if a subtree is
	     referenced.  */
	  unsigned int die_enter, die_exit;
	} p1;
      /* Fields used only after the first phase (from compute_abbrevs
	 till the end).  */
      struct dw_die_p2
	{
	  /* Pointer to internal representation of new .debug_abbrev
	     entry for this DIE.  */
	  struct abbrev_tag *die_new_abbrev;
	  /* Offset within the new .debug_info CU.  Unlike die_offset
	     this one is CU relative, so die_cu (die)->cu_new_offset needs
	     to be added to it to get .debug_info offset.  */
	  unsigned int die_new_offset;
	  /* Used during compute_abbrevs DW_FORM_ref_udata optimization.  */
	  unsigned int die_intracu_udata_size;
	} p2;
     } u;

  /* The remaining fields are present only if die_toplevel is
     1.  */

  /* Pointer to a duplicate DIE.  */
  dw_die_ref die_dup;
  /* Chain of duplicate DIEs.  If die_dup is NULL, but die_nextdup
     is non-NULL, this is the reference DIE of the duplicates.
     All DIEs in the die->nextdup linked list have die_dup pointing
     to this node.  The reference DIE is initially just a DIE in the
     lowest CU that has the matching DIE, later on it is a DIE in
     the newly created partial unit CU.  */
  dw_die_ref die_nextdup;
};

#include "iterators.h"

/* Return CU structure pointer for a DIE.  In order to save memory,
   individual DIEs don't have a dw_cu_ref field, and the pointer can
   be only found by overriding the die_parent pointer in a
   DW_TAG_{compile,partial}_unit descriptor, which has no parent.  */
static inline dw_cu_ref
die_cu (dw_die_ref die)
{
  while (!die->die_root)
    die = die->die_parent;
  return (dw_cu_ref) die->die_parent;
}

/* Given a toplevel die DIE, return the first (that is, the reference die) in
   the duplicate chain.  */
#define first_dup(die)				\
  (die->die_dup					\
   ? die->die_dup				\
   : (die->die_nextdup				\
      ? die					\
      : NULL))

/* Safe variant that check die_toplevel.  Can't be used on LHS.  */
#define die_safe_dup(die) \
  ((die)->die_toplevel ? (die)->die_dup : (dw_die_ref) NULL)
#define die_safe_nextdup(die) \
  ((die)->die_toplevel ? (die)->die_nextdup : (dw_die_ref) NULL)

#ifdef __GNUC__
# define ALIGN_STRUCT(name)
#else
# define ALIGN_STRUCT(name) struct align_##name { char c; struct name s; };
#endif
ALIGN_STRUCT (abbrev_tag)
ALIGN_STRUCT (dw_file)
ALIGN_STRUCT (dw_cu)
ALIGN_STRUCT (dw_die)

/* Big pool allocator.  obstack isn't efficient, because it aligns everything
   too much, and allocates too small chunks.  All these objects are only freed
   together.  */

/* Pointer to the start of the current pool chunk, current first free byte
   in the chunk and byte after the end of the current pool chunk.  */
static unsigned char *pool, *pool_next, *pool_limit;

/* After read_multifile, pool variable is moved over to this variable
   as the pool from read_multifile needs to be around for subsequent dwz
   calls.  Freed only during the final cleanup at the very end.  */
static unsigned char *alt_pool;

/* Allocate SIZE bytes with ALIGN bytes alignment from the pool.  */
static void *
pool_alloc_1 (unsigned int align, unsigned int size)
{
  void *ret;
  if (pool == NULL
      || (size_t) (pool_limit - pool_next) < (size_t) align + size)
    {
      size_t new_size = (size_t) align + size;
      unsigned char *new_pool;
      new_size += sizeof (void *);
      if (new_size < 16384 * 1024 - 64)
	new_size = 16384 * 1024 - 64;
      new_pool = (unsigned char *) malloc (new_size);
      if (new_pool == NULL)
	dwz_oom ();
      *(unsigned char **) new_pool = pool;
      pool_next = new_pool + sizeof (unsigned char *);
      pool_limit = new_pool + new_size;
      pool = new_pool;
    }
  pool_next = (unsigned char *) (((uintptr_t) pool_next + align - 1)
				 & ~(uintptr_t) (align - 1));
  ret = pool_next;
  pool_next += size;
  return ret;
}

/* Free the whole pool.  */
static void
pool_destroy (void)
{
  pool_next = NULL;
  pool_limit = NULL;
  while (pool)
    {
      void *p = (void *) pool;
      pool = *(unsigned char **) pool;
      free (p);
    }
}

#ifdef __GNUC__
# define pool_alloc(name, size) \
  (struct name *) pool_alloc_1 (__alignof__ (struct name), size)
#else
# define pool_alloc(name, size) \
  (struct name *) pool_alloc_1 (offsetof (struct align_##name, s), size)
#endif

static struct abbrev_tag *
pool_clone_abbrev (struct abbrev_tag *t)
{
  struct abbrev_tag *newt;
  size_t newt_size;
  unsigned nvalue = 0;
  if (t->values != NULL)
    {
      unsigned i;
      for (i = 0; i < t->nattr; i++)
	if (t->attr[i].form == DW_FORM_implicit_const)
	  nvalue = i + 1;
    }
  newt_size = (sizeof (*newt)
	       + t->nattr * sizeof (struct abbrev_attr)
	       + nvalue * sizeof (int64_t));
  newt = pool_alloc (abbrev_tag, newt_size);
  memcpy (newt, t, newt_size - (nvalue * sizeof (int64_t)));
  if (nvalue == 0)
    newt->values = NULL;
  else
    {
      newt->values = (int64_t *) &newt->attr[newt->nattr];
      memcpy (newt->values, t->values, nvalue * sizeof (int64_t));
    }
  return newt;
}

/* Hash function in first abbrev hash table as well as cu->cu_new_abbrev
   htab.  */
static hashval_t
abbrev_hash (const void *p)
{
  struct abbrev_tag *t = (struct abbrev_tag *)p;

  return t->hash;
}

/* Equality function in first abbrev htab.  */
static int
abbrev_eq (const void *p, const void *q)
{
  struct abbrev_tag *t1 = (struct abbrev_tag *)p;
  struct abbrev_tag *t2 = (struct abbrev_tag *)q;

  return t1->entry == t2->entry;
}

/* Equality function in cu->cu_new_abbrev htab.  */
static int
abbrev_eq2 (const void *p, const void *q)
{
  struct abbrev_tag *t1 = (struct abbrev_tag *)p;
  struct abbrev_tag *t2 = (struct abbrev_tag *)q;
  unsigned int i;

  if (t1->hash != t2->hash
      || t1->tag != t2->tag
      || t1->nattr != t2->nattr
      || t1->children != t2->children)
    return 0;
  for (i = 0; i < t1->nattr; i++)
    if (t1->attr[i].attr != t2->attr[i].attr
	|| t1->attr[i].form != t2->attr[i].form
	|| (t1->attr[i].form == DW_FORM_implicit_const
	    && t1->values[i] != t2->values[i]))
      return 0;
  return 1;
}

/* Helper function to compute abbrev entry iterative hash value.  */
static void
compute_abbrev_hash (struct abbrev_tag *t)
{
  unsigned int i;

  t->hash = iterative_hash_object (t->tag, 0);
  t->hash = iterative_hash_object (t->nattr, t->hash);
  t->hash = iterative_hash_object (t->children, t->hash);
  for (i = 0; i < t->nattr; i++)
    {
      t->hash = iterative_hash_object (t->attr[i].attr, t->hash);
      t->hash = iterative_hash_object (t->attr[i].form, t->hash);
      if (t->attr[i].form == DW_FORM_implicit_const)
	t->hash = iterative_hash_object (t->values[i], t->hash);
    }
}

/* Maximum number of attributes in a DIE.  */
static unsigned int max_nattr;

/* Parse a .debug_abbrev entry at PTR.  */
static htab_t
read_abbrev (DSO *dso, unsigned char *ptr)
{
  htab_t h;
  unsigned int attr, form;
  struct abbrev_tag *t;
  void **slot;

  h = htab_try_create (50, abbrev_hash, abbrev_eq, NULL);
  if (h == NULL)
    dwz_oom ();

  while ((attr = read_uleb128 (ptr)) != 0)
    {
      int highest_implicit_value_ndx = -1;
      unsigned int nattr = 0;
      unsigned char *p = ptr;

      skip_leb128 (p);
      p++;
      while (read_uleb128 (p) != 0)
	{
	  nattr++;
	  form = read_uleb128 (p);
	  if (form == DW_FORM_implicit_const)
	    {
	      skip_leb128 (p);
	      highest_implicit_value_ndx = nattr - 1;
	    }
	  else if (form == 2
	      || (form > DW_FORM_flag_present
		  && !(form == DW_FORM_ref_sig8
		       || form == DW_FORM_data16
		       || form == DW_FORM_line_strp)))
	    {
	      error (0, 0, "%s: Unknown DWARF %s",
		     dso->filename, get_DW_FORM_str (form));
	      htab_delete (h);
	      return NULL;
	    }
	}
      if (read_uleb128 (p) != 0)
	{
	  error (0, 0, "%s: DWARF abbreviation does not end with 2 zeros",
		 dso->filename);
	  htab_delete (h);
	  return NULL;
	}

      t = pool_alloc (abbrev_tag,
		      sizeof (*t) + nattr * sizeof (struct abbrev_attr)
		      + sizeof (int64_t) * (highest_implicit_value_ndx + 1));
      t->entry = attr;
      t->hash = attr;
      t->nattr = nattr;
      t->nusers = 0;
      t->tag = read_uleb128 (ptr);
      t->children = *ptr++ == DW_CHILDREN_yes;
      t->op_type_referenced = false;
      t->values = (highest_implicit_value_ndx >= 0
		   ? (int64_t *) &t->attr[nattr] : NULL);
      nattr = 0;
      while ((attr = read_uleb128 (ptr)) != 0)
	{
	  form = read_uleb128 (ptr);
	  if (form == DW_FORM_implicit_const)
	    t->values[nattr] = read_sleb128 (ptr);
	  t->attr[nattr].attr = attr;
	  t->attr[nattr++].form = form;
	}
      skip_leb128 (ptr);
      if (t->nattr > max_nattr)
	max_nattr = t->nattr;
      slot = htab_find_slot_with_hash (h, t, t->hash, INSERT);
      if (slot == NULL)
	{
	  htab_delete (h);
	  dwz_oom ();
	}
      if (*slot != NULL)
	{
	  error (0, 0, "%s: Duplicate DWARF abbreviation %d", dso->filename,
		 t->entry);
	  htab_delete (h);
	  return NULL;
	}
      *slot = t;
    }

  return h;
}

/* For a die attribute with form FORM starting at PTR, with the die in CU,
   return the pointer after the attribute, assuming FORM is not
   dw_form_indirect.  */
static inline unsigned char * FORCE_INLINE
skip_attr_no_dw_form_indirect (unsigned int cu_version, uint32_t form,
			       unsigned char *ptr)
{
  size_t len = 0;

  switch (form)
    {
    case DW_FORM_ref_addr:
      ptr += cu_version == 2 ? ptr_size : 4;
      break;
    case DW_FORM_addr:
      ptr += ptr_size;
      break;
    case DW_FORM_flag_present:
    case DW_FORM_implicit_const:
      break;
    case DW_FORM_ref1:
    case DW_FORM_flag:
    case DW_FORM_data1:
      ++ptr;
      break;
    case DW_FORM_ref2:
    case DW_FORM_data2:
      ptr += 2;
      break;
    case DW_FORM_ref4:
    case DW_FORM_data4:
    case DW_FORM_sec_offset:
    case DW_FORM_strp:
    case DW_FORM_line_strp:
      ptr += 4;
      break;
    case DW_FORM_ref8:
    case DW_FORM_data8:
    case DW_FORM_ref_sig8:
      ptr += 8;
      break;
    case DW_FORM_data16:
      ptr += 16;
      break;
    case DW_FORM_sdata:
    case DW_FORM_ref_udata:
    case DW_FORM_udata:
      skip_leb128 (ptr);
      break;
    case DW_FORM_string:
      ptr = (unsigned char *) strchr ((char *)ptr, '\0') + 1;
      break;
    case DW_FORM_indirect:
      abort ();
    case DW_FORM_block1:
      len = *ptr++;
      break;
    case DW_FORM_block2:
      len = read_16 (ptr);
      form = DW_FORM_block1;
      break;
    case DW_FORM_block4:
      len = read_32 (ptr);
      form = DW_FORM_block1;
      break;
    case DW_FORM_block:
    case DW_FORM_exprloc:
      len = read_uleb128 (ptr);
      form = DW_FORM_block1;
      break;
    default:
      abort ();
    }

  if (form == DW_FORM_block1)
    ptr += len;

  return ptr;
}

/* Read the directory and file table from .debug_line offset OFF,
   record it in CU.  */
static int
read_debug_line (DSO *dso, dw_cu_ref cu, uint32_t off)
{
  unsigned char *ptr = debug_sections[DEBUG_LINE].data, *dir, *file;
  unsigned char **dirt;
  unsigned char *endsec = ptr + debug_sections[DEBUG_LINE].size;
  unsigned char *endcu, *endprol;
  unsigned char opcode_base;
  unsigned int culen;
  uint32_t value, version, ndirs, nfiles, dirt_cnt, file_cnt;
  /* DWARF5 has a dynamic table of elements in possible different
     forms.  But we are only interested in the known elements (path,
     dir index, time, size and possibly later md5).  */
  unsigned char n, nelems = 0;
  int path_ndx = -1;
  int dir_ndx = -1;
  int time_ndx = -1;
  int size_ndx = -1;
  uint16_t elems[256];

  if (off >= debug_sections[DEBUG_LINE].size - 4)
    {
      error (0, 0, "%s: .debug_line reference above end of section",
	     dso->filename);
      return 1;
    }

  ptr += off;

  endcu = ptr + 4;
  culen = read_32 (ptr);
  if (culen >= 0xfffffff0)
    {
      error (0, 0, "%s: 64-bit DWARF not supported", dso->filename);
      return 1;
    }
  endcu += culen;

  if (endcu > endsec)
    {
      error (0, 0, "%s: .debug_line CU does not fit into section",
	     dso->filename);
      return 1;
    }

  value = read_16 (ptr);
  if (value < 2 || value > 5)
    {
      error (0, 0, "%s: DWARF version %d in .debug_line unhandled",
	     dso->filename, value);
      return 1;
    }
  version = value;

  if (version < lowest_line_version)
    lowest_line_version = version;

  if (version >= 5)
    {
      int addr_size, seg_size;
      if (ptr + 2 > endcu)
	{
	  error (0, 0, "%s: .debug_line header too short", dso->filename);
	  return 1;
	}
      addr_size = *ptr++;
      seg_size = *ptr++;
      if (addr_size != ptr_size)
	{
	  error (0, 0, "%s: .debug_line address size differs from CU ptr size",
		 dso->filename);
	  return 1;
	}
      if (seg_size != 0)
	{
	  error (0, 0, "%s: .debug_line non-zero segment selector size",
		 dso->filename);
	  return 1;
	}
    }

  endprol = ptr + 4;
  endprol += read_32 (ptr);
  if (endprol > endcu)
    {
      error (0, 0, "%s: .debug_line CU prologue does not fit into CU",
	     dso->filename);
      return 1;
    }

  opcode_base = ptr[4 + (version >= 4)];
  ptr = dir = ptr + 4 + (version >= 4) + opcode_base;

  /* dir table: */
  if (version < 5)
    {
      value = 1;
      while (*ptr != 0)
	{
	  ptr = (unsigned char *) strchr ((char *)ptr, 0) + 1;
	  ++value;
	}
      ndirs = value;
    }
  else
    {
      nelems = *ptr++;
      for (n = 0; n < nelems; n++)
	{
	  uint16_t lnct = read_uleb128 (ptr);
	  uint16_t form = read_uleb128 (ptr);
	  if (lnct == DW_LNCT_path)
	    {
	      if (path_ndx != -1)
		{
		  error (0, 0, "%s: .debug_line duplicate dir path elements",
			 dso->filename);
		  return 1;
		}
	      path_ndx = n;
	    }
	  else
	    {
	      error (0, 0, "%s: .debug_line unhandled dir element %s",
		     dso->filename, get_DW_LNCT_str (lnct));
	      return 1;
	    }

	  if (form != DW_FORM_string
	      && form != DW_FORM_strp
	      && form != DW_FORM_line_strp)
	    {
	      error (0, 0, "%s: .debug_line unhandled form %s for dir path",
		     dso->filename, get_DW_FORM_str (form));
	      return 1;
	    }

	  elems[n] = form;
	}

      ndirs = read_uleb128 (ptr);
    }

  dirt = (unsigned char **) alloca (ndirs * sizeof (unsigned char *));
  if (version < 5)
    {
      dirt[0] = NULL;
      dirt_cnt = 1;
      ptr = dir;
      while (*ptr != 0)
	{
	  dirt[dirt_cnt++] = ptr;
	  ptr = (unsigned char *) strchr ((char *)ptr, 0) + 1;
	}
      ptr++;
    }
  else
    {
      for (dirt_cnt = 0; dirt_cnt < ndirs; dirt_cnt++)
	{
	  for (n = 0; n < nelems; n++)
	    {
	      uint32_t form = elems[n];
	      if (n == path_ndx)
		{
		  unsigned char *d;
		  switch (form)
		    {
		    case DW_FORM_string:
		      d = (unsigned char *) ptr;
		      break;
		    case DW_FORM_strp:
		      {
			unsigned int strp = do_read_32 (ptr);
			if (strp >= debug_sections[DEBUG_STR].size)
			  d = NULL;
			else
			  d = ((unsigned char *)
			       debug_sections[DEBUG_STR].data
			       + strp);
		      }
		      break;
		    case DW_FORM_line_strp:
		      {
			unsigned int line_strp = do_read_32 (ptr);
			if (line_strp >= debug_sections[DEBUG_LINE_STR].size)
			  d = NULL;
			else
			  d = ((unsigned char *)
			       debug_sections[DEBUG_LINE_STR].data
			       + line_strp);
		      }
		      break;
		    default:
		      d = NULL;
		      break;
		    }

		  if (d == NULL)
		    {
		      error (0, 0, "%s: .debug_line bad dir path",
			     dso->filename);
		      return 1;
		    }

		  /* Note we do this even for the zero entry, which is
		     marked as NULL for pre-DWARF5 line tables.  This
		     is important for when we merge file entries
		     together for a multifile because the zero dir
		     entry could differ.  It is should be equivalent
		     to the CU DIE comp_dir attribute, but we don't
		     track that all CUs referring to the (same) line
		     table share identical an DW_AT_comp_dir value.  */
		  dirt[dirt_cnt] = d;
		}
	      ptr = skip_attr_no_dw_form_indirect (cu->cu_version, form, ptr);
	    }
	}
    }

  /* file table: */
  file = ptr;
  if (version < 5)
    {
      file_cnt = 0;
      while (*ptr != 0)
	{
	  ptr = (unsigned char *) strchr ((char *)ptr, 0) + 1;
	  value = read_uleb128 (ptr);

	  if (value >= dirt_cnt)
	    {
	      error (0, 0, "%s: Wrong directory table index %u",
		     dso->filename, value);
	      return 1;
	    }

	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  file_cnt++;
	}
      nfiles = file_cnt;
    }
  else
    {
      nelems = *ptr++;
      path_ndx = -1;
      for (n = 0; n < nelems; n++)
	{
	  uint16_t lnct = read_uleb128 (ptr);
	  uint16_t form = read_uleb128 (ptr);
	  switch (lnct)
	    {
	    case DW_LNCT_path:
	      if (path_ndx != -1)
		{
		  error (0, 0,
			 "%s: .debug_line duplicate file path elements",
			 dso->filename);
		  return 1;
		}
	      path_ndx = n;

	      /* Currently we only handle two string form which always
		 stay... */
	      if (form != DW_FORM_string && form != DW_FORM_line_strp)
		{
		  error (0, 0,
			 "%s: .debug_line unhandled form %s for file path",
			 dso->filename, get_DW_FORM_str (form));
		  return 1;
		}
	      break;

	    case DW_LNCT_directory_index:
	      if (dir_ndx != -1)
		{
		  error (0, 0,
			 "%s: .debug_line duplicate file dir elements",
			 dso->filename);
		  return 1;
		}
	      dir_ndx = n;

	      if (form != DW_FORM_data1
		  && form != DW_FORM_data2
		  && form != DW_FORM_udata)
		{
		  error (0, 0,
			 "%s: .debug_line unhandled form %s for dir index",
			 dso->filename, get_DW_FORM_str (form));
		  return 1;
		}
	      break;

	    case DW_LNCT_timestamp:
	      if (time_ndx != -1)
		{
		  error (0, 0,
			 "%s: .debug_line duplicate file time elements",
			 dso->filename);
		  return 1;
		}
	      time_ndx = n;

	      if (form != DW_FORM_udata
		  && form != DW_FORM_data4
		  && form != DW_FORM_data8)
		{
		  error (0, 0,
			 "%s: .debug_line unhandled form %s for file time",
			 dso->filename, get_DW_FORM_str (form));
		  return 1;
		}
	      break;

	    case DW_LNCT_size:
	      if (size_ndx != -1)
		{
		  error (0, 0,
			 "%s: .debug_line duplicate file size elements",
			 dso->filename);
		  return 1;
		}
	      size_ndx = n;

	      if (form != DW_FORM_udata
		  && form != DW_FORM_data1
		  && form != DW_FORM_data2
		  && form != DW_FORM_data4
		  && form != DW_FORM_data8)
		{
		  error (0, 0,
			 "%s: .debug_line unhandled form %s for file size",
			 dso->filename, get_DW_FORM_str (form));
		  return 1;
		}
	      break;

	    default:
	      error (0, 0, "%s: .debug_line unhandled file element %s",
		     dso->filename, get_DW_LNCT_str (lnct));
	      return 1;
	    }
	  elems[n] = form;
	}

      nfiles = read_uleb128 (ptr);
      if (nfiles > 0)
       nfiles--; /* We will skip the first (zero) entry.  */
    }

  cu->cu_nfiles = nfiles;
  cu->cu_files = pool_alloc (dw_file, nfiles * sizeof (struct dw_file));
  memset (cu->cu_files, 0, nfiles * sizeof (struct dw_file));

  if (version < 5)
    ptr = file;

  for (file_cnt = 0; file_cnt < nfiles; file_cnt++)
    {
      char *f = NULL;
      char *end = NULL;
      uint32_t d = 0;
      uint64_t time = 0;
      uint64_t size = 0;
      if (version < 5)
	{
	  f = (char *) ptr;
	  ptr = (unsigned char *) strchr ((char *)ptr, 0) + 1;
	  end = (char *) ptr;
	  d = read_uleb128 (ptr);
	  time = read_uleb128 (ptr);
	  size = read_uleb128 (ptr);
	}
      else
	{
	  /* Skip zero entry.  */
	  if (file_cnt == 0)
	    for (n = 0; n < nelems; n++)
	      ptr = skip_attr_no_dw_form_indirect (cu->cu_version,
						   elems[n], ptr);

	  for (n = 0; n < nelems; n++)
	    {
	      uint32_t form = elems[n];
	      if (n == path_ndx)
		{
		  switch (form)
		    {
		    case DW_FORM_string:
		      f = (char *) ptr;
		      end = strchr ((char *)ptr, 0) + 1;;
		      break;
		    case DW_FORM_strp:
		      {
			unsigned int strp = do_read_32 (ptr);
			if (strp >= debug_sections[DEBUG_STR].size)
			  f = NULL;
			else
			  {
			    f = ((char *) debug_sections[DEBUG_STR].data
				 + strp);
			    end = f + strlen (f) + 1;
			  }
		      }
		      break;
		    case DW_FORM_line_strp:
		      {
			unsigned int line_strp = do_read_32 (ptr);
			if (line_strp >= debug_sections[DEBUG_LINE_STR].size)
			  f = NULL;
			else
			  {
			    f = ((char *) debug_sections[DEBUG_LINE_STR].data
				 + line_strp);
			    end = f + strlen (f) + 1;
			  }
		      }
		      break;
		    default:
		      f = NULL;
		      break;
		    }

		  if (f == NULL)
		    {
		      error (0, 0, "%s: .debug_line bad file path",
			     dso->filename);
		      return 1;
		    }
		}
	      else if (n == dir_ndx)
		{
		  switch (form)
		    {
		    case DW_FORM_data1:
		      d = *ptr;
		      break;
		    case DW_FORM_data2:
		      d = do_read_16 (ptr);
		      break;
		    case DW_FORM_udata:
		      {
			unsigned char *p = ptr;
			d = read_uleb128 (p);
		      }
		      break;
		    }
		}
	      ptr = skip_attr_no_dw_form_indirect (cu->cu_version, form, ptr);
	    }
	}

      cu->cu_files[file_cnt].file = f;
      if (d >= dirt_cnt)
	{
	  error (0, 0, "%s: Wrong directory table index %u",
		 dso->filename, value);
	  return 1;
	}

      cu->cu_files[file_cnt].dir = (char *) dirt[d];
      cu->cu_files[file_cnt].time = time;
      cu->cu_files[file_cnt].size = size;
      size_t file_len = (char *) end - f;
      size_t strlen_file = file_len - 1;
      bool file_has_slash = false;
      if (cu->cu_files[file_cnt].file[0] != '/'
	  && cu->cu_files[file_cnt].dir != NULL)
	{
	  size_t dir_len = strlen (cu->cu_files[file_cnt].dir);
	  if (dir_len)
	    {
	      obstack_grow (&ob, cu->cu_files[file_cnt].dir,
			    dir_len);
	      strlen_file += dir_len;
	      if (cu->cu_files[file_cnt].dir[dir_len - 1] != '/')
		{
		  obstack_1grow (&ob, '/');
		  strlen_file++;
		}
	      file_has_slash = true;
	      obstack_grow (&ob, cu->cu_files[file_cnt].file,
			    file_len);
	      cu->cu_files[file_cnt].file
		= (char *) obstack_finish (&ob);
	      cu->cu_files[file_cnt].dir = NULL;
	    }
	}
      cu->cu_files[file_cnt].file_angle_brackets_encapsulated_no_slash
	= (!file_has_slash
	   && cu->cu_files[file_cnt].file[0] == '<'
	   && cu->cu_files[file_cnt].file[strlen_file - 1] == '>'
	   && strchr (cu->cu_files[file_cnt].file, '/') == NULL);
    }

  return 0;
}

/* Estimate the amount of DIEs in the .debug_info section, based on the size
   of that section.  */
static unsigned int
estimate_nr_dies (void)
{
  unsigned int average_die_size = 11;
  unsigned int nr_dies = debug_sections[DEBUG_INFO].size / average_die_size;
  return nr_dies;
}

static size_t
emulate_htab (size_t initial, size_t final_nr_elements)
{
  size_t size = initial;

  /* Emulate creation.  */
  size = higher_prime_number (size);

  /* Emulate growing till htab contains find_nr_elements.  */
  while (1)
    {
      /* Emulate expansion trigger.  */
      size_t nr_elements = size * 3 / 4;
      while (!(size * 3 <= nr_elements * 4))
	nr_elements++;

      if (nr_elements > final_nr_elements)
	{
	  nr_elements = final_nr_elements;
	  break;
	}

      /* Emulate expansion.  */
      size = size * 2;
      size = higher_prime_number (size);
    }

  return size;
}

/* Print hash table statistics for hash table HTAB with message string MSG.  */
static void
htab_report (htab_t htab, const char *msg)
{
  double collisions = htab_collisions (htab);
  unsigned int searches = htab->searches;
  size_t elements = htab->n_elements;
  size_t deleted = htab->n_deleted;
  size_t adjusted_elements = elements - deleted;
  size_t size = htab->size;
  double occupancy = (double)elements / (double)size;
  double adjusted_occupancy = (double)adjusted_elements / (double)size;
  /* Indent unconditional fprintfs similar to conditional fprintfs to
     left-align literal strings.  */
  if (1)
    fprintf (stderr, "htab: %s\n", msg);
  if (1)
    fprintf (stderr, "      size: %zu\n", size);
  if (elements > 0 && deleted == 0)
    fprintf (stderr, "      elements: %zu, occupancy: %f\n", elements,
	     occupancy);
  if (deleted > 0)
    fprintf (stderr, "      elements (incl. deleted): %zu, occupancy: %f\n",
	     elements, occupancy);
  if (deleted > 0)
    fprintf (stderr, "      elements (excl. deleted): %zu, occupancy: %f\n",
	     adjusted_elements, adjusted_occupancy);
  if (elements > 0)
    fprintf (stderr, "      searches: %u, collisions: %f\n", searches,
	     collisions);
}

/* Hash function for off_htab hash table.  */
static hashval_t
off_hash (const void *p)
{
  dw_die_ref die = (dw_die_ref) p;

  return die->die_offset / 6;
}

/* Equality function for off_htab hash table.  */
static int
off_eq (const void *p, const void *q)
{
  return ((dw_die_ref) p)->die_offset == ((dw_die_ref) q)->die_offset;
}

/* Hash table to map die_offset values to struct dw_die pointers.  */
static htab_t off_htab;

/* After read_multifile off_htab is copied over to this variable.
   Offsets in the alternate .debug_info are found using this hash table.  */
static htab_t alt_off_htab;

/* Offset hash table for .debug_types section.  */
static htab_t types_off_htab;

/* Function to add DIE into the hash table (and create the hash table
   when not already created).  */
static void
off_htab_add_die (dw_cu_ref cu, dw_die_ref die, unsigned int *die_count)
{
  void **slot;

  if (unlikely (cu->cu_kind == CU_TYPES))
    {
      if (types_off_htab == NULL)
	{
	  types_off_htab = htab_try_create (100000, off_hash, off_eq, NULL);
	  if (types_off_htab == NULL)
	    dwz_oom ();
	}

      slot = htab_find_slot (types_off_htab, die, INSERT);
      if (slot == NULL)
	dwz_oom ();
      assert (*slot == NULL);
      *slot = die;
      return;
    }

  if (off_htab == NULL)
    {
      unsigned int estimated_nr_dies = estimate_nr_dies ();
      size_t default_initial_size = 100000;
      size_t initial_size;
      if (low_mem
	  || op_multifile
	  || (multifile_mode == 0
	      && die_count_method == estimate
	      && (estimated_nr_dies >= low_mem_die_limit
		  || estimated_nr_dies >= max_die_limit)))
	initial_size = default_initial_size;
      else
	{
	  size_t nr_dies;
	  if (die_count && *die_count != 0)
	    {
	      nr_dies = *die_count;
	      if (tracing)
		fprintf (stderr, "Using die count %zu for off_htab"
			 " allocation\n", nr_dies);
	    }
	  else if (die_count_method == none)
	    nr_dies = 0;
	  else if (die_count_method == estimate)
	    {
	      nr_dies = estimated_nr_dies;
	      if (tracing)
		fprintf (stderr, "Using die count estimate %zu for off_htab"
			 " allocation\n", nr_dies);
	    }
	  else
	    assert (false);

	  if (nr_dies != 0)
	    {
	      size_t final_hashtab_size
		= emulate_htab (default_initial_size, nr_dies);
	      initial_size = final_hashtab_size;
	    }
	  else
	    initial_size = default_initial_size;
	}
      off_htab = htab_try_create (initial_size, off_hash, off_eq, NULL);
      if (tracing)
	htab_report (off_htab, "off_htab allocation");
      if (off_htab == NULL)
	dwz_oom ();
      if (rd_multifile)
	alt_off_htab = off_htab;
    }

  slot = htab_find_slot_with_hash (off_htab, die, off_hash (die), INSERT);
  if (slot == NULL)
    dwz_oom ();
  assert (*slot == NULL);
  *slot = die;
}

/* For DIE_OFFSET return dw_die_ref whose die_offset field is equal
   to that value.  Return NULL if no DIE is at that position (buggy
   DWARF input?).  */
static dw_die_ref
off_htab_lookup (dw_cu_ref cu, unsigned int die_offset)
{
  struct dw_die die;
  die.die_offset = die_offset;
  if (cu == NULL)
    return (dw_die_ref) htab_find_with_hash (off_htab, &die, off_hash (&die));
  if (unlikely (cu->cu_kind == CU_ALT))
    return (dw_die_ref) htab_find_with_hash (alt_off_htab, &die,
					     off_hash (&die));
  if (unlikely (cu->cu_kind == CU_TYPES))
    return (dw_die_ref) htab_find_with_hash (types_off_htab, &die,
					     off_hash (&die));
  return (dw_die_ref) htab_find_with_hash (off_htab, &die, off_hash (&die));
}

/* For a die attribute ATTR starting at PTR, with the die in CU, return the
   pointer after the attribute.  */
static inline unsigned char * FORCE_INLINE
skip_attr (unsigned int cu_version, struct abbrev_attr *attr,
	   unsigned char *ptr)
{
  uint32_t form = attr->form;

  while (form == DW_FORM_indirect)
    form = read_uleb128 (ptr);
  return skip_attr_no_dw_form_indirect (cu_version, form, ptr);
}

/* Return a pointer at which DIE's attribute AT is encoded, and fill in
   its form into *FORMP.  Return NULL if the attribute is not present.  */
static unsigned char *
get_AT (dw_die_ref die, enum dwarf_attribute at, enum dwarf_form *formp)
{
  struct abbrev_tag *t = die->die_abbrev;
  unsigned int i;
  unsigned char *ptr;
  dw_cu_ref cu = die_cu (die);
  if (unlikely (fi_multifile) && cu->cu_kind == CU_ALT)
    ptr = alt_data[DEBUG_INFO];
  else if (cu->cu_kind == CU_TYPES)
    ptr = debug_sections[DEBUG_TYPES].data;
  else
    ptr = debug_sections[DEBUG_INFO].data;
  ptr += die->die_offset;
  skip_leb128 (ptr);
  for (i = 0; i < t->nattr; ++i)
    {
      uint32_t form = t->attr[i].form;

      while (form == DW_FORM_indirect)
	form = read_uleb128 (ptr);
      if (t->attr[i].attr == at)
	{
	  *formp = form;
	  if (form == DW_FORM_implicit_const)
	    return (unsigned char *) &t->values[i];
	  return ptr;
	}

      ptr = skip_attr_no_dw_form_indirect (cu->cu_version, form, ptr);
    }
  return NULL;
}

/* Return an integer attribute AT of DIE.  Set *PRESENT to true
   if found.  */
static uint64_t
get_AT_int (dw_die_ref die, enum dwarf_attribute at, bool *present,
	    enum dwarf_form *formp)
{
  unsigned char *ptr;
  ptr = get_AT (die, at, formp);
  *present = false;
  if (ptr == NULL)
    return 0;
  *present = true;
  switch (*formp)
    {
    case DW_FORM_ref_addr:
      return read_size (ptr, die_cu (die)->cu_version == 2 ? ptr_size : 4);
    case DW_FORM_addr:
      return read_size (ptr, ptr_size);
    case DW_FORM_flag_present:
      return 1;
    case DW_FORM_ref1:
    case DW_FORM_flag:
    case DW_FORM_data1:
      return read_8 (ptr);
    case DW_FORM_ref2:
    case DW_FORM_data2:
      return read_16 (ptr);
    case DW_FORM_ref4:
    case DW_FORM_data4:
    case DW_FORM_sec_offset:
      return read_32 (ptr);
    case DW_FORM_ref8:
    case DW_FORM_data8:
    case DW_FORM_ref_sig8:
      return read_64 (ptr);
    case DW_FORM_sdata:
      return read_sleb128 (ptr);
    case DW_FORM_ref_udata:
    case DW_FORM_udata:
      return read_uleb128 (ptr);
    case DW_FORM_implicit_const:
      return *(uint64_t *)ptr; /* See get_AT.  */
    default:
      *present = false;
      return 0;
    }
}

/* Return a pointer to string attribute AT in DIE, or NULL
   if the attribute is not present.  */
static char *
get_AT_string (dw_die_ref die, enum dwarf_attribute at)
{
  enum dwarf_form form;
  unsigned char *ptr;
  ptr = get_AT (die, at, &form);
  if (ptr == NULL)
    return NULL;
  switch (form)
    {
    case DW_FORM_string:
      return (char *) ptr;
    case DW_FORM_strp:
      {
	unsigned int strp = read_32 (ptr);
	if (unlikely (fi_multifile) && die_cu (die)->cu_kind == CU_ALT)
	  {
	    if (strp >= alt_size[DEBUG_STR])
	      return NULL;
	    return (char *) alt_data[DEBUG_STR] + strp;
	  }
	if (strp >= debug_sections[DEBUG_STR].size)
	  return NULL;
	return (char *) debug_sections[DEBUG_STR].data + strp;
      }
    case DW_FORM_line_strp:
      {
	unsigned int line_strp = read_32 (ptr);
	if (line_strp >= debug_sections[DEBUG_LINE_STR].size)
	  return NULL;
	else
	  return (char *) debug_sections[DEBUG_LINE_STR].data + line_strp;
      }
    default:
      return NULL;
    }
}

/* Parse DWARF expression referenced or stored in DIE, starting at
   PTR with LEN bytes.  Return non-zero on error.  If NEED_ADJUST
   is non-NULL, set *NEED_ADJUST to true if it contains DIE references
   that will need adjusting.  Some opcodes cause DIE or referenced
   DIEs as unsuitable for moving into partial units, or limit their
   location.  */
static int
read_exprloc (DSO *dso, dw_die_ref die, unsigned char *ptr, size_t len,
	      bool *need_adjust)
{
  unsigned char *end = ptr + len;
  unsigned char op;
  GElf_Addr addr;
  dw_die_ref ref;
  dw_cu_ref cu;

  while (ptr < end)
    {
      op = *ptr++;
      switch (op)
	{
	case DW_OP_addr:
	  die->die_no_multifile = 1;
	  ptr += ptr_size;
	  break;
	case DW_OP_deref:
	case DW_OP_dup:
	case DW_OP_drop:
	case DW_OP_over:
	case DW_OP_swap:
	case DW_OP_rot:
	case DW_OP_xderef:
	case DW_OP_abs:
	case DW_OP_and:
	case DW_OP_div:
	case DW_OP_minus:
	case DW_OP_mod:
	case DW_OP_mul:
	case DW_OP_neg:
	case DW_OP_not:
	case DW_OP_or:
	case DW_OP_plus:
	case DW_OP_shl:
	case DW_OP_shr:
	case DW_OP_shra:
	case DW_OP_xor:
	case DW_OP_eq:
	case DW_OP_ge:
	case DW_OP_gt:
	case DW_OP_le:
	case DW_OP_lt:
	case DW_OP_ne:
	case DW_OP_lit0 ... DW_OP_lit31:
	case DW_OP_reg0 ... DW_OP_reg31:
	case DW_OP_nop:
	case DW_OP_push_object_address:
	case DW_OP_form_tls_address:
	case DW_OP_call_frame_cfa:
	case DW_OP_stack_value:
	case DW_OP_GNU_push_tls_address:
	case DW_OP_GNU_uninit:
	  break;
	case DW_OP_const1u:
	case DW_OP_pick:
	case DW_OP_deref_size:
	case DW_OP_xderef_size:
	case DW_OP_const1s:
	  ++ptr;
	  break;
	case DW_OP_const2u:
	case DW_OP_const2s:
	case DW_OP_skip:
	case DW_OP_bra:
	  ptr += 2;
	  break;
	case DW_OP_call2:
	case DW_OP_call4:
	case DW_OP_GNU_parameter_ref:
	  if (op == DW_OP_call2)
	    addr = read_16 (ptr);
	  else
	    addr = read_32 (ptr);
	  cu = die_cu (die);
	  ref = off_htab_lookup (cu, cu->cu_offset + addr);
	  if (ref == NULL)
	    {
	      error (0, 0, "%s: Couldn't find DIE at [%" PRIx64 "] "
		     "referenced by %s from DIE at [%x]",
		     dso->filename, cu->cu_offset + addr,
		     get_DW_OP_str (op), die->die_offset);
	      return 1;
	    }
	  if (op == DW_OP_call2)
	    ref->die_op_call2_referenced = 1;
	  if (ref->die_ck_state == CK_KNOWN)
	    {
	      dw_die_ref d;
	      ref->die_ck_state = CK_BAD;

	      d = ref;
	      while (!d->die_root
		     && d->die_parent->die_ck_state == CK_KNOWN)
		{
		  d = d->die_parent;
		  d->die_ck_state = CK_BAD;
		}
	    }
	  else
	    ref->die_ck_state = CK_BAD;
	  if (unlikely (low_mem))
	    {
	      ref->die_referenced = 1;
	      /* As .debug_loc adjustment is done after
		 write_info finishes, we need to keep the referenced
		 DIEs around uncollapsed.  */
	      if (need_adjust)
		ref->die_intercu_referenced = 1;
	    }
	  die->die_ck_state = CK_BAD;
	  if (need_adjust)
	    *need_adjust = true;
	  break;
	case DW_OP_const4u:
	case DW_OP_const4s:
	  ptr += 4;
	  break;
	case DW_OP_call_ref:
	case DW_OP_GNU_implicit_pointer:
	case DW_OP_implicit_pointer:
	case DW_OP_GNU_variable_value:
	  cu = die_cu (die);
	  addr = read_size (ptr, cu->cu_version == 2 ? ptr_size : 4);
	  if (cu->cu_version == 2)
	    ptr += ptr_size;
	  else
	    ptr += 4;
	  ref = off_htab_lookup (NULL, addr);
	  if (ref == NULL || (unlikely (low_mem) && ref->die_tag == 0))
	    {
	      error (0, 0, "%s: Couldn't find DIE at [%" PRIx64 "] "
		     "referenced by %s from DIE at [%x]",
		     dso->filename, addr, get_DW_OP_str (op), die->die_offset);
	      return 1;
	    }
	  ref->die_no_multifile = 1;
	  if (unlikely (low_mem))
	    {
	      ref->die_referenced = 1;
	      /* As .debug_loc adjustment is done after
		 write_info finishes, we need to keep the referenced
		 DIEs around uncollapsed.  */
	      if (die_cu (ref) != cu || need_adjust)
		ref->die_intercu_referenced = 1;
	    }
	  die->die_ck_state = CK_BAD;
	  if (need_adjust)
	    *need_adjust = true;
	  if (op == DW_OP_GNU_implicit_pointer || op == DW_OP_implicit_pointer)
	    skip_leb128 (ptr);
	  break;
	case DW_OP_const8u:
	case DW_OP_const8s:
	  ptr += 8;
	  break;
	case DW_OP_constu:
	case DW_OP_plus_uconst:
	case DW_OP_regx:
	case DW_OP_piece:
	case DW_OP_consts:
	case DW_OP_breg0 ... DW_OP_breg31:
	case DW_OP_fbreg:
	  skip_leb128 (ptr);
	  break;
	case DW_OP_bregx:
	case DW_OP_bit_piece:
	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  break;
	case DW_OP_implicit_value:
	  {
	    uint32_t leni = read_uleb128 (ptr);
	    ptr += leni;
	  }
	  break;
	case DW_OP_GNU_entry_value:
	case DW_OP_entry_value:
	  {
	    uint32_t leni = read_uleb128 (ptr);
	    if ((uint64_t) (end - ptr) < leni)
	      {
		error (0, 0, "%s: %s with too large length",
		       get_DW_OP_str (op),  dso->filename);
		return 1;
	      }
	    if (read_exprloc (dso, die, ptr, leni, need_adjust))
	      return 1;
	    ptr += leni;
	  }
	  break;
	case DW_OP_GNU_convert:
	case DW_OP_convert:
	case DW_OP_GNU_reinterpret:
	case DW_OP_reinterpret:
	  addr = read_uleb128 (ptr);
	  if (addr == 0)
	    break;
	  goto typed_dwarf;
	case DW_OP_GNU_regval_type:
	case DW_OP_regval_type:
	  skip_leb128 (ptr);
	  addr = read_uleb128 (ptr);
	  goto typed_dwarf;
	case DW_OP_GNU_const_type:
	case DW_OP_const_type:
	  addr = read_uleb128 (ptr);
	  ptr += *ptr + 1;
	  goto typed_dwarf;
	case DW_OP_GNU_deref_type:
	case DW_OP_deref_type:
	  ++ptr;
	  addr = read_uleb128 (ptr);
	typed_dwarf:
	  cu = die_cu (die);
	  ref = off_htab_lookup (cu, cu->cu_offset + addr);
	  if (ref == NULL)
	    {
	      error (0, 0, "%s: Couldn't find DIE at [%" PRIx64 "] "
			   "referenced by %s from DIE at [%x]",
		     dso->filename, cu->cu_offset + addr,
		     get_DW_OP_str (op), die->die_offset);
	      return 1;
	    }
	  if (unlikely (low_mem))
	    {
	      ref->die_referenced = 1;
	      /* As .debug_loc adjustment is done after
		 write_info finishes, we need to keep the referenced
		 DIEs around uncollapsed.  */
	      if (need_adjust)
		ref->die_intercu_referenced = 1;
	    }
	  ref->die_op_type_referenced = 1;
	  die->die_ck_state = CK_BAD;
	  if (need_adjust)
	    *need_adjust = true;
	  break;
	default:
	  error (0, 0, "%s: Unknown DWARF %s",
		 dso->filename, get_DW_OP_str (op));
	  return 1;
	}
    }
  if (die->die_ck_state != CK_BAD)
    die->u.p1.die_hash = iterative_hash (end - len, len, die->u.p1.die_hash);
  return 0;
}

/* Add dummy die in CU at OFFSET.  */
static inline void FORCE_INLINE
add_dummy_die (dw_cu_ref cu, unsigned int offset)
{
  dw_die_ref ref;
  struct dw_die ref_buf;
  void **slot;

  memset (&ref_buf, '\0', offsetof (struct dw_die, die_child));
  ref_buf.die_offset = offset;
  ref_buf.die_collapsed_child = 1;
  ref_buf.die_referenced = 1;
  ref_buf.die_intercu_referenced = 1;
  if (off_htab == NULL)
    {
      ref = pool_alloc (dw_die, offsetof (struct dw_die, die_child));
      memcpy (ref, &ref_buf, offsetof (struct dw_die, die_child));
      off_htab_add_die (cu, ref, NULL);
      return;
    }

  slot
    = htab_find_slot_with_hash (off_htab, &ref_buf, off_hash (&ref_buf),
				INSERT);
  if (slot == NULL)
    dwz_oom ();
  if (*slot != NULL)
    return;

  ref = pool_alloc (dw_die, offsetof (struct dw_die, die_child));
  memcpy (ref, &ref_buf, offsetof (struct dw_die, die_child));
  *slot = (void *) ref;
}

/* Add dummy DIEs for expr_loc at PTR.  */
static int
read_exprloc_low_mem_phase1 (DSO *dso, dw_die_ref die, unsigned char *ptr,
			     size_t len)
{
  unsigned char *end = ptr + len;
  unsigned char op;
  GElf_Addr addr;
  dw_cu_ref cu;

  while (ptr < end)
    {
      op = *ptr++;
      switch (op)
	{
	case DW_OP_addr:
	  ptr += ptr_size;
	  break;
	case DW_OP_deref:
	case DW_OP_dup:
	case DW_OP_drop:
	case DW_OP_over:
	case DW_OP_swap:
	case DW_OP_rot:
	case DW_OP_xderef:
	case DW_OP_abs:
	case DW_OP_and:
	case DW_OP_div:
	case DW_OP_minus:
	case DW_OP_mod:
	case DW_OP_mul:
	case DW_OP_neg:
	case DW_OP_not:
	case DW_OP_or:
	case DW_OP_plus:
	case DW_OP_shl:
	case DW_OP_shr:
	case DW_OP_shra:
	case DW_OP_xor:
	case DW_OP_eq:
	case DW_OP_ge:
	case DW_OP_gt:
	case DW_OP_le:
	case DW_OP_lt:
	case DW_OP_ne:
	case DW_OP_lit0 ... DW_OP_lit31:
	case DW_OP_reg0 ... DW_OP_reg31:
	case DW_OP_nop:
	case DW_OP_push_object_address:
	case DW_OP_form_tls_address:
	case DW_OP_call_frame_cfa:
	case DW_OP_stack_value:
	case DW_OP_GNU_push_tls_address:
	case DW_OP_GNU_uninit:
	  break;
	case DW_OP_const1u:
	case DW_OP_pick:
	case DW_OP_deref_size:
	case DW_OP_xderef_size:
	case DW_OP_const1s:
	  ++ptr;
	  break;
	case DW_OP_const2u:
	case DW_OP_const2s:
	case DW_OP_skip:
	case DW_OP_bra:
	  ptr += 2;
	  break;
	case DW_OP_call2:
	case DW_OP_call4:
	case DW_OP_GNU_parameter_ref:
	  if (op == DW_OP_call2)
	    read_16 (ptr);
	  else
	    read_32 (ptr);
	  break;
	case DW_OP_const4u:
	case DW_OP_const4s:
	  ptr += 4;
	  break;
	case DW_OP_call_ref:
	case DW_OP_GNU_implicit_pointer:
	case DW_OP_implicit_pointer:
	case DW_OP_GNU_variable_value:
	  cu = die_cu (die);
	  addr = read_size (ptr, cu->cu_version == 2 ? ptr_size : 4);
	  if (cu->cu_version == 2)
	    ptr += ptr_size;
	  else
	    ptr += 4;
	  /* Adding a dummy DIE ref to mark an intercu reference is only
	     necessary if die_cu (ref) != cu, but we don't track cu's during
	     low-mem phase1.  */
	  add_dummy_die (cu, addr);
	  if (op == DW_OP_GNU_implicit_pointer || op == DW_OP_implicit_pointer)
	    skip_leb128 (ptr);
	  break;
	case DW_OP_const8u:
	case DW_OP_const8s:
	  ptr += 8;
	  break;
	case DW_OP_constu:
	case DW_OP_plus_uconst:
	case DW_OP_regx:
	case DW_OP_piece:
	case DW_OP_consts:
	case DW_OP_breg0 ... DW_OP_breg31:
	case DW_OP_fbreg:
	  skip_leb128 (ptr);
	  break;
	case DW_OP_bregx:
	case DW_OP_bit_piece:
	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  break;
	case DW_OP_implicit_value:
	  {
	    uint32_t leni = read_uleb128 (ptr);
	    ptr += leni;
	  }
	  break;
	case DW_OP_GNU_entry_value:
	case DW_OP_entry_value:
	  {
	    uint32_t leni = read_uleb128 (ptr);
	    if ((uint64_t) (end - ptr) < leni)
	      {
		error (0, 0, "%s: %s with too large length",
		       get_DW_OP_str (op), dso->filename);
		return 1;
	      }
	    if (read_exprloc_low_mem_phase1 (dso, die, ptr, leni))
	      return 1;
	    ptr += leni;
	  }
	  break;
	case DW_OP_GNU_convert:
	case DW_OP_convert:
	case DW_OP_GNU_reinterpret:
	case DW_OP_reinterpret:
	  skip_leb128 (ptr);
	  break;
	case DW_OP_GNU_regval_type:
	case DW_OP_regval_type:
	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  break;
	case DW_OP_GNU_const_type:
	case DW_OP_const_type:
	  read_uleb128 (ptr);
	  ptr += *ptr + 1;
	  break;
	case DW_OP_GNU_deref_type:
	case DW_OP_deref_type:
	  ++ptr;
	  skip_leb128 (ptr);
	  break;
	default:
	  error (0, 0, "%s: Unknown DWARF %s",
		 dso->filename, get_DW_OP_str (op));
	  return 1;
	}
    }

  return 0;
}

/* Add dummy DIEs for loclist at OFFSET.  */
static int
read_loclist_low_mem_phase1 (DSO *dso, dw_cu_ref cu, dw_die_ref die,
			     GElf_Addr offset)
{
  unsigned char *ptr, *endsec;
  GElf_Addr low, high;
  size_t len = 0;
  int sec;

  sec = cu->cu_version < 5 ? DEBUG_LOC : DEBUG_LOCLISTS;
  ptr = debug_sections[sec].data;
  if (ptr == NULL)
    {
      error (0, 0, "%s: loclistptr attribute, yet no %s section",
	     dso->filename, debug_sections[sec].name);
      return 1;
    }
  if (offset >= debug_sections[sec].size)
    {
      error (0, 0,
	     "%s: loclistptr offset %Ld outside of %s section",
	     dso->filename, (long long) offset, debug_sections[sec].name);
      return 1;
    }
  endsec = ptr + debug_sections[sec].size;
  ptr += offset;
again:
  while (ptr < endsec)
    {
      if (sec == DEBUG_LOC)
	{
	  low = read_size (ptr, ptr_size);
	  high = read_size (ptr + ptr_size, ptr_size);
	  ptr += 2 * ptr_size;
	  if (low == 0 && high == 0)
	    break;

	  if (low == ~ (GElf_Addr) 0 || (ptr_size == 4 && low == 0xffffffff))
	    continue;

	  len = read_16 (ptr);
	}
      else
	{
	  uint8_t lle = *ptr++;
	  switch (lle)
	    {
	    case DW_LLE_end_of_list:
	      goto done;

	    case DW_LLE_base_addressx:
	      skip_leb128 (ptr);
	      goto again;

	    case DW_LLE_startx_endx:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_startx_length:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_offset_pair:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_default_location:
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_base_address:
	      ptr += ptr_size;
	      goto again;

	    case DW_LLE_start_end:
	      ptr += 2 * ptr_size;
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_start_length:
	      ptr += ptr_size;
	      skip_leb128 (ptr);
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_GNU_view_pair:
	      if (cu->cu_version != 5)
		error (0, 0,
		       "%s: DW_LLE_GNU_view_pair used with DWARF version %u",
		       dso->filename, cu->cu_version);
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      goto again;

	    default:
	      error (0, 0,
		     "%s: unhandled location list entry 0x%x in %s section",
		     dso->filename, lle, debug_sections[sec].name);
	      return 1;
	    }
	}

      if (unlikely (!(ptr + len <= endsec)))
	{
	  error (0, 0,
		 "%s: locexpr length 0x%Lx exceeds %s section",
		 dso->filename, (long long) len, debug_sections[sec].name);
	  return 1;
	}

      if (len > 0)
	if (read_exprloc_low_mem_phase1 (dso, die, ptr, len))
	  return 1;

      ptr += len;
    }

done:
  return 0;
}

/* Add dummy dies for loc_exprs and loc_lists referenced from DIE.  */
static int
add_locexpr_dummy_dies (DSO *dso, dw_cu_ref cu, dw_die_ref die,
			unsigned char *ptr, uint32_t form, unsigned int attr,
			size_t len)
{
  if (form == DW_FORM_block1 && cu->cu_version < 4)
    {
      /* Old DWARF uses blocks instead of exprlocs.  */
      switch (attr)
	{
	case DW_AT_frame_base:
	case DW_AT_location:
	case DW_AT_data_member_location:
	case DW_AT_vtable_elem_location:
	case DW_AT_byte_size:
	case DW_AT_bit_offset:
	case DW_AT_bit_size:
	case DW_AT_string_length:
	case DW_AT_lower_bound:
	case DW_AT_return_addr:
	case DW_AT_bit_stride:
	case DW_AT_upper_bound:
	case DW_AT_count:
	case DW_AT_segment:
	case DW_AT_static_link:
	case DW_AT_use_location:
	case DW_AT_allocated:
	case DW_AT_associated:
	case DW_AT_data_location:
	case DW_AT_byte_stride:
	case DW_AT_rank:
	case DW_AT_call_value:
	case DW_AT_call_target:
	case DW_AT_call_target_clobbered:
	case DW_AT_call_data_location:
	case DW_AT_call_data_value:
	case DW_AT_GNU_call_site_value:
	case DW_AT_GNU_call_site_data_value:
	case DW_AT_GNU_call_site_target:
	case DW_AT_GNU_call_site_target_clobbered:
	  if (read_exprloc_low_mem_phase1 (dso, die, ptr, len))
	    return 1;
	default:
	  break;
	}

      return 0;
    }

  if (form == DW_FORM_exprloc)
    return read_exprloc_low_mem_phase1 (dso, die, ptr, len);

  switch (attr)
    {
    case DW_AT_location:
    case DW_AT_string_length:
    case DW_AT_return_addr:
    case DW_AT_data_member_location:
    case DW_AT_frame_base:
    case DW_AT_segment:
    case DW_AT_static_link:
    case DW_AT_use_location:
    case DW_AT_vtable_elem_location:
      if ((cu->cu_version < 4 && form == DW_FORM_data4)
	  || form == DW_FORM_sec_offset)
	{
	  if (read_loclist_low_mem_phase1 (dso, cu, die, do_read_32 (ptr)))
	    return 1;
	  break;
	}
      else if (cu->cu_version < 4 && form == DW_FORM_data8)
	{
	  if (read_loclist_low_mem_phase1 (dso, cu, die, do_read_64 (ptr)))
	    return 1;
	  break;
	}
      break;
    default:
      break;
    }

  return 0;
}

/* Structure recording a portion of .debug_loc section that will need
   adjusting.  */
struct debug_loc_adjust
{
  /* Starting offset in .debug_loc that needs adjusting.  */
  unsigned int start_offset;
  /* End offset.  This is used for hashing, as in theory some DIE
     might be referencing a middle of a .debug_loc sequence (the address
     part of it) referenced by a different DIE.  */
  unsigned int end_offset;
  /* Owning CU.  We give up if the same .debug_loc part that needs adjusting
     is owned by more than one CU.  */
  dw_cu_ref cu;
};
ALIGN_STRUCT (debug_loc_adjust)

/* Hash table and obstack for recording .debug_loc and .debug_loclists
   adjustment ranges.  */
static htab_t loc_htab;
static htab_t loclists_htab;

/* Hash function for loc[lists]_htab.  */
static hashval_t
loc_hash (const void *p)
{
  struct debug_loc_adjust *a = (struct debug_loc_adjust *)p;

  return a->end_offset;
}

/* Equality function for loc[lists]_htab.  */
static int
loc_eq (const void *p, const void *q)
{
  struct debug_loc_adjust *t1 = (struct debug_loc_adjust *)p;
  struct debug_loc_adjust *t2 = (struct debug_loc_adjust *)q;

  return t1->end_offset == t2->end_offset;
}

/* Parse .debug_loc portion starting at OFFSET, referenced by
   DIE.  Call read_exprloc on each of the DWARF expressions
   contained in it.  */
static int
read_loclist (DSO *dso, dw_cu_ref cu, dw_die_ref die, GElf_Addr offset)
{
  unsigned char *ptr, *endsec;
  GElf_Addr low, high;
  size_t len;
  int sec;
  bool need_adjust = false;

  die->die_ck_state = CK_BAD;
  sec = cu->cu_version < 5 ? DEBUG_LOC : DEBUG_LOCLISTS;
  ptr = debug_sections[sec].data;
  if (ptr == NULL)
    {
      error (0, 0, "%s: loclistptr attribute, yet no %s section",
	     dso->filename, debug_sections[sec].name);
      return 1;
    }
  if (offset >= debug_sections[sec].size)
    {
      error (0, 0,
	     "%s: loclistptr offset %Ld outside of %s section",
	     dso->filename, (long long) offset, debug_sections[sec].name);
      return 1;
    }
  endsec = ptr + debug_sections[sec].size;
  ptr += offset;
again:
  while (ptr < endsec)
    {
      if (cu->cu_version < 5)
	{
	  low = read_size (ptr, ptr_size);
	  high = read_size (ptr + ptr_size, ptr_size);
	  ptr += 2 * ptr_size;
	  if (low == 0 && high == 0)
	    break;

	  if (low == ~ (GElf_Addr) 0 || (ptr_size == 4 && low == 0xffffffff))
	    continue;

	  len = read_16 (ptr);
	}
      else
	{
	  uint8_t lle = *ptr++;
	  switch (lle)
	    {
	    case DW_LLE_end_of_list:
	      goto done;

	    case DW_LLE_base_addressx:
	      skip_leb128 (ptr);
	      goto again;

	    case DW_LLE_startx_endx:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_startx_length:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_offset_pair:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_default_location:
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_base_address:
	      ptr += ptr_size;
	      goto again;

	    case DW_LLE_start_end:
	      ptr += 2 * ptr_size;
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_start_length:
	      ptr += ptr_size;
	      skip_leb128 (ptr);
	      len = read_uleb128 (ptr);
	      break;

	    case DW_LLE_GNU_view_pair:
	      if (cu->cu_version != 5)
		error (0, 0,
		       "%s: DW_LLE_GNU_view_pair used with DWARF version %u",
		       dso->filename, cu->cu_version);
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      goto again;

	    default:
	      error (0, 0,
		     "%s: unhandled location list entry 0x%x in %s section",
		     dso->filename, lle, debug_sections[sec].name);
	      return 1;
	    }
	}

      if (unlikely (!(ptr + len <= endsec)))
	{
	  error (0, 0,
		 "%s: locexpr length 0x%Lx exceeds %s section",
		 dso->filename, (long long) len, debug_sections[sec].name);
	  return 1;
	}

      if (read_exprloc (dso, die, ptr, len, &need_adjust))
	return 1;

      ptr += len;
    }

done:
  if (need_adjust)
    {
      struct debug_loc_adjust adj, *a;
      void **slot;

      adj.start_offset = offset;
      adj.end_offset = ptr - debug_sections[sec].data;
      adj.cu = cu;
      if (sec == DEBUG_LOC)
	{
	  if (loc_htab == NULL)
	    {
	      loc_htab = htab_try_create (50, loc_hash, loc_eq, NULL);
	      if (loc_htab == NULL)
		dwz_oom ();
	    }
	  slot = htab_find_slot_with_hash (loc_htab, &adj, adj.end_offset,
					   INSERT);
	}
      else
	{
	  if (loclists_htab == NULL)
	    {
	      loclists_htab = htab_try_create (50, loc_hash, loc_eq, NULL);
	      if (loclists_htab == NULL)
		dwz_oom ();
	    }
	  slot = htab_find_slot_with_hash (loclists_htab, &adj, adj.end_offset,
					   INSERT);
	}
      if (slot == NULL)
	dwz_oom ();
      if (*slot == NULL)
	{
	  a = pool_alloc (debug_loc_adjust, sizeof (*a));
	  *a = adj;
	  *slot = (void *) a;
	}
      else if (((struct debug_loc_adjust *)*slot)->cu != adj.cu)
	{
	  error (0, 0, "%s: can't adjust %s section because multiple "
		 "CUs refer to it", dso->filename, debug_sections[sec].name);
	  return 1;
	}
      else if (((struct debug_loc_adjust *)*slot)->start_offset > offset)
	((struct debug_loc_adjust *)*slot)->start_offset = offset;
    }

  return 0;
}

/* Initialize die_odr_state field for DIE with CU.  */
static void
set_die_odr_state (dw_cu_ref cu, dw_die_ref die)
{
  unsigned char *ptr;
  struct abbrev_tag *t;
  unsigned int i;
  bool decl_p;
  bool name_p;
  bool other_p;

  assert (die->die_odr_state == ODR_UNKNOWN);
  die->die_odr_state = ODR_NONE;

  if (low_mem)
    /* Todo: allow low-mem mode.  */
    return;

  if (multifile_mode == 0)
    /* We're in regular mode, enable the ODR optimization.  */
    ;
  else
    /* One definition rule does not hold across executables and shared
       libraries, so disable.  */
    return;

  if (!die->die_toplevel)
    /* A nested struct is not uniquely identified by its name.  There may be a
       different type with the same name nested in a different struct.  */
    return;

  switch (cu->lang)
    {
    case DW_LANG_C_plus_plus:
    case DW_LANG_C_plus_plus_03:
    case DW_LANG_C_plus_plus_11:
    case DW_LANG_C_plus_plus_14:
      /* c++ defines one-definition-rule.  */
      if (die->die_tag == DW_TAG_structure_type
	  || die->die_tag == DW_TAG_class_type
	  || die->die_tag == DW_TAG_union_type)
	/* ODR holds for all types, but we limit the optimization to these
	   tags, which are the ones likely to profit from it.  */
	;
      else
	return;
      break;
    default:
      return;
    }

  ptr = debug_sections[DEBUG_INFO].data + die->die_offset;
  skip_leb128 (ptr);

  t = die->die_abbrev;

  decl_p = false;
  name_p = false;
  other_p = false;
  for (i = 0; i < t->nattr; ++i)
    {
      if (t->attr[i].attr == DW_AT_name)
	{
	  name_p = true;
	  continue;
	}

      if (t->attr[i].attr == DW_AT_declaration)
	{
	  decl_p = true;
	  continue;
	}

      other_p = true;
    }

  if (!name_p)
    /* Ignore anonymous types.  */
    return;

  odr_active_p = true;

  if (decl_p && !other_p && die->die_child == NULL)
    {
      /* Detected a declaration with no attributes other than DW_AT_name and
	 DW_AT_declaration, and no children.  */
      die->die_odr_state = ODR_DECL;
      return;
    }

  die->die_odr_state = ODR_DEF;
}

/* Return the initialized die_odr_state field for DIE with CU.  */
static unsigned int
die_odr_state (dw_die_ref die)
{
  assert (die->die_odr_state != ODR_UNKNOWN);
  return die->die_odr_state;
}

/* This function computes u.p1.die_hash and die_ck_state of DIE.
   The field u.p1.die_hash is an iterative hash of:
   - the die_tag,
   - for all attributes except DW_AT_sibling: the attribute code,
   - for non-reference class attributes: the value of the attribute (magic
     for DW_AT_*_file),
   - for DW_FORM_ref_addr attributes: the value of the attribute,
   - for reference class attributes that point into the subtree of TOP_DIE
     (note, other references are intentionally ignored here):
     ref->u.p1.die_enter - top_die->u.p1.die_enter,
   - for all children: their hashes.
   The field die_ck_state is set to CK_BAD if the die is unsuitable for
   moving into a partial unit (contains code references or other reasons).
   TOP_DIE is initially NULL when DW_TAG_*_unit or die_named_namespace dies
   are walked.  */
static int
checksum_die (DSO *dso, dw_cu_ref cu, dw_die_ref top_die, dw_die_ref die)
{
  unsigned short s;
  struct abbrev_tag *t;
  unsigned int i;
  unsigned char *ptr;
  dw_die_ref child;
  bool only_hash_name_p;
  hashval_t die_hash2;

  switch (die->die_ck_state)
    {
    case CK_UNKNOWN:
      break;
    case CK_KNOWN:
    case CK_BAD:
      return 0;
    case CK_BEING_COMPUTED:
      die->die_ck_state = CK_BAD;
      return 0;
    }
  die->die_ck_state = CK_BEING_COMPUTED;
  die->u.p1.die_hash = 0;
  if (die->die_tag == DW_TAG_compile_unit
      || die->die_tag == DW_TAG_partial_unit
      || die->die_tag == DW_TAG_namespace
      || die->die_tag == DW_TAG_module
      || die->die_tag == DW_TAG_imported_unit)
    die->die_ck_state = CK_BAD;
  t = die->die_abbrev;
  ptr = debug_sections[DEBUG_INFO].data + die->die_offset;
  skip_leb128 (ptr);
  s = die->die_tag;
  die->u.p1.die_hash = iterative_hash_object (s, die->u.p1.die_hash);
  if (dump_checksum_p)
    fprintf (stderr, "DIE %x, hash: %x, tag\n", die->die_offset,
	     die->u.p1.die_hash);
  if (uni_lang_p && die == top_die)
    {
      die->u.p1.die_hash
	= iterative_hash_object (cu->lang, die->u.p1.die_hash);
      if (dump_checksum_p)
	fprintf (stderr, "DIE %x, hash: %x, lang\n", die->die_offset,
		 die->u.p1.die_hash);
    }

  if (odr && die->die_odr_state == ODR_UNKNOWN)
    set_die_odr_state (die_cu (die), die);
  only_hash_name_p = odr && die_odr_state (die) != ODR_NONE;
  die_hash2 = 0;
  if (only_hash_name_p)
    die_hash2 = die->u.p1.die_hash;
  for (i = 0; i < t->nattr; ++i)
    {
      uint32_t form = t->attr[i].form;
      size_t len = 0;
      unsigned char *old_ptr;
      bool handled = false;
      uint64_t value;

      while (form == DW_FORM_indirect)
	form = read_uleb128 (ptr);
      old_ptr = ptr;

      switch (t->attr[i].attr)
	{
	/* Ignore DW_AT_sibling attribute.  */
	case DW_AT_sibling:
	  handled = true;
	  break;
	/* These attributes reference code, prevent moving
	   DIEs with them.  */
	case DW_AT_low_pc:
	case DW_AT_high_pc:
	case DW_AT_entry_pc:
	case DW_AT_ranges:
	case DW_AT_call_return_pc:
	case DW_AT_call_pc:
	  die->die_ck_state = CK_BAD;
	  break;
	case DW_AT_start_scope:
	  if (form == DW_FORM_sec_offset)
	    die->die_ck_state = CK_BAD;
	  break;
	/* These attributes reference other sections, they
	   can't be moved to other files easily.  */
	case DW_AT_stmt_list:
	case DW_AT_macro_info:
	case DW_AT_macros:
	case DW_AT_GNU_macros:
	  if (!die->die_root)
	    die->die_no_multifile = 1;
	  break;
	/* loclistptr attributes.  */
	case DW_AT_location:
	case DW_AT_string_length:
	case DW_AT_return_addr:
	case DW_AT_data_member_location:
	case DW_AT_frame_base:
	case DW_AT_segment:
	case DW_AT_static_link:
	case DW_AT_use_location:
	case DW_AT_vtable_elem_location:
	  if ((cu->cu_version < 4 && form == DW_FORM_data4)
	      || form == DW_FORM_sec_offset)
	    {
	      if (read_loclist (dso, cu, die, read_32 (ptr)))
		return 1;
	      ptr = old_ptr;
	      break;
	    }
	  else if (cu->cu_version < 4 && form == DW_FORM_data8)
	    {
	      if (read_loclist (dso, cu, die, read_64 (ptr)))
		return 1;
	      ptr = old_ptr;
	      break;
	    }
	  break;
	case DW_AT_decl_file:
	case DW_AT_call_file:
	  switch (form)
	    {
	    case DW_FORM_data1: value = read_8 (ptr); handled = true; break;
	    case DW_FORM_data2: value = read_16 (ptr); handled = true; break;
	    case DW_FORM_data4: value = read_32 (ptr); handled = true; break;
	    case DW_FORM_data8: value = read_64 (ptr); handled = true; break;
	    case DW_FORM_udata:
	      value = read_uleb128 (ptr); handled = true; break;
	    case DW_FORM_sdata:
	      {
		int64_t svalue = read_sleb128 (ptr);
		if (svalue >= 0)
		  {
		    value = svalue;
		    handled = true;
		    break;
		  }
		else
		  {
		  negative:
		    error (0, 0, "%s: negative value %" PRId64 " for %s",
			   dso->filename, svalue,
			   get_DW_AT_str (t->attr[i].attr));
		    return 1;
		  }
	      }
	    case DW_FORM_implicit_const:
	      {
		if (t->values[i] >= 0)
		  {
		    value = t->values[i];
		    handled = true;
		    break;
		  }
		else
		  goto negative;
	      }
	    default:
	      error (0, 0, "%s: Unhandled %s for %s",
		     dso->filename, get_DW_FORM_str (form),
		     get_DW_AT_str (t->attr[i].attr));
	      return 1;
	    }
	  if (handled)
	    {
	      unsigned char *new_ptr = ptr;
	      ptr = old_ptr;
	      if (value > cu->cu_nfiles)
		{
		  error (0, 0, "%s: Invalid %s file number %d",
			 dso->filename, get_DW_AT_str (t->attr[i].attr),
			 (int) value);
		  return 1;
		}
	      if (value == 0)
		handled = false;
	      else if (!ignore_locus && die->die_ck_state != CK_BAD)
		{
		  struct dw_file *cu_file = &cu->cu_files[value - 1];
		  size_t file_len = strlen (cu_file->file);
		  s = t->attr[i].attr;
		  die->u.p1.die_hash
		    = iterative_hash_object (s, die->u.p1.die_hash);
		  die->u.p1.die_hash
		    = iterative_hash_object (cu_file->time,
					     die->u.p1.die_hash);
		  die->u.p1.die_hash
		    = iterative_hash_object (cu_file->size,
					     die->u.p1.die_hash);
		  die->u.p1.die_hash
		    = iterative_hash (cu_file->file, file_len + 1,
				      die->u.p1.die_hash);
		  if (cu_file->dir)
		    die->u.p1.die_hash
		      = iterative_hash (cu_file->dir,
					strlen (cu_file->dir) + 1,
					die->u.p1.die_hash);
		  /* Ignore DW_AT_comp_dir for DW_AT_*_file <built-in>
		     etc. if immediately followed by DW_AT_*_line 0.  */
		  else if (cu_file->file_angle_brackets_encapsulated_no_slash
			   && i + 1 < t->nattr
			   && t->attr[i + 1].attr
			      == (t->attr[i].attr == DW_AT_decl_file
				  ? DW_AT_decl_line : DW_AT_call_line)
			   && t->attr[i + 1].form == DW_FORM_data1
			   && *new_ptr == 0)
		    break;
		  if (cu->cu_comp_dir
		      && (cu_file->dir ? cu_file->dir[0]
				       : cu_file->file[0]) != '/')
		    die->u.p1.die_hash
		      = iterative_hash (cu->cu_comp_dir,
					strlen (cu->cu_comp_dir) + 1,
					die->u.p1.die_hash);
		}
	    }
	  break;
	case DW_AT_decl_line:
	case DW_AT_decl_column:
	case DW_AT_call_line:
	case DW_AT_call_column:
	  if (ignore_locus)
	    {
	      handled = true;
	      break;
	    }
	  switch (form)
	    {
	    case DW_FORM_data1: value = read_8 (ptr); handled = true; break;
	    case DW_FORM_data2: value = read_16 (ptr); handled = true; break;
	    case DW_FORM_data4: value = read_32 (ptr); handled = true; break;
	    case DW_FORM_data8: value = read_64 (ptr); handled = true; break;
	    case DW_FORM_udata:
	      value = read_uleb128 (ptr); handled = true; break;
	    case DW_FORM_sdata:
	      {
		int64_t svalue = read_sleb128 (ptr);
		if (svalue >= 0)
		  {
		    value = svalue;
		    handled = true;
		    break;
		  }
		else
		  goto negative;
	      }
	    case DW_FORM_implicit_const:
	      if (t->values[i] >= 0)
		{
		  value = t->values[i];
		  handled = true;
		  break;
		}
	      else
		goto negative;
	    default:
	      error (0, 0, "%s: Unhandled %s for %s",
		     dso->filename, get_DW_FORM_str (form),
		     get_DW_AT_str (t->attr[i].attr));
	      return 1;
	    }
	  if (handled)
	    {
	      ptr = old_ptr;
	      s = t->attr[i].attr;
	      die->u.p1.die_hash
		= iterative_hash_object (s, die->u.p1.die_hash);
	      die->u.p1.die_hash
		= iterative_hash_object (value, die->u.p1.die_hash);
	    }
	  break;
	default:
	  break;
	}

      switch (form)
	{
	case DW_FORM_ref_addr:
	  if (unlikely (op_multifile || rd_multifile || fi_multifile))
	    {
	      dw_die_ref ref;

	      value = read_size (ptr, cu->cu_version == 2
				      ? ptr_size : 4);
	      ptr += cu->cu_version == 2 ? ptr_size : 4;
	      if (die->die_ck_state != CK_BAD)
		{
		  s = t->attr[i].attr;
		  die->u.p1.die_hash
		    = iterative_hash_object (s, die->u.p1.die_hash);
		}
	      ref = off_htab_lookup (cu, value);
	      if (ref == NULL)
		{
		  error (0, 0, "%s: Couldn't find DIE at [%" PRIx64 "] "
			       "referenced by %s from DIE at [%x]",
			 dso->filename, value,
			 get_DW_AT_str (t->attr[i].attr), die->die_offset);
		  return 1;
		}
	      if (unlikely (op_multifile) && ref->die_collapsed_child)
		ref = ref->die_parent;
	      if (cu == die_cu (ref))
		{
		  /* The reference was encoded using a section-relative
		     encoding, while if it could have been encoded using
		     CU-relative encoding.  Typically, the latter is used,
		     because:
		     - it's potentially smaller, and
		     - it doesn't require a link-time relocation.  */

		  /* Assert that the multifile only contains section-relative
		     encoding when necessary.  */
		  assert (!op_multifile && !rd_multifile);

		  if (fi_multifile)
		    {
		      /* It's possible that the input DWARF contains this
			 sub-optimal reference.  We currently don't optimize
			 this during single-file optimization, so it will still
			 be there during finalize_multifile.  Bail out to handle
			 this conservatively.  */
		      die->die_ck_state = CK_BAD;
		      return 0;
		    }
		}
	      /* Assert that during op_multifile, die belongs to the same object
		 as ref.  */
	      assert (!op_multifile || cu->cu_chunk == die_cu (ref)->cu_chunk);
	      handled = true;
	      break;
	    }
	  die->die_no_multifile = 1;
	  ptr += cu->cu_version == 2 ? ptr_size : 4;
	  break;
	case DW_FORM_addr:
	  die->die_no_multifile = 1;
	  ptr += ptr_size;
	  break;
	case DW_FORM_flag_present:
	  break;
	case DW_FORM_implicit_const:
	  if (!handled && die->die_ck_state != CK_BAD)
	    {
	      handled = true;
	      s = t->attr[i].attr;
	      die->u.p1.die_hash
		= iterative_hash_object (s, die->u.p1.die_hash);
	      die->u.p1.die_hash
		= iterative_hash_object (t->values[i], die->u.p1.die_hash);
	    }
	  break;
	case DW_FORM_flag:
	case DW_FORM_data1:
	  ++ptr;
	  break;
	case DW_FORM_data2:
	  ptr += 2;
	  break;
	case DW_FORM_data4:
	case DW_FORM_sec_offset:
	  ptr += 4;
	  break;
	case DW_FORM_data8:
	  ptr += 8;
	  break;
	case DW_FORM_data16:
	  ptr += 16;
	  break;
	case DW_FORM_ref_sig8:
	  die->die_no_multifile = 1;
	  ptr += 8;
	  break;
	case DW_FORM_sdata:
	case DW_FORM_udata:
	  skip_leb128 (ptr);
	  break;
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	  switch (form)
	    {
	    case DW_FORM_ref_udata: value = read_uleb128 (ptr); break;
	    case DW_FORM_ref1: value = read_8 (ptr); break;
	    case DW_FORM_ref2: value = read_16 (ptr); break;
	    case DW_FORM_ref4: value = read_32 (ptr); break;
	    case DW_FORM_ref8: value = read_64 (ptr); break;
	    default: abort ();
	    }
	  if (!handled)
	    {
	      dw_die_ref ref
		= off_htab_lookup (cu, cu->cu_offset + value);
	      if (ref == NULL)
		{
		  error (0, 0, "%s: Couldn't find DIE at [%" PRIx64 "] "
			 "referenced by %s from DIE at [%x]",
			 dso->filename, cu->cu_offset + value,
			 get_DW_AT_str (t->attr[i].attr), die->die_offset);
		  return 1;
		}
	      if (die->die_ck_state != CK_BAD)
		{
		  s = t->attr[i].attr;
		  die->u.p1.die_hash
		    = iterative_hash_object (s, die->u.p1.die_hash);
		}
	      if (top_die
		  && !ref->die_collapsed_child
		  && ref->u.p1.die_enter >= top_die->u.p1.die_enter
		  && ref->u.p1.die_exit <= top_die->u.p1.die_exit)
		{
		  if (die->die_ck_state != CK_BAD)
		    {
		      unsigned int val
			= ref->u.p1.die_enter - top_die->u.p1.die_enter;
		      die->u.p1.die_hash
			= iterative_hash_object (val, die->u.p1.die_hash);
		    }
		}
	      handled = true;
	    }
	  break;
	case DW_FORM_strp:
	  if (unlikely (op_multifile || rd_multifile || fi_multifile)
	      && die->die_ck_state != CK_BAD)
	    {
	      value = read_32 (ptr);
	      if (value >= debug_sections[DEBUG_STR].size)
		die->die_ck_state = CK_BAD;
	      else
		{
		  unsigned char *p = debug_sections[DEBUG_STR].data + value;
		  unsigned int l = strlen ((char *) p) + 1;
		  s = t->attr[i].attr;
		  die->u.p1.die_hash
		    = iterative_hash_object (s, die->u.p1.die_hash);
		  die->u.p1.die_hash
		    = iterative_hash (p, l, die->u.p1.die_hash);
		  handled = true;
		}
	    }
	  else
	    {
	      ptr += 4;
	      if (only_hash_name_p && t->attr[i].attr == DW_AT_name)
		{
		  s = t->attr[i].attr;
		  die_hash2 = iterative_hash_object (s, die_hash2);
		  die_hash2
		    = iterative_hash (old_ptr, ptr - old_ptr, die_hash2);
		}
	    }
	  break;
	case DW_FORM_line_strp:
	  /* There is no .debug_line_str in the alt file, so we cannot
	     move this DIE unless we change the string reference.
	     This is not that bad because DW_FORM_line_strp is often
	     only used in the CU DIE for file name and comp_dir and we
	     don't move the CU DIE anyway.  */
	  die->die_ck_state = CK_BAD;
	  break;
	case DW_FORM_string:
	  ptr = (unsigned char *) strchr ((char *)ptr, '\0') + 1;
	  if (only_hash_name_p && t->attr[i].attr == DW_AT_name)
	    {
	      s = t->attr[i].attr;
	      die_hash2 = iterative_hash_object (s, die_hash2);
	      die_hash2
		= iterative_hash (old_ptr, ptr - old_ptr, die_hash2);
	    }
	  break;
	case DW_FORM_indirect:
	  abort ();
	case DW_FORM_block1:
	  len = *ptr++;
	  break;
	case DW_FORM_block2:
	  len = read_16 (ptr);
	  form = DW_FORM_block1;
	  break;
	case DW_FORM_block4:
	  len = read_32 (ptr);
	  form = DW_FORM_block1;
	  break;
	case DW_FORM_block:
	  len = read_uleb128 (ptr);
	  form = DW_FORM_block1;
	  break;
	case DW_FORM_exprloc:
	  len = read_uleb128 (ptr);
	  break;
	default:
	  abort ();
	}

      if (form == DW_FORM_block1 && cu->cu_version < 4)
	{
	  /* Old DWARF uses blocks instead of exprlocs.  */
	  switch (t->attr[i].attr)
	    {
	    case DW_AT_frame_base:
	    case DW_AT_location:
	    case DW_AT_data_member_location:
	    case DW_AT_vtable_elem_location:
	    case DW_AT_byte_size:
	    case DW_AT_bit_offset:
	    case DW_AT_bit_size:
	    case DW_AT_string_length:
	    case DW_AT_lower_bound:
	    case DW_AT_return_addr:
	    case DW_AT_bit_stride:
	    case DW_AT_upper_bound:
	    case DW_AT_count:
	    case DW_AT_segment:
	    case DW_AT_static_link:
	    case DW_AT_use_location:
	    case DW_AT_allocated:
	    case DW_AT_associated:
	    case DW_AT_data_location:
	    case DW_AT_byte_stride:
	    case DW_AT_rank:
	    case DW_AT_call_value:
	    case DW_AT_call_target:
	    case DW_AT_call_target_clobbered:
	    case DW_AT_call_data_location:
	    case DW_AT_call_data_value:
	    case DW_AT_GNU_call_site_value:
	    case DW_AT_GNU_call_site_data_value:
	    case DW_AT_GNU_call_site_target:
	    case DW_AT_GNU_call_site_target_clobbered:
	      if (die->die_ck_state != CK_BAD)
		{
		  s = t->attr[i].attr;
		  die->u.p1.die_hash
		    = iterative_hash_object (s, die->u.p1.die_hash);
		}
	      if (read_exprloc (dso, die, ptr, len, NULL))
		return 1;
	      handled = true;
	    default:
	      break;
	    }
	}
      else if (form == DW_FORM_exprloc)
	{
	  if (die->die_ck_state != CK_BAD)
	    {
	      s = t->attr[i].attr;
	      die->u.p1.die_hash
		= iterative_hash_object (s, die->u.p1.die_hash);
	    }
	  if (read_exprloc (dso, die, ptr, len, NULL))
	    return 1;
	  handled = true;
	}
      ptr += len; /* Skip expr/blocks.  */
      if (!handled && die->die_ck_state != CK_BAD)
	{
	  s = t->attr[i].attr;
	  die->u.p1.die_hash = iterative_hash_object (s, die->u.p1.die_hash);
	  die->u.p1.die_hash
	    = iterative_hash (old_ptr, ptr - old_ptr, die->u.p1.die_hash);
	}

      if (dump_checksum_p)
	fprintf (stderr, "DIE %x, hash: %x, attr (%d)\n", die->die_offset,
		 die->u.p1.die_hash, i);
    }

  for (child = die->die_child, i = 0; child; child = child->die_sib, ++i)
    if (checksum_die (dso, cu,
		      top_die ? top_die
			      : child->die_named_namespace
			      ? NULL : child, child))
      return 1;
    else if (die->die_ck_state != CK_BAD)
      {
	if (child->die_ck_state == CK_KNOWN)
	  {
	    die->u.p1.die_hash
	      = iterative_hash_object (child->u.p1.die_hash,
				       die->u.p1.die_hash);
	    if (dump_checksum_p)
	      fprintf (stderr, "DIE %x, hash: %x, child (%i)\n",
		       die->die_offset, die->u.p1.die_hash, i);
	    die->die_no_multifile
	      |= child->die_no_multifile;
	  }
	else
	  die->die_ck_state = CK_BAD;
      }
  if (die->die_ck_state == CK_BEING_COMPUTED)
    die->die_ck_state = CK_KNOWN;

  if (dump_checksum_p)
    fprintf (stderr, "DIE %x, hash: %x, final\n", die->die_offset,
	     die->u.p1.die_hash);

  if (only_hash_name_p)
    {
      unsigned int tmp = die->u.p1.die_hash;
      die->u.p1.die_hash = die_hash2;
      die->u.p1.die_hash2 = tmp;
    }

  return 0;
}

/* Helper function for checksum_ref_die to sort DIE pointers
   by increasing u.p1.die_hash.  */
static int
checksum_ref_die_cmp (const void *p, const void *q)
{
  dw_die_ref die1 = *(dw_die_ref *)p;
  dw_die_ref die2 = *(dw_die_ref *)q;
  if (die1->u.p1.die_hash < die2->u.p1.die_hash)
    return -1;
  if (die1->u.p1.die_hash > die2->u.p1.die_hash)
    return 1;
  /* The rest is just to keep the sort stable.  If there is more than
     one DIE with the same hash, we don't consider any of them as suitable
     starting point for the walk.  */
  if (die1->die_offset < die2->die_offset)
    return -1;
  if (die1->die_offset > die2->die_offset)
    return 1;
  return 0;
}

/* This function is the second phase of hash computation, which computes
   u.p1.die_ref_hash after u.p1.die_hash has been computed.
   u.p1.die_ref_hash is an iterative hash of the references (other than
   those checksummed already into u.p1.die_hash by checksum_die).
   u.p1.die_ref_hash is only computed for the toplevel DIEs, i.e. children
   of DW_TAG_*_unit or die_named_namespace DIEs.  So, in the graph
   containing DIEs as nodes and parent<->child and referrer<->referree edges
   we virtually coalesce all children of toplevel DIEs into the
   corresponding toplevel DIE ultimate parent node.  The function has 4
   modes of operation:

   The first one is when TOP_DIE, SECOND_IDX and SECOND_HASH are all NULL,
   this is when we walk through DW_TAG_*_unit and die_named_namespace DIEs
   to reach their children.

   The second mode of operation is with TOP_DIE != NULL and both SECOND_IDX
   and SECOND_HASH NULL.  In this mode we optimistically assume there are no
   cycles in the graph, first hash into TOP_DIE's u.p1.die_ref_hash its
   u.p1.die_hash, push the TOP_DIE into a vector (in OB obstack), for each
   reference if the referree isn't already toplevel DIE find its
   (grand)*parent that is a toplevel DIE, recurse on that and if it computed
   the referree toplevel DIE's u.p1.die_ref_hash (i.e. no cycle),
   iteratively hash in the referree toplevel DIE's u.p1.die_ref_hash (and,
   if referree isn't toplevel, before that also its relative position in the
   subtree).  When existing, remove the TOP_DIE from the vector and set
   die_ref_hash_computed to note that it is computed and doesn't have to be
   computed again.  If there are no cycles, the return value of the function
   is 0.  If a cycle is found, things are more complicated.  We can't just
   not walk into DIEs we've already seen and compute u.p1.die_ref_hash for
   toplevel DIEs on the cycle(s), because in different CUs matching cycles
   might be starting computation of the hash from different nodes on the
   cycle (the order of children of DW_TAG_*_unit or DW_TAG_namespace is
   usually not significant in DWARF).  So, if a cycle is found, the return
   value is a minimum of the die_ref_seen indexes (positions in the
   vector); at that point it makes no sense to further compute
   u.p1.die_ref_hash of the toplevel DIEs on the cycle, but for references
   to acyclic subgraphs we still continue computing their u.p1.die_ref_hash.
   For DIEs on the cycle(s) pointers to them aren't immediately removed from
   the vector and everything is handled only after reaching the TOP_DIE with
   die_ref_seen equal to the minimum vector index (i.e. the first of
   the DIEs on the cycle(s) we've seen).  At this point in the vector
   starting with that index should be a list of DIEs on the cycle, and all
   references to (toplevel) DIEs not on that list from those DIEs should
   have die_ref_hash_computed already set.  If the cycle has matches in
   different CUs, we should have the same set of u.p1.die_hash values in the
   list in between all those CUs, but the order might be different.  At this
   point we try to find a DIE from which to start walk using third mode of
   operation of this function.  We can't base that decision on e.g.
   die_offset, as it may be not just different between the CUs, but the
   matching DIEs might be in different relative orders.  So we look if there
   is just a single DIE with lowest u.p1.die_hash value and use that in that
   case, (and if not, look if there is just a single DIE with second lowest
   u.p1.die_hash and so on up to 20th).  If none is found, the more
   expensive 4th mode of operation is used instead.

   The third mode of operation is when TOP_DIE, SECOND_IDX and SECOND_HASH
   are all non-NULL.  This mode is used when the initial TOP_DIE is
   a uniquely chosen DIE on the cycle (same in each CU that has
   matching cycle).  In this mode into each TOP_DIE's u.p1.die_ref_hash
   we hash in *SECOND_IDX (counter when in that walk the DIE has been
   seen first) and relative referree positions in subtree, and hash in
   referree toplevel u.p1.die_ref_hash into *SECOND_HASH, and finally
   when the walk finishes, the caller will compute the final
   u.p1.die_ref_hash for DIEs on the cycle(s) from their intermediate
   u.p1.die_ref_hash and *SECOND_HASH.

   The last mode of operation is when TOP_DIE and SECOND_HASH
   are non-NULL, but SECOND_IDX is NULL.  This mode is used when no
   suitable DIE from which to start walking the cycle has been discovered.
   In that case we for each DIE on the cycle walk everything that hasn't
   die_ref_hash_computed yet, for DIEs seen that have die_ref_hash_computed
   hash in their u.p1.die_ref_hash, otherwise (DIEs on the current cycle(s))
   hash in their u.p1.die_hash.  */
static unsigned int
checksum_ref_die (dw_cu_ref cu, dw_die_ref top_die, dw_die_ref die,
		  unsigned int *second_idx, hashval_t *second_hash)
{
  struct abbrev_tag *t;
  unsigned int i, ret = 0;
  unsigned char *ptr;
  dw_die_ref child;

  if (top_die == die)
    {
      if (die->die_ref_hash_computed)
	return 0;
      if (die->die_ck_state != CK_KNOWN)
	return 0;
      if (die->die_ref_seen)
	return second_hash != NULL ? 0 : die->die_ref_seen;
      if (second_hash != NULL)
	{
	  die->die_ref_seen = 1;
	  if (second_idx != NULL)
	    {
	      die->u.p1.die_ref_hash
		= iterative_hash_object (*second_idx, die->u.p1.die_hash);
	      (*second_idx)++;
	    }
	}
      else
	{
	  die->die_ref_seen
	    = obstack_object_size (&ob) / sizeof (void *) + 1;
	  obstack_ptr_grow (&ob, die);
	  die->u.p1.die_ref_hash = die->u.p1.die_hash;
	}
    }
  else
    assert (top_die == NULL || die->die_ck_state == CK_KNOWN);
  t = die->die_abbrev;
  for (i = 0; i < t->nattr; ++i)
    if (t->attr[i].attr != DW_AT_sibling)
      switch (t->attr[i].form)
	{
	case DW_FORM_ref_addr:
	  if (unlikely (op_multifile || rd_multifile || fi_multifile))
	    i = -2U;
	  break;
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_indirect:
	  i = -2U;
	  break;
	}
  if (i == -1U)
    {
      ptr = debug_sections[DEBUG_INFO].data + die->die_offset;
      skip_leb128 (ptr);
      for (i = 0; i < t->nattr; ++i)
	{
	  uint32_t form = t->attr[i].form;
	  size_t len = 0;
	  uint64_t value;
	  dw_die_ref ref, reft;

	  while (form == DW_FORM_indirect)
	    form = read_uleb128 (ptr);

	  switch (form)
	    {
	    case DW_FORM_ref_addr:
	      if (unlikely (op_multifile || rd_multifile || fi_multifile))
		{
		  value = read_size (ptr, cu->cu_version == 2 ? ptr_size : 4);
		  ptr += cu->cu_version == 2 ? ptr_size : 4;
		  assert (t->attr[i].attr != DW_AT_sibling);
		  if (top_die == NULL)
		    break;
		  ref = off_htab_lookup (cu, value);
		  goto finish_ref;
		}
	      ptr += cu->cu_version == 2 ? ptr_size : 4;
	      break;
	    case DW_FORM_addr:
	      ptr += ptr_size;
	      break;
	    case DW_FORM_flag_present:
	    case DW_FORM_implicit_const:
	      break;
	    case DW_FORM_flag:
	    case DW_FORM_data1:
	      ++ptr;
	      break;
	    case DW_FORM_data2:
	      ptr += 2;
	      break;
	    case DW_FORM_data4:
	    case DW_FORM_sec_offset:
	    case DW_FORM_strp:
	    case DW_FORM_line_strp:
	      ptr += 4;
	      break;
	    case DW_FORM_data8:
	    case DW_FORM_ref_sig8:
	      ptr += 8;
	      break;
	    case DW_FORM_data16:
	      ptr += 16;
	      break;
	    case DW_FORM_sdata:
	    case DW_FORM_udata:
	      skip_leb128 (ptr);
	      break;
	    case DW_FORM_ref_udata:
	    case DW_FORM_ref1:
	    case DW_FORM_ref2:
	    case DW_FORM_ref4:
	    case DW_FORM_ref8:
	      switch (form)
		{
		case DW_FORM_ref_udata: value = read_uleb128 (ptr); break;
		case DW_FORM_ref1: value = read_8 (ptr); break;
		case DW_FORM_ref2: value = read_16 (ptr); break;
		case DW_FORM_ref4: value = read_32 (ptr); break;
		case DW_FORM_ref8: value = read_64 (ptr); break;
		default: abort ();
		}
	      if (t->attr[i].attr == DW_AT_sibling || top_die == NULL)
		break;
	      ref = off_htab_lookup (cu, cu->cu_offset + value);
	      if (ref->u.p1.die_enter >= top_die->u.p1.die_enter
		  && ref->u.p1.die_exit <= top_die->u.p1.die_exit)
		break;
	    finish_ref:
	      reft = ref;
	      while (!reft->die_root
		     && reft->die_parent->die_tag != DW_TAG_compile_unit
		     && reft->die_parent->die_tag != DW_TAG_partial_unit
		     && !reft->die_parent->die_named_namespace)
		reft = reft->die_parent;
	      if (reft->die_ck_state != CK_KNOWN || reft->die_root)
		top_die->die_ck_state = CK_BAD;
	      else
		{
		  unsigned int r = checksum_ref_die (die_cu (reft), reft, reft,
						     second_idx, second_hash);
		  if (ret == 0 || (r && r < ret))
		    ret = r;
		  if (reft->die_ck_state != CK_KNOWN)
		    top_die->die_ck_state = CK_BAD;
		  else
		    top_die->die_no_multifile |= reft->die_no_multifile;
		}
	      if (top_die->die_ck_state == CK_BAD)
		{
		  if (top_die != die)
		    return ret;
		  i = t->nattr - 1;
		  break;
		}
	      if (ret)
		break;
	      if (reft != ref)
		{
		  unsigned int val
		    = ref->u.p1.die_enter - reft->u.p1.die_enter;
		  if (second_hash != NULL && second_idx == NULL)
		    *second_hash
		      = iterative_hash_object (val, *second_hash);
		  else
		    top_die->u.p1.die_ref_hash
		      = iterative_hash_object (val,
					       top_die->u.p1.die_ref_hash);
		}
	      if (second_hash)
		{
		  if (second_idx == NULL && !reft->die_ref_hash_computed)
		    *second_hash
		      = iterative_hash_object (reft->u.p1.die_hash,
					       *second_hash);
		  else
		    *second_hash
		      = iterative_hash_object (reft->u.p1.die_ref_hash,
					       *second_hash);
		}
	      else
		top_die->u.p1.die_ref_hash
		  = iterative_hash_object (reft->u.p1.die_ref_hash,
					   top_die->u.p1.die_ref_hash);
	      break;
	    case DW_FORM_string:
	      ptr = (unsigned char *) strchr ((char *)ptr, '\0') + 1;
	      break;
	    case DW_FORM_indirect:
	      abort ();
	    case DW_FORM_block1:
	      len = *ptr++;
	      break;
	    case DW_FORM_block2:
	      len = read_16 (ptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_block4:
	      len = read_32 (ptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_block:
	    case DW_FORM_exprloc:
	      len = read_uleb128 (ptr);
	      form = DW_FORM_block1;
	      break;
	    default:
	      abort ();
	    }

	  if (form == DW_FORM_block1)
	    ptr += len;
	}
    }

  if (top_die == NULL || top_die->die_ck_state != CK_BAD)
    {
      for (child = die->die_child; child; child = child->die_sib)
	{
	  unsigned int r
	    = checksum_ref_die (cu,
				top_die ? top_die
				: child->die_named_namespace
				? NULL : child, child,
				second_idx, second_hash);
	  if (top_die == NULL)
	    assert (r == 0 && obstack_object_size (&ob) == 0);

	  if (ret == 0 || (r && r < ret))
	    ret = r;
	  if (top_die && top_die->die_ck_state == CK_BAD)
	    break;
	}
     }

  if (top_die == die)
    {
      if (ret == 0)
	{
	  if (second_hash != NULL)
	    return 0;
	  die->die_ref_seen = 0;
	  die->die_ref_hash_computed = 1;
	  obstack_blank_fast (&ob, -(int) sizeof (void *));
	  return 0;
	}
      assert (ret <= die->die_ref_seen);
      if (ret == die->die_ref_seen)
	{
	  unsigned int first = die->die_ref_seen - 1;
	  dw_die_ref *arr;
	  unsigned int count
	    = obstack_object_size (&ob) / sizeof (void *) - first;
	  unsigned int idx, minidx;
	  hashval_t ref_hash = 0;
	  bool bad = false;
	  bool no_multifile = false;

	  arr = (dw_die_ref *) obstack_base (&ob) + first;
	  for (i = 0; i < count; i++)
	    {
	      arr[i]->die_ref_seen = 0;
	      if (arr[i]->die_ck_state == CK_BAD)
		bad = true;
	      else if (arr[i]->die_no_multifile)
		no_multifile = true;
	    }
	  if (bad)
	    {
	      for (i = 0; i < count; i++)
		arr[i]->die_ck_state = CK_BAD;
	      obstack_blank_fast (&ob, -(int) (count * sizeof (void *)));
	      return 0;
	    }
	  /* Find the DIE in the array with the smallest u.p1.die_hash.  */
	  for (i = 0, minidx = -1U, bad = true; i < count; i++)
	    {
	      if (no_multifile)
		arr[i]->die_no_multifile = 1;
	      if (minidx == -1U
		  || arr[i]->u.p1.die_hash < arr[minidx]->u.p1.die_hash)
		{
		  minidx = i;
		  bad = false;
		}
	      else if (arr[i]->u.p1.die_hash == arr[minidx]->u.p1.die_hash)
		bad = true;
	    }
	  if (bad)
	    {
	      unsigned int iter, limv;
	      /* If there is more than one smallest u.p1.die_hash,
		 look for second (up to 6th) smallest u.p1.die_hash
		 if there is just one of that value.  */
	      for (iter = 0; iter < 5; iter++)
		{
		  limv = arr[minidx]->u.p1.die_hash;
		  for (i = 0, minidx = -1U, bad = true; i < count; i++)
		    if (arr[i]->u.p1.die_hash <= limv)
		      continue;
		    else if (minidx == -1U
			     || arr[i]->u.p1.die_hash
				< arr[minidx]->u.p1.die_hash)
		      {
			minidx = i;
			bad = false;
		      }
		    else if (arr[i]->u.p1.die_hash
			     == arr[minidx]->u.p1.die_hash)
		      bad = true;
		  if (minidx == -1U || !bad)
		    break;
		}
	      /* If all of 1st to 6th smallest u.p1.die_hash has more than
		 one DIE with that u.p1.die_hash, sort the array and find
		 the smallest u.p1.die_hash that only a single DIE has.  */
	      if (minidx != -1U && iter == 5)
		{
		  unsigned int j;
		  qsort (arr, count, sizeof (void *), checksum_ref_die_cmp);
		  for (i = 0, minidx = -1U; i < count; i = j)
		    {
		      if (i + 1 == count
			  || arr[i + 1]->u.p1.die_hash
			     != arr[i]->u.p1.die_hash)
			{
			  minidx = i;
			  break;
			}
		      for (j = i + 1; j < count; j++)
			if (arr[j]->u.p1.die_hash != arr[i]->u.p1.die_hash)
			  break;
		    }
		}
	    }
	  if (checksum_cycle_opt && minidx != -1U)
	    {
	      idx = 0;
	      checksum_ref_die (die_cu (arr[minidx]), arr[minidx],
				arr[minidx], &idx, &ref_hash);
	      assert (arr == (dw_die_ref *) obstack_base (&ob) + first);
	      for (i = 0; i < count; i++)
		{
		  arr[i]->u.p1.die_ref_hash
		    = iterative_hash_object (arr[i]->u.p1.die_ref_hash,
					     ref_hash);
		  arr[i]->die_ref_hash_computed = 1;
		  arr[i]->die_ref_seen = 0;
		}
	    }
	  else
	    {
	      /* If we get here, all u.p1.die_hash values in the arr array
		 are used by more than one DIE.  Do the more expensive
		 computation as fallback.  */
	      for (i = 0; i < count; i++)
		{
		  unsigned int j;
		  arr[i]->u.p1.die_ref_hash = arr[i]->u.p1.die_hash;
		  checksum_ref_die (die_cu (arr[i]), arr[i], arr[i], NULL,
				    &arr[i]->u.p1.die_ref_hash);
		  assert (arr == (dw_die_ref *) obstack_base (&ob) + first);
		  for (j = 0; j < count; j++)
		    arr[j]->die_ref_seen = 0;
		}
	      for (i = 0; i < count; i++)
		arr[i]->die_ref_hash_computed = 1;
	    }
	  obstack_blank_fast (&ob, -(int) (count * sizeof (void *)));
	  return 0;
	}
    }
  return ret;
}

/* Hash function for dup_htab.  u.p1.die_ref_hash should have u.p1.die_hash
   iteratively hashed into it already.  */
static hashval_t
die_hash (const void *p)
{
  dw_die_ref die = (dw_die_ref) p;

  return die->u.p1.die_ref_hash;
}

/* Freelist of !die->die_toplevel DIEs, chained through die_sib fields.  */
static dw_die_ref die_nontoplevel_freelist;
/* Freelist of die->die_collapsed_child DIEs, chained through die_parent
   fields.  */
static dw_die_ref die_collapsed_child_freelist;

/* Return pointer after the attributes of a DIE from a cu with CU_VERSION
   which uses abbrevs T and starts at PTR.  */
static unsigned char *
skip_attrs_1 (unsigned int cu_version, struct abbrev_tag *t, unsigned char *ptr)
{
  unsigned int i;
  for (i = 0; i < t->nattr; ++i)
    ptr = skip_attr (cu_version, &t->attr[i], ptr);

  return ptr;
}

/* Return pointer after the attributes of a DIE from CU which uses abbrevs
   T and starts at PTR.  */
static unsigned char *
skip_attrs (dw_cu_ref cu, struct abbrev_tag *t, unsigned char *ptr)
{
  return skip_attrs_1 (cu->cu_version, t, ptr);
}

/* Expand children of TOP_DIE that have been collapsed by
   collapse_child.  CHECKSUM is true if checksum should be
   computed - expansion is performed during read_debug_info
   when duplicates are looked for - or false, if the expansion
   is performed late (e.g. during compute_abbrevs or write_{info,types}.  */
static void
expand_child (dw_die_ref top_die, bool checksum)
{
  dw_cu_ref cu = die_cu (top_die);
  dw_die_ref *diep = &top_die->die_child;
  dw_die_ref parent = top_die, child;
  unsigned char *ptr, *base;
  struct abbrev_tag tag, *t;
  dw_die_ref die;
  unsigned int tick = checksum ? top_die->u.p1.die_enter + 1 : 0;

  if (unlikely (cu->cu_kind == CU_TYPES))
    base = debug_sections[DEBUG_TYPES].data;
  else
    base = debug_sections[DEBUG_INFO].data;
  ptr = base + top_die->die_offset;
  if (likely (checksum))
    ptr += top_die->die_size;
  else
    {
      t = top_die->die_abbrev;
      skip_leb128 (ptr);
      ptr = skip_attrs (cu, t, ptr);
    }

  while (1)
    {
      unsigned int die_offset = ptr - base;
      void **slot;
      struct dw_die diebuf;
      dw_die_ref collapsed;

      tag.entry = read_uleb128 (ptr);
      if (tag.entry == 0)
	{
	  if (parent == top_die)
	    break;
	  diep = &parent->die_sib;
	  if (checksum)
	    parent->u.p1.die_exit = tick++;
	  parent = parent->die_parent;
	  continue;
	}

      diebuf.die_offset = die_offset;
      slot = htab_find_slot_with_hash (cu->cu_kind == CU_TYPES
				       ? types_off_htab : off_htab,
				       &diebuf, off_hash (&diebuf), NO_INSERT);
      if (slot == NULL)
	die = NULL;
      else
	die = (dw_die_ref) *slot;
      if (die != NULL && !die->die_collapsed_child)
	{
	  *diep = die;
	  die->die_parent = parent;
	  die->die_ck_state = CK_UNKNOWN;
	  die->die_ref_seen = 0;
	  assert (!checksum || die->u.p1.die_enter == tick);
	  if (die->die_abbrev->children)
	    {
	      diep = &die->die_child;
	      parent = die;
	    }
	  else
	    {
	      diep = &die->die_sib;
	      assert (!checksum || die->u.p1.die_exit == tick);
	    }
	  tick++;
	  if (checksum)
	    ptr = base + die_offset + die->die_size;
	  else
	    ptr = skip_attrs (cu, die->die_abbrev, ptr);
	  continue;
	}

      collapsed = die;
      t = htab_find_with_hash (cu->cu_abbrev, &tag, tag.entry);
      if (die_nontoplevel_freelist)
	{
	  die = die_nontoplevel_freelist;
	  die_nontoplevel_freelist = die->die_sib;
	}
      else
	die = pool_alloc (dw_die, offsetof (struct dw_die, die_dup));
      memset (die, '\0', offsetof (struct dw_die, die_dup));
      *diep = die;
      die->die_tag = t->tag;
      die->die_abbrev = t;
      die->die_offset = die_offset;
      die->die_parent = parent;
      if (checksum)
	{
	  die->u.p1.die_enter = tick;
	  die->u.p1.die_exit = tick++;
	}
      if (t->children)
	{
	  diep = &die->die_child;
	  parent = die;
	}
      else
	diep = &die->die_sib;

      ptr = skip_attrs (cu, t, ptr);
      die->die_size = (ptr - base) - die_offset;
      if (collapsed != NULL)
	{
	  die->die_referenced = collapsed->die_referenced;
	  *slot = (void *) die;
	  memset (collapsed, '\0', offsetof (struct dw_die, die_child));
	  collapsed->die_parent = die_collapsed_child_freelist;
	  die_collapsed_child_freelist = collapsed;
	}
    }
  assert (!checksum || top_die->u.p1.die_exit == tick);
  top_die->die_collapsed_children = 0;
  if (checksum && likely (cu->cu_kind != CU_TYPES))
    for (child = top_die->die_child; child; child = child->die_sib)
      checksum_die (NULL, cu, top_die, child);
}

/* Call expand_child on all collapsed toplevel children DIEs.  */
static bool
expand_children (dw_die_ref die)
{
  dw_die_ref child;
  bool ret = false;
  for (child = die->die_child; child; child = child->die_sib)
    if (child->die_named_namespace)
      ret |= expand_children (child);
    else if (child->die_collapsed_children)
      {
	expand_child (child, false);
	ret = true;
      }
  return ret;
}

static unsigned odr_phase;

/* Return 1 if DIE1 and DIE2 match.  TOP_DIE1 and TOP_DIE2
   is the corresponding ultimate parent with die_toplevel
   set.  u.p1.die_hash and u.p1.die_ref_hash hashes should
   hopefully ensure that in most cases this function actually
   just verifies matching.  */
static int
die_eq_1 (dw_cu_ref cu1, dw_cu_ref cu2,
	  dw_die_ref top_die1, dw_die_ref top_die2,
	  dw_die_ref die1, dw_die_ref die2)
{
  struct abbrev_tag *t1, *t2;
  unsigned int i, j;
  unsigned char *ptr1, *ptr2;
  dw_die_ref ref1, ref2;
  dw_die_ref child1, child2;
  bool only_compare_name_p;

#define FAIL goto fail
  if (die1 == die2 || die_safe_dup (die2) == die1)
    return 1;
  if (die1->u.p1.die_hash != die2->u.p1.die_hash
      || die1->u.p1.die_ref_hash != die2->u.p1.die_ref_hash
      || die1->die_tag != die2->die_tag
      || (!odr && (die1->u.p1.die_exit - die1->u.p1.die_enter
		   != die2->u.p1.die_exit - die2->u.p1.die_enter))
      || die_safe_dup (die2) != NULL
      || die1->die_ck_state != CK_KNOWN
      || die2->die_ck_state != CK_KNOWN
      || die1->die_toplevel != die2->die_toplevel)
    return 0;
  assert (!die1->die_root && !die2->die_root);

  if (uni_lang_p && die1 == top_die1 && die2 == top_die2
      && cu1->lang != cu2->lang)
    return 0;

  only_compare_name_p
    = odr && die1->die_odr_state != ODR_NONE && die2->die_odr_state != ODR_NONE;

  if (only_compare_name_p && odr_phase == 1)
    {
      const char *name1 = get_AT_string (die1, DW_AT_name);
      const char *name2 = get_AT_string (die2, DW_AT_name);
      // TODO: Handle DW_AT_linkage_name?
      if (name1 == NULL || name2 == NULL)
	return 0;
      if (strcmp (name1, name2) != 0)
	return 0;
    }
  else if (die1->u.p1.die_exit - die1->u.p1.die_enter
	   != die2->u.p1.die_exit - die2->u.p1.die_enter)
    return 0;

  if (only_compare_name_p && odr_phase == 2
      && die1->die_odr_state == ODR_DEF && die2->die_odr_state == ODR_DEF)
    {
      if (die1->u.p1.die_hash2 != die2->u.p1.die_hash2)
	return 0;
    }

  t1 = die1->die_abbrev;
  t2 = die2->die_abbrev;
  if (likely (!fi_multifile))
    {
      ptr1 = debug_sections[DEBUG_INFO].data + die1->die_offset;
      ptr2 = debug_sections[DEBUG_INFO].data + die2->die_offset;
    }
  else
    {
      if (cu1->cu_kind == CU_ALT)
	ptr1 = alt_data[DEBUG_INFO];
      else
	ptr1 = debug_sections[DEBUG_INFO].data;
      ptr1 += die1->die_offset;
      if (cu2->cu_kind == CU_ALT)
	ptr2 = alt_data[DEBUG_INFO];
      else
	ptr2 = debug_sections[DEBUG_INFO].data;
      ptr2 += die2->die_offset;
    }
  skip_leb128 (ptr1);
  skip_leb128 (ptr2);
  i = 0;
  j = 0;
  if (die1->die_toplevel)
    {
      for (ref1 = die1->die_parent, ref2 = die2->die_parent; ref1 && ref2; )
	{
	  const char *name1, *name2;
	  if ((ref1->die_tag == DW_TAG_compile_unit
	       || ref1->die_tag == DW_TAG_partial_unit)
	      && (ref2->die_tag == DW_TAG_compile_unit
		  || ref2->die_tag == DW_TAG_partial_unit))
	    break;
	  if (ref1->die_tag != ref2->die_tag)
	    return 0;
	  if (!ref1->die_named_namespace || !ref2->die_named_namespace)
	    return 0;
	  name1 = get_AT_string (ref1, DW_AT_name);
	  name2 = get_AT_string (ref2, DW_AT_name);
	  if (strcmp (name1, name2))
	    return 0;
	  ref1 = ref1->die_root ? NULL : ref1->die_parent;
	  ref2 = ref2->die_root ? NULL : ref2->die_parent;
	}
      if (ref1 == NULL || ref2 == NULL)
	return 0;
      /* For each toplevel die seen, record optimistically
	 that we expect them to match, to avoid recursing
	 on it again.  If non-match is determined later,
	 die_eq wrapper undoes this (which is why the DIE
	 pointer is added to the vector).  */
      if (!die2->die_op_type_referenced)
	die2->die_remove = 1;
      obstack_ptr_grow (&ob, die2);
      if (likely (die2->die_nextdup == NULL))
	{
	  die2->die_dup = die1;
	  die2->die_nextdup = die1->die_nextdup;
	  obstack_ptr_grow (&ob, NULL);
	}
      else
	{
	  dw_die_ref next;
	  for (next = die2; next->die_nextdup; next = next->die_nextdup)
	    next->die_dup = die1;
	  next->die_dup = die1;
	  next->die_nextdup = die1->die_nextdup;
	  obstack_ptr_grow (&ob, next);
	}
      die1->die_nextdup = die2;
    }

  if (only_compare_name_p && odr_phase == 1)
    return 1;

  while (1)
    {
      uint32_t form1, form2;
      size_t len = 0;
      unsigned char *old_ptr1;
      unsigned char *old_ptr2;
      uint64_t value1, value2;

      while (i < t1->nattr && t1->attr[i].attr == DW_AT_sibling)
	{
	  form1 = t1->attr[i].form;
	  while (form1 == DW_FORM_indirect)
	    form1 = read_uleb128 (ptr1);
	  switch (form1)
	    {
	    case DW_FORM_ref_udata: skip_leb128 (ptr1); break;
	    case DW_FORM_ref1: ptr1++; break;
	    case DW_FORM_ref2: read_16 (ptr1); break;
	    case DW_FORM_ref4: read_32 (ptr1); break;
	    case DW_FORM_ref8: read_64 (ptr1); break;
	    default: FAIL;
	    }
	  i++;
	}
      while (j < t2->nattr && t2->attr[j].attr == DW_AT_sibling)
	{
	  form2 = t2->attr[j].form;
	  while (form2 == DW_FORM_indirect)
	    form2 = read_uleb128 (ptr2);
	  switch (form2)
	    {
	    case DW_FORM_ref_udata: skip_leb128 (ptr2); break;
	    case DW_FORM_ref1: ptr2++; break;
	    case DW_FORM_ref2: read_16 (ptr2); break;
	    case DW_FORM_ref4: read_32 (ptr2); break;
	    case DW_FORM_ref8: read_64 (ptr2); break;
	    default: FAIL;
	    }
	  j++;
	}
      if (i == t1->nattr)
	{
	  if (j != t2->nattr)
	    FAIL;
	  break;
	}
      if (j == t2->nattr)
	FAIL;

      if (t1->attr[i].attr != t2->attr[j].attr)
	FAIL;

      form1 = t1->attr[i].form;
      while (form1 == DW_FORM_indirect)
	form1 = read_uleb128 (ptr1);
      form2 = t2->attr[j].form;
      while (form2 == DW_FORM_indirect)
	form2 = read_uleb128 (ptr2);
      old_ptr1 = ptr1;
      old_ptr2 = ptr2;

      switch (t1->attr[i].attr)
	{
	case DW_AT_sibling:
	case DW_AT_low_pc:
	case DW_AT_high_pc:
	case DW_AT_entry_pc:
	case DW_AT_ranges:
	case DW_AT_call_return_pc:
	case DW_AT_call_pc:
	  /* We shouldn't be hitting DIEs with attributes referencing
	     addresses and we should have removed DW_AT_subling.  */
	  abort ();
	case DW_AT_decl_file:
	case DW_AT_call_file:
	  switch (form1)
	    {
	    case DW_FORM_data1: value1 = read_8 (ptr1); break;
	    case DW_FORM_data2: value1 = read_16 (ptr1); break;
	    case DW_FORM_data4: value1 = read_32 (ptr1); break;
	    case DW_FORM_data8: value1 = read_64 (ptr1); break;
	    case DW_FORM_udata: value1 = read_uleb128 (ptr1); break;
	    case DW_FORM_sdata: value1 = read_sleb128 (ptr1); break;
	    case DW_FORM_implicit_const: value1 = t1->values[i]; break;
	    default: abort ();
	    }
	  switch (form2)
	    {
	    case DW_FORM_data1: value2 = read_8 (ptr2); break;
	    case DW_FORM_data2: value2 = read_16 (ptr2); break;
	    case DW_FORM_data4: value2 = read_32 (ptr2); break;
	    case DW_FORM_data8: value2 = read_64 (ptr2); break;
	    case DW_FORM_udata: value2 = read_uleb128 (ptr2); break;
	    case DW_FORM_sdata: value2 = read_sleb128 (ptr2); break;
	    case DW_FORM_implicit_const: value2 = t2->values[j]; break;
	    default: abort ();
	    }
	  if (ignore_locus)
	    {
	      i++;
	      j++;
	      continue;
	    }
	  if ((value1 == 0) ^ (value2 == 0))
	    FAIL;
	  if (value1 != 0)
	    {
	      struct dw_file *cu_file1
		= &cu1->cu_files[value1 - 1];
	      struct dw_file *cu_file2
		= &cu2->cu_files[value2 - 1];

	      if (cu_file1->time != cu_file2->time
		  || cu_file1->size != cu_file2->size
		  || strcmp (cu_file1->file, cu_file2->file))
		FAIL;

	      if (cu_file1->dir != NULL)
		{
		  if (cu_file2->dir == NULL
		      || strcmp (cu_file1->dir, cu_file2->dir))
		    FAIL;
		}
	      else if (cu_file2->dir != NULL)
		FAIL;
	      /* Ignore DW_AT_comp_dir for DW_AT_*_file <built-in>
		 etc. if immediately followed by DW_AT_*_line 0.  */
	      else if (cu_file1->file_angle_brackets_encapsulated_no_slash
		       && i + 1 < t1->nattr
		       && j + 1 < t2->nattr
		       && t1->attr[i + 1].attr
			  == (t1->attr[i].attr == DW_AT_decl_file
			      ? DW_AT_decl_line : DW_AT_call_line)
		       && t1->attr[i + 1].form == DW_FORM_data1
		       && t1->attr[i + 1].attr == t2->attr[j + 1].attr
		       && t2->attr[j + 1].form == DW_FORM_data1
		       && *ptr1 == 0
		       && *ptr2 == 0)
		{
		  i++;
		  j++;
		  continue;
		}

	      if ((cu_file1->dir ? cu_file1->dir[0] : cu_file1->file[0])
		  != '/')
		{
		  if (cu1->cu_comp_dir != NULL)
		    {
		      if (cu2->cu_comp_dir == NULL
			  || strcmp (cu1->cu_comp_dir, cu2->cu_comp_dir))
			FAIL;
		    }
		  else if (cu2->cu_comp_dir != NULL)
		    FAIL;
		}
	    }
	  i++;
	  j++;
	  continue;
	case DW_AT_decl_line:
	case DW_AT_decl_column:
	case DW_AT_call_line:
	case DW_AT_call_column:
	  if (ignore_locus)
	    {
	      old_ptr1 = NULL;
	      break;
	    }
	  switch (form1)
	    {
	    case DW_FORM_data1: value1 = read_8 (ptr1); break;
	    case DW_FORM_data2: value1 = read_16 (ptr1); break;
	    case DW_FORM_data4: value1 = read_32 (ptr1); break;
	    case DW_FORM_data8: value1 = read_64 (ptr1); break;
	    case DW_FORM_udata: value1 = read_uleb128 (ptr1); break;
	    case DW_FORM_sdata: value1 = read_sleb128 (ptr1); break;
	    case DW_FORM_implicit_const: value1 = t1->values[i]; break;
	    default: abort ();
	    }
	  switch (form2)
	    {
	    case DW_FORM_data1: value2 = read_8 (ptr2); break;
	    case DW_FORM_data2: value2 = read_16 (ptr2); break;
	    case DW_FORM_data4: value2 = read_32 (ptr2); break;
	    case DW_FORM_data8: value2 = read_64 (ptr2); break;
	    case DW_FORM_udata: value2 = read_uleb128 (ptr2); break;
	    case DW_FORM_sdata: value2 = read_sleb128 (ptr2); break;
	    case DW_FORM_implicit_const: value2 = t2->values[j]; break;
	    default: abort ();
	    }
	  if (value1 != value2)
	    FAIL;
	  i++;
	  j++;
	  continue;
	default:
	  break;
	}

      switch (form1)
	{
	case DW_FORM_ref_addr:
	  if (likely (!op_multifile && !rd_multifile && !fi_multifile))
	    {
	      if (form1 != form2)
		FAIL;
	      break;
	    }
	  /* FALLTHRU */
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	  switch (form2)
	    {
	    case DW_FORM_ref_addr:
	      if (likely (!op_multifile && !rd_multifile && !fi_multifile))
		FAIL;
	      break;
	    case DW_FORM_ref_udata:
	    case DW_FORM_ref1:
	    case DW_FORM_ref2:
	    case DW_FORM_ref4:
	    case DW_FORM_ref8:
	      break;
	    default:
	      FAIL;
	    }
	  break;
	default:
	  if (form1 != form2)
	    FAIL;
	  break;
	}

      switch (form1)
	{
	case DW_FORM_addr:
	  ptr1 += ptr_size;
	  ptr2 += ptr_size;
	  break;
	case DW_FORM_flag_present:
	  break;
	case DW_FORM_implicit_const:
	  if ((!ignore_locus || old_ptr1) && t1->values[i] != t2->values[j])
	    FAIL;
	  break;
	case DW_FORM_flag:
	case DW_FORM_data1:
	  ++ptr1;
	  ++ptr2;
	  break;
	case DW_FORM_data2:
	  ptr1 += 2;
	  ptr2 += 2;
	  break;
	case DW_FORM_data4:
	case DW_FORM_sec_offset:
	  ptr1 += 4;
	  ptr2 += 4;
	  break;
	case DW_FORM_data8:
	case DW_FORM_ref_sig8:
	  ptr1 += 8;
	  ptr2 += 8;
	  break;
	case DW_FORM_data16:
	  ptr1 += 16;
	  ptr2 += 16;
	  break;
	case DW_FORM_sdata:
	case DW_FORM_udata:
	  skip_leb128 (ptr1);
	  skip_leb128 (ptr2);
	  break;
	case DW_FORM_strp:
	  if (unlikely (op_multifile || rd_multifile || fi_multifile))
	    {
	      value1 = read_32 (ptr1);
	      value2 = read_32 (ptr2);
	      if (fi_multifile)
		{
		  if (strcmp ((char *) (cu1->cu_kind == CU_ALT
					? alt_data[DEBUG_STR]
					: debug_sections[DEBUG_STR].data)
			      + value1,
			      (char *) (cu2->cu_kind == CU_ALT
					? alt_data[DEBUG_STR]
					: debug_sections[DEBUG_STR].data)
			      + value2) != 0)
		    FAIL;
		  i++;
		  j++;
		  continue;
		}
	      if (strcmp ((char *) debug_sections[DEBUG_STR].data + value1,
			  (char *) debug_sections[DEBUG_STR].data + value2)
		  != 0)
		FAIL;
	      i++;
	      j++;
	      continue;
	    }
	  ptr1 += 4;
	  ptr2 += 4;
	  break;
	case DW_FORM_line_strp:
	  ptr1 += 4;
	  ptr2 += 4;
	  break;
	case DW_FORM_string:
	  ptr1 = (unsigned char *) strchr ((char *)ptr1, '\0') + 1;
	  ptr2 = (unsigned char *) strchr ((char *)ptr2, '\0') + 1;
	  break;
	case DW_FORM_indirect:
	  abort ();
	case DW_FORM_block1:
	  len = *ptr1++;
	  ptr1 += len;
	  len = *ptr2++;
	  ptr2 += len;
	  break;
	case DW_FORM_block2:
	  len = read_16 (ptr1);
	  ptr1 += len;
	  len = read_16 (ptr2);
	  ptr2 += len;
	  break;
	case DW_FORM_block4:
	  len = read_32 (ptr1);
	  ptr1 += len;
	  len = read_32 (ptr2);
	  ptr2 += len;
	  break;
	case DW_FORM_block:
	case DW_FORM_exprloc:
	  len = read_uleb128 (ptr1);
	  ptr1 += len;
	  len = read_uleb128 (ptr2);
	  ptr2 += len;
	  break;
	case DW_FORM_ref_addr:
	  if (likely (!op_multifile && !rd_multifile && !fi_multifile))
	    {
	      ptr1 += cu1->cu_version == 2 ? ptr_size : 4;
	      ptr2 += cu2->cu_version == 2 ? ptr_size : 4;
	      break;
	    }
	  /* FALLTHRU */
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	  switch (form1)
	    {
	    case DW_FORM_ref_addr:
	      value1 = read_size (ptr1, cu1->cu_version == 2
					? ptr_size : 4)
		       - cu1->cu_offset;
	      ptr1 += cu1->cu_version == 2 ? ptr_size : 4;
	      break;
	    case DW_FORM_ref_udata:
	      value1 = read_uleb128 (ptr1);
	      break;
	    case DW_FORM_ref1:
	      value1 = read_8 (ptr1);
	      break;
	    case DW_FORM_ref2:
	      value1 = read_16 (ptr1);
	      break;
	    case DW_FORM_ref4:
	      value1 = read_32 (ptr1);
	      break;
	    case DW_FORM_ref8:
	      value1 = read_64 (ptr1);
	      break;
	    default: abort ();
	    }
	  ref1 = off_htab_lookup (cu1, cu1->cu_offset + value1);
	  switch (form2)
	    {
	    case DW_FORM_ref_addr:
	      value2 = read_size (ptr2, cu2->cu_version == 2
					? ptr_size : 4)
		       - cu2->cu_offset;
	      ptr2 += cu2->cu_version == 2 ? ptr_size : 4;
	      break;
	    case DW_FORM_ref_udata:
	      value2 = read_uleb128 (ptr2);
	      break;
	    case DW_FORM_ref1:
	      value2 = read_8 (ptr2);
	      break;
	    case DW_FORM_ref2:
	      value2 = read_16 (ptr2);
	      break;
	    case DW_FORM_ref4:
	      value2 = read_32 (ptr2);
	      break;
	    case DW_FORM_ref8:
	      value2 = read_64 (ptr2);
	      break;
	    default: abort ();
	    }
	  ref2 = off_htab_lookup (cu2, cu2->cu_offset + value2);
	  assert (ref1 != NULL && ref2 != NULL);
	  if (unlikely (op_multifile || low_mem))
	    {
	      if (die1->die_collapsed_children && ref1->die_collapsed_child)
		{
		  expand_child (die1, true);
		  ref1 = off_htab_lookup (cu1, cu1->cu_offset + value1);
		}
	      assert (ref2->die_collapsed_child == 0);
	    }
	  if (likely (!ref1->die_collapsed_child)
	      && die_cu (ref1) == cu1
	      && ref1->u.p1.die_enter >= top_die1->u.p1.die_enter
	      && ref1->u.p1.die_exit <= top_die1->u.p1.die_exit)
	    {
	      /* A reference into a subdie of the DIE being compared.  */
	      if (die_cu (ref2) != cu2
		  || ref1->u.p1.die_enter - top_die1->u.p1.die_enter
		     != ref2->u.p1.die_enter - top_die2->u.p1.die_enter
		  || top_die1->u.p1.die_exit - ref1->u.p1.die_exit
		     != top_die2->u.p1.die_exit - ref2->u.p1.die_exit)
		FAIL;
	    }
	  else
	    {
	      dw_die_ref reft1 = ref1, reft2 = ref2;
	      dw_cu_ref refcu1, refcu2;
	      while (reft1->die_toplevel == 0)
		reft1 = reft1->die_parent;
	      while (reft2->die_toplevel == 0)
		reft2 = reft2->die_parent;
	      if (unlikely (ref1->die_collapsed_child))
		{
		  if (ref1->die_tag
		      != ref2->u.p1.die_enter - reft2->u.p1.die_enter)
		    FAIL;
		}
	      else if (ref1->u.p1.die_enter - reft1->u.p1.die_enter
		       != ref2->u.p1.die_enter - reft2->u.p1.die_enter)
		FAIL;
	      refcu1 = die_cu (reft1);
	      refcu2 = die_cu (reft2);
	      if (unlikely (refcu1->cu_chunk == refcu2->cu_chunk)
		  && likely (!fi_multifile))
		{
		  if (reft1->die_dup
		      && die_cu (reft1->die_dup)->cu_chunk
			 == refcu1->cu_chunk)
		    reft1 = reft1->die_dup;
		  if (reft2->die_dup
		      && die_cu (reft2->die_dup)->cu_chunk
			 == refcu2->cu_chunk)
		    reft2 = reft2->die_dup;
		  if (reft2->die_offset < reft1->die_offset)
		    {
		      dw_die_ref tem = reft1;
		      reft1 = reft2;
		      reft2 = tem;
		    }
		  if (reft1->die_dup == NULL && reft2->die_dup != NULL)
		    {
		      dw_die_ref tem = reft1;
		      reft1 = reft2;
		      reft2 = tem;
		    }
		}
	      /* If reft1 (die1 or whatever refers to it is already
		 in the hash table) already has a dup, follow to that
		 dup.  Don't do the same for reft2, {{top_,}die,reft,child}2
		 should always be from the current CU.  */
	      if (reft1->die_dup)
		reft1 = reft1->die_dup;
	      refcu1 = die_cu (reft1);
	      refcu2 = die_cu (reft2);
	      if (die_eq_1 (refcu1, refcu2, reft1, reft2, reft1, reft2) == 0)
		FAIL;
	    }
	  i++;
	  j++;
	  continue;
	default:
	  abort ();
	}

      if ((!ignore_locus || old_ptr1)
	  && (ptr1 - old_ptr1 != ptr2 - old_ptr2
	      || memcmp (old_ptr1, old_ptr2, ptr1 - old_ptr1)))
	FAIL;
      i++;
      j++;
    }

  if (unlikely (op_multifile || low_mem))
    {
      if (die1->die_collapsed_children)
	expand_child (die1, true);
      assert (die2->die_collapsed_children == 0);
    }

  for (child1 = die1->die_child, child2 = die2->die_child;
       child1 && child2;
       child1 = child1->die_sib, child2 = child2->die_sib)
    if (die_eq_1 (cu1, cu2, top_die1, top_die2, child1, child2) == 0)
      FAIL;

  if (child1 || child2)
    {
    fail:
      return 0;
    }

  if (unlikely (fi_multifile))
    assert (cu1->cu_kind == CU_ALT && cu2->cu_kind != CU_ALT);
  return 1;
}

/* Wrapper around die_eq_1, used as equality function in
   dup_htab hash table.  If zero (non-match) is returned and
   any toplevel DIEs have been pushed to the vector in ob obstack,
   undo the optimistic assignment of die_dup and die_nextdup.  */
static int
die_eq (const void *p, const void *q)
{
  dw_die_ref die1 = (dw_die_ref) p;
  dw_die_ref die2 = (dw_die_ref) q;
  dw_die_ref *arr;
  unsigned int i, count;
  int ret;

  if (die1->u.p1.die_hash != die2->u.p1.die_hash
      || die1->u.p1.die_ref_hash != die2->u.p1.die_ref_hash)
    return 0;
  ret = die_eq_1 (die_cu (die1), die_cu (die2), die1, die2, die1, die2);
  count = obstack_object_size (&ob) / sizeof (void *);
  arr = (dw_die_ref *) obstack_finish (&ob);
  if (!ret)
    for (i = count; i;)
      {
	dw_die_ref die;
	i -= 2;
	die = arr[i]->die_dup;
	if (likely (arr[i + 1] == NULL))
	  {
	    die->die_nextdup = arr[i]->die_nextdup;
	    arr[i]->die_nextdup = NULL;
	    arr[i]->die_dup = NULL;
	  }
	else
	  {
	    dw_die_ref next;

	    assert (die->die_nextdup == arr[i]);
	    for (next = arr[i]->die_nextdup;
		 next != arr[i + 1];
		 next = next->die_nextdup)
	      {
		assert (next->die_dup == die);
		next->die_dup = arr[i];
	      }
	    assert (next->die_dup == die);
	    next->die_dup = arr[i];
	    die->die_nextdup = next->die_nextdup;
	    next->die_nextdup = NULL;
	    arr[i]->die_dup = NULL;
	  }
	arr[i]->die_remove = 0;
      }
  obstack_free (&ob, (void *) arr);
  return ret;
}

/* Hash table for finding of matching toplevel DIEs (and all
   its children together with it).  */
static htab_t dup_htab;

/* After read_multifile dup_htab is moved to this variable.  */
static htab_t alt_dup_htab;

/* First CU, start of the linked list of CUs, and the tail
   of that list.  Initially this contains just the original
   CUs, later on newly created partial units are added
   to the beginning of the list and optionally .debug_types
   CUs are added to its tail.  */
static dw_cu_ref first_cu, last_cu;

/* After read_multifile first_cu is copied to this variable.  */
static dw_cu_ref alt_first_cu;

/* Compute approximate size of DIE and all its children together.  */
static unsigned long
calc_sizes (dw_die_ref die)
{
  unsigned long ret = die->die_size;
  dw_die_ref child;
  if (wr_multifile ? die->die_no_multifile : die->die_remove)
    return 0;
  for (child = die->die_child; child; child = child->die_sib)
    ret += calc_sizes (child);
  return ret;
}

/* Verify the duplicate chains starting at DIE.  If ORDERED, also check that
   the duplicate chain is in the correct order.  */
static void
verify_dups (dw_die_ref die, bool ordered)
{
  dw_die_ref d, prev;

  assert (die->die_dup == NULL);
  assert (die->die_collapsed_children == 0);
  assert (die->die_remove == 0);

  for (prev = die, d = prev->die_nextdup;
       d;
       prev = d, d = prev->die_nextdup)
    {
      if (ordered)
	assert (die_cu (prev)->cu_chunk <= die_cu (d)->cu_chunk);
      assert (d->die_offset != -1U);
      assert (d->die_dup == die);
      assert (d->die_remove != d->die_op_type_referenced);
      assert (d->die_tag == die->die_tag);
    }
}

/* Walk toplevel DIEs in tree rooted by PARENT, and see if they
   match previously processed DIEs.  */
static int
find_dups (dw_die_ref parent)
{
  void **slot;
  dw_die_ref child;

  if (stats_p && parent->die_root)
    stats->root_cnt++;

  for (child = parent->die_child; child; child = child->die_sib)
    {
      if (child->die_ck_state == CK_KNOWN)
	{
	  if (stats_p)
	    stats->lower_toplevel_with_checksum++;
	  if (child->die_dup != NULL)
	    continue;
	  slot = htab_find_slot_with_hash (dup_htab, child,
					   child->u.p1.die_ref_hash,
					   INSERT);
	  if (slot == NULL)
	    dwz_oom ();
	  if (*slot == NULL)
	    *slot = child;
	}
      else if (child->die_named_namespace)
	{
	  if (stats_p)
	    stats->namespace_cnt++;
	  if (find_dups (child))
	    return 1;
	}
      else if (stats_p)
	stats->lower_toplevel++;
    }
  return 0;
}

/* Like find_dups, but for the last multifile optimization phase,
   where it only looks at duplicates in the common .debug_info
   section.  */
static int
find_dups_fi (dw_die_ref parent)
{
  dw_die_ref child;

  for (child = parent->die_child; child; child = child->die_sib)
    {
      if (child->die_ck_state == CK_KNOWN)
	{
	  if (child->die_dup != NULL)
	    continue;
	  htab_find_with_hash (alt_dup_htab, child, child->u.p1.die_ref_hash);
	}
      else if (child->die_named_namespace)
	if (find_dups_fi (child))
	  return 1;
    }
  return 0;
}

/* Return value of DW_AT_name for DIE, or for its specification or abstract
   origin.  */
static const char *
get_name (dw_die_ref die)
{
  if (die->die_collapsed_child)
    return NULL;
  const char *name = get_AT_string (die, DW_AT_name);
  if (name)
    return name;
  dw_cu_ref cu = die_cu (die);
  bool present;
  enum dwarf_form form;
  unsigned int value = get_AT_int (die, DW_AT_specification, &present, &form);
  if (present)
    {
      dw_die_ref ref;
      if (form != DW_FORM_ref_addr)
	value = cu->cu_offset + value;
      ref = off_htab_lookup (cu, value);
      if (ref)
	return get_name (ref);
    }
  value = get_AT_int (die, DW_AT_abstract_origin, &present, &form);
  if (present)
    {
      dw_die_ref ref;
      if (form != DW_FORM_ref_addr)
	value = cu->cu_offset + value;
      ref = off_htab_lookup (die_cu (die), value);
      if (ref)
	return get_name (ref);
    }
  return NULL;
}

/* Dump type of DIE to stderr.  */
static void
dump_type (dw_die_ref die)
{
  bool present;
  enum dwarf_form form;
  if (die->die_collapsed_child)
    return;
  unsigned int value = get_AT_int (die, DW_AT_type, &present, &form);
  if (!present)
    return;

  dw_cu_ref cu = die_cu (die);
  if (cu == NULL)
    return;

  dw_die_ref ref;
  if (form != DW_FORM_ref_addr)
    value = cu->cu_offset + value;
  fprintf (stderr, " (type: %x", value);
  ref = off_htab_lookup (cu, value);
  if (ref != NULL && !ref->die_collapsed_child)
    {
      const char *type_name = get_name (ref);
      if (type_name)
	fprintf (stderr, " %s", type_name);
      fprintf (stderr, " %s", get_DW_TAG_name (ref->die_tag) + 7);
      dump_type (ref);
    }
  fprintf (stderr, ")");
}

/* Dump DIE to stderr with INDENT.  */
static void
dump_die_with_indent (int indent, dw_die_ref die)
{
  if (die == NULL)
    fprintf (stderr, "%*s null", indent, "");
  else if (die->die_offset == -1U)
    {
      fprintf (stderr, "%*s -1 %s", indent, "",
	       get_DW_TAG_name (die->die_tag) + 7);
      dw_die_ref d = die->die_nextdup;
      while (d)
	{
	  const char *name = get_name (d);
	  fprintf (stderr, " -> %x %s %s", d->die_offset, name ? name : "",
		   get_DW_TAG_name (d->die_tag) + 7);
	  d = d->die_nextdup;
	}
    }
  else if (die->die_collapsed_child)
    {
      fprintf (stderr, "%*s %x %c", indent, "", die->die_offset,
	   die->die_ck_state == CK_KNOWN ? 'O' : 'X');
    }
  else
    {
      const char *name = get_name (die);
      fprintf (stderr, "%*s %x %c %x", indent, "", die->die_offset,
	       die->die_ck_state == CK_KNOWN ? 'O' : 'X',
	       (unsigned) die->u.p1.die_hash);
      if (odr && die->die_odr_state != ODR_NONE
	   && die->die_odr_state != ODR_UNKNOWN)
	  fprintf (stderr, "(%x)", (unsigned) die->u.p1.die_hash2);
      fprintf (stderr, " %x %s %s", (unsigned) die->u.p1.die_ref_hash,
	       name ? name : "", get_DW_TAG_name (die->die_tag) + 7);
      dump_type (die);
    }
  fprintf (stderr, "\n");
}

/* Dump DIE to stderr.  */
static void
dump_die (dw_die_ref die)
{
  dump_die_with_indent (0, die);
}

static void
dump_dups (dw_die_ref die)
{
  dw_die_ref d;
  for (d = die; d; d = d->die_nextdup)
    dump_die (d);
}

/* Dump DIE tree at tree depth DEPTH.  */
static void
dump_dies (int depth, dw_die_ref die)
{
  dw_die_ref child;
  dump_die_with_indent (depth, die);
  for (child = die->die_child; child; child = child->die_sib)
    dump_dies (depth + 1, child);
}

/* Hash table for .debug_str.  Depending on multifile optimization
   phase this hash table has 3 different hash/equality functions.
   The first set is used to record tail optimized strings, during
   write_multifile the whole .debug_str section is written as is,
   plus then all the strings which are just suffixes of other
   strings.  E.g. if .debug_str section contains "foobar" string
   and .debug_info section refers to the whole "foobar" string
   as well as "bar" by referring to "foobar" + 3.
   The second set is used during op_multifile and fi_multifile,
   noting each string and in addition to that how many times it
   has been seen (0, 1 or more than 1).  If 0 then it isn't present
   in the hash table, 1 has lowest bit of new_off clear, more than 1
   the LSB of new_off is set.
   The final set is used during finalize_strp and afterwards, it is
   then used to map strings to their location in the new .debug_str
   section.  */
static htab_t strp_htab;
/* Current offset in .debug_str when adding the tail optimized strings.
   This is initially the size of .debug_str section in the object,
   and as unique tail optimized strings are found, this is increased
   each time.  */
static unsigned int max_strp_off;

/* At the end of read_multifile strp_htab is moved to this variable,
   which is used to find strings in the shared .debug_str section.  */
static htab_t alt_strp_htab;

/* Structure describing strings in strp_htab.  */
struct strp_entry
{
  /* Original .debug_str offset.  */
  unsigned int off;
  /* New .debug_str offset, or when using strp_{hash,eq}2
     this is initially iterative hash of the string with the
     LSB bit used for whether the string has been seen just once
     or more than once.  */
  unsigned int new_off;
};
ALIGN_STRUCT (strp_entry)

/* Hash function in strp_htab used for discovery of tail optimized
   strings.  */
static hashval_t
strp_hash (const void *p)
{
  struct strp_entry *s = (struct strp_entry *)p;

  return s->off;
}

/* Corresponding equality function in strp_htab.  */
static int
strp_eq (const void *p, const void *q)
{
  struct strp_entry *s1 = (struct strp_entry *)p;
  struct strp_entry *s2 = (struct strp_entry *)q;

  return s1->off == s2->off;
}

/* Hash function in strp_htab used to find what strings are
   used by more than one object.  */
static hashval_t
strp_hash2 (const void *p)
{
  struct strp_entry *s = (struct strp_entry *)p;

  return s->new_off & ~1U;
}

/* Corresponding equality function in strp_htab.  */
static int
strp_eq2 (const void *p, const void *q)
{
  struct strp_entry *s1 = (struct strp_entry *)p;
  struct strp_entry *s2 = (struct strp_entry *)q;

  return strcmp ((char *) debug_sections[DEBUG_STR].data + s1->off,
		 (char *) debug_sections[DEBUG_STR].data + s2->off) == 0;
}

/* Hash function in strp_htab used from finalize_strp onwards,
   mapping strings into strings in the new .debug_str section.  */
static hashval_t
strp_hash3 (const void *p)
{
  return iterative_hash (p, strlen (p), 0);
}

/* Corresponding equality function in strp_htab.  */
static int
strp_eq3 (const void *p, const void *q)
{
  return strcmp (p, q) == 0;
}

/* Called for each DW_FORM_strp offset seen during initial
   .debug_{info,types,macro} parsing.  Before fi_multifile phase
   this records just tail optimized strings, during fi_multifile
   it checks whether the string is already in the shared .debug_str
   section and if not, notes that it will need to be added to the
   new local .debug_str section.  */
static void
note_strp_offset (unsigned int off)
{
  void **slot;
  struct strp_entry se;

  if (unlikely (fi_multifile))
    {
      unsigned char *p;
      unsigned int len;
      hashval_t hash;

      p = debug_sections[DEBUG_STR].data + off;
      len = strlen ((char *) p);
      hash = iterative_hash (p, len, 0);
      if (alt_strp_htab)
	{
	  if (htab_find_with_hash (alt_strp_htab, p, hash))
	    return;
	}
      if (strp_htab == NULL)
	{
	  unsigned int strp_count = debug_sections[DEBUG_STR].size / 64;

	  if (strp_count < 100)
	    strp_count = 100;
	  strp_htab = htab_try_create (strp_count, strp_hash2, strp_eq2, NULL);
	  if (strp_htab == NULL)
	    dwz_oom ();
	}

      se.off = off;
      se.new_off = hash | 1;
      slot = htab_find_slot_with_hash (strp_htab, &se, se.new_off & ~1U, INSERT);
      if (slot == NULL)
	dwz_oom ();
      if (*slot == NULL)
	{
	  struct strp_entry *s = pool_alloc (strp_entry, sizeof (*s));
	  *s = se;
	  *slot = (void *) s;
	}
      return;
    }
  if (off >= debug_sections[DEBUG_STR].size || off == 0)
    return;
  if (debug_sections[DEBUG_STR].data[off - 1] == '\0')
    return;
  if (strp_htab == NULL)
    {
      if (multifile == NULL)
	return;
      strp_htab = htab_try_create (50, strp_hash, strp_eq, NULL);
      if (strp_htab == NULL)
	dwz_oom ();
      max_strp_off = debug_sections[DEBUG_STR].size;
    }
  se.off = off;
  slot = htab_find_slot_with_hash (strp_htab, &se, off, INSERT);
  if (slot == NULL)
    dwz_oom ();
  if (*slot == NULL)
    {
      struct strp_entry *s = pool_alloc (strp_entry, sizeof (*s));
      s->off = off;
      s->new_off = max_strp_off;
      max_strp_off += strlen ((char *) debug_sections[DEBUG_STR].data
			      + off) + 1;
      if (max_strp_off < s->new_off)
	{
	  htab_delete (strp_htab);
	  strp_htab = NULL;
	  max_strp_off = 0;
	  multifile = NULL;
	  error (0, 0, ".debug_str too large for multi-file optimization");
	}
      *slot = (void *) s;
    }
}

/* Map offset in original .debug_str section into
   offset in new .debug_str, either the shared .debug_str
   or new local .debug_str.  */
static unsigned
lookup_strp_offset (unsigned int off)
{
  struct strp_entry *s, se;

  if (unlikely (op_multifile || fi_multifile))
    {
      unsigned char *p;
      unsigned int len;
      hashval_t hash;

      p = debug_sections[DEBUG_STR].data + off;
      len = strlen ((char *) p);
      hash = iterative_hash (p, len, 0);
      if (alt_strp_htab)
	{
	  unsigned char *q = (unsigned char *)
			     htab_find_with_hash (alt_strp_htab, p, hash);
	  if (q != NULL)
	    return q - alt_data[DEBUG_STR];
	}
      assert (strp_htab);
      p = (unsigned char *) htab_find_with_hash (strp_htab, p, hash);
      assert (p != NULL);
      return p - debug_sections[DEBUG_STR].new_data;
    }
  if (off >= debug_sections[DEBUG_STR].size || off == 0)
    return off + multi_str_off;
  if (debug_sections[DEBUG_STR].data[off - 1] == '\0')
    return off + multi_str_off;
  se.off = off;
  s = (struct strp_entry *) htab_find_with_hash (strp_htab, &se, off);
  return s->new_off + multi_str_off;
}

/* Note .debug_str offset during write_macro or compute_abbrevs,
   return either DW_FORM_strp if the string will be in the local
   .debug_str section, or DW_FORM_strp_sup / DW_FORM_GNU_strp_alt if it
   will be in the shared .debug_str section.  */
static enum dwarf_form
note_strp_offset2 (unsigned int off)
{
  hashval_t hash;
  struct strp_entry se;
  unsigned char *p, *q;

  if (likely (fi_multifile))
    {
      unsigned int len;

      if (alt_strp_htab)
	{
	  p = debug_sections[DEBUG_STR].data + off;
	  len = strlen ((char *) p);
	  hash = iterative_hash (p, len, 0);
	  if (htab_find_with_hash (alt_strp_htab, p, hash))
	    return dwarf_5 ? DW_FORM_strp_sup : DW_FORM_GNU_strp_alt;
	}
      return DW_FORM_strp;
    }
  if (off >= debug_sections[DEBUG_STR].size)
    return DW_FORM_strp;
  p = debug_sections[DEBUG_STR].data + off;
  q = (unsigned char *) strchr ((char *) p, '\0');
  hash = iterative_hash (p, q - p, 0);
  se.off = off;
  se.new_off = hash & ~1U;
  struct strp_entry *s = (struct strp_entry *)
			 htab_find_with_hash (strp_htab, &se, se.new_off);
  assert (s != NULL);
  s->new_off |= 1;
  return DW_FORM_strp;
}

/* Helper to record all strp_entry entries from strp_htab.
   Called through htab_traverse.  */
static int
list_strp_entries (void **slot, void *data)
{
  struct strp_entry ***end = (struct strp_entry ***) data;
  **end = (struct strp_entry *) *slot;
  (*end)++;
  return 1;
}

/* Adapted from bfd/merge.c strrevcmp.  */
static int
strrevcmp (const void *p, const void *q)
{
  struct strp_entry *s1 = *(struct strp_entry **)p;
  struct strp_entry *s2 = *(struct strp_entry **)q;
  unsigned int len1 = s1->new_off & ~1U;
  unsigned int len2 = s2->new_off & ~1U;
  unsigned int len;
  unsigned char *p1 = debug_sections[DEBUG_STR].data + s1->off;
  unsigned char *p2 = debug_sections[DEBUG_STR].data + s2->off;

  if (p1[len1])
    len1++;
  if (p2[len2])
    len2++;
  p1 += len1;
  p2 += len2;
  len = len1;
  if (len2 < len)
    len = len2;
  while (len)
    {
      p1--;
      p2--;
      if (*p1 != *p2)
	{
	  if (*p1 < *p2)
	    return -1;
	  return 1;
	}
      len--;
    }
  if (len1 < len2)
    return 1;
  if (len1 > len2)
    return -1;
  assert (s1->off == s2->off);
  return 0;
}

/* Compute new .debug_str section, from strp_htab content,
   replace strp_htab hash table with a new one, which maps strings
   to new .debug_str locations.  */
static unsigned int *
finalize_strp (bool build_tail_offset_list)
{
  unsigned int count, new_count, i, *tail_offset_list = NULL;
  unsigned int strp_index = 0, tail_offset_list_count = 0, k;
  struct strp_entry **arr, **end;
  unsigned char *p;

  if (strp_htab == NULL)
    {
      debug_sections[DEBUG_STR].new_data = NULL;
      debug_sections[DEBUG_STR].new_size = 0;
      return NULL;
    }
  count = htab_elements (strp_htab);
  arr = (struct strp_entry **)
	obstack_alloc (&ob, count * sizeof (struct strp_entry *));
  end = arr;
  htab_traverse (strp_htab, list_strp_entries, (void *) &end);
  for (i = 0; i < count; i++)
    {
      unsigned int len = strlen ((char *) debug_sections[DEBUG_STR].data
				 + arr[i]->off);
      arr[i]->new_off = (len & ~1U) | (arr[i]->new_off & 1);
    }
  qsort (arr, count, sizeof (struct strp_entry *), strrevcmp);
  htab_delete (strp_htab);
  strp_htab = NULL;
  new_count = count;
  for (i = 0; i < count; i++)
    if ((arr[i]->new_off & 1) == 0)
      {
	arr[i]->off = -1U;
	arr[i]->new_off = -1U;
	new_count--;
      }
    else
      {
	unsigned int len1, len2, lastlen, j;
	unsigned char *p1, *p2;
	len1 = arr[i]->new_off & ~1U;
	p1 = debug_sections[DEBUG_STR].data + arr[i]->off;
	if (p1[len1])
	  len1++;
	lastlen = len1;
	arr[i]->new_off = strp_index;
	strp_index += len1 + 1;
	for (j = i + 1; j < count; j++)
	  {
	    len2 = arr[j]->new_off & ~1U;
	    p2 = debug_sections[DEBUG_STR].data + arr[j]->off;
	    if (p2[len2])
	      len2++;
	    if (len2 >= lastlen)
	      break;
	    if (memcmp (p1 + len1 - len2, p2, len2 + 1) != 0)
	      break;
	    arr[j]->new_off = arr[i]->new_off + len1 - len2;
	    lastlen = len2;
	    tail_offset_list_count++;
	  }
	i = j - 1;
      }
  debug_sections[DEBUG_STR].new_data = malloc (strp_index);
  if (debug_sections[DEBUG_STR].new_data == NULL)
    dwz_oom ();
  debug_sections[DEBUG_STR].new_size = strp_index;
  strp_htab = htab_try_create (new_count < 32 ? 32 : new_count,
			       strp_hash3, strp_eq3, NULL);
  if (strp_htab == NULL)
    dwz_oom ();
  if (build_tail_offset_list && tail_offset_list_count++ != 0)
    {
      tail_offset_list
	= mmap (NULL, tail_offset_list_count * sizeof (int),
		PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
      if (tail_offset_list == MAP_FAILED)
	dwz_oom ();
    }
  for (i = 0, k = 0, p = debug_sections[DEBUG_STR].new_data; i < count; i++)
    if (arr[i]->off == -1U && arr[i]->new_off == -1U)
      continue;
    else
      {
	unsigned int len = strlen ((char *) debug_sections[DEBUG_STR].data
				   + arr[i]->off) + 1;
	unsigned int j;
	void **slot;

	memcpy (p, debug_sections[DEBUG_STR].data + arr[i]->off, len);
	slot = htab_find_slot_with_hash (strp_htab, p,
					 iterative_hash (p, len - 1, 0),
					 INSERT);
	if (slot == NULL)
	  dwz_oom ();
	assert (*slot == NULL);
	*slot = (void *) p;
	for (j = i + 1; j < count; j++)
	  if (arr[j]->new_off >= arr[i]->new_off + len)
	    break;
	  else
	    {
	      unsigned char *q = p + arr[j]->new_off - arr[i]->new_off;
	      unsigned int l = len + arr[i]->new_off - arr[j]->new_off;
	      if (tail_offset_list != NULL)
		tail_offset_list[k++] = arr[j]->new_off;
	      slot = htab_find_slot_with_hash (strp_htab, q,
					       iterative_hash (q, l - 1, 0),
					       INSERT);
	      if (slot == NULL)
		dwz_oom ();
	      assert (*slot == NULL);
	      *slot = (void *) q;
	    }
	p += len;
	i = j - 1;
      }
  assert (p == debug_sections[DEBUG_STR].new_data + strp_index);
  if (tail_offset_list != NULL)
    {
      tail_offset_list[k++] = 0;
      assert (k == tail_offset_list_count);
    }
  obstack_free (&ob, (void *) arr);
  return tail_offset_list;
}

enum mark_refs_mode
{
  MARK_REFS_FOLLOW_DUPS = 1,
  MARK_REFS_RETURN_VAL = 2,
  MARK_REFS_REFERENCED = 4
};

/* Mark all DIEs referenced from DIE by setting die_ref_seen to 1,
   unless already marked.  */
static bool
mark_refs (dw_cu_ref cu, dw_die_ref top_die, dw_die_ref die, int mode)
{
  struct abbrev_tag *t;
  unsigned int i;
  unsigned char *ptr;
  dw_die_ref child;

  t = die->die_abbrev;
  for (i = 0; i < t->nattr; ++i)
    if (t->attr[i].attr != DW_AT_sibling)
      switch (t->attr[i].form)
	{
	case DW_FORM_ref_addr:
	  if (unlikely (op_multifile))
	    i = -2U;
	  break;
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_indirect:
	  i = -2U;
	  break;
	}
  if (i == -1U)
    {
      if (unlikely (cu->cu_kind == CU_TYPES))
	ptr = debug_sections[DEBUG_TYPES].data;
      else
	ptr = debug_sections[DEBUG_INFO].data;
      ptr += die->die_offset;
      skip_leb128 (ptr);
      for (i = 0; i < t->nattr; ++i)
	{
	  uint32_t form = t->attr[i].form;
	  size_t len = 0;
	  uint64_t value;
	  dw_die_ref ref, reft;

	  while (form == DW_FORM_indirect)
	    form = read_uleb128 (ptr);

	  switch (form)
	    {
	    case DW_FORM_ref_addr:
	      if (unlikely (op_multifile))
		{
		  value = read_size (ptr, cu->cu_version == 2
					  ? ptr_size : 4);
		  ptr += cu->cu_version == 2 ? ptr_size : 4;
		  assert (t->attr[i].attr != DW_AT_sibling);
		  ref = off_htab_lookup (cu, value);
		  if ((mode & MARK_REFS_REFERENCED) != 0)
		    ref->die_referenced = 1;
		  goto finish_ref;
		}
	      ptr += cu->cu_version == 2 ? ptr_size : 4;
	      break;
	    case DW_FORM_addr:
	      ptr += ptr_size;
	      break;
	    case DW_FORM_flag_present:
	    case DW_FORM_implicit_const:
	      break;
	    case DW_FORM_flag:
	    case DW_FORM_data1:
	      ++ptr;
	      break;
	    case DW_FORM_data2:
	      ptr += 2;
	      break;
	    case DW_FORM_data4:
	    case DW_FORM_sec_offset:
	    case DW_FORM_strp:
	    case DW_FORM_line_strp:
	      ptr += 4;
	      break;
	    case DW_FORM_data8:
	    case DW_FORM_ref_sig8:
	      ptr += 8;
	      break;
	    case DW_FORM_data16:
	      ptr += 16;
	      break;
	    case DW_FORM_sdata:
	    case DW_FORM_udata:
	      skip_leb128 (ptr);
	      break;
	    case DW_FORM_ref_udata:
	    case DW_FORM_ref1:
	    case DW_FORM_ref2:
	    case DW_FORM_ref4:
	    case DW_FORM_ref8:
	      switch (form)
		{
		case DW_FORM_ref_udata: value = read_uleb128 (ptr); break;
		case DW_FORM_ref1: value = read_8 (ptr); break;
		case DW_FORM_ref2: value = read_16 (ptr); break;
		case DW_FORM_ref4: value = read_32 (ptr); break;
		case DW_FORM_ref8: value = read_64 (ptr); break;
		default: abort ();
		}
	      if (t->attr[i].attr == DW_AT_sibling)
		break;
	      ref = off_htab_lookup (cu, cu->cu_offset + value);
	      if ((mode & MARK_REFS_REFERENCED) != 0)
		ref->die_referenced = 1;
	      if (!ref->die_collapsed_child
		  && ref->u.p1.die_enter >= top_die->u.p1.die_enter
		  && ref->u.p1.die_exit <= top_die->u.p1.die_exit)
		break;
	    finish_ref:
	      reft = ref;
	      while (!reft->die_root
		     && reft->die_parent->die_tag != DW_TAG_compile_unit
		     && reft->die_parent->die_tag != DW_TAG_partial_unit
		     && !reft->die_parent->die_named_namespace)
		reft = reft->die_parent;
	      if ((mode & MARK_REFS_FOLLOW_DUPS) && reft->die_dup != NULL)
		{
		  reft = reft->die_dup;
		  if (die_cu (reft)->cu_kind == CU_PU)
		    break;
		}
	      if (reft->die_ref_seen == 0)
		{
		  if ((mode & MARK_REFS_RETURN_VAL))
		    return false;
		  reft->die_ref_seen = 1;
		  mark_refs (die_cu (reft), reft, reft, mode);
		}
	      break;
	    case DW_FORM_string:
	      ptr = (unsigned char *) strchr ((char *)ptr, '\0') + 1;
	      break;
	    case DW_FORM_indirect:
	      abort ();
	    case DW_FORM_block1:
	      len = *ptr++;
	      break;
	    case DW_FORM_block2:
	      len = read_16 (ptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_block4:
	      len = read_32 (ptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_block:
	    case DW_FORM_exprloc:
	      len = read_uleb128 (ptr);
	      form = DW_FORM_block1;
	      break;
	    default:
	      abort ();
	    }

	  if (form == DW_FORM_block1)
	    ptr += len;
	}
    }

  for (child = die->die_child; child; child = child->die_sib)
    if (!mark_refs (cu, top_die, child, mode))
      return false;
  return true;
}

/* Remove completely unneeded children of DIE and remove unreferenced DIEs
   from offset hash tables.  */
static void
remove_dies (dw_cu_ref cu, dw_die_ref die, bool remove)
{
  dw_die_ref child, next;
  if (die->die_toplevel && die->die_ref_seen == 0 && !low_mem)
    remove = true;
  for (child = die->die_child; child; child = next)
    {
      next = child->die_sib;
      remove_dies (cu, child, remove);
    }
  if (die->die_referenced == 0)
    {
      htab_t h = cu->cu_kind == CU_TYPES ? types_off_htab : off_htab;
      void **slot = htab_find_slot_with_hash (h, die, off_hash (die),
					      NO_INSERT);
      if (slot != NULL)
	htab_clear_slot (h, slot);
    }
  if (!remove)
    return;
  if (die->die_toplevel == 0)
    {
      memset (die, '\0', offsetof (struct dw_die, die_dup));
      die->die_sib = die_nontoplevel_freelist;
      die_nontoplevel_freelist = die;
    }
  else
    die->die_child = NULL;
}

/* Remove unneeded children DIEs.  During phase 0 die_ref_seen
   of toplevel DIEs is computed, during phase 1 mark_refs is called
   to find referenced DIEs, during phase 2 unneeded children DIEs
   are removed.  */
static void
remove_unneeded (dw_cu_ref cu, dw_die_ref die, unsigned int phase)
{
  dw_die_ref child;
  for (child = die->die_child; child; child = child->die_sib)
    {
      if (child->die_named_namespace)
	{
	  remove_unneeded (cu, child, phase);
	  if (phase == 2)
	    child->die_ref_seen = 0;
	}
      else
	switch (phase)
	  {
	  case 0:
	    child->die_ref_seen = child->die_dup == NULL;
	    break;
	  case 1:
	    if (child->die_dup == NULL || low_mem)
	      mark_refs (cu, child, child, MARK_REFS_REFERENCED);
	    break;
	  case 2:
	    remove_dies (cu, child, false);
	    child->die_ref_seen = 0;
	    break;
	  }
    }
}

/* Entries in meta_abbrev_htab, mapping .debug_abbrev section offsets
   to abbrev hash tables.  */
struct meta_abbrev_entry
{
  /* .debug_abbrev offset.  */
  unsigned int abbrev_off;
  /* Corresponding hash table.  */
  htab_t abbrev_htab;
};

/* Hash table for mapping of .debug_abbrev section offsets to
   abbrev hash tables.  */
static htab_t meta_abbrev_htab;
/* Dummy entry used during OOM handling.  */
static struct meta_abbrev_entry meta_abbrev_fallback;

/* Hash function for meta_abbrev_htab.  */
static hashval_t
meta_abbrev_hash (const void *p)
{
  struct meta_abbrev_entry *m = (struct meta_abbrev_entry *)p;

  return m->abbrev_off;
}

/* Equality function for meta_abbrev_htab.  */
static int
meta_abbrev_eq (const void *p, const void *q)
{
  struct meta_abbrev_entry *m1 = (struct meta_abbrev_entry *)p;
  struct meta_abbrev_entry *m2 = (struct meta_abbrev_entry *)q;

  return m1->abbrev_off == m2->abbrev_off;
}

/* Delete function for meta_abbrev_htab.  */
static void
meta_abbrev_del (void *p)
{
  struct meta_abbrev_entry *m = (struct meta_abbrev_entry *)p;

  if (m->abbrev_htab != NULL)
    htab_delete (m->abbrev_htab);
}

/* Collapse children of TOP_DIE to decrease memory usage.  */
static void
collapse_child (dw_cu_ref cu, dw_die_ref top_die, dw_die_ref die,
		unsigned int *tick)
{
  dw_die_ref child, next;
  bool has_children = die->die_child != NULL;
  unsigned int tick_diff = *tick;
  for (child = die->die_child; child; child = next)
    {
      next = child->die_sib;
      (*tick)++;
      collapse_child (cu, top_die, child, tick);
    }
  if (has_children)
    (*tick)++;
  if (top_die == die)
    {
      die->die_child = NULL;
      die->die_collapsed_children = 1;
    }
  else if (die->die_referenced)
    {
      die->die_parent = top_die;
      if (tick_diff <= 0xffff && !die->die_intercu_referenced)
	{
	  dw_die_ref ref;
	  void **slot;
	  if (die_collapsed_child_freelist)
	    {
	      ref = die_collapsed_child_freelist;
	      die_collapsed_child_freelist = ref->die_parent;
	    }
	  else
	    ref = pool_alloc (dw_die, offsetof (struct dw_die, die_child));
	  memcpy (ref, die, offsetof (struct dw_die, die_child));
	  ref->die_collapsed_child = 1;
	  ref->die_tag = tick_diff;
	  slot = htab_find_slot_with_hash (cu->cu_kind == CU_TYPES
					   ? types_off_htab : off_htab,
					   ref, off_hash (ref), NO_INSERT);
	  assert (slot != NULL);
	  *slot = (void *) ref;
	  memset (die, '\0', offsetof (struct dw_die, die_dup));
	  die->die_sib = die_nontoplevel_freelist;
	  die_nontoplevel_freelist = die;
	}
      else
	{
	  die->die_child = NULL;
	  die->die_sib = NULL;
	  die->die_ref_seen = tick_diff;
	}
    }
  else
    {
      memset (die, '\0', offsetof (struct dw_die, die_dup));
      die->die_sib = die_nontoplevel_freelist;
      die_nontoplevel_freelist = die;
    }
}

/* Collapse children of all toplevel DIEs that can be collapsed.  */
static void
collapse_children (dw_cu_ref cu, dw_die_ref die)
{
  dw_die_ref child;
  for (child = die->die_child; child; child = child->die_sib)
    if (child->die_named_namespace)
      collapse_children (cu, child);
    else if (child->die_child == NULL)
      continue;
    else if (child->die_nextdup == NULL
	     || (child->die_dup != NULL
		 && (die_cu (child->die_dup)->cu_kind != CU_PU
		     || child->die_dup->die_nextdup != child)))
      {
	unsigned int tick = 0;
	collapse_child (cu, child, child, &tick);
      }
}

/* Count the number of DIEs in the .debug_info section, and see if we run into
   some limit.  */
static int
try_debug_info (DSO *dso)
{
  unsigned char *ptr, *endcu, *endsec;
  unsigned int value;
  htab_t abbrev = NULL;
  unsigned int last_abbrev_offset = 0;
  struct abbrev_tag tag, *t;
  unsigned int ndies;
  unsigned ret = 1;
  int kind = DEBUG_INFO;
  bool low_mem_die_limit_hit = false;

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "try_debug_info\n");
    }

  if (tracing)
    fprintf (stderr, "Counting DIEs\n");

  ndies = 0;
  ptr = debug_sections[kind].data;
  endsec = ptr + debug_sections[kind].size;
  while (ptr < endsec)
    {
      unsigned int culen;
      int cu_version;

      /* Note header is one bigger with DWARF version 5.  */
      if (ptr + (kind == DEBUG_TYPES ? 23 : 11) > endsec)
	{
	  error (0, 0, "%s: %s CU header too small", dso->filename,
		 debug_sections[kind].name);
	  goto fail;
	}

      endcu = ptr + 4;
      culen = read_32 (ptr);
      if (culen >= 0xfffffff0)
	{
	  error (0, 0, "%s: 64-bit DWARF not supported", dso->filename);
	  goto fail;
	}
      endcu += culen;

      if (endcu > endsec)
	{
	  error (0, 0, "%s: %s too small", dso->filename,
		 debug_sections[kind].name);
	  goto fail;
	}

      cu_version = read_16 (ptr);
      if (kind == DEBUG_TYPES && (cu_version < 2 || cu_version > 4))
	{
	  error (0, 0, "%s: DWARF version %d in .debug_types unhandled",
		 dso->filename, cu_version);
	  goto fail;
	}
      else if (cu_version < 2 || cu_version > 5)
	{
	  error (0, 0, "%s: DWARF version %d in .debug_info unhandled",
		 dso->filename, cu_version);
	  goto fail;
	}

      if (cu_version == 5)
	{
	  value = read_8 (ptr);
	  if (value != DW_UT_compile && value != DW_UT_partial)
	    error (0, 0, "%s: DWARF CU type %s unhandled", dso->filename,
		   get_DW_UT_str (value));
	}
      else
	{
	  value = read_32 (ptr);
	  if (value >= debug_sections[DEBUG_ABBREV].size)
	    {
	      if (debug_sections[DEBUG_ABBREV].data == NULL)
		error (0, 0, "%s: .debug_abbrev not present", dso->filename);
	      else
		error (0, 0, "%s: DWARF CU abbrev offset too large",
		       dso->filename);
	      goto fail;
	    }
	}

      if (ptr_size == 0)
	{
	  ptr_size = read_8 (ptr);
	  if (ptr_size != 4 && ptr_size != 8)
	    {
	      error (0, 0, "%s: Invalid DWARF pointer size %d",
		     dso->filename, ptr_size);
	      goto fail;
	    }
	}
      else if (read_8 (ptr) != ptr_size)
	{
	  error (0, 0, "%s: DWARF pointer size differs between CUs",
		 dso->filename);
	  goto fail;
	}

      if (cu_version == 5)
	{
	  /* Above we only checked for the smaller version 4 header size.  */
	  if (ptr + 4 > endsec)
	    {
	      error (0, 0, "%s: %s CU version 5 header too small",
		     dso->filename, debug_sections[kind].name);
	      goto fail;
	    }
	  value = read_32 (ptr);
	  if (value >= debug_sections[DEBUG_ABBREV].size)
	    {
	      if (debug_sections[DEBUG_ABBREV].data == NULL)
		error (0, 0, "%s: .debug_abbrev not present", dso->filename);
	      else
		error (0, 0, "%s: DWARF CU abbrev offset too large",
		       dso->filename);
	      goto fail;
	    }
	}

      if (abbrev == NULL || value != last_abbrev_offset)
	{
	  if (abbrev)
	    htab_delete (abbrev);
	  abbrev
	    = read_abbrev (dso, debug_sections[DEBUG_ABBREV].data + value);
	  if (abbrev == NULL)
	    {
	      error (0, 0, "%s: Couldn't read abbrev at offset 0x%x",
		     dso->filename, value);
	      goto fail;
	    }
	}
      last_abbrev_offset = value;

      while (ptr < endcu)
	{
	  tag.entry = read_uleb128 (ptr);
	  if (tag.entry == 0)
	    continue;
	  if (ndies == max_die_limit)
	    {
	      error (0, 0, "%s: Too many DIEs, not optimizing",
		     dso->filename);
	      goto fail;
	    }
	  /* If we reach the DIE limit, signal the dwz caller that it
	     should retry with low_mem.  */
	  if (likely (!low_mem) && ndies == low_mem_die_limit)
	    {
	      if (tracing)
		fprintf (stderr, "Hit low-mem die-limit\n");
	      if (estimate_nr_dies () > max_die_limit)
		/* Keep going, we still might hit the max die-limit.  */
		low_mem_die_limit_hit = true;
	      else
		{
		  ret = 2;
		  goto fail;
		}
	    }
	  ndies++;
	  t = htab_find_with_hash (abbrev, &tag, tag.entry);
	  if (t == NULL)
	    {
	      error (0, 0, "%s: Could not find DWARF abbreviation %d",
		     dso->filename, tag.entry);
	      goto fail;
	    }
	  ptr = skip_attrs_1 (cu_version, t, ptr);
	}
    }

  if (low_mem_die_limit_hit)
    ret = 2;
  else
    ret = 0;

 fail:
  if (abbrev)
    htab_delete (abbrev);

  return ret;
}

/* Read language attribute encoded using FORM from location PTR, return
   pointer to location after the attribute.  Assign the attribute value
   to *LANG.  */
static unsigned char *
read_lang (unsigned char *ptr, enum dwarf_form form,
	   enum dwarf_source_language *lang)
{
  bool error_p = false;
  *lang = read_u16 (ptr, form, error_p);
  if (unlikely (error_p))
    {
      *lang = 0;
      error (0, 0, "Invalid DW_AT_language attribute, ignoring");
    }
  return ptr;
}

/* First phase of the DWARF compression.  Parse .debug_info section
   (for kind == DEBUG_INFO) or .debug_types section (for kind == DEBUG_TYPES)
   for each CU in it construct internal representation for the CU
   and its DIE tree, compute checksums of DIEs and look for duplicates.  */
static int
read_debug_info (DSO *dso, int kind, unsigned int *die_count)
{
  unsigned char *ptr, *endcu, *endsec;
  unsigned int value;
  htab_t abbrev = NULL;
  unsigned int last_abbrev_offset = 0;
  unsigned int last_debug_line_off = 0;
  struct dw_file *cu_files = NULL;
  unsigned int cu_nfiles = 0;
  bool note_strp_forms = multifile != NULL && !op_multifile
			 && !rd_multifile && !low_mem;
  struct abbrev_tag tag, *t;
  unsigned int cu_chunk = 0;
  dw_cu_ref cu_tail = NULL, cu_collapse = NULL;
  unsigned int cu_kind = rd_multifile ? CU_ALT
			 : kind == DEBUG_TYPES ? CU_TYPES : CU_NORMAL;
  void *to_free = NULL;
  int ret = 1;
  unsigned int ndies;
  bool low_mem_phase1 = low_mem && kind == DEBUG_INFO;
  struct dw_cu cu_buf;
  struct dw_die die_buf;
  bool lang_p = odr || uni_lang_p;

  odr_active_p = false;
  if (odr)
    odr_phase = 1;

  unsigned int estimated_nr_dies = estimate_nr_dies ();
  if (kind == DEBUG_INFO
      && multifile_mode == 0
      && die_count_method == estimate)
    {
      bool do_count = (estimated_nr_dies > max_die_limit
		       || estimated_nr_dies > low_mem_die_limit);
      if (tracing)
	fprintf (stderr, "Using die count estimate %u to decide whether to"
		 " count DIEs: %s\n", estimated_nr_dies,
		 do_count ? "yes" : "no");
      if (do_count)
	{
	  int try_ret = try_debug_info (dso);
	  if (try_ret != 0)
	    return try_ret;
	}
    }

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "read_debug_info %s%s\n",
	       kind == DEBUG_INFO ? ".debug_info" : ".debug_types",
	       low_mem && kind == DEBUG_INFO ? " (low-mem)" : "");
    }

  if (likely (!fi_multifile && kind != DEBUG_TYPES))
    {
      dup_htab = htab_try_create (100000, die_hash, die_eq, NULL);
      if (dup_htab == NULL)
	dwz_oom ();
    }
  if (unlikely (meta_abbrev_htab == NULL
		&& (op_multifile || rd_multifile || fi_multifile || low_mem)))
    {
      meta_abbrev_htab
	= htab_try_create (500, meta_abbrev_hash, meta_abbrev_eq,
			   meta_abbrev_del);
      if (meta_abbrev_htab == NULL)
	dwz_oom ();
      to_free = obstack_alloc (&ob2, 1);
    }

 low_mem_phase2:
  ndies = 0;
  ptr = debug_sections[kind].data;
  endsec = ptr + debug_sections[kind].size;
  while (ptr < endsec)
    {
      unsigned int cu_offset = ptr - debug_sections[kind].data;
      unsigned int tick = 0, culen;
      int cu_version;
      dw_cu_ref cu;
      dw_die_ref *diep, parent, die;
      bool present;
      unsigned int debug_line_off;
      unsigned int type_offset = 0;

      /* Note header is one bigger with DWARF version 5.  */
      if (ptr + (kind == DEBUG_TYPES ? 23 : 11) > endsec)
	{
	  error (0, 0, "%s: %s CU header too small", dso->filename,
		 debug_sections[kind].name);
	  goto fail;
	}

      endcu = ptr + 4;
      culen = read_32 (ptr);
      if (culen >= 0xfffffff0)
	{
	  error (0, 0, "%s: 64-bit DWARF not supported", dso->filename);
	  goto fail;
	}
      endcu += culen;

      if (endcu > endsec)
	{
	  error (0, 0, "%s: %s too small", dso->filename,
		 debug_sections[kind].name);
	  goto fail;
	}

      cu_version = read_16 (ptr);
      if (kind == DEBUG_TYPES && (cu_version < 2 || cu_version > 4))
	{
	  error (0, 0, "%s: DWARF version %d in .debug_types unhandled",
		 dso->filename, cu_version);
	  goto fail;
	}
      else if (cu_version < 2 || cu_version > 5)
	{
	  error (0, 0, "%s: DWARF version %d in .debug_info unhandled",
		 dso->filename, cu_version);
	  goto fail;
	}

      if (cu_version == 5)
	{
	  value = read_8 (ptr);
	  if (value != DW_UT_compile && value != DW_UT_partial)
	    {
	      error (0, 0, "%s: DWARF CU type %s unhandled", dso->filename,
		     get_DW_UT_str (value));
	      goto fail;
	    }
	}
      else
	{
	  value = read_32 (ptr);
	  if (value >= debug_sections[DEBUG_ABBREV].size)
	    {
	      if (debug_sections[DEBUG_ABBREV].data == NULL)
		error (0, 0, "%s: .debug_abbrev not present", dso->filename);
	      else
		error (0, 0, "%s: DWARF CU abbrev offset too large",
		       dso->filename);
	      goto fail;
	    }
	}

      if (ptr_size == 0)
	{
	  ptr_size = read_8 (ptr);
	  if (ptr_size != 4 && ptr_size != 8)
	    {
	      error (0, 0, "%s: Invalid DWARF pointer size %d",
		     dso->filename, ptr_size);
	      goto fail;
	    }
	}
      else if (read_8 (ptr) != ptr_size)
	{
	  error (0, 0, "%s: DWARF pointer size differs between CUs",
		 dso->filename);
	  goto fail;
	}

      if (cu_version == 5)
	{
	  /* Above we only checked for the smaller version 4 header size.  */
	  if (ptr + 4 > endsec)
	    {
	      error (0, 0, "%s: %s CU version 5 header too small",
		     dso->filename, debug_sections[kind].name);
	      goto fail;
	    }
	  value = read_32 (ptr);
	  if (value >= debug_sections[DEBUG_ABBREV].size)
	    {
	      if (debug_sections[DEBUG_ABBREV].data == NULL)
		error (0, 0, "%s: .debug_abbrev not present", dso->filename);
	      else
		error (0, 0, "%s: DWARF CU abbrev offset too large",
		       dso->filename);
	      goto fail;
	    }
	}

      if (unlikely (op_multifile))
	{
	  if (ptr == endcu)
	    {
	      dw_cu_ref cuf = cu_tail ? cu_tail->cu_next : first_cu;
	      /* Inside of optimize_multifile, DIE hashes are computed
		 only after all the CUs from a particular DSO or
		 executable have been parsed, as we follow
		 DW_FORM_ref_addr then.  */
	      for (cu = cuf; cu; cu = cu->cu_next)
		if (checksum_die (dso, cu, NULL, cu->cu_die))
		  goto fail;

	      for (cu = cuf; cu; cu = cu->cu_next)
		checksum_ref_die (cu, NULL, cu->cu_die, NULL, NULL);

	      if (dump_dies_p)
		for (cu = cuf; cu; cu = cu->cu_next)
		  dump_dies (0, cu->cu_die);

	      for (cu = cuf; cu; cu = cu->cu_next)
		if (find_dups (cu->cu_die))
		  goto fail;

	      for (cu = cuf; cu; cu = cu->cu_next)
		remove_unneeded (cu, cu->cu_die, 0);
	      for (cu = cuf; cu; cu = cu->cu_next)
		remove_unneeded (cu, cu->cu_die, 1);
	      for (cu = cuf; cu; cu = cu->cu_next)
		remove_unneeded (cu, cu->cu_die, 2);

	      if (cu_collapse == NULL)
		cu_collapse = first_cu;
	      while (cu_collapse->cu_chunk < cu_chunk)
		{
		  collapse_children (cu_collapse, cu_collapse->cu_die);
		  cu_collapse = cu_collapse->cu_next;
		}

	      cu_tail = last_cu;
	      cu_chunk++;
	      continue;
	    }
	}
      else
	cu_chunk++;

      if (unlikely (meta_abbrev_htab != NULL))
	{
	  struct meta_abbrev_entry m, *mp;
	  void **slot;
	  m.abbrev_off = value;
	  slot = htab_find_slot_with_hash (meta_abbrev_htab, &m,
					   m.abbrev_off, INSERT);
	  if (slot == NULL)
	    dwz_oom ();
	  else if (*slot != NULL)
	    abbrev = ((struct meta_abbrev_entry *) *slot)->abbrev_htab;
	  else
	    {
	      *slot = (void *) &meta_abbrev_fallback;
	      abbrev
		= read_abbrev (dso, debug_sections[DEBUG_ABBREV].data + value);
	      if (abbrev == NULL)
		goto fail;
	      mp = (struct meta_abbrev_entry *)
		   obstack_alloc (&ob2, sizeof (*mp));
	      mp->abbrev_off = value;
	      mp->abbrev_htab = abbrev;
	      *slot = (void *) mp;
	    }
	}
      else if (abbrev == NULL || value != last_abbrev_offset)
	{
	  if (abbrev)
	    htab_delete (abbrev);
	  abbrev
	    = read_abbrev (dso, debug_sections[DEBUG_ABBREV].data + value);
	  if (abbrev == NULL)
	    {
	      error (0, 0, "%s: Couldn't read abbrev at offset 0x%x",
		     dso->filename, value);

	      goto fail;
	    }
	}
      last_abbrev_offset = value;

      if (unlikely (kind == DEBUG_TYPES))
	{
	  ptr += 8;
	  type_offset = read_32 (ptr);
	}

      if (unlikely (low_mem_phase1))
	cu = &cu_buf;
      else
	cu = pool_alloc (dw_cu, sizeof (struct dw_cu));
      memset (cu, '\0', sizeof (*cu));
      cu->cu_kind = cu_kind;
      cu->cu_offset = cu_offset;
      cu->cu_version = cu_version;
      cu->cu_chunk = cu_chunk;
      if (unlikely (op_multifile || low_mem))
	cu->cu_abbrev = abbrev;
      diep = &cu->cu_die;
      parent = NULL;
      if (unlikely (low_mem_phase1))
	;
      else if (first_cu == NULL)
	first_cu = last_cu = cu;
      else
	{
	  last_cu->cu_next = cu;
	  last_cu = cu;
	}

      while (ptr < endcu)
	{
	  unsigned int i;
	  unsigned int die_offset = ptr - debug_sections[kind].data;

	  tag.entry = read_uleb128 (ptr);
	  if (tag.entry == 0)
	    {
	      if (unlikely (low_mem_phase1))
		continue;
	      if (parent)
		{
		  diep = &parent->die_sib;
		  parent->u.p1.die_exit = tick++;
		  if (parent->die_root == 0)
		    parent = parent->die_parent;
		  else
		    parent = NULL;
		}
	      else
		diep = NULL;
	      continue;
	    }
	  if (diep == NULL)
	    {
	      error (0, 0, "%s: Wrong %s DIE tree", dso->filename,
		     debug_sections[kind].name);
	      goto fail;
	    }
	  t = htab_find_with_hash (abbrev, &tag, tag.entry);
	  if (t == NULL)
	    {
	      error (0, 0, "%s: Could not find DWARF abbreviation %d",
		     dso->filename, tag.entry);
	      goto fail;
	    }
	  if (likely (!op_multifile && !rd_multifile && !fi_multifile)
	      && likely (kind == DEBUG_INFO))
	    {
	      if (ndies == max_die_limit)
		{
		  error (0, 0, "%s: Too many DIEs, not optimizing",
			 dso->filename);
		  goto fail;
		}
	      /* If we reach the DIE limit, silently signal the dwz
		 caller that it should retry with low_mem.  */
	      if (likely (!low_mem) && ndies == low_mem_die_limit)
		{
		  if (tracing)
		    fprintf (stderr, "Hit low-mem die-limit\n");
		  ret = 2;
		  goto fail;
		}
	    }
	  ndies++;
	  if (unlikely (low_mem_phase1))
	    die = &die_buf;
	  else if (parent == NULL
		   || parent->die_root
		   || parent->die_named_namespace)
	    {
	      die = pool_alloc (dw_die, sizeof (struct dw_die));
	      memset (die, '\0', sizeof (struct dw_die));
	      die->die_toplevel = 1;
	    }
	  else
	    {
	      if (die_nontoplevel_freelist)
		{
		  die = die_nontoplevel_freelist;
		  die_nontoplevel_freelist = die->die_sib;
		}
	      else
		die = pool_alloc (dw_die, offsetof (struct dw_die, die_dup));
	      memset (die, '\0', offsetof (struct dw_die, die_dup));
	    }
	  *diep = die;
	  die->die_tag = t->tag;
	  die->die_abbrev = t;
	  die->die_offset = die_offset;
	  if (parent)
	    die->die_parent = parent;
	  else
	    {
	      die->die_root = 1;
	      die->die_parent = (dw_die_ref) cu;
	    }
	  die->u.p1.die_enter = tick;
	  die->u.p1.die_exit = tick++;
	  if (likely (!low_mem_phase1))
	    {
	      if (t->children)
		{
		  diep = &die->die_child;
		  parent = die;
		}
	      else
		diep = &die->die_sib;
	    }
	  for (i = 0; i < t->nattr; ++i)
	    {
	      uint32_t form = t->attr[i].form;
	      size_t len = 0;

	      while (form == DW_FORM_indirect)
		{
		  form = read_uleb128 (ptr);
		  if (ptr > endcu)
		    {
		      error (0, 0, "%s: Attributes extend beyond end of CU",
			     dso->filename);
		      goto fail;
		    }
		}

	      /* Get length of expr/blocks first.  Canonicalize all,
		 except exprloc, to DW_FORM_block1.  */
	      switch (form)
		{
		case DW_FORM_block1:
		  len = *ptr++;
		  break;
		case DW_FORM_block2:
		  len = read_16 (ptr);
		  form = DW_FORM_block1;
		  break;
		case DW_FORM_block4:
		  len = read_32 (ptr);
		  form = DW_FORM_block1;
		  break;
		case DW_FORM_block:
		  len = read_uleb128 (ptr);
		  form = DW_FORM_block1;
		  break;
		case DW_FORM_exprloc:
		  len = read_uleb128 (ptr);
		  break;
		default:
		  break;
		}

	      if (unlikely (low_mem_phase1)
		  && add_locexpr_dummy_dies (dso, cu, die, ptr, form,
					     t->attr[i].attr, len))
		  goto fail;

	      switch (form)
		{
		case DW_FORM_ref_addr:
		  if (unlikely (low_mem_phase1))
		    {
		      unsigned int offset
			= read_size (ptr, cu->cu_version == 2 ? ptr_size : 4);
		      add_dummy_die (cu, offset);
		    }
		  ptr += cu->cu_version == 2 ? ptr_size : 4;
		  break;
		case DW_FORM_addr:
		  ptr += ptr_size;
		  break;
		case DW_FORM_flag_present:
		  break;
		case DW_FORM_implicit_const:
		  if (lang_p
		      && (die->die_tag == DW_TAG_compile_unit
			  || die->die_tag == DW_TAG_partial_unit)
		      && t->attr[i].attr == DW_AT_language)
		    cu->lang = t->values[i];
		  break;
		case DW_FORM_data1:
		  if (lang_p
		      && (die->die_tag == DW_TAG_compile_unit
			  || die->die_tag == DW_TAG_partial_unit)
		      && t->attr[i].attr == DW_AT_language)
		    cu->lang = *ptr;
		  /* FALLTHRU */
		case DW_FORM_ref1:
		case DW_FORM_flag:
		  ++ptr;
		  break;
		case DW_FORM_data2:
		  if (lang_p
		      && (die->die_tag == DW_TAG_compile_unit
			  || die->die_tag == DW_TAG_partial_unit)
		      && t->attr[i].attr == DW_AT_language)
		    cu->lang = do_read_16 (ptr);
		  /* FALLTHRU */
		case DW_FORM_ref2:
		  ptr += 2;
		  break;
		case DW_FORM_data4:
		  if (lang_p
		      && (die->die_tag == DW_TAG_compile_unit
			  || die->die_tag == DW_TAG_partial_unit)
		      && t->attr[i].attr == DW_AT_language)
		    read_lang (ptr, form, &cu->lang);
		  /* FALLTHRU */
		case DW_FORM_ref4:
		case DW_FORM_sec_offset:
		  ptr += 4;
		  break;
		case DW_FORM_data8:
		  if (lang_p
		      && (die->die_tag == DW_TAG_compile_unit
			  || die->die_tag == DW_TAG_partial_unit)
		      && t->attr[i].attr == DW_AT_language)
		    read_lang (ptr, form, &cu->lang);
		  /* FALLTHRU */
		case DW_FORM_ref8:
		case DW_FORM_ref_sig8:
		  ptr += 8;
		  break;
		case DW_FORM_data16:
		  ptr += 16;
		  break;
		case DW_FORM_sdata:
		case DW_FORM_udata:
		  if (lang_p
		      && (die->die_tag == DW_TAG_compile_unit
			  || die->die_tag == DW_TAG_partial_unit)
		      && t->attr[i].attr == DW_AT_language)
		    {
		      ptr = read_lang (ptr, form, &cu->lang);
		      break;
		    }
		  /* FALLTHRU */
		case DW_FORM_ref_udata:
		  skip_leb128 (ptr);
		  break;
		case DW_FORM_strp:
		  if (t->attr[i].attr == DW_AT_name
		      && (die->die_tag == DW_TAG_namespace
			  || die->die_tag == DW_TAG_module)
		      && !die->die_root
		      && (die->die_parent->die_root
			  || die->die_parent->die_named_namespace))
		    die->die_named_namespace = 1;
		  if (note_strp_forms)
		    note_strp_offset (read_32 (ptr));
		  else
		    ptr += 4;
		  break;
		case DW_FORM_line_strp:
		  if (t->attr[i].attr == DW_AT_name
		      && (die->die_tag == DW_TAG_namespace
			  || die->die_tag == DW_TAG_module)
		      && !die->die_root
		      && (die->die_parent->die_root
			  || die->die_parent->die_named_namespace))
		    die->die_named_namespace = 1;
		  /* Don't note strp, different string table.  */
		  ptr += 4;
		  break;
		case DW_FORM_string:
		  ptr = (unsigned char *) strchr ((char *)ptr, '\0') + 1;
		  if (t->attr[i].attr == DW_AT_name
		      && (die->die_tag == DW_TAG_namespace
			  || die->die_tag == DW_TAG_module)
		      && !die->die_root
		      && (die->die_parent->die_root
			  || die->die_parent->die_named_namespace))
		    die->die_named_namespace = 1;
		  break;
		case DW_FORM_indirect:
		  abort ();
		/* All expr/blocks lengths already handled above.
		   Just canonicalize exprloc to block1 too.  */
		case DW_FORM_exprloc:
		  form = DW_FORM_block1;
		  break;
		case DW_FORM_block1:
		  break;
		case DW_FORM_block2:
		case DW_FORM_block4:
		case DW_FORM_block:
		  abort ();
		default:
		  error (0, 0, "%s: Unknown DWARF %s",
			 dso->filename, get_DW_FORM_str (form));
		  goto fail;
		}

	      if (ptr > endcu)
		{
		  error (0, 0, "%s: Attributes extend beyond end of CU",
			 dso->filename);
		  goto fail;
		}

	      if (form == DW_FORM_block1)
		{
		  if (len >= (size_t) (endcu - ptr))
		    {
		      error (0, 0, "%s: Attributes extend beyond end of CU",
			     dso->filename);
		      goto fail;
		    }

		  if (t->attr[i].attr > DW_AT_loclists_base
		      && (t->attr[i].attr < DW_AT_MIPS_fde
			  || t->attr[i].attr > DW_AT_MIPS_has_inlines)
		      && (t->attr[i].attr < DW_AT_sf_names
			  || t->attr[i].attr > DW_AT_body_end)
		      && (t->attr[i].attr < DW_AT_GNU_call_site_value
			  || t->attr[i].attr
			     > DW_AT_GNU_call_site_target_clobbered))
		    {
		      error (0, 0, "%s: Unknown DWARF %s with "
				   "block DW_FORM",
			     dso->filename, get_DW_AT_str (t->attr[i].attr));
		      goto fail;
		    }

		  ptr += len;
		}
	    }
	  die->die_size = (ptr - debug_sections[kind].data)
			  - die_offset;
	  if (unlikely (low_mem))
	    {
	      if (low_mem_phase1)
		continue;
	      if (off_htab != NULL && kind == DEBUG_INFO)
		{
		  void **slot
		    = htab_find_slot_with_hash (off_htab, die, off_hash (die),
						INSERT);
		  if (slot == NULL)
		    dwz_oom ();
		  if (*slot != NULL)
		    {
		      dw_die_ref ref = (dw_die_ref) *slot;
		      assert (ref->die_collapsed_child);
		      die->die_referenced = 1;
		      die->die_intercu_referenced = 1;
		      memset (ref, '\0', offsetof (struct dw_die, die_child));
		      ref->die_parent = die_collapsed_child_freelist;
		      die_collapsed_child_freelist = ref;
		    }
		  *slot = (void *) die;
		  continue;
		}
	    }

	  off_htab_add_die (cu, die, die_count);
	}

      if (unlikely (low_mem_phase1))
	continue;

      if (cu->cu_die == NULL
	  || (cu->cu_die->die_tag != DW_TAG_compile_unit
	      && cu->cu_die->die_tag != DW_TAG_partial_unit
	      && cu->cu_die->die_tag != DW_TAG_type_unit)
	  || cu->cu_die->die_sib != NULL)
	{
	  error (0, 0, "%s: %s section chunk doesn't contain a single"
			" compile_unit or partial_unit", dso->filename,
		 debug_sections[kind].name);
	  goto fail;
	}

      cu->cu_comp_dir = get_AT_string (cu->cu_die, DW_AT_comp_dir);
      if (skip_producers_p
	  && skip_producer (get_AT_string (cu->cu_die, DW_AT_producer)))
	{
	  cu->cu_die->die_remove = 1;
	  continue;
	}
      enum dwarf_form form;
      debug_line_off
	= get_AT_int (cu->cu_die, DW_AT_stmt_list, &present, &form);
      if (present)
	{
	  if (!(form == DW_FORM_sec_offset || form == DW_FORM_data4))
	    {
	      error (0, 0, "%s: DW_AT_stmt_list not DW_FORM_sec_offset or"
		     " DW_FORM_data4", dso->filename);
	      goto fail;
	    }

	  if (cu_files != NULL && last_debug_line_off == debug_line_off)
	    {
	      cu->cu_nfiles = cu_nfiles;
	      cu->cu_files = cu_files;
	    }
	  else
	    {
	      if (read_debug_line (dso, cu, debug_line_off))
		goto fail;
	      cu_nfiles = cu->cu_nfiles;
	      cu_files = cu->cu_files;
	      last_debug_line_off = debug_line_off;
	    }
	}

      if (likely (!op_multifile && !rd_multifile && !fi_multifile)
	  && likely (kind == DEBUG_INFO))
	{
	  if (checksum_die (dso, cu, NULL, cu->cu_die))
	    goto fail;
	  checksum_ref_die (cu, NULL, cu->cu_die, NULL, NULL);
	  if (odr)
	    {
	      dw_die_ref die;
	      FOREACH_LOW_TOPLEVEL_DIE_IN_CU (die, cu)
		{
		  if (die->die_ck_state != CK_KNOWN)
		    continue;
		  if (die_odr_state (die) != ODR_NONE)
		    die->u.p1.die_ref_hash = die->u.p1.die_hash;
		  else
		    die->die_ref_hash_computed = 0;
		}
	      checksum_ref_die (cu, NULL, cu->cu_die, NULL, NULL);
	    }

	  if (dump_dies_p)
	    dump_dies (0, cu->cu_die);

	  if (find_dups (cu->cu_die))
	    goto fail;
	}
      if (unlikely (kind == DEBUG_TYPES))
	{
	  dw_die_ref ref = off_htab_lookup (cu, cu->cu_offset + type_offset);
	  if (ref == NULL)
	    {
	      error (0, 0, "%s: Couldn't find DIE at [%x] "
		     "referenced by type_offset from cu DIE at [%x]",
		     dso->filename, cu->cu_offset + type_offset,
		     cu->cu_die->die_offset);
	      goto fail;
	    }
	  if (unlikely (low_mem))
	    {
	      ref->die_referenced = 1;
	      ref->die_intercu_referenced = 1;
	    }
	}
      if (unlikely (low_mem))
	{
	  remove_unneeded (cu, cu->cu_die, 1);
	  remove_unneeded (cu, cu->cu_die, 2);
	  collapse_children (cu, cu->cu_die);
	}
    }

  if (unlikely (low_mem_phase1))
    {
      low_mem_phase1 = false;
      cu_chunk = 0;
      goto low_mem_phase2;
    }

  if (unlikely (low_mem))
    ;
  else if (unlikely (meta_abbrev_htab != NULL))
    {
      dw_cu_ref cu;

      if (unlikely (op_multifile))
	for (cu = first_cu; cu; cu = cu->cu_next)
	  cu->cu_abbrev = NULL;
      htab_delete (meta_abbrev_htab);
      meta_abbrev_htab = NULL;
      obstack_free (&ob2, to_free);
      abbrev = NULL;
    }
  else if (abbrev)
    htab_delete (abbrev);

  if (unlikely (kind == DEBUG_TYPES))
    return 0;

  if (unlikely (rd_multifile || fi_multifile))
    {
      dw_cu_ref cu;

      /* Inside of read_multifile, DIE hashes are computed
	 only after all the PUs are parsed, as we follow
	 DW_FORM_ref_addr then.  */
      for (cu = first_cu; cu; cu = cu->cu_next)
	if (checksum_die (dso, cu, NULL, cu->cu_die))
	  goto fail;

      for (cu = first_cu; cu; cu = cu->cu_next)
	checksum_ref_die (cu, NULL, cu->cu_die, NULL, NULL);

      if (dump_dies_p)
	for (cu = first_cu; cu; cu = cu->cu_next)
	  dump_dies (0, cu->cu_die);

      if (rd_multifile)
	{
	  for (cu = first_cu; cu; cu = cu->cu_next)
	    if (find_dups (cu->cu_die))
	      goto fail;
	}
      else
	for (cu = first_cu; cu; cu = cu->cu_next)
	  if (find_dups_fi (cu->cu_die))
	    goto fail;

      return 0;
    }

  if (tracing)
    {
      if (op_multifile)
	fprintf (stderr, "Die count: %u\n", ndies);
      else
	fprintf (stderr, "Die count: %u, %.2f%% of estimate\n", ndies,
		 (double)ndies / ((double)estimated_nr_dies / 100));
    }
  if (tracing)
    htab_report (off_htab, "off_htab post-parsing");
  if (stats_p)
    stats->die_count = ndies;
  if (die_count)
    *die_count = ndies;
  htab_delete (dup_htab);
  dup_htab = NULL;
  return 0;
fail:
  if (unlikely (meta_abbrev_htab != NULL))
    {
      dw_cu_ref cu;

      for (cu = first_cu; cu; cu = cu->cu_next)
	cu->cu_abbrev = NULL;
      htab_delete (meta_abbrev_htab);
      meta_abbrev_htab = NULL;
      obstack_free (&ob2, to_free);
    }
  else if (abbrev)
    htab_delete (abbrev);
  if (dup_htab && kind == DEBUG_INFO)
    {
      htab_delete (dup_htab);
      dup_htab = NULL;
    }
  return ret;
}

/* Compare function called from qsort, which should ensure that
   dup candidate dies with the same set of referrer CUs are
   adjacent.  */
static int
partition_cmp (const void *p, const void *q)
{
  dw_die_ref die1 = *(dw_die_ref *) p;
  dw_die_ref die2 = *(dw_die_ref *) q;
  dw_die_ref ref1, ref2;
  dw_cu_ref last_cu1 = NULL, last_cu2 = NULL;
  ref1 = die1;
  ref2 = die2;
  if (odr_active_p && odr_mode != ODR_BASIC)
    {
      while (ref1 && die_odr_state (ref1) == ODR_DECL)
	ref1 = ref1->die_nextdup;
      if (ref1 == NULL)
	ref1 = die1;
      while (ref2 && die_odr_state (ref2) == ODR_DECL)
	ref2 = ref2->die_nextdup;
      if (ref2 == NULL)
	ref2 = die2;
    }
  for (;; ref1 = ref1->die_nextdup, ref2 = ref2->die_nextdup)
    {
      dw_cu_ref ref1cu = NULL;
      dw_cu_ref ref2cu = NULL;
      while (ref1 && (ref1cu = die_cu (ref1)) == last_cu1)
	ref1 = ref1->die_nextdup;
      while (ref2 && (ref2cu = die_cu (ref2)) == last_cu2)
	ref2 = ref2->die_nextdup;
      if (ref1 == NULL || ref2 == NULL)
	break;
      last_cu1 = ref1cu;
      last_cu2 = ref2cu;
      if (last_cu1->cu_offset < last_cu2->cu_offset)
	return -1;
      else if (last_cu1->cu_offset > last_cu2->cu_offset)
	return 1;
    }
  if (ref1)
    return -1;
  if (ref2)
    return 1;
  /* The rest is just to keep sort stable.  */
  if (die1->die_offset < die2->die_offset)
    return -1;
  if (die1->die_offset > die2->die_offset)
    return 1;
  return 0;
}

/* Add duplicate chain for DIE to VEC.  */
static void
partition_found_dups (dw_die_ref die, struct obstack *vec)
{
  assert (die->die_ck_state == CK_KNOWN);
  obstack_ptr_grow (vec, die);
  if (unlikely (verify_dups_p))
    verify_dups (die, true);

  if (stats_p)
    {
      uint64_t length = 0;
      for (; die; die = die->die_nextdup)
	length++;
      stats->dup_cnt += length;
      stats->dup_chain_max_length = MAX (stats->dup_chain_max_length, length);
      stats->dup_chain_cnt++;
    }
}

/* Sort duplication chain for HEAD, assuming the chain was formed by
   die_eq.  */
static void
sort_dups (dw_die_ref head)
{
  dw_die_ref prev = NULL, die, next;
  /* Sort the die_nextdup list by increasing die_cu ()->cu_chunk.
     When it is originally added, child has the lowest
     cu_offset, then the DIEs are sorted in the linked list
     from highest cu_offset down to lowest or second lowest.  */
  for (die = head->die_nextdup; die; prev = die, die = next)
    {
      next = die->die_nextdup;
      die->die_nextdup = prev;
    }
  head->die_nextdup = prev;
}

/* Merge duplicate chains D and D2, and return the head of the merged
chain.  */
static dw_die_ref
merge_dups (dw_die_ref d, dw_die_ref d2)
{
  if (d == NULL)
    return d2;
  if (d2 == NULL)
    return d;

  dw_die_ref tail = NULL;
  dw_die_ref head = NULL;
  while (true)
    {
      dw_die_ref next;
      if (d && d2)
	{
	  if (d->die_offset < d2->die_offset)
	    {
	      next = d;
	      d = d->die_nextdup;
	    }
	  else
	    {
	      next = d2;
	      d2 = d2->die_nextdup;
	    }
	}
      else if (d)
	{
	  next = d;
	  d = d->die_nextdup;
	}
      else if (d2)
	{
	  next = d2;
	  d2 = d2->die_nextdup;
	}
      else
	break;
      if (!head)
	head = next;
      if (tail)
	tail->die_nextdup = next;
      tail = next;
    }

  for (d = head; d; d = d->die_nextdup)
    if (d == head)
      d->die_dup = NULL;
    else
      d->die_dup = head;

  if (unlikely (verify_dups_p))
    verify_dups (head, true);
  return head;
}

static void
mark_singletons (dw_cu_ref cu, dw_die_ref top_die, dw_die_ref die,
		 struct obstack *vec)
{
  struct abbrev_tag *t;
  unsigned int i;
  unsigned char *ptr;
  dw_die_ref child;
  bool found;

  t = die->die_abbrev;

  found = false;
  for (i = 0; i < t->nattr; ++i)
    {
      struct abbrev_attr *attr = &t->attr[i];
      if (attr->attr == DW_AT_sibling)
	continue;
      switch (attr->form)
	{
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	case DW_FORM_indirect:
	  found = true;
	  break;
	}
    }
  if (!found)
    goto handle_children;

  if (unlikely (cu->cu_kind == CU_TYPES))
    ptr = debug_sections[DEBUG_TYPES].data;
  else
    ptr = debug_sections[DEBUG_INFO].data;
  ptr += die->die_offset;
  skip_leb128 (ptr);
  for (i = 0; i < t->nattr; ++i)
    {
      struct abbrev_attr *attr = &t->attr[i];
      uint32_t form = attr->form;
      uint64_t value;
      dw_die_ref ref, reft;

      while (form == DW_FORM_indirect)
	form = read_uleb128 (ptr);

      switch (form)
	{
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	  switch (form)
	    {
	    case DW_FORM_ref_udata: value = read_uleb128 (ptr); break;
	    case DW_FORM_ref1: value = read_8 (ptr); break;
	    case DW_FORM_ref2: value = read_16 (ptr); break;
	    case DW_FORM_ref4: value = read_32 (ptr); break;
	    case DW_FORM_ref8: value = read_64 (ptr); break;
	    default: abort ();
	    }
	  if (t->attr[i].attr == DW_AT_sibling)
	    break;
	  ref = off_htab_lookup (cu, cu->cu_offset + value);
	  if (!ref->die_collapsed_child
	      && ref->u.p1.die_enter >= top_die->u.p1.die_enter
	      && ref->u.p1.die_exit <= top_die->u.p1.die_exit)
	    break;
	  reft = ref;
	  while (!reft->die_root
		 && reft->die_parent->die_tag != DW_TAG_compile_unit
		 && reft->die_parent->die_tag != DW_TAG_partial_unit
		 && !reft->die_parent->die_named_namespace)
	    reft = reft->die_parent;
	  if (reft->die_dup != NULL || reft->die_nextdup != NULL)
	    break;
	  if (reft->die_ref_seen)
	    break;
	  reft->die_ref_seen = 1;
	  partition_found_dups (reft, vec);
	  mark_singletons (die_cu (reft), reft, reft, vec);
	  break;
	default:
	  ptr = skip_attr_no_dw_form_indirect (cu->cu_version, form, ptr);
	  break;
	}
    }

 handle_children:
  for (child = die->die_child; child; child = child->die_sib)
    mark_singletons (cu, top_die, child, vec);
}

/* Split maximal duplicate chain DIE into smaller chains that contain
   structurally equal defs, and combine the decls with one of those.
   Return the first chain, and call partition_found_dups for the others.  */
static dw_die_ref
split_dups (dw_die_ref die, struct obstack *vec)
{
  dw_die_ref res = NULL;

  /* Count the DIEs in the duplicate chain.  */
  unsigned count = 0;
  dw_die_ref d;
  for (d = die; d; d = d->die_nextdup)
    count++;
  assert (count >= 2);

  /* Break up the duplicate chain.  */
  dw_die_ref arr[count];
  unsigned int i;
  for (d = die, i = 0; d; d = d->die_nextdup, i++)
    arr[i] = d;
  for (i = 0; i < count; i++)
    {
      d = arr[i];
      d->die_nextdup = NULL;
      d->die_dup = NULL;
    }

  /* Build decls duplicate chain.  */
  dw_die_ref tail = NULL;
  dw_die_ref head = NULL;
  for (i = 0; i < count; i++)
    {
      d = arr[i];
      if (die_odr_state (d) != ODR_DECL)
	continue;
      if (!head)
	head = d;
      if (tail)
	tail->die_nextdup = d;
      if (d != head)
	d->die_dup = head;
      tail = d;
    }
  dw_die_ref decls = head;

  /* Build def duplicate chains.  */
  unsigned int j;
  dw_die_ref d2;
  for (i = 0; i < count; i++)
    {
      d = arr[i];
      if (d->die_dup || d->die_nextdup
	  || die_odr_state (d) == ODR_DECL)
	continue;
      tail = d;
      for (j = i + 1; j < count; j++)
	{
	  d2 = arr[j];
	  if (d2->die_dup || d2->die_nextdup
	      || die_odr_state (d2) == ODR_DECL)
	    continue;
	  die_eq (d, d2);
	}
      sort_dups (d);
    }

  if (odr_mode != ODR_BASIC)
    {
      /* Find the first duplicate chain containing defs.  */
      dw_die_ref def = NULL;
      for (i = 0; i < count; i++)
	{
	  d = arr[i];
	  if (die_odr_state (d) == ODR_DECL
	      || d->die_dup != NULL)
	    continue;
	  def = d;
	  break;
	}

      /* Merge the def chain with the decls.  */
      merge_dups (def, decls);
    }

  for (i = 0; i < count; i++)
    {
      d = arr[i];
      if (d->die_dup == NULL)
	/* If DIE is now either:
	   - no longer part of a duplicate chain, or
	   - head of a duplicate chain,
	   don't remove it.  */
	d->die_remove = 0;
    }

  /* Notice the new duplicate chains.  */
  for (i = 0; i < count; i++)
    {
      d = arr[i];
      if (d->die_dup != NULL)
	continue;
      if (res == NULL)
	res = d;
      else
	partition_found_dups (d, vec);
    }
  return res;
}

/* Search for duplicate removal reference DIE candidates
   in tree rooted by PARENT.  */
static void
partition_find_dups (struct obstack *vec, dw_die_ref parent)
{
  dw_die_ref child;
  for (child = parent->die_child; child; child = child->die_sib)
    {
      if (child->die_nextdup != NULL
	  && child->die_dup == NULL
	  && child->die_offset != -1U)
	{
	  dw_die_ref die;

	  if (unlikely (op_multifile))
	    {
	      /* If all the dups are from the same DSO or executable,
		 there is nothing in it to optimize in between different
		 objects.  */
	      unsigned int cu_chunk = die_cu (child)->cu_chunk;
	      for (die = child->die_nextdup; die; die = die->die_nextdup)
		if (die_cu (die)->cu_chunk != cu_chunk)
		  break;
	      if (die == NULL)
		continue;
	    }
	  sort_dups (child);
	  partition_found_dups (child, vec);
	}
      else if (child->die_named_namespace)
	partition_find_dups (vec, child);
    }
}

/* Reorder duplicate chain DIE to make sure it doesn't start with a decl.  */
static dw_die_ref
reorder_dups (dw_die_ref die)
{
  unsigned decl_count = 0;
  unsigned def_count = 0;
  dw_die_ref d;

  if (die_odr_state (die) == ODR_NONE)
    return die;

  for (d = die; d; d = d->die_nextdup)
    {
      if (die_odr_state (d) == ODR_DECL)
	decl_count++;
      else
	def_count++;
    }
  if (def_count == 0 || decl_count == 0)
    return die;

  if (die_odr_state (die) != ODR_DECL)
    return die;

  dw_die_ref def = NULL;
  dw_die_ref prev = NULL;
  for (d = die; d; prev = d, d = d->die_nextdup)
    {
      if (die_odr_state (d) == ODR_DECL)
	continue;
      def = d;
      break;
    }

  assert (!die->die_remove);
  assert (def->die_remove);
  def->die_remove = 0;
  die->die_remove = 1;
  def->die_ref_seen = die->die_ref_seen;
  dw_die_ref next = def->die_nextdup;
  if (prev)
    prev->die_nextdup = next;
  def->die_nextdup = die;
  for (d = def; d; prev = d, d = d->die_nextdup)
    {
      if (d == def)
	d->die_dup = NULL;
      else
	d->die_dup = def;
    }

  if (unlikely (verify_dups_p))
    verify_dups (def, false);
  return def;
}

/* Copy DIE tree of DIE, as children of new DIE PARENT.  */
static dw_die_ref
copy_die_tree (dw_die_ref parent, dw_die_ref die)
{
  dw_die_ref child, new_child, *diep;
  dw_die_ref new_die;
  if (die->die_toplevel)
    {
      new_die = pool_alloc (dw_die, sizeof (struct dw_die));
      memset (new_die, '\0', sizeof (*new_die));
      new_die->die_toplevel = 1;
      die->die_dup = new_die;
      new_die->die_nextdup = die;
      if (!die->die_op_type_referenced)
	die->die_remove = 1;
    }
  else
    {
      new_die = pool_alloc (dw_die, offsetof (struct dw_die, die_dup));
      memset (new_die, '\0', offsetof (struct dw_die, die_dup));
    }
  new_die->die_parent = parent;
  new_die->die_tag = die->die_tag;
  new_die->die_offset = -1U;
  new_die->die_size = die->die_size;
  diep = &new_die->die_child;
  for (child = die->die_child; child; child = child->die_sib)
    {
      new_child = copy_die_tree (new_die, child);
      *diep = new_child;
      diep = &new_child->die_sib;
    }
  return new_die;
}

/* If all DIEs in the duplication chain DIE are in CUs with the same
   language, return that language.  Otherwise, return 0.  */
static enum dwarf_source_language
partition_lang (dw_die_ref die)
{
  enum dwarf_source_language lang;
  dw_die_ref d;

  if (die == NULL)
    return 0;

  lang = die_cu (die)->lang;
  switch (lang)
    {
    case DW_LANG_C_plus_plus:
    case DW_LANG_C_plus_plus_03:
    case DW_LANG_C_plus_plus_11:
    case DW_LANG_C_plus_plus_14:
      break;
    default:
      return 0;
    }

  for (d = die->die_nextdup; d; d = d->die_nextdup)
    if (die_cu (d)->lang != lang)
      return 0;

  return lang;
}

/* Return how many bytes we need to encode VAL.  */
static unsigned int
nr_bytes_for (uint64_t val)
{
  unsigned int n;

  if (val == 0)
    return 1;

  for (n = 0; val > 0; n++)
    val = val >> 8;

  return n;
}

/* Return true if duplicate chains REF1 and REF2 have the same set of
   referrer CUs.  If so, return the number of unique referrer CUs
   in *CNT.  */
static inline unsigned int FORCE_INLINE
same_ref_cus_p (dw_die_ref ref1, dw_die_ref ref2, size_t *cnt)
{
  dw_cu_ref last_cu1 = NULL, last_cu2 = NULL;

  *cnt = 0;

  if (odr_active_p && odr_mode != ODR_BASIC)
    {
      dw_die_ref orig_ref1 = ref1, orig_ref2 = ref2;
      while (ref1 && die_odr_state (ref1) == ODR_DECL)
	ref1 = ref1->die_nextdup;
      if (ref1 == NULL)
	ref1 = orig_ref1;
      while (ref2 && die_odr_state (ref2) == ODR_DECL)
	ref2 = ref2->die_nextdup;
      if (ref2 == NULL)
	ref2 = orig_ref2;
    }
  for (;; ref1 = ref1->die_nextdup, ref2 = ref2->die_nextdup)
    {
      dw_cu_ref ref1cu = NULL;
      dw_cu_ref ref2cu = NULL;

      while (ref1 && (ref1cu = die_cu (ref1)) == last_cu1)
	ref1 = ref1->die_nextdup;
      while (ref2 && (ref2cu = die_cu (ref2)) == last_cu2)
	ref2 = ref2->die_nextdup;
      if (ref1 == NULL || ref2 == NULL)
	break;

      last_cu1 = ref1cu;
      last_cu2 = ref2cu;

      if (last_cu1 != last_cu2)
	break;
      else
	(*cnt)++;
    }

  if (ref1 || ref2)
    return false;

  return true;
}

/* Return the number of unique referrer CUs in duplicate chain REF.  */
static inline size_t FORCE_INLINE
cnt_ref_cus (dw_die_ref ref)
{
  dw_cu_ref last_cu1 = NULL;
  size_t cnt = 0;

  for (;; ref = ref->die_nextdup)
    {
      dw_cu_ref refcu = NULL;
      while (ref && (refcu = die_cu (ref)) == last_cu1)
	ref = ref->die_nextdup;
      if (ref == NULL)
	break;
      last_cu1 = refcu;
      cnt++;
    }

  return cnt;
}

/* Helper function of partition_dups_1.  Decide what DIEs matching in
   multiple CUs might be worthwhile to be moved into partial units,
   construct those partial units.  */
static bool
partition_dups_1 (dw_die_ref *arr, size_t nr_partitions, size_t *partitions,
		  dw_cu_ref *first_partial_cu,
		  dw_cu_ref *last_partial_cu,
		  bool second_phase)
{
  size_t i, j, cnt;
  bool ret = false;
  size_t idx = 0;
  for (idx = 0; idx < nr_partitions * 2; idx += 2)
    {
      i = partitions[idx];
      cnt = partitions[idx + 1];
      j = partitions[idx + 2];

      if (arr[i]->die_dup != NULL)
	continue;

      dw_die_ref ref;
      size_t size = 0, k, orig_size, new_size, namespaces = 0;
      unsigned int force = 0;
      enum dwarf_source_language part_lang
	= gen_cu_p ? partition_lang (arr[i]) : 0;
      for (k = i; k < j; k++)
	{
	  if (second_phase && arr[k]->die_ref_seen)
	    force++;
	  size += calc_sizes (arr[k]);
	  for (ref = arr[k]->die_parent;
	       ref->die_named_namespace && ref->die_dup == NULL;
	       ref = ref->die_parent)
	    {
	      ref->die_dup = arr[k];
	      namespaces++;
	    }
	}
      /* If during second_phase there are some DIEs we want to force
	 into a partial unit because they are referenced from something
	 already forced into a partial unit, but also some DIEs with
	 the same set of referrers, try to see if we can put also those
	 into the partial unit.  They can be put there only if they
	 don't refer to DIEs that won't be put into partial units.  */
      if (unlikely (partition_dups_opt)
	  && second_phase && force && force < j - i)
	{
	  /* First optimistically assume all such DIEs can be put there,
	     thus mark all such DIEs as going to be included, so that
	     even if one of those DIEs references another one from those
	     DIEs it can be included.  */
	  for (k = i; k < j; k++)
	    {
	      assert (arr[k]->die_ref_seen < 2);
	      if (arr[k]->die_ref_seen == 0)
		arr[k]->die_ref_seen = 2;
	    }
	  for (k = i; k < j; k++)
	    if (arr[k]->die_ref_seen == 2
		&& !mark_refs (die_cu (arr[k]), arr[k], arr[k],
			       (MARK_REFS_FOLLOW_DUPS | MARK_REFS_RETURN_VAL)))
	      break;
	  /* If that is not possible and some DIEs couldn't be included,
	     fallback to assume other DIEs won't be included.  */
	  if (k < j)
	    {
	      for (k = i; k < j; k++)
		if (arr[k]->die_ref_seen == 2)
		  arr[k]->die_ref_seen = 0;
	      for (k = i; k < j; k++)
		if (arr[k]->die_ref_seen == 0)
		  {
		    arr[k]->die_ref_seen = 2;
		    if (!mark_refs (die_cu (arr[k]), arr[k], arr[k],
				    (MARK_REFS_FOLLOW_DUPS
				     | MARK_REFS_RETURN_VAL)))
		      arr[k]->die_ref_seen = 0;
		  }
	    }
	}
      if (namespaces)
	{
	  for (k = i; k < j; k++)
	    for (ref = arr[k]->die_parent; ref->die_named_namespace;
		 ref = ref->die_parent)
	      ref->die_dup = NULL;
	}
      orig_size = size * cnt;
      /* Estimated size of CU header and DW_TAG_partial_unit
	 with DW_AT_stmt_list and DW_AT_comp_dir attributes
	 21 (also child end byte).  With DW_AT_language c++, 22.  */
      size_t pu_size
	= (/* CU Header: unit length (initial length).
	      32-bit DWARF: 4 bytes, 64-bit DWARF: 12 bytes.  */
	   4
	   /* CU Header: version (uhalf).
	      2 bytes.  */
	   + 2
	   /* CU Header: debug_abbrev_offset (section offset).
	      32-bit DWARF: 4 bytes, 64-bit DWARF: 8 bytes.  */
	   + 4
	   /* CU Header: address_size (ubyte).
	      1 byte.  */
	   + 1
	   /* DWARF5 CU header: unit_type (ubyte).  */
	   + (die_cu (arr[i])->cu_version >= 5 ? 1 : 0)
	   /* CU Root DIE: abbreviation code (unsigned LEB128).
	      1 or more bytes.  Optimistically assume 1.  */
	   + 1
	   /* CU Root DIE: DW_AT_stmt_list (lineptr).
	      32-bit DWARF: 4 bytes, 64-bit DWARF: 8 bytes.  */
	   + 4
	   /* CU Root DIE: DW_AT_comp_dir (string).
	      DW_FORM_strp: 32-bit DWARF: 4 bytes, 64-bit DWARF: 8 bytes.
	      DW_FORM_string: 1 or more bytes.
	      Assume 4 bytes.  */
	   + 4
	  /* CU Root DIE: DW_AT_language (constant).
	     1 or 2 bytes.  */
	   + ((uni_lang_p || part_lang)
	      ? nr_bytes_for (die_cu (arr[i])->lang)
	      : 0)
	   /* CU root DIE children terminator: abbreviation code 0
					       (unsigned LEB128).
	      1 byte.  */
	   + 1);
      /* DW_TAG_imported_unit with DW_AT_import attribute
	 (5 or 9 bytes (the latter for DWARF2 and ptr_size 8)).  */
      size_t import_size
	= (die_cu (arr[i])->cu_version == 2 ? 1 + ptr_size : 5);
      /* For DW_TAG_namespace or DW_TAG_module needed as
	 parents of the DIEs conservatively assume 10 bytes
	 for the abbrev index, DW_AT_name attribute and
	 DW_AT_sibling attribute and child end.  */
      size_t namespace_size = 10;
      new_size = (/* Size of DIEs.  */
		  size
		  /* Size of PU.  */
		  + pu_size
		  /* Size of imports.  */
		  + (part_lang != 0 ? 0 : import_size * cnt)
		  /* Size of namespace DIEs.  */
		  + namespace_size * namespaces);
      if (!second_phase)
	force = ((deduplication_mode == dm_inter_cu)
		 && (ignore_size || orig_size > new_size));
      if (force)
	{
	  dw_die_ref die, *diep;
	  dw_cu_ref refcu = die_cu (arr[i]);
	  dw_cu_ref partial_cu = pool_alloc (dw_cu, sizeof (struct dw_cu));
	  memset (partial_cu, '\0', sizeof (*partial_cu));
	  if (stats_p)
	    {
	      if (!second_phase)
		stats->pu_ph1_cnt++;
	      else
		stats->pu_ph2_cnt++;
	    }
	  partial_cu->cu_kind = CU_PU;
	  partial_cu->cu_offset = *last_partial_cu == NULL
				  ? 0 : (*last_partial_cu)->cu_offset + 1;
	  if (dump_pus_p)
	    fprintf (stderr, "Partial unit (%s) @ 0x%x:\n",
		     second_phase ? "phase two" : "phase one",
		     partial_cu->cu_offset);
	  partial_cu->cu_version = refcu->cu_version;
	  if (uni_lang_p)
	    partial_cu->lang = refcu->lang;
	  if (*first_partial_cu == NULL)
	    *first_partial_cu = *last_partial_cu = partial_cu;
	  else
	    {
	      (*last_partial_cu)->cu_next = partial_cu;
	      *last_partial_cu = partial_cu;
	    }
	  die = pool_alloc (dw_die, sizeof (struct dw_die));
	  memset (die, '\0', sizeof (*die));
	  die->die_toplevel = 1;
	  partial_cu->cu_die = die;
	  die->die_tag = DW_TAG_partial_unit;
	  die->die_offset = -1U;
	  die->die_root = 1;
	  die->die_parent = (dw_die_ref) partial_cu;
	  die->die_nextdup = refcu->cu_die;
	  die->die_size = 9;
	  diep = &die->die_child;
	  for (k = i; k < j; k++)
	    {
	      dw_die_ref child;
	      if (second_phase && !arr[k]->die_ref_seen)
		continue;
	      if (dump_pus_p)
		dump_die (arr[k]);
	      child = copy_die_tree (die, arr[k]);
	      if (stats_p)
		stats->pu_toplevel_die_cnt++;
	      for (ref = arr[k]->die_nextdup; ref; ref = ref->die_nextdup)
		ref->die_dup = child;
	      if (unlikely (verify_dups_p))
		verify_dups (child, odr_mode == ODR_BASIC);
	      if (part_lang != 0)
		{
		  die->die_tag = DW_TAG_compile_unit;
		  partial_cu->lang = part_lang;
		}
	      if (namespaces)
		{
		  for (ref = arr[k]->die_parent;
		       ref->die_named_namespace && ref->die_dup == NULL;
		       ref = ref->die_parent)
		    {
		      dw_die_ref namespc
			= pool_alloc (dw_die, sizeof (struct dw_die));
		      memset (namespc, '\0', sizeof (struct dw_die));
		      namespc->die_toplevel = 1;
		      namespc->die_tag = ref->die_tag;
		      namespc->die_offset = -1U;
		      namespc->die_nextdup = ref;
		      namespc->die_child = child;
		      namespc->die_parent = die;
		      namespc->die_size = 9;
		      namespc->die_named_namespace = 1;
		      child->die_parent = namespc;
		      ref->die_dup = namespc;
		      child = namespc;
		    }
		  if (ref->die_dup != NULL)
		    {
		      dw_die_ref *diep2;
		      for (diep2 = &ref->die_dup->die_child->die_sib;
			   *diep2; diep2 = &(*diep2)->die_sib)
			;
		      *diep2 = child;
		      child->die_parent = ref->die_dup;
		      continue;
		    }
		}
	      *diep = child;
	      diep = &child->die_sib;
	    }
	  if (namespaces)
	    {
	      for (k = i; k < j; k++)
		{
		  if (second_phase && !arr[k]->die_ref_seen)
		    continue;
		  for (ref = arr[k]->die_parent;
		       ref->die_named_namespace; ref = ref->die_parent)
		    ref->die_dup = NULL;
		}
	    }
	}
      else if (!second_phase)
	ret = true;
      if (second_phase)
	{
	  dw_die_ref next;
	  for (k = i; k < j; k++)
	    {
	      if (arr[k]->die_dup != NULL)
		continue;
	      for (ref = arr[k]; ref; ref = next)
		{
		  dw_cu_ref refcu = die_cu (ref);
		  next = ref->die_nextdup;
		  ref->die_dup = NULL;
		  ref->die_nextdup = NULL;
		  ref->die_remove = 0;
		  /* If there are dups within a single CU
		     (arguably a bug in the DWARF producer),
		     keep them linked together, but don't link
		     DIEs across different CUs.  */
		  while (deduplication_mode != dm_none
			 && next && refcu == die_cu (next))
		    {
		      dw_die_ref cur = next;
		      next = cur->die_nextdup;
		      cur->die_dup = ref;
		      cur->die_nextdup = ref->die_nextdup;
		      ref->die_nextdup = cur;
		    }
		}
	    }
	}
    }
  return ret;
}

/* Partition the duplicate chains in array ARR with size VEC_SIZE, and store
   the partitions on obstack ob2, with for each partition two entries:
   the start and the number of unique reffer CUs.  */
static void
calculate_partitions (dw_die_ref *arr, size_t vec_size)
{
  size_t i, j;
  for (i = 0; i < vec_size; i = j)
    {
      size_t cnt = 0;
      for (j = i + 1; j < vec_size; j++)
	{
	  size_t this_cnt;
	  if (!same_ref_cus_p (arr[i], arr[j], &this_cnt))
	    break;
	  cnt = this_cnt;
	}
      if (cnt == 0)
	cnt = cnt_ref_cus (arr[i]);
      obstack_grow (&ob2, &i, sizeof (size_t));
      obstack_grow (&ob2, &cnt, sizeof (size_t));
    }

  /* Add element to mark end of partition list.  This allows us to do
     'j = partitions[idx + 2]' for all partitions.  */
  obstack_grow (&ob2, &j, sizeof (size_t));
  size_t zero = 0;
  obstack_grow (&ob2, &zero, sizeof (size_t));
}

static inline void FORCE_INLINE
reset_die_ref_seen (void)
{
  dw_die_ref die;
  dw_cu_ref cu;
  FOREACH_CU_NORMAL_LOW_TOPLEVEL_DIE (cu, die)
    die->die_ref_seen = 0;
}

/* If the duplicate chain DIE consists of a singleton ODR_DEF die merged with
   the ODR_DECL chain, return the singleton ODR_DEF die.  Otherwise, return
   NULL.  */
static inline dw_die_ref FORCE_INLINE
merged_singleton (dw_die_ref die)
{
  dw_die_ref res = NULL;
  dw_die_ref d;
  size_t decl_cnt = 0;

  for (d = die; d; d = d->die_nextdup)
    switch (die_odr_state (d))
      {
      case ODR_DEF:
	if (res)
	  {
	    if (die_cu (res) == die_cu (d))
	      continue;
	    else
	      return NULL;
	  }
	else
	  res = d;
	break;
      case ODR_DECL:
	decl_cnt++;
	break;
      default:
	return NULL;
      }

  if (decl_cnt == 0)
    return NULL;

  return res;
}

/* Decide what DIEs matching in multiple CUs might be worthwhile
   to be moved into partial units, construct those partial units.  */
static int
partition_dups (void)
{
  dw_cu_ref cu, first_partial_cu = NULL, last_partial_cu = NULL;
  size_t vec_size, i;
  unsigned char *to_free;
  dw_die_ref *arr;

  if (unlikely (fi_multifile))
    return 0;

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "partition_dups\n");
    }

  to_free = obstack_alloc (&ob2, 1);

  if (odr_active_p)
    odr_phase = 2;

  for (cu = first_cu; cu; cu = cu->cu_next)
    partition_find_dups (&ob2, cu->cu_die);
  vec_size = obstack_object_size (&ob2) / sizeof (void *);

  if (odr_active_p)
    {
      arr = (dw_die_ref *) obstack_base (&ob2);
      if (progress_p)
	{
	  report_progress ();
	  fprintf (stderr, "partition_dups split_dups\n");
	}
      for (i = 0; i < vec_size; i++)
	{
	  dw_die_ref die = arr[i];
	  if (die_odr_state (die) == ODR_NONE)
	    continue;
	  die = split_dups (die, &ob2);
	  assert (die != NULL);
	  if (unlikely (verify_dups_p))
	    verify_dups (die, true);
	  arr = (dw_die_ref *) obstack_base (&ob2);
	  arr[i] = die;
	}

      vec_size = obstack_object_size (&ob2) / sizeof (void *);

      reset_die_ref_seen ();
      for (i = 0; i < vec_size; i++)
	{
	  dw_die_ref die = arr[i];
	  if (die->die_dup == NULL
	      && die->die_nextdup == NULL)
	    die->die_ref_seen = 1;
	}
      for (i = 0; i < vec_size; i++)
	{
	  dw_die_ref die = arr[i];
	  if (die->die_dup == NULL
	      && die->die_nextdup == NULL)
	    mark_singletons (die_cu (die), die, die, &ob2);
	  else if (odr_mode != ODR_BASIC
		   && die_odr_state (die) != ODR_NONE)
	    {
	      dw_die_ref s = merged_singleton (die);
	      if (s)
		mark_singletons (die_cu (s), s, s, &ob2);
	    }
	  else if (cnt_ref_cus (die) == 1)
	    mark_singletons (die_cu (die), die, die, &ob2);

	  arr = (dw_die_ref *) obstack_base (&ob2);
	}

      vec_size = obstack_object_size (&ob2) / sizeof (void *);
    }

  if (odr_active_p)
    odr_phase = 3;

  if (stats_p)
    print_dups_stats ();

  if (vec_size != 0)
    {
      arr = (dw_die_ref *) obstack_finish (&ob2);
      if (odr_active_p)
	for (i = 0; i < vec_size; ++i)
	  {
	    assert (arr[i] != NULL);
	    if (unlikely (verify_dups_p))
	      verify_dups (arr[i], true);
	  }
      if (dump_dups_p)
	{
	  for (i = 0; i < vec_size; ++i)
	    {
	      fprintf (stderr, "duplicate chain:\n");
	      dump_dups (arr[i]);
	    }
	}
      if (unlikely (progress_p))
	{
	  report_progress ();
	  fprintf (stderr, "partition_dups qsort\n");
	}
      qsort (arr, vec_size, sizeof (dw_die_ref), partition_cmp);
      if (unlikely (progress_p))
	{
	  report_progress ();
	  fprintf (stderr, "partition_dups after qsort\n");
	}

      size_t *partitions = (size_t *) obstack_base (&ob2);
      calculate_partitions (arr, vec_size);
      size_t nr_partitions
	= (obstack_object_size (&ob2) / sizeof (size_t)) / 2 - 1;
      partitions = (size_t *) obstack_finish (&ob2);
      if (stats_p)
	stats->part_cnt += nr_partitions;

      if (odr_active_p && odr_mode != ODR_BASIC)
	for (i = 0; i < vec_size; ++i)
	  arr[i] = reorder_dups (arr[i]);
      if (partition_dups_1 (arr, nr_partitions, partitions, &first_partial_cu,
			    &last_partial_cu, false))
	{
	  for (i = 0; i < vec_size; i++)
	    arr[i]->die_ref_seen = arr[i]->die_dup != NULL;
	  for (i = 0; i < vec_size; i++)
	    if (arr[i]->die_dup != NULL)
	      mark_refs (die_cu (arr[i]), arr[i], arr[i],
			 MARK_REFS_FOLLOW_DUPS);
	  partition_dups_1 (arr, nr_partitions, partitions, &first_partial_cu,
			    &last_partial_cu, true);
	  for (i = 0; i < vec_size; i++)
	    arr[i]->die_ref_seen = 0;
	}
    }
  if (first_partial_cu)
    {
      last_partial_cu->cu_next = first_cu;
      first_cu = first_partial_cu;
    }
  obstack_free (&ob2, to_free);

  if (stats_p)
    print_part_stats ();

  return 0;
}

/* The create_import_tree function below and all its helper
   data structures and functions attempt to optimize the size of
   DW_TAG_imported_unit DIEs, from the initial assumption that
   each CU that needs to include some newly created DW_TAG_partial_unit
   will contain DW_TAG_imported_unit for each such partial unit (PU)
   (so basically a bipartite graph with CUs and PUs as nodes
   and DW_TAG_imported_unit DIEs as edges) into a tree, where some
   of the partial units may also include DW_TAG_imported_unit
   DIEs, or when beneficial new PUs are created to hold some
   DW_TAG_imported_unit DIEs.  */

struct import_edge;

/* Structure describing details about a CU or PU (i.e. a node
   in the graph).  */
struct import_cu
{
  /* Corresponding CU.  CU->u1.cu_icu points back to this
     structure while in create_import_tree.  */
  dw_cu_ref cu;
  /* Linked list of incoming resp. outgoing edges.  */
  struct import_edge *incoming, *outgoing;
  /* The tail of the linked list of incoming edges.  */
  struct import_edge *incoming_tail;
  /* Next import_cu (used to chain PUs together).  */
  struct import_cu *next;
  /* Number of incoming resp. outgoing edges.  */
  unsigned int incoming_count, outgoing_count;
  /* Index.  Lowest indexes are assigned to partition_dups
     created PUs (sorted by decreasing number of incoming
     edges at the start), then referencing CUs
     (similarly, sorted by decreasing number of outgoing
     edges at the start), then optionally any PUs
     created by create_import_tree.  */
  unsigned int idx;
};

/* An edge in a linked list.  */
struct import_edge
{
  struct import_cu *icu;
  struct import_edge *next;
};

/* Called through qsort to sort an array of edges by decreasing
   incoming resp. outgoing_count (this is called when the graph
   is bipartite, so CUs only have non-zero outgoing_count
   and PUs only have non-zero incoming_count).  */
static int
import_edge_cmp (const void *p, const void *q)
{
  struct import_edge *e1 = (struct import_edge *) p;
  struct import_edge *e2 = (struct import_edge *) q;
  if (e1->icu->incoming_count > e2->icu->incoming_count)
    return -1;
  if (e1->icu->incoming_count < e2->icu->incoming_count)
    return 1;
  if (e1->icu->outgoing_count > e2->icu->outgoing_count)
    return -1;
  if (e1->icu->outgoing_count < e2->icu->outgoing_count)
    return 1;
  /* The rest is just to keep qsort stable.  */
  if (e1->icu->cu->cu_offset < e2->icu->cu->cu_offset)
    return -1;
  if (e1->icu->cu->cu_offset > e2->icu->cu->cu_offset)
    return 1;
  return 0;
}

/* Called through qsort to sort an array of CUs/PUs by decreasing
   incoming resp. outgoing_count (this is called when the graph
   is bipartite, so CUs only have non-zero outgoing_count
   and PUs only have non-zero incoming_count).  */
static int
import_cu_cmp (const void *p, const void *q)
{
  struct import_cu *c1 = *(struct import_cu **) p;
  struct import_cu *c2 = *(struct import_cu **) q;
  if (c1->incoming_count > c2->incoming_count)
    return -1;
  if (c1->incoming_count < c2->incoming_count)
    return 1;
  if (c1->outgoing_count > c2->outgoing_count)
    return -1;
  if (c1->outgoing_count < c2->outgoing_count)
    return 1;
  /* The rest is just to keep qsort stable.  */
  if (c1->cu->cu_offset < c2->cu->cu_offset)
    return -1;
  if (c1->cu->cu_offset > c2->cu->cu_offset)
    return 1;
  return 0;
}

/* Freelist for removed edges.  */
static struct import_edge *edge_freelist;

/* Prepare edge E to add to edge_freelist.  */
static inline void FORCE_INLINE
prepare_free_edge (struct import_edge *e UNUSED)
{
#if DEVEL
  e->icu = (void *)(uintptr_t)-1;
#endif
}

/* Add edge E to edge_freelist.  */
static inline void FORCE_INLINE
free_edge (struct import_edge *e)
{
  prepare_free_edge (e);
  e->next = edge_freelist;
  edge_freelist = e;
}

/* Add edge list starting at HEAD and ending at TAIL to edge_freelist.
   Assume that prepare_free_edge has been called on all elements.  */
static inline void FORCE_INLINE
free_edges (struct import_edge *head, struct import_edge *tail)
{
#if DEVEL
  if (verify_edge_freelist)
    {
      struct import_edge *e;
      for (e = head; e; e = e->next)
	{
	  assert (e->icu == (void *)(uintptr_t)-1);
	  if (e == tail)
	    break;
	}
      assert (e != NULL);
    }
#endif
  tail->next = edge_freelist;
  edge_freelist = head;
}

/* Detach an edge from edge_freelist, and return it.  */
static inline struct import_edge * FORCE_INLINE
edge_from_freelist (void)
{
#if DEVEL
  assert (edge_freelist);
#endif
  struct import_edge *e = edge_freelist;
  edge_freelist = edge_freelist->next;
#if DEVEL
  e->next = (void *)(uintptr_t)-1;
#endif
  return e;
}

/* Return edge_freelist, and set it to NULL.  */
static inline struct import_edge * FORCE_INLINE
first_edge_from_freelist (void)
{
#if DEVEL
  assert (edge_freelist);
#endif
  struct import_edge *e = edge_freelist;
#if DEVEL
  edge_freelist = NULL;
#endif
  return e;
}

/* Set edge_freelist to TAIL->next and return HEAD.  Assume HEAD was returned
   by first_edge_from_freelist, and TAIL is reachable from HEAD.  */
static inline struct import_edge * FORCE_INLINE
last_edge_from_freelist (struct import_edge *head, struct import_edge *tail)
{
#if DEVEL
  assert (!edge_freelist);
  if (verify_edge_freelist)
    {
      struct import_edge *e;
      for (e = head; e; e = e->next)
	{
	  if (e == tail)
	    break;
	}
      assert (e != NULL);
    }
#endif
  edge_freelist = tail->next;
  tail->next = NULL;
  return head;
}

/* Remove edges in linked list EP that refer to CUS, which
   is an array of CUCOUNT CUs/PUs.  If ADD is true, additionally
   add a new edge at the end of the linked list and return it.  */
static struct import_edge *
remove_import_edges (struct import_edge **ep, struct import_edge **ep_tail,
		     struct import_cu **cus, unsigned int cucount, bool add)
{
  unsigned int i = 0;
  struct import_edge *e, *efirst = NULL, *prev = NULL;
  while (*ep)
    if (i < cucount && (*ep)->icu == cus[i])
      {
	e = *ep;
	*ep = e->next;
	if (efirst == NULL)
	  efirst = e;
	else
	  free_edge (e);
	i++;
	if (ep_tail && *ep_tail == e)
	  *ep_tail = prev;
	if (i == cucount && !add)
	  return NULL;
      }
    else
      {
	if (ep_tail)
	  prev = *ep;
	ep = &(*ep)->next;
      }
  assert (i == cucount);
  *ep = efirst;
  efirst->next = NULL;
  if (ep_tail)
    *ep_tail = efirst;
  return efirst;
}

static void
dump_edges_1 (struct import_cu *ipu)
{
  fprintf (stderr, "idx: %u\n", ipu->idx);
  fprintf (stderr, "cu: 0x%x\n", ipu->cu->cu_offset);
  struct import_edge *e1;
  for (e1 = ipu->incoming; e1; e1 = e1->next)
    fprintf (stderr, "incoming: %u\n", e1->icu->idx);
  for (e1 = ipu->outgoing; e1; e1 = e1->next)
    fprintf (stderr, "outgoing: %u\n", e1->icu->idx);
}

static void
dump_edges (const char *msg, struct import_cu **ipus, unsigned int npus,
	    unsigned int ncus)
{
  struct import_cu *ipu;
  unsigned int i;
  fprintf (stderr, "PRINT_EDGES: %s\n", msg);
  fprintf (stderr, "PUs\n");
  for (ipu = ipus[0]; ipu; ipu = ipu->next)
    dump_edges_1 (ipu);
  fprintf (stderr, "CUs\n");
  for (i = 0; i < ncus; i++)
    dump_edges_1 (ipus[i + npus]);
}

/* Enumerate the different kinds of nodes in the import_cu/import_edge
   graph.  */
enum node_kind { NODE_CU, NODE_PU_INITIAL, NODE_PU_NEW };

/* Return the node kind for node IDX, given that:
   - [0, NPUS - 1] are initial PUs,
   - [NPUS, NPUS + NCUS - 1] are CUs, and
   - [NPUS + NCUS, ] are new PUs.  */
static enum node_kind
get_node_kind (unsigned int idx, unsigned int npus, unsigned int ncus)
{
  if (idx < npus)
    return NODE_PU_INITIAL;
  if (idx < npus + ncus)
    return NODE_CU;
  return NODE_PU_NEW;
}

/* Verify an edge from SRC to DEST during create_import_tree phase PHASE.  */
static void
verify_edge (enum node_kind src, enum node_kind dest, unsigned int phase)
{
  if (phase == 1)
    {
      assert (src == NODE_CU && dest == NODE_PU_INITIAL);
      return;
    }

  assert (IMPLIES (src == NODE_CU, dest != NODE_CU));

  if (phase == 2)
    {
      assert (IMPLIES (src == NODE_PU_NEW, dest == NODE_PU_INITIAL));
      assert (src != NODE_PU_INITIAL);
    }
  else
    assert (IMPLIES (src == NODE_PU_NEW, dest != NODE_CU));
}

/* Helper function for debugging create_import_tree.  Verify
   various invariants for CU/PU IPU.  */
static void
verify_edges_1 (struct import_cu *ipu, unsigned int *ic, unsigned int *oc,
		enum node_kind kind, unsigned int npus, unsigned int ncus,
		unsigned int phase)
{
  struct import_edge *e1, *e2;
  unsigned int last_idx, count;
  enum node_kind kind2;

  for (last_idx = 0, count = 0, e1 = ipu->incoming;
       e1;
       last_idx = e1->icu->idx, count++, e1 = e1->next)
    {
      /* Verify that incoming edges are in ascending idx order.  */
      assert (count == 0 || e1->icu->idx > last_idx);

      /* Verify that each incoming edge has a corresponding outgoing edge.  */
      for (e2 = e1->icu->outgoing; e2; e2 = e2->next)
	if (e2->icu == ipu)
	  break;
      assert (e2);

      kind2 = get_node_kind (e1->icu->idx, npus, ncus);
      verify_edge (kind2, kind, phase);

      if (count == ipu->incoming_count - 1)
	assert (ipu->incoming_tail == e1);
    }

  /* Verify the number of incoming edges.  */
  assert (ipu->incoming_count == count);

  for (last_idx = 0, count = 0, e1 = ipu->outgoing;
       e1;
       last_idx = e1->icu->idx, count++, e1 = e1->next)
    {
      /* Verify that outgoing edges are in ascending idx order.  */
      assert (count == 0 || e1->icu->idx > last_idx);

      /* Verify that each outgoing edge has a corresponding incoming edge.  */
      for (e2 = e1->icu->incoming; e2; e2 = e2->next)
	if (e2->icu == ipu)
	  break;
      assert (e2);

      kind2 = get_node_kind (e1->icu->idx, npus, ncus);
      verify_edge (kind, kind2, phase);
    }

  /* Verify the number of outgoing edges.  */
  assert (ipu->outgoing_count == count);

  *ic += ipu->incoming_count;
  *oc += ipu->outgoing_count;
}

/* Helper function for debugging create_import_tree.  Call verify_edges_1
   on all CUs and PUs.  */
static void
verify_edges (struct import_cu **ipus, unsigned int npus, unsigned int ncus,
	      unsigned int phase)
{
  struct import_cu *ipu;
  unsigned int i, ic, oc;

  ic = 0;
  oc = 0;

  /* Verify initial PUs.  */
  ipu = NULL;
  for (i = 0; i < npus; ++i)
    {
      ipu = ipus[i];
      assert (ipu->cu != NULL);
      if (i < npus - 1)
	assert (ipu->next == ipus[i + 1]);
      assert (ipu->incoming != NULL);
      if (phase <= 2)
	assert (ipu->outgoing == NULL);
      verify_edges_1 (ipu, &ic, &oc, NODE_PU_INITIAL, npus, ncus, phase);
    }

  /* Verify new PUs.  */
  assert (ipu != NULL);
  for (ipu = ipu->next; ipu; ipu = ipu->next)
    {
      assert (phase != 1);
      assert (ipu->cu == NULL);
      assert (ipu->incoming != NULL);
      assert (ipu->outgoing != NULL);
      verify_edges_1 (ipu, &ic, &oc, NODE_PU_NEW, npus, ncus, phase);
    }

  /* Verify CUs.  */
  for (i = 0; i < ncus; i++)
    {
      ipu = ipus[npus + i];
      assert (ipu->cu != NULL);
      assert (ipu->next == NULL);
      assert (ipu->incoming == NULL);
      assert (ipu->outgoing != NULL);
      verify_edges_1 (ipu, &ic, &oc, NODE_CU, npus, ncus, phase);
    }

  /* Verify that the overall number of incoming and outgoing edges is
     equal.  */
  assert (ic == oc);
}

#define BITVECTOR_TYPE unsigned int

/* Return a bitvector containing NBITS bits.  */
static inline BITVECTOR_TYPE *
bitvector_alloc (unsigned nbits)
{
  size_t nbytes = (nbits / 8) + 1;
  size_t size = nbytes + sizeof (BITVECTOR_TYPE);
  BITVECTOR_TYPE *res = (BITVECTOR_TYPE *)malloc (size);
  if (res == NULL)
    dwz_oom ();
  memset (res, 0, size);
  return res;
}

/* Set bit IDX in bitvector VECTOR.  */
static inline void FORCE_INLINE
bitvector_set_bit (BITVECTOR_TYPE *vector, unsigned idx)
{
  unsigned div = idx / (sizeof (BITVECTOR_TYPE) * 8);
  unsigned mod = idx % (sizeof (BITVECTOR_TYPE) * 8);
  vector[div] |= (1U << mod);
}

/* Test bit IDX in bitvector VECTOR.  */
static inline bool FORCE_INLINE
bitvector_bit_p (BITVECTOR_TYPE *vector, unsigned idx)
{
  unsigned div = idx / (sizeof (BITVECTOR_TYPE) * 8);
  unsigned mod = idx % (sizeof (BITVECTOR_TYPE) * 8);
  return (vector[div] & (1U << mod)) != 0;
}

/* Clear at least bits [A, B] in VECTOR, possibly more.  */
static inline void FORCE_INLINE
bitvector_clear_bits (BITVECTOR_TYPE *vector, unsigned int a, unsigned int b)
{
  unsigned int range_min = a / (sizeof (BITVECTOR_TYPE) * 8);
  unsigned int range_max = b / (sizeof (BITVECTOR_TYPE) * 8);
  memset (&vector[range_min], 0,
	  (range_max - range_min + 1) * sizeof (BITVECTOR_TYPE));
}

/* Function to optimize the size of DW_TAG_imported_unit DIEs by
   creating an inclusion tree, instead of each CU importing all
   PUs it needs directly, by optionally creating new PUs or
   adding DW_TAG_imported_unit to the already created PUs.
   At the end this function constructs any new PUs needed, and
   adds DW_TAG_imported_unit DIEs to them as well as the CUs
   and partition_dups created PUs.  */
static int
create_import_tree (void)
{
  dw_cu_ref pu, cu, last_partial_cu = NULL;
  unsigned int i, new_pu_version = 2, min_cu_version, npus, ncus;
  struct import_cu **ipus, *ipu, *icu;
  unsigned int cu_off;
  unsigned int puidx;
  struct import_cu *last_pu, *pu_freelist = NULL;
  unsigned char *to_free;

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "create_import_tree phase 1\n");
    }

  /* size doesn't count anything already created before this
     function (partial units etc.) or already preexisting, just
     initially the cumulative sizes of DW_TAG_imported_unit DIEs
     that would need to be added, and if some new DW_TAG_partial_unit
     CUs are going to be created as a result of this routine, that size
     too.  DW_TAG_imported_unit has size 5 (for DWARF3+) or 1 + ptr_size
     (DWARF2), DW_TAG_partial_unit has size 13/14 (11 CU header + 1 byte
     abbrev number + 1 byte child end + 1 byte for DWARF5 unit_type).  */
  unsigned int size = 0;
  /* Size of DW_TAG_imported_unit if the same everywhere, otherwise
     (mixing DWARF2 and DWARF3+ with ptr_size != 4) 0.  */
  unsigned int edge_cost = 0;
  /* Number of bytes needed for outgoing edges of PUs created by
     this function (which all have DWARF version new_pu_version).  */
  unsigned int new_edge_cost;

  /* If no PUs were created, there is nothing to do here.  */
  if (first_cu == NULL || (fi_multifile ? alt_first_cu == NULL
			   : first_cu->cu_kind != CU_PU))
    return 0;

  edge_freelist = NULL;
  to_free = obstack_alloc (&ob2, 1);
  min_cu_version = first_cu->cu_version;
  /* First construct a bipartite graph between CUs and PUs.  */
  for (pu = fi_multifile ? alt_first_cu : first_cu, npus = 0;
       pu && pu->cu_kind != CU_NORMAL; pu = pu->cu_next)
    {
      dw_die_ref die, rdie;
      dw_cu_ref prev_cu;

      if (pu->cu_die->die_tag == DW_TAG_compile_unit)
	continue;

      last_partial_cu = pu;
      for (rdie = pu->cu_die->die_child;
	   rdie->die_named_namespace; rdie = rdie->die_child)
	;
      if (unlikely (fi_multifile) && rdie->die_nextdup == NULL)
	{
	  pu->u1.cu_icu = NULL;
	  continue;
	}
      npus++;
      if (pu->cu_version > new_pu_version)
	new_pu_version = pu->cu_version;
      if (pu->cu_version < min_cu_version)
	min_cu_version = pu->cu_version;
      ipu = (struct import_cu *) obstack_alloc (&ob2, sizeof (*ipu));
      memset (ipu, 0, sizeof (*ipu));
      ipu->cu = pu;
      pu->u1.cu_icu = ipu;
      assert (rdie->die_toplevel);
      dw_die_ref firstdie = NULL;
      dw_cu_ref firstdiecu = NULL;
      for (die = rdie->die_nextdup, prev_cu = NULL;
	   die; die = die->die_nextdup)
	{
	  dw_cu_ref diecu = die_cu (die);
	  if (firstdie == NULL)
	    {
	      firstdie = die;
	      firstdiecu = die_cu (firstdie);
	    }
	  if (diecu == prev_cu || (die != firstdie && diecu == firstdiecu))
	    continue;
	  ipu->incoming_count++;
	  size += 1 + (diecu->cu_version == 2 ? ptr_size : 4);
	  prev_cu = diecu;
	}
      ipu->incoming = (struct import_edge *)
		       obstack_alloc (&ob2,
				      ipu->incoming_count
				      * sizeof (*ipu->incoming));
      firstdie = NULL;
      firstdiecu = NULL;
      for (die = rdie->die_nextdup, i = 0, prev_cu = NULL;
	   die; die = die->die_nextdup)
	{
	  dw_cu_ref diecu = die_cu (die);
	  if (firstdie == NULL)
	    {
	      firstdie = die;
	      firstdiecu = die_cu (firstdie);
	    }
	  if (diecu == prev_cu || (die != firstdie && diecu == firstdiecu))
	    continue;
	  icu = diecu->u1.cu_icu;
	  if (icu == NULL)
	    {
	      icu = (struct import_cu *)
		    obstack_alloc (&ob2, sizeof (*ipu));
	      memset (icu, 0, sizeof (*icu));
	      icu->cu = diecu;
	      diecu->u1.cu_icu = icu;
	    }
	  ipu->incoming[i++].icu = icu;
	  icu->outgoing_count++;
	  prev_cu = diecu;
	}
      ipu->incoming_tail = &ipu->incoming[ipu->incoming_count - 1];
    }
  if (npus == 0)
    {
      obstack_free (&ob2, to_free);
      return 0;
    }
  for (cu = fi_multifile ? first_cu : pu, ncus = 0; cu; cu = cu->cu_next)
    if (cu->u1.cu_icu)
      {
	ncus++;
	if (cu->cu_version > new_pu_version)
	  new_pu_version = cu->cu_version;
	if (cu->cu_version < min_cu_version)
	  min_cu_version = cu->cu_version;
	cu->u1.cu_icu->outgoing
	  = (struct import_edge *)
	    obstack_alloc (&ob2,
			   cu->u1.cu_icu->outgoing_count
			   * sizeof (*cu->u1.cu_icu->outgoing));
	cu->u1.cu_icu->outgoing_count = 0;
      }
  if (ptr_size == 4 || min_cu_version > 2)
    edge_cost = 5;
  else if (new_pu_version == 2)
    edge_cost = 1 + ptr_size;
  new_edge_cost = new_pu_version == 2 ? 1 + ptr_size : 5;
  for (pu = fi_multifile ? alt_first_cu : first_cu;
       pu && pu->cu_kind != CU_NORMAL; pu = pu->cu_next)
    {
      ipu = pu->u1.cu_icu;
      if (ipu == NULL)
	continue;
      for (i = 0; i < ipu->incoming_count; i++)
	{
	  icu = ipu->incoming[i].icu;
	  icu->outgoing[icu->outgoing_count++].icu = ipu;
	}
    }
  ipus = (struct import_cu **)
	 obstack_alloc (&ob2, (npus + ncus) * sizeof (*ipus));
  for (pu = fi_multifile ? alt_first_cu : first_cu, npus = 0;
       pu && pu->cu_kind != CU_NORMAL; pu = pu->cu_next)
    {
      ipu = pu->u1.cu_icu;
      if (ipu == NULL)
	continue;
      qsort (ipu->incoming, ipu->incoming_count, sizeof (*ipu->incoming),
	     import_edge_cmp);
      for (i = 0; i < ipu->incoming_count; i++)
	{
	  ipu->incoming[i].next
	    = i != ipu->incoming_count - 1 ? &ipu->incoming[i + 1] : NULL;
	}
      ipus[npus++] = ipu;
    }
  for (cu = fi_multifile ? first_cu : pu, ncus = 0; cu; cu = cu->cu_next)
    if (cu->u1.cu_icu)
      {
	icu = cu->u1.cu_icu;
	qsort (icu->outgoing, icu->outgoing_count, sizeof (*icu->outgoing),
	       import_edge_cmp);
	for (i = 0; i < icu->outgoing_count - 1; i++)
	  icu->outgoing[i].next = &icu->outgoing[i + 1];
	icu->outgoing[i].next = NULL;
	ipus[npus + ncus] = icu;
	ncus++;
      }
  qsort (ipus, npus, sizeof (*ipus), import_cu_cmp);
  qsort (ipus + npus, ncus, sizeof (*ipus), import_cu_cmp);
  for (puidx = 0; puidx < npus; puidx++)
    {
      ipus[puidx]->idx = puidx;
      if (puidx + 1 < npus)
	ipus[puidx]->next = ipus[puidx + 1];
    }
  for (; puidx < npus + ncus; puidx++)
    ipus[puidx]->idx = puidx;
  last_pu = ipus[npus - 1];
  if (unlikely (dump_edges_p))
    dump_edges ("phase 1", ipus, npus, ncus);
  if (unlikely (verify_edges_p))
    verify_edges (ipus, npus, ncus, 1);
  if (!import_opt_p)
    goto opt_done;
  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "create_import_tree phase 2\n");
    }
  /* Now, for the above constructed bipartite graph, find K x,2 components
     where x >= 5 (for DWARF3 and above or ptr_size 4, for DWARF2 and
     ptr_size 8 it can be even x == 4) and add a new PU node, where all
     CUs from the component will point to the new PU node and that new PU
     will point to all the destination PUs.  In theory with DWARF2
     and ptr_size 1 we could need x >= 9.

     The example below demonstrates the type of transformation.  The
     transformation is an optimization if the benefit of reducing the number
     of imports (in other words, edges) is bigger than the cost of adding an
     extra PU.  OTOH, the transformation can be done in the presence of
     additional incoming edges for PU_3 and PU_4.

     Before:                    After:

     CU_1---------->PU_3        CU_1                PU_3
         \          ^  ^            \               ^
          \        /  /              \             /
           \      /  /                \           /
            x----o  /                  \         /
           / \     /                    \       /
          /   \   /                      \     /
         /     \ /                        v   /
     CU_2       x               CU_2----->PU_5
         \     / \                        ^   \
          \   /   \                      /     \
           \ /     \                    /       \
            x----o  \                  /         \
           /      \  \                /           \
          /        \  \              /             \
         /          v  v            /               v
     CU_3---------->PU_4        CU_3                PU_4
  */
  for (i = 0; i < npus - 1; i++)
    {
      struct import_cu *pudst[2], *pusrc[10];
      struct import_edge *e1, *e2, *e3, *e4;
      struct import_edge *e1next, *e2next, *e3next;
      pudst[0] = ipus[i];
      for (e1 = pudst[0]->incoming; e1; e1 = e1next)
	{
	  e1next = e1->next;
	  if (e1->icu->cu == NULL)
	    break;
	  for (e2 = e1->icu->outgoing; e2; e2 = e2next)
	    {
	      unsigned int srccount, dstcount, cost;
	      struct import_cu *npu = NULL;
	      struct import_edge **ep = NULL;

	      e2next = e2->next;
	      if (e2->icu->idx <= pudst[0]->idx)
		continue;
	      if (e2->icu->cu == NULL)
		break;

	      pudst[1] = e2->icu;
	      pusrc[0] = e1->icu;
	      srccount = 1;
	      cost = edge_cost;
	      if (!edge_cost)
		cost = pusrc[0]->cu->cu_version == 2 ? 1 + ptr_size : 5;
	      for (e3 = e1next; e3; e3 = e3next)
		{
		  e3next = e3->next;
		  if (e3->icu->cu == NULL)
		    break;
		  dstcount = 0;
		  for (e4 = e3->icu->outgoing; e4; e4 = e4->next)
		    {
		      if (e4->icu == pudst[0])
			dstcount++;
		      else if (e4->icu == pudst[1])
			{
			  dstcount++;
			  break;
			}
		      else if (e4->icu->idx > pudst[1]->idx)
			break;
		    }
		  if (dstcount != 2)
		    continue;
		  if (npu == NULL)
		    {
		      unsigned int header_size;
		      pusrc[srccount] = e3->icu;
		      header_size = (pusrc[srccount]->cu->cu_version >= 5
				     ? 14 : 13); /* DWARF5 unit_type byte.  */
		      cost += edge_cost;
		      if (!edge_cost)
			cost += pusrc[srccount]->cu->cu_version == 2
				? 1 + ptr_size : 5;
		      srccount++;
		      if (ignore_size || ((dstcount - 1) * cost
					  > (header_size
					     + dstcount * new_edge_cost)))
			{
			  unsigned int j;

			  e2next = NULL;
			  if (pu_freelist)
			    {
			      npu = pu_freelist;
			      pu_freelist = pu_freelist->next;
			    }
			  else
			    npu = (struct import_cu *)
				  obstack_alloc (&ob2, sizeof (*npu));
			  memset (npu, 0, sizeof (*npu));
			  npu->incoming_count = srccount;
			  npu->outgoing_count = dstcount;
			  npu->idx = puidx++;
			  last_pu->next = npu;
			  last_pu = npu;
			  for (j = 0; j < srccount; j++)
			    {
			      if (e1next && e1next->icu == pusrc[j])
				e1next = e1next->next;
			      remove_import_edges (&pusrc[j]->outgoing, NULL,
						   pudst, dstcount, true)->icu
				= npu;
			      pusrc[j]->outgoing_count -= dstcount - 1;
			    }
			  for (j = 0; j < dstcount; j++)
			    {
			      remove_import_edges (&pudst[j]->incoming,
						   &pudst[j]->incoming_tail,
						   pusrc, srccount, true)->icu
				= npu;
			      pudst[j]->incoming_count -= srccount - 1;
			    }
			  npu->incoming = first_edge_from_freelist ();
			  for (j = 0, e4 = npu->incoming; j < srccount; j++)
			    {
			      e4->icu = pusrc[j];
			      if (j == srccount - 1)
				{
				  npu->incoming
				    = last_edge_from_freelist (npu->incoming,
							       e4);
				  npu->incoming_tail = e4;
				  ep = &e4->next;
				}
			      else
				e4 = e4->next;
			    }
			  npu->outgoing = first_edge_from_freelist ();
			  for (j = 0, e4 = npu->outgoing; j < dstcount; j++)
			    {
			      e4->icu = pudst[j];
			      if (j == dstcount - 1)
				npu->outgoing
				  = last_edge_from_freelist (npu->outgoing, e4);
			      else
				e4 = e4->next;
			    }
			  size -= (dstcount - 1) * cost;
			  size += 13 + dstcount * new_edge_cost;
			}
		    }
		  else
		    {
		      unsigned int j;

		      pusrc[srccount] = e3->icu;
		      cost = edge_cost;
		      if (!edge_cost)
			cost = pusrc[srccount]->cu->cu_version == 2
			       ? 1 + ptr_size : 5;
		      if (e1next && e1next->icu == pusrc[srccount])
			e1next = e1next->next;
		      remove_import_edges (&pusrc[srccount]->outgoing, NULL,
					   pudst, dstcount, true)->icu = npu;
		      pusrc[srccount]->outgoing_count -= dstcount - 1;
		      for (j = 0; j < dstcount; j++)
			{
			  remove_import_edges (&pudst[j]->incoming,
					       &pudst[j]->incoming_tail,
					       pusrc + srccount, 1, false);
			  pudst[j]->incoming_count--;
			}
		      *ep = edge_from_freelist ();
		      npu->incoming_count++;
		      (*ep)->icu = pusrc[srccount];
		      (*ep)->next = NULL;
		      npu->incoming_tail = *ep;
		      ep = &(*ep)->next;
		      size -= (dstcount - 1) * cost;
		    }
		}
	    }
	}
    }
  if (unlikely (dump_edges_p))
    dump_edges ("phase 2", ipus, npus, ncus);
  if (unlikely (verify_edges_p))
    verify_edges (ipus, npus, ncus, 2);
  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "create_import_tree phase 3\n");
    }
  /* Try to merge PUs which have the same set of referrers if
     beneficial.

     The example below demonstrates the type of transformation.  The
     transformation is an optimization because it reduces the number of import
     statements (in other words, edges) as well as the number of PUs.  It can
     however not be done if PU_3 or PU_4 have additional incoming edges.

     Before:               After:

     CU_1----->PU_3        CU_1
         \     ^               \
          \   /                 \
           \ /                   v
            x                    PU_3_4
           / \                   ^
          /   \                 /
         /     v               /
     CU_2----->PU_4        CU_2

     Or, if one PU has a subset of referrers of the other, attempt to replace
     all the incoming edges from the referrers intersection to the PU with
     larger number of incoming edges by an edge from the other PU.

     The example below demonstrates the type of transformation.  The
     transformation is an optimization because it reduces the number of import
     statements (in other words, edges).  It can however not be done if PU_3
     has additional incoming edges.

     Before:               After:

     CU_1----->PU_3        CU_1------>PU_3
         \     ^                      ^  |
          \   /                      /   |
           \ /                      /    |
            x                      /     |
           / \                    /      |
          /   \                  /       |
         /     \                /        |
     CU_2       \           CU_2         o
         \       \                       |
          \       o                      |
           \      |                      |
            \     |                      |
             \    |                      |
              \   |                      |
               v  v                      v
     CU_3----->PU_4        CU_3------>PU_4
  */
  /* Flag used during PU merging, set for PUs already considered
     for merging for the given first PU.  */
  BITVECTOR_TYPE *seen = bitvector_alloc (puidx);
  unsigned int min_seen = UINT_MAX;
  unsigned int max_seen = 0;
  for (ipu = ipus[0]; ipu; ipu = ipu->next)
    {
      struct import_edge *e1, *e2, *e3, *e4, **e1p, **ep, *prev;
      for (e1p = &ipu->incoming, e1 = *e1p;
	   e1; e1 = *e1p != e1 ? *e1p : (e1p = &e1->next, e1->next))
	{
	  for (e2 = e1->icu->outgoing; e2; e2 = e2->next)
	    {
	      unsigned int size_inc, size_dec;
	      struct import_cu *ipu2 = e2->icu, *ipusub, *ipusup;
	      /* True if IPU's src set might be a subset
		 of IPU2's src set.  */
	      bool maybe_subset;
	      /* True if IPU's src set might be a superset
		 of IPU2's src set.  */
	      bool maybe_superset;
	      unsigned int intersection;

	      if (ipu2->idx <= ipu->idx || bitvector_bit_p (seen, ipu2->idx))
		continue;
	      bitvector_set_bit (seen, ipu2->idx);
	      min_seen = MIN (min_seen, ipu2->idx);
	      max_seen = MAX (max_seen, ipu2->idx);
	      maybe_subset = (e1 == ipu->incoming
			      && ipu->incoming_count <= ipu2->incoming_count);
	      maybe_superset = ipu->incoming_count >= ipu2->incoming_count;
	      if (maybe_superset)
		{
		  /* If the referrer nodes of ipu are a superset of the
		     referrer nodes of ipu2, then ipu's last referrer node
		     should have index larger or equal to the last referrer
		     node of ipu2.  */
		  maybe_superset
		    = (ipu->incoming_tail->icu->idx
		       >= ipu2->incoming_tail->icu->idx);
		}
	      if (maybe_subset)
		{
		  /* If the referrer nodes of ipu are a subset of the
		     referrer nodes of ipu2, then ipu's last referrer node
		     should have index smaller or equal to the last referrer
		     node of ipu2.  */
		  maybe_subset
		    = (ipu->incoming_tail->icu->idx
		       <= ipu2->incoming_tail->icu->idx);
		}
	      e3 = e1;
	      e4 = ipu2->incoming;
	      intersection = 0;
	      while ((maybe_subset || maybe_superset) && e3 && e4)
		{
		  if (e3->icu == e4->icu)
		    {
		      intersection++;
		      e3 = e3->next;
		      e4 = e4->next;
		      continue;
		    }
		  if (e3->icu->idx < e4->icu->idx)
		    {
		      maybe_subset = false;
		      e3 = e3->next;
		      continue;
		    }
		  maybe_superset = false;
		  e4 = e4->next;
		}
	      if (e3)
		maybe_subset = false;
	      if (e4)
		maybe_superset = false;
	      if ((!maybe_superset && !maybe_subset) || intersection < 2)
		continue;
	      if (maybe_superset && maybe_subset)
		{
		  if (unlikely (fi_multifile) && ipu2->idx < npus + ncus)
		    continue;
		  if (odr_active_p && odr_mode != ODR_BASIC
		      && ipu2->idx < npus + ncus)
		    continue;
		  /* If IPU and IPU2 have the same set of src nodes, then
		     (if beneficial, with edge_cost != 0 always), merge
		     IPU2 node into IPU, by removing all incoming edges
		     of IPU2 and moving over all outgoing edges of IPU2
		     to IPU.  */
		  assert (ipu2->idx >= npus + ncus);
		  size_inc = 0;
		  if (edge_cost)
		    size_dec = 13 + ipu2->incoming_count * edge_cost;
		  else
		    {
		      size_dec = 13;
		      if (ipu->cu && ipu->cu->cu_version == 2)
			{
			  if (ptr_size > 4)
			    size_inc = ipu2->outgoing_count * (ptr_size - 4);
			  else
			    size_dec += ipu2->outgoing_count * (4 - ptr_size);
			}
		      for (e4 = ipu2->incoming; e4; e4 = e4->next)
			size_dec += (e4->icu->cu
				     && e4->icu->cu->cu_version == 2)
				    ? 1 + ptr_size : 5;
		    }
		  if (!ignore_size || size_dec > size_inc)
		    {
		      struct import_cu **ipup;
		      for (e4 = ipu2->incoming, e3 = NULL; e4; e4 = e4->next)
			{
			  remove_import_edges (&e4->icu->outgoing, NULL, &ipu2,
					       1, false);
			  e4->icu->outgoing_count--;
			  prepare_free_edge (e4);
			  e3 = e4;
			}
		      free_edges (ipu2->incoming, e3);
		      for (e4 = ipu2->outgoing; e4; e4 = e4->next)
			{
			  for (ep = &e4->icu->incoming; *ep; ep = &(*ep)->next)
			    if ((*ep)->icu->idx >= ipu->idx)
			      break;
			  assert ((*ep)->icu != ipu);
			  if ((*ep)->icu == ipu2)
			    (*ep)->icu = ipu;
			  else
			    {
			      struct import_edge **ep2;
			      for (ep2 = &(*ep)->next;
				   *ep2; ep2 = &(*ep2)->next)
				if ((*ep2)->icu == ipu2)
				  break;
			      e3 = *ep2;
			      *ep2 = e3->next;
			      e3->next = *ep;
			      *ep = e3;
			      e3->icu = ipu;
			      while (e4->icu->incoming_tail->next != NULL)
				e4->icu->incoming_tail
				  = e4->icu->incoming_tail->next;
			    }
			}
		      e3 = ipu->outgoing;
		      ep = &ipu->outgoing;
		      for (e4 = ipu2->outgoing; e3 && e4; )
			if (e3->icu->idx < e4->icu->idx)
			  {
			    *ep = e3;
			    ep = &e3->next;
			    e3 = e3->next;
			  }
			else
			  {
			    assert (e3->icu != e4->icu);
			    *ep = e4;
			    ep = &e4->next;
			    e4 = e4->next;
			  }
		      if (e3)
			*ep = e3;
		      else if (e4)
			*ep = e4;
		      else
			*ep = NULL;
		      ipu->outgoing_count += ipu2->outgoing_count;
		      size -= size_dec - size_inc;
		      if (ipu->idx >= npus + ncus)
			ipup = &ipu->next;
		      else
			ipup = &ipus[npus - 1]->next;
		      while (*ipup != ipu2)
			ipup = &(*ipup)->next;
		      *ipup = ipu2->next;
		      ipu2->next = pu_freelist;
		      pu_freelist = ipu2;
		      continue;
		    }
		}
	      if (maybe_superset)
		{
		  ipusup = ipu;
		  ipusub = ipu2;
		}
	      else
		{
		  ipusub = ipu;
		  ipusup = ipu2;
		}
	      /* If IPUSUB's src set is a subset of IPUSUP's src set
		 and intersection is at least 2, remove edges from
		 IPUSUB's src set to IPUSUP node and instead add
		 an edge from IPUSUB to IPUSUP.  */
	      size_inc = 0;
	      if (edge_cost)
		size_dec = (ipusub->incoming_count - 1) * edge_cost;
	      else
		{
		  size_inc = ipusub->cu && ipusub->cu->cu_version == 2
			     ? 1 + ptr_size : 5;
		  size_dec = 0;
		  for (e3 = ipusub->incoming; e3; e3 = e3->next)
		    size_dec += (e3->icu->cu
				 && e3->icu->cu->cu_version == 2)
				? 1 + ptr_size : 5;
		}
	      if (size_dec > size_inc
		  && (!fi_multifile || ipusub->idx >= npus + ncus))
		{
		  for (e3 = ipusub->incoming, ep = &ipusup->incoming,
			 prev = NULL;
		       e3; e3 = e3->next)
		    {
		      remove_import_edges (&e3->icu->outgoing, NULL, &ipusup, 1,
					   false);
		      e3->icu->outgoing_count--;
		      while ((*ep)->icu != e3->icu)
			{
			    prev = *ep;
			    ep = &(*ep)->next;
			}
		      e4 = *ep;
		      *ep = e4->next;
		      free_edge (e4);
		      if (ipusup->incoming_tail == e4)
			ipusup->incoming_tail  = prev;
		    }
		  for (ep = &ipusub->outgoing; *ep; ep = &(*ep)->next)
		    if ((*ep)->icu->idx >= ipusup->idx)
		      break;
		  assert (*ep == NULL || (*ep)->icu != ipusup);
		  e4 = edge_from_freelist ();
		  e4->icu = ipusup;
		  e4->next = *ep;
		  *ep = e4;
		  ipusub->outgoing_count++;
		  for (ep = &ipusup->incoming; *ep; ep = &(*ep)->next)
		    if ((*ep)->icu->idx >= ipusub->idx)
		      break;
		  assert (*ep == NULL || (*ep)->icu != ipusub);
		  e4 = edge_from_freelist ();
		  e4->icu = ipusub;
		  e4->next = *ep;
		  *ep = e4;
		  if (ipusup->incoming_tail->next == e4)
		    ipusup->incoming_tail = e4;
		  ipusup->incoming_count -= ipusub->incoming_count - 1;
		  size -= size_dec - size_inc;
		  if (ipusup == ipu)
		    break;
		}
	    }
	}
      if (min_seen <= max_seen)
	{
	  bitvector_clear_bits (seen, min_seen, max_seen);
	  min_seen = UINT_MAX;
	  max_seen = 0;
	}
    }
  free (seen);
  if (unlikely (dump_edges_p))
    dump_edges ("phase 3", ipus, npus, ncus);
  if (unlikely (verify_edges_p))
    verify_edges (ipus, npus, ncus, 3);
 opt_done:
  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "create_import_tree phase 4 (create partial units)\n");
    }
  /* Create DW_TAG_partial_unit (and containing dw_cu structures).  */
  if (fi_multifile)
    {
      cu_off = 0;
      last_partial_cu = NULL;
    }
  else
    cu_off = last_partial_cu->cu_offset + 1;
  for (ipu = ipus[npus - 1]->next; ipu; ipu = ipu->next)
    {
      dw_die_ref die;
      dw_cu_ref partial_cu = pool_alloc (dw_cu, sizeof (struct dw_cu));
      memset (partial_cu, '\0', sizeof (*partial_cu));
      partial_cu->cu_kind = CU_PU;
      partial_cu->cu_offset = cu_off++;
      partial_cu->cu_version = new_pu_version;
      partial_cu->u1.cu_icu = ipu;
      if (unlikely (last_partial_cu == NULL))
	{
	  partial_cu->cu_next = first_cu;
	  first_cu = partial_cu;
	}
      else
	{
	  partial_cu->cu_next = last_partial_cu->cu_next;
	  last_partial_cu->cu_next = partial_cu;
	}
      last_partial_cu = partial_cu;
      die = pool_alloc (dw_die, sizeof (struct dw_die));
      memset (die, '\0', sizeof (struct dw_die));
      die->die_toplevel = 1;
      partial_cu->cu_die = die;
      die->die_tag = DW_TAG_partial_unit;
      die->die_offset = -1U;
      die->die_root = 1;
      die->die_parent = (dw_die_ref) partial_cu;
      die->die_size = 1;
      ipu->cu = partial_cu;
    }
  /* Next add all needed DW_TAG_imported_unit DIEs.  */
  for (cu = first_cu; cu; cu = cu->cu_next)
    {
      struct import_edge *e;

      icu = cu->u1.cu_icu;
      if (icu == NULL)
	continue;
      for (e = icu->outgoing; e; e = e->next)
	{
	  dw_die_ref *diep;
	  dw_die_ref die = pool_alloc (dw_die, sizeof (struct dw_die));
	  memset (die, '\0', sizeof (*die));
	  die->die_toplevel = 1;
	  die->die_tag = DW_TAG_imported_unit;
	  die->die_offset = -1U;
	  die->die_nextdup = e->icu->cu->cu_die;
	  die->die_parent = cu->cu_die;
	  assert (e->icu->cu->cu_die->die_tag == DW_TAG_partial_unit);
	  die->die_size = (cu->cu_version == 2 ? 1 + ptr_size : 5);
	  /* Put the new DW_TAG_imported_unit DIE after all typed DWARF
	     stack referenced base types and after all previously added
	     new DW_TAG_imported_unit DIEs.  */
	  for (diep = &die->die_parent->die_child;
	       *diep; diep = &(*diep)->die_sib)
	    if (!(*diep)->die_op_type_referenced
		&& ((*diep)->die_tag != DW_TAG_imported_unit
		    || (*diep)->die_offset != -1U))
	      break;
	  die->die_sib = *diep;
	  *diep = die;
	}
    }
  for (cu = first_cu; cu; cu = cu->cu_next)
    cu->u1.cu_icu = NULL;
  if (unlikely (fi_multifile))
    for (cu = alt_first_cu; cu; cu = cu->cu_next)
      cu->u1.cu_icu = NULL;
  obstack_free (&ob2, to_free);
  return 0;
}

/* Helper function for die_find_dup, when ORIG has collapsed children.  */
static dw_die_ref
die_find_collapsed_dup (dw_die_ref die, unsigned int *tick)
{
  dw_die_ref child, ret;

  for (child = die->die_child; child; child = child->die_sib)
    if ((*tick)-- == 0)
      return child;
    else if (child->die_child == NULL)
      continue;
    else if ((ret = die_find_collapsed_dup (child, tick)) != NULL)
      return ret;
  (*tick)--;
  return NULL;
}

/* If DIE is equal to ORIG, return DUP, otherwise if DIE is
   a child of ORIG, return corresponding child in DUP's subtree,
   or return NULL.  */
static dw_die_ref
die_find_dup (dw_die_ref orig, dw_die_ref dup, dw_die_ref die)
{
  dw_die_ref orig_child, dup_child;
  if (orig == die)
    return dup;
  if (orig->die_collapsed_children)
    {
      dw_die_ref ret;
      unsigned int tick;
      if (die->die_collapsed_child)
	tick = die->die_tag - 1;
      else
	tick = die->die_ref_seen - 1;
      assert (dup->die_collapsed_children == 0
	      && die->die_parent == orig);
      ret = die_find_collapsed_dup (dup, &tick);
      assert (die->die_collapsed_child || ret->die_tag == die->die_tag);
      return ret;
    }
  for (orig_child = orig->die_child, dup_child = dup->die_child;
       orig_child;
       orig_child = orig_child->die_sib, dup_child = dup_child->die_sib)
    {
      dw_die_ref ret = die_find_dup (orig_child, dup_child, die);
      if (ret)
	return ret;
    }
  return NULL;
}

/* Return number of bytes needed to encode VAL using
   uleb128.  */
static unsigned int
size_of_uleb128 (uint64_t val)
{
  unsigned int size;
  for (size = 1; (val >>= 7) != 0; size++)
    ;
  return size;
}

/* Return number of bytes needed to encode VAL using
   sleb128.  */
static unsigned int
size_of_sleb128 (int64_t val)
{
  unsigned int size = 0;
  unsigned char c;
  do
    {
      c = val & 0x7f;
      val >>= 7;
      size++;
    }
  while ((val != 0 || (c & 0x40) != 0)
	 && (val != -1 || (c & 0x40) == 0));
  return size;
}

/* Hash table mapping original file IDs to new ids.  */
static htab_t line_htab;
/* Current new maximum file ID.  */
static unsigned int max_line_id;

struct line_entry
{
  /* File pointer.  */
  struct dw_file *file;
  /* Precomputed hash value.  */
  unsigned int hash;
  /* Corresponding new file ID.  */
  unsigned int new_id;
};
ALIGN_STRUCT (line_entry)

/* Hash function in line_htab.  */
static hashval_t
line_hash (const void *p)
{
  struct line_entry *s = (struct line_entry *)p;

  return s->hash;
}

/* Equality function in line_htab.  */
static int
line_eq (const void *p, const void *q)
{
  struct line_entry *s1 = (struct line_entry *)p;
  struct line_entry *s2 = (struct line_entry *)q;

  if (s1->hash != s2->hash)
    return 0;
  if (s1->file == s2->file)
    return 1;
  if (strcmp (s1->file->file, s2->file->file) != 0)
    return 0;
  if ((s1->file->dir == NULL) ^ (s2->file->dir == NULL))
    return 0;
  if (s1->file->dir && strcmp (s1->file->dir, s2->file->dir) != 0)
    return 0;
  return s1->file->time == s2->file->time && s1->file->size == s2->file->size;
}

/* Map original file ID to new file ID.  */
static unsigned int
line_htab_lookup (dw_cu_ref cu, unsigned int id)
{
  void **slot;
  struct line_entry le;
  hashval_t h;

  if (id == 0)
    return 0;
  assert (id <= cu->cu_nfiles);
  le.file = &cu->cu_files[id - 1];
  h = iterative_hash_object (le.file->time, 0);
  h = iterative_hash_object (le.file->size, h);
  h = iterative_hash (le.file->file, strlen (le.file->file) + 1, h);
  if (le.file->dir)
    h = iterative_hash (le.file->dir, strlen (le.file->dir) + 1, h);
  if (line_htab == NULL)
    {
      line_htab = htab_try_create (50, line_hash, line_eq, NULL);
      if (line_htab == NULL)
	dwz_oom ();
      max_line_id = 1;
    }
  le.hash = h;
  slot = htab_find_slot_with_hash (line_htab, &le, h, INSERT);
  if (slot == NULL)
    dwz_oom ();
  if (*slot == NULL)
    {
      struct line_entry *l = pool_alloc (line_entry, sizeof (*l));
      l->file = le.file;
      l->hash = h;
      l->new_id = max_line_id++;
      *slot = (void *) l;
      return l->new_id;
    }
  else
    return ((struct line_entry *) *slot)->new_id;
}

/* Hash table for finding duplicate .debug_macro opcode sequences.
   This hash table is used with two different sets of hash/equality
   callbacks.  One is used either within handle_macro function (from within
   optimize_multifile), or from handle_macro onwards (read_multifile).
   The second set is used from read_macro onwards during fi_multifile.  */
static htab_t macro_htab;

/* At the end of read_multifile macro_htab is copied to this variable.  */
static htab_t alt_macro_htab;

struct macro_entry
{
  /* Start of the sequence.  */
  unsigned char *ptr;
  /* Precomputed hash value.  LSB bit is used for a flag whether
     a particular .debug_macro sequence is seen more than once.  */
  unsigned int hash;
  /* And it's length or 0 if non-shareable.  */
  unsigned int len;
};
ALIGN_STRUCT (macro_entry)

/* Hash function in macro_htab.  */
static hashval_t
macro_hash (const void *p)
{
  struct macro_entry *m = (struct macro_entry *)p;

  return m->hash & ~1U;
}

/* Equality function in macro_htab.  */
static int
macro_eq (const void *p, const void *q)
{
  struct macro_entry *m1 = (struct macro_entry *)p;
  struct macro_entry *m2 = (struct macro_entry *)q;
  unsigned char *p1, *p2, *s1, op;
  unsigned int strp1, strp2;

  if (m1->hash != m2->hash || m1->len != m2->len)
    return 0;
  if (rd_multifile)
    return 0;

  s1 = m1->ptr;
  p2 = m2->ptr;
  p1 = s1 + 3;

  while (1)
    {
      op = read_8 (p1);
      if (op == 0)
	break;

      switch (op)
	{
	case DW_MACRO_define:
	case DW_MACRO_undef:
	  skip_leb128 (p1);
	  p1 = (unsigned char *) strchr ((char *) p1, '\0') + 1;
	  break;
	case DW_MACRO_define_strp:
	case DW_MACRO_undef_strp:
	  skip_leb128 (p1);
	  if (memcmp (s1, p2, p1 - s1) != 0)
	    return 0;
	  p2 += p1 - s1;
	  strp1 = read_32 (p1);
	  strp2 = read_32 (p2);
	  if (op_multifile)
	    {
	      if (strcmp ((char *) debug_sections[DEBUG_STR].data + strp1,
			  (char *) debug_sections[DEBUG_STR].data + strp2)
		  != 0)
		return 0;
	    }
	  else if (lookup_strp_offset (strp2) != strp1)
	    return 0;
	  s1 = p1;
	  break;
	default:
	  abort ();
	}
    }
  return memcmp (s1, p2, p1 - s1) == 0;
}

/* Hash function in macro_htab.  */
static hashval_t
macro_hash2 (const void *p)
{
  struct macro_entry *m = (struct macro_entry *)p;

  return m->ptr - debug_sections[DEBUG_MACRO].data;
}

/* Equality function in macro_htab.  */
static int
macro_eq2 (const void *p, const void *q)
{
  struct macro_entry *m1 = (struct macro_entry *)p;
  struct macro_entry *m2 = (struct macro_entry *)q;
  return m1->ptr == m2->ptr;
}

/* Parse .debug_macro section, either during write_multifile
   or during fi_multifile phase.  During write_multifile it
   selects potentially shareable .debug_macro sequences and
   writes them into debug_sections[DEBUG_MACRO].new_data
   block it allocates.  During fi_multifile it populates
   macro_htab.  In both cases it calls note_strp_offset
   on DW_FORM_strp offsets.  */
static int
read_macro (DSO *dso)
{
  unsigned char *ptr, *endsec, *dst = NULL;
  unsigned int version, flags, op, strp;
  struct macro_entry me, *m;

  ptr = debug_sections[DEBUG_MACRO].data;
  endsec = ptr + debug_sections[DEBUG_MACRO].size;
  debug_sections[DEBUG_MACRO].new_size = 0;
  if (!wr_multifile)
    {
      macro_htab = htab_try_create (50, macro_hash2, macro_eq2, NULL);
      if (macro_htab == NULL)
	dwz_oom ();
    }

  while (ptr < endsec)
    {
      unsigned char *start = ptr, *s = ptr;
      bool can_share = true;
      hashval_t hash = 0;
      unsigned int strp;
      void **slot;

      if (ptr + 4 > endsec)
	{
	  error (0, 0, "%s: .debug_macro header too small", dso->filename);
	  return 1;
	}

      version = read_16 (ptr);
      bool supported_version_p = version >= 4 && version <= 5;
      if (!supported_version_p)
	{
	  error (0, 0, "%s: Unhandled .debug_macro version %d", dso->filename,
		 version);
	  return 1;
	}
      flags = read_8 (ptr);
      if ((flags & ~2U) != 0)
	{
	  error (0, 0, "%s: Unhandled .debug_macro flags %d", dso->filename,
		 flags);
	  return 1;
	}
      if ((flags & 2) != 0)
	{
	  ptr += 4;
	  can_share = false;
	}
      if (fi_multifile && alt_macro_htab == NULL)
	can_share = false;

      op = -1U;
      while (ptr < endsec)
	{
	  op = read_8 (ptr);
	  if (op == 0)
	    break;

	  switch (op)
	    {
	    case DW_MACRO_define:
	    case DW_MACRO_undef:
	      skip_leb128 (ptr);
	      ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
	      break;
	    case DW_MACRO_start_file:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      can_share = false;
	      break;
	    case DW_MACRO_end_file:
	      can_share = false;
	      break;
	    case DW_MACRO_define_strp:
	    case DW_MACRO_undef_strp:
	      skip_leb128 (ptr);
	      strp = read_32 (ptr);
	      note_strp_offset (strp);
	      if (wr_multifile)
		break;
	      if (can_share)
		hash = iterative_hash (s, ptr - 4 - s, hash);
	      if (can_share)
		{
		  unsigned char *p = debug_sections[DEBUG_STR].data + strp;
		  unsigned int len = strlen ((char *) p);
		  hash = iterative_hash (p, len, hash);
		  s = ptr;
		}
	      break;
	    case DW_MACRO_import:
	      ptr += 4;
	      can_share = false;
	      break;
	    default:
	      error (0, 0, "%s: Unhandled .debug_macro opcode 0x%x",
		     dso->filename, op);
	      return 1;
	    }
	}
      if (op != 0)
	{
	  error (0, 0, "%s: .debug_macro section not zero terminated",
		 dso->filename);
	  return 1;
	}
      if (wr_multifile)
	{
	  if (can_share)
	    debug_sections[DEBUG_MACRO].new_size += ptr - start;
	  continue;
	}

      me.ptr = start;
      if (can_share)
	{
	  hash = iterative_hash (s, ptr - s, hash);
	  me.hash = hash & ~1U;
	  me.len = ptr - start;
	  m = (struct macro_entry *)
	      htab_find_with_hash (alt_macro_htab, &me, me.hash);
	  if (m == NULL)
	    can_share = false;
	  else
	    me.hash = m->ptr - alt_data[DEBUG_MACRO];
	}
      if (!can_share)
	{
	  me.len = 0;
	  me.hash = debug_sections[DEBUG_MACRO].new_size;
	  debug_sections[DEBUG_MACRO].new_size += ptr - start;
	}
      slot
	= htab_find_slot_with_hash (macro_htab, &me,
				    me.ptr - debug_sections[DEBUG_MACRO].data,
				    INSERT);
      if (slot == NULL)
	dwz_oom ();
      else
	{
	  assert (*slot == NULL);
	  m = pool_alloc (macro_entry, sizeof (*m));
	  *m = me;
	  *slot = (void *) m;
	}
    }

  if (!wr_multifile)
    return 0;

  debug_sections[DEBUG_MACRO].new_data
    = (unsigned char *) malloc (debug_sections[DEBUG_MACRO].new_size);
  if (debug_sections[DEBUG_MACRO].new_data == NULL)
    dwz_oom ();
  dst = debug_sections[DEBUG_MACRO].new_data;
  for (ptr = debug_sections[DEBUG_MACRO].data; ptr < endsec; )
    {
      unsigned char *start = ptr;
      bool can_share = true;

      ptr += 2;
      flags = read_8 (ptr);
      if ((flags & 2) != 0)
	{
	  ptr += 4;
	  can_share = false;
	}

      while (1)
	{
	  op = read_8 (ptr);
	  if (op == 0)
	    break;

	  switch (op)
	    {
	    case DW_MACRO_define:
	    case DW_MACRO_undef:
	      skip_leb128 (ptr);
	      ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
	      break;
	    case DW_MACRO_start_file:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      can_share = false;
	      break;
	    case DW_MACRO_end_file:
	      can_share = false;
	      break;
	    case DW_MACRO_define_strp:
	    case DW_MACRO_undef_strp:
	      skip_leb128 (ptr);
	      ptr += 4;
	      break;
	    case DW_MACRO_import:
	      ptr += 4;
	      can_share = false;
	      break;
	    default:
	      abort ();
	    }
	}
      if (can_share)
	{
	  ptr = start + 3;

	  while (1)
	    {
	      op = read_8 (ptr);
	      if (op == 0)
		break;

	      switch (op)
		{
		case DW_MACRO_define:
		case DW_MACRO_undef:
		  skip_leb128 (ptr);
		  ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
		  break;
		case DW_MACRO_define_strp:
		case DW_MACRO_undef_strp:
		  skip_leb128 (ptr);
		  memcpy (dst, start, ptr - start);
		  dst += ptr - start;
		  strp = lookup_strp_offset (read_32 (ptr));
		  write_32 (dst, strp);
		  start = ptr;
		  break;
		default:
		  abort ();
		}
	    }
	  memcpy (dst, start, ptr - start);
	  dst += ptr - start;
	}
    }
  assert (dst == debug_sections[DEBUG_MACRO].new_data
		 + debug_sections[DEBUG_MACRO].new_size);

  return 0;
}

/* Helper function for handle_macro, called through htab_traverse.
   Write .debug_macro opcode sequence seen by more than one
   executable or shared library.  */
static int
optimize_write_macro (void **slot, void *data)
{
  struct macro_entry *m = (struct macro_entry *) *slot;
  unsigned char **pp = (unsigned char **) data;
  unsigned char *s = m->ptr;
  unsigned char *p = s + 3, *q, op;
  unsigned int strp;

  if ((m->hash & 1) == 0)
    return 1;
  while (1)
    {
      op = read_8 (p);
      if (op == 0)
	break;

      switch (op)
	{
	case DW_MACRO_define:
	case DW_MACRO_undef:
	  skip_leb128 (p);
	  p = (unsigned char *) strchr ((char *) p, '\0') + 1;
	  break;
	case DW_MACRO_define_strp:
	case DW_MACRO_undef_strp:
	  skip_leb128 (p);
	  memcpy (*pp, s, p - s);
	  *pp += p - s;
	  strp = read_32 (p);
	  q = *pp;
	  write_32 (q, lookup_strp_offset (strp));
	  *pp += 4;
	  s = p;
	  break;
	default:
	  abort ();
	}
    }
  memcpy (*pp, s, p - s);
  *pp += p - s;
  return 1;
}

/* Parse .debug_macro section, during optimize_multifile
   or during read_multifile.  It parses .debug_macro written
   by write_multifile, so it only contains shareable sequences.
   Find duplicate sequences, during optimize_multifile write them
   into debug_sections[DEBUG_MACRO].new_data it allocates,
   during read_multifile just populates macro_htab (soon to be
   alt_macro_htab).  */
static void
handle_macro (void)
{
  unsigned char *ptr, *endsec, op;
  unsigned char *to_free = NULL;
  struct macro_entry me, *m;

  macro_htab = htab_try_create (50, macro_hash, macro_eq, NULL);
  if (macro_htab == NULL)
    dwz_oom ();

  endsec = debug_sections[DEBUG_MACRO].data + debug_sections[DEBUG_MACRO].size;
  if (op_multifile)
    {
      debug_sections[DEBUG_MACRO].new_size = 0;
      to_free = obstack_alloc (&ob, 1);
    }

  for (ptr = debug_sections[DEBUG_MACRO].data; ptr < endsec; )
    {
      unsigned char *start = ptr, *s = ptr, *p;
      hashval_t hash = 0;
      unsigned int len;
      void **slot;
      bool can_share = true;

      ptr += 3;
      while (1)
	{
	  op = read_8 (ptr);
	  if (op == 0)
	    break;

	  switch (op)
	    {
	    case DW_MACRO_define:
	    case DW_MACRO_undef:
	      skip_leb128 (ptr);
	      ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
	      break;
	    case DW_MACRO_define_strp:
	    case DW_MACRO_undef_strp:
	      skip_leb128 (ptr);
	      hash = iterative_hash (s, ptr - s, hash);
	      p = debug_sections[DEBUG_STR].data + read_32 (ptr);
	      len = strlen ((char *) p);
	      hash = iterative_hash (p, len, hash);
	      if (op_multifile
		  /* This should only happen if there were multiple
		     same transparent units within a single object file.  */
		  && htab_find_with_hash (strp_htab, p,
					  iterative_hash (p, len, 0)) == NULL)
		can_share = false;
	      s = ptr;
	      break;
	    default:
	      abort ();
	    }
	}
      if (!can_share)
	continue;
      hash = iterative_hash (s, ptr - s, hash);
      me.ptr = start;
      me.hash = hash & ~1U;
      me.len = ptr - start;
      slot = htab_find_slot_with_hash (macro_htab, &me, me.hash, INSERT);
      if (slot == NULL)
	dwz_oom ();
      else if (*slot != NULL)
	{
	  m = (struct macro_entry *) *slot;
	  if (op_multifile && (m->hash & 1) == 0)
	    {
	      m->hash |= 1;
	      debug_sections[DEBUG_MACRO].new_size += me.len;
	    }
	}
      else if (op_multifile)
	{
	  m = (struct macro_entry *) obstack_alloc (&ob, sizeof (*m));
	  *m = me;
	  *slot = (void *) m;
	}
      else
	{
	  m = pool_alloc (macro_entry, sizeof (*m));
	  *m = me;
	  *slot = (void *) m;
	}
    }

  if (op_multifile)
    {
      if (debug_sections[DEBUG_MACRO].new_size)
	{
	  unsigned char *p;
	  debug_sections[DEBUG_MACRO].new_data
	    = malloc (debug_sections[DEBUG_MACRO].new_size);
	  p = debug_sections[DEBUG_MACRO].new_data;
	  htab_traverse (macro_htab, optimize_write_macro, &p);
	  assert (p == debug_sections[DEBUG_MACRO].new_data
		       + debug_sections[DEBUG_MACRO].new_size);
	  htab_delete (macro_htab);
	  macro_htab = NULL;
	}
      obstack_free (&ob, (void *) to_free);
    }
}

/* Write new content of .debug_macro section during fi_multifile phase.  */
static void
write_macro (void)
{
  unsigned char *ptr, *endsec, *dst;
  unsigned int op, strp;
  struct macro_entry me, *m;

  endsec = debug_sections[DEBUG_MACRO].data + debug_sections[DEBUG_MACRO].size;
  debug_sections[DEBUG_MACRO].new_data
    = (unsigned char *) malloc (debug_sections[DEBUG_MACRO].new_size);
  if (debug_sections[DEBUG_MACRO].new_data == NULL)
    dwz_oom ();
  dst = debug_sections[DEBUG_MACRO].new_data;
  for (ptr = debug_sections[DEBUG_MACRO].data; ptr < endsec; )
    {
      unsigned char *s = ptr;
      unsigned char flags;

      me.ptr = ptr;
      m = (struct macro_entry *)
	  htab_find_with_hash (macro_htab, &me,
			       me.ptr - debug_sections[DEBUG_MACRO].data);
      if (m->len)
	{
	  ptr += m->len;
	  continue;
	}

      ptr += 2;
      flags = read_8 (ptr);
      if ((flags & 2) != 0)
	ptr += 4;

      while (1)
	{
	  op = read_8 (ptr);
	  if (op == 0)
	    break;

	  switch (op)
	    {
	    case DW_MACRO_define:
	    case DW_MACRO_undef:
	      skip_leb128 (ptr);
	      ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
	      break;
	    case DW_MACRO_start_file:
	      skip_leb128 (ptr);
	      skip_leb128 (ptr);
	      break;
	    case DW_MACRO_end_file:
	      break;
	    case DW_MACRO_define_strp:
	    case DW_MACRO_undef_strp:
	      memcpy (dst, s, ptr - 1 - s);
	      dst += ptr - 1 - s;
	      s = ptr - 1;
	      skip_leb128 (ptr);
	      strp = read_32 (ptr);
	      switch (note_strp_offset2 (strp))
		{
		case DW_FORM_GNU_strp_alt:
		case DW_FORM_strp_sup:
		  *dst = op == DW_MACRO_define_strp
			 ? DW_MACRO_define_sup
			 : DW_MACRO_undef_sup;
		  dst++;
		  s++;
		  break;
		default:
		  break;
		}
	      memcpy (dst, s, ptr - 4 - s);
	      dst += ptr - 4 - s;
	      write_32 (dst, lookup_strp_offset (strp));
	      s = ptr;
	      break;
	    case DW_MACRO_import:
	      memcpy (dst, s, ptr - 1 - s);
	      dst += ptr - 1 - s;
	      me.ptr = debug_sections[DEBUG_MACRO].data + read_32 (ptr);
	      m = (struct macro_entry *)
		  htab_find_with_hash (macro_htab, &me,
				       me.ptr
				       - debug_sections[DEBUG_MACRO].data);
	      if (m->len)
		*dst = DW_MACRO_import_sup;
	      else
		*dst = DW_MACRO_import;
	      dst++;
	      write_32 (dst, m->hash);
	      s = ptr;
	      break;
	    default:
	      abort ();
	    }
	}
      memcpy (dst, s, ptr - s);
      dst += ptr - s;
    }
  assert (dst == debug_sections[DEBUG_MACRO].new_data
		 + debug_sections[DEBUG_MACRO].new_size);
}

/* Compute new abbreviations for DIE (with reference DIE REF).
   T is a temporary buffer.  Fill in *NDIES - number of DIEs
   in the tree, and record pairs of referrer/referree DIEs for
   intra-CU references into obstack vector VEC.  */
static int
build_abbrevs_for_die (htab_t h, dw_cu_ref cu, dw_die_ref die,
		       dw_cu_ref refcu, dw_die_ref ref,
		       struct abbrev_tag *t, unsigned int *ndies,
		       struct obstack *vec, bool recompute)
{
  dw_die_ref child, ref_child, sib = NULL, origin = NULL;
  unsigned int i, j;
  uint64_t low_pc = 0;
  void **slot;

  if (unlikely (recompute) && die->u.p2.die_new_abbrev != NULL)
    {
      if (cu->cu_intracu_form == DW_FORM_ref_udata)
	die->die_ref_seen = 1;
      else
	{
	  die->die_size -= size_of_uleb128 (die->u.p2.die_new_abbrev->entry)
			   + die->u.p2.die_intracu_udata_size;
	  die->die_ref_seen = 0;
	}
      for (child = die->die_child; child; child = child->die_sib)
	if (build_abbrevs_for_die (h, cu, child, NULL, NULL, t, ndies, vec,
				   true))
	  return 1;
      return 0;
    }

  die->u.p2.die_new_abbrev = NULL;
  die->u.p2.die_new_offset = 0;
  die->u.p2.die_intracu_udata_size = 0;
  die->die_ref_seen = 0;

  if (wr_multifile ? die->die_no_multifile : die->die_remove)
    return 0;
  t->entry = 0;
  t->tag = die->die_tag;
  t->children = die->die_child != NULL;
  t->op_type_referenced = false;
  t->nusers = 1;
  if (die->die_offset == -1U)
    {
      if (ref != NULL)
	;
      else if (die_safe_nextdup (die) && die->die_nextdup->die_dup == die)
	{
	  ref = die->die_nextdup;
	  if (ref != NULL)
	    refcu = die_cu (ref);
	}
      if (ref == NULL)
	origin = die->die_nextdup;
    }
  else
    {
      ref = die;
      refcu = cu;
      if (wr_multifile
	  && (die->die_root || die->die_named_namespace))
	origin = die;
    }
  if (die->die_child && die->die_sib)
    for (sib = die->die_sib; sib; sib = sib->die_sib)
      if (wr_multifile ? !sib->die_no_multifile : !sib->die_remove)
	break;
  if (ref != NULL && origin == NULL)
    {
      unsigned char *base
	= cu->cu_kind == CU_TYPES
	  ? debug_sections[DEBUG_TYPES].data
	  : debug_sections[DEBUG_INFO].data;
      unsigned char *ptr = base + ref->die_offset;
      struct abbrev_tag *reft = ref->die_abbrev;

      skip_leb128 (ptr);
      /* No longer count the abbrev uleb128 size in die_size.
	 We'll add it back after determining the new abbrevs.  */
      if (unlikely (wr_multifile || op_multifile || fi_multifile)
	  || unlikely (recompute))
	i = -1U;
      else
	for (i = 0; i < reft->nattr; i++)
	  switch (reft->attr[i].form)
	    {
	    case DW_FORM_ref1:
	    case DW_FORM_ref2:
	    case DW_FORM_ref4:
	    case DW_FORM_ref8:
	    case DW_FORM_ref_udata:
	    case DW_FORM_indirect:
	      i = -2U;
	      break;
	    case DW_FORM_data4:
	    case DW_FORM_data8:
	      if (reft->attr[i].attr == DW_AT_high_pc)
		i = -2U;
	      break;
	    case DW_FORM_addr:
	      if (reft->attr[i].attr == DW_AT_high_pc
		  && cu->cu_version >= 4)
		i = -2U;
	      break;
	    default:
	      break;
	    }
      if (i != -1U)
	{
	  die->die_size -= ptr - (base + ref->die_offset);
	  /* If there are no references, size stays the same
	     and no need to walk the actual attribute values.  */
	  for (i = 0; i < reft->nattr; i++)
	    {
	      t->attr[i].attr = reft->attr[i].attr;
	      t->attr[i].form = reft->attr[i].form;
	      if (t->attr[i].form == DW_FORM_implicit_const)
		t->values[i] = reft->values[i];
	    }
	  t->nattr = reft->nattr;
	}
      else
	{
	  die->die_size = 0;
	  /* Otherwise, we need to walk the actual attributes.  */
	  for (i = 0, j = 0; i < reft->nattr; ++i)
	    {
	      uint32_t form = reft->attr[i].form;
	      size_t len = 0;
	      dw_die_ref refd;
	      uint64_t value = 0;
	      unsigned char *orig_ptr = ptr;

	      while (form == DW_FORM_indirect)
		form = read_uleb128 (ptr);

	      if (unlikely (wr_multifile || op_multifile)
		  && (reft->attr[i].attr == DW_AT_decl_file
		      || reft->attr[i].attr == DW_AT_call_file))
		{
		  switch (form)
		    {
		    case DW_FORM_data1: value = read_8 (ptr); break;
		    case DW_FORM_data2: value = read_16 (ptr); break;
		    case DW_FORM_data4: value = read_32 (ptr); break;
		    case DW_FORM_data8: value = read_64 (ptr); break;
		    case DW_FORM_udata: value = read_uleb128 (ptr); break;
		    case DW_FORM_sdata: value = read_sleb128 (ptr); break;
		    case DW_FORM_implicit_const:
		      value = reft->values[i];
		      break;
		    default:
		      error (0, 0, "Unhandled %s for %s",
			     get_DW_FORM_str (form),
			     get_DW_AT_str (reft->attr[i].attr));
		      return 1;
		    }
		  value = line_htab_lookup (refcu, value);
		  if (form != DW_FORM_implicit_const)
		    {
		      if (value <= 0xff)
			{
			  form = DW_FORM_data1;
			  die->die_size++;
			}
		      else if (value <= 0xffff)
			{
			  form = DW_FORM_data2;
			  die->die_size += 2;
			}
		      else if (value <= 0xffffffff)
			{
			  form = DW_FORM_data4;
			  die->die_size += 4;
			}
		      else
			{
			  form = DW_FORM_data8;
			  die->die_size += 8;
			}
		    }
		  t->attr[j].attr = reft->attr[i].attr;
		  t->attr[j].form = form;
		  if (form == DW_FORM_implicit_const)
		    t->values[j] = value;
		  j++;
		  continue;
		}

	      if (unlikely (fi_multifile)
		  && (reft->attr[i].attr == DW_AT_GNU_macros
		      || reft->attr[i].attr == DW_AT_macros)
		  && alt_macro_htab != NULL)
		{
		  struct macro_entry me, *m;

		  switch (form)
		    {
		    case DW_FORM_data4:
		    case DW_FORM_sec_offset:
		      value = read_32 (ptr);
		      break;
		    default:
		      error (0, 0, "Unhandled %s for %s",
			     get_DW_FORM_str (form),
			     get_DW_AT_str (reft->attr[i].attr));
		      return 1;
		    }
		  me.ptr = debug_sections[DEBUG_MACRO].data + value;
		  m = (struct macro_entry *)
		    htab_find_with_hash (macro_htab, &me, value);
		  if (m->len)
		    {
		      error (0, 0, "%s referencing transparent include",
			     get_DW_AT_str (reft->attr[i].attr));
		      return 1;
		    }
		  ptr -= 4;
		}

	      switch (form)
		{
		case DW_FORM_ref_addr:
		  if (unlikely (fi_multifile))
		    {
		      dw_die_ref refdt;
		      value = read_size (ptr,
					 refcu->cu_version == 2
					 ? ptr_size : 4);
		      ptr += refcu->cu_version == 2 ? ptr_size : 4;
		      refd = off_htab_lookup (NULL, value);
		      assert (refd != NULL);
		      refdt = refd;
		      while (refdt->die_toplevel == 0)
			refdt = refdt->die_parent;
		      if (refdt->die_dup
			  && !refdt->die_op_type_referenced
			  && die_cu (refdt->die_dup)->cu_kind == CU_ALT)
			{
			  t->attr[j].attr = reft->attr[i].attr;
			  t->attr[j++].form
			    = dwarf_5 ? DW_FORM_ref_sup4 : DW_FORM_GNU_ref_alt;
			  die->die_size += 4;
			  continue;
			}
		      break;
		    }
		  ptr += refcu->cu_version == 2 ? ptr_size : 4;
		  break;
		case DW_FORM_addr:
		  ptr += ptr_size;
		  if (reft->attr[i].attr == DW_AT_low_pc
		      && cu->cu_version >= 4)
		    low_pc = read_size (ptr - ptr_size, ptr_size);
		  else if (reft->attr[i].attr == DW_AT_high_pc
			   && low_pc)
		    {
		      uint64_t high_pc = read_size (ptr - ptr_size, ptr_size);
		      /* If both DW_AT_low_pc and DW_AT_high_pc attributes
			 are present and have DW_FORM_addr, attempt to shrink
			 the DIE by using DW_FORM_udata or DW_FORM_data4
			 form for the latter in DWARF4+.  Don't try
			 DW_FORM_data[12], that might increase .debug_abbrev
			 size too much or increase the uleb128 size of too
			 many abbrev numbers.  */
		      if (high_pc > low_pc)
			{
			  unsigned int nform = 0;
			  unsigned int sz = size_of_uleb128 (high_pc - low_pc);
			  if (sz <= 4 && sz <= (unsigned) ptr_size)
			    nform = DW_FORM_udata;
			  else if (ptr_size > 4
				   && high_pc - low_pc <= 0xffffffff)
			    {
			      nform = DW_FORM_data4;
			      sz = 4;
			    }
			  else if (sz <= (unsigned) ptr_size)
			    nform = DW_FORM_udata;
			  if (nform)
			    {
			      t->attr[j].attr = reft->attr[i].attr;
			      t->attr[j++].form = nform;
			      die->die_size += sz;
			      continue;
			    }
			}
		    }
		  break;
		case DW_FORM_flag_present:
		case DW_FORM_implicit_const:
		  break;
		case DW_FORM_flag:
		case DW_FORM_data1:
		  ++ptr;
		  break;
		case DW_FORM_data2:
		  ptr += 2;
		  break;
		case DW_FORM_data4:
		  if (reft->attr[i].attr == DW_AT_high_pc)
		    {
		      uint32_t range_len = read_32 (ptr);
		      unsigned int sz = size_of_uleb128 (range_len);
		      if (sz <= 4)
			{
			  t->attr[j].attr = reft->attr[i].attr;
			  t->attr[j++].form = DW_FORM_udata;
			  die->die_size += sz;
			  continue;
			}
		      break;
		    }
		  ptr += 4;
		  break;
		case DW_FORM_sec_offset:
		  ptr += 4;
		  break;
		case DW_FORM_data8:
		  if (reft->attr[i].attr == DW_AT_high_pc)
		    {
		      unsigned int nform = 0;
		      uint64_t range_len = read_64 (ptr);
		      unsigned int sz = size_of_uleb128 (range_len);
		      if (sz <= 4)
			nform = DW_FORM_udata;
		      else if (range_len <= 0xffffffff)
			{
			  nform = DW_FORM_data4;
			  sz = 4;
			}
		      else if (sz <= 8)
			nform = DW_FORM_udata;
		      if (nform)
			{
			  t->attr[j].attr = reft->attr[i].attr;
			  t->attr[j++].form = nform;
			  die->die_size += sz;
			  continue;
			}
		      break;
		    }
		  ptr += 8;
		  break;
		case DW_FORM_ref_sig8:
		  ptr += 8;
		  break;
		case DW_FORM_data16:
		  ptr += 16;
		  break;
		case DW_FORM_sdata:
		case DW_FORM_udata:
		  skip_leb128 (ptr);
		  break;
		case DW_FORM_strp:
		  if (unlikely (op_multifile || fi_multifile))
		    {
		      form = note_strp_offset2 (read_32 (ptr));
		      if (form != DW_FORM_strp)
			{
			  t->attr[j].attr = reft->attr[i].attr;
			  t->attr[j++].form = form;
			  die->die_size += 4;
			  continue;
			}
		    }
		  else
		    ptr += 4;
		  break;
		case DW_FORM_line_strp:
		  /* Since we don't register the line_strp we cannot
		     change the form in the case of multifile.  */
		  ptr += 4;
		  break;
		case DW_FORM_string:
		  ptr = (unsigned char *) strchr ((char *)ptr, '\0') + 1;
		  break;
		case DW_FORM_indirect:
		  abort ();
		case DW_FORM_block1:
		  len = *ptr++;
		  break;
		case DW_FORM_block2:
		  len = read_16 (ptr);
		  form = DW_FORM_block1;
		  break;
		case DW_FORM_block4:
		  len = read_32 (ptr);
		  form = DW_FORM_block1;
		  break;
		case DW_FORM_block:
		case DW_FORM_exprloc:
		  len = read_uleb128 (ptr);
		  form = DW_FORM_block1;
		  break;
		case DW_FORM_ref1:
		case DW_FORM_ref2:
		case DW_FORM_ref4:
		case DW_FORM_ref8:
		case DW_FORM_ref_udata:
		  switch (form)
		    {
		    case DW_FORM_ref1: value = read_8 (ptr); break;
		    case DW_FORM_ref2: value = read_16 (ptr); break;
		    case DW_FORM_ref4: value = read_32 (ptr); break;
		    case DW_FORM_ref8: value = read_64 (ptr); break;
		    case DW_FORM_ref_udata: value = read_uleb128 (ptr); break;
		    default: abort ();
		    }
		  if (reft->attr[i].attr == DW_AT_sibling)
		    {
		      if (sib == NULL)
			continue;
		      form = DW_FORM_ref4;
		      refd = sib;
		    }
		  else
		    {
		      dw_die_ref refdt;
		      refd = off_htab_lookup (refcu, refcu->cu_offset + value);
		      assert (refd != NULL);
		      refdt = refd;
		      while (refdt->die_toplevel == 0)
			refdt = refdt->die_parent;
		      if (refdt->die_dup && refdt->die_op_type_referenced)
			{
			  if (cu == die_cu (refdt))
			    form = DW_FORM_ref4;
			  else if (cu == die_cu (refdt->die_dup))
			    {
			      form = DW_FORM_ref4;
			      refd = die_find_dup (refdt, refdt->die_dup,
						   refd);
			    }
			  else
			    form = DW_FORM_ref_addr;
			}
		      else
			{
			  if (refdt->die_dup)
			    refd = die_find_dup (refdt, refdt->die_dup, refd);
			  if (cu == die_cu (refd))
			    form = DW_FORM_ref4;
			  else if (die_cu (refd)->cu_kind == CU_ALT)
			    form = (dwarf_5
				    ? DW_FORM_ref_sup4 : DW_FORM_GNU_ref_alt);
			  else
			    form = DW_FORM_ref_addr;
			}
		    }
		  if (form == DW_FORM_ref_addr)
		    die->die_size += cu->cu_version == 2 ? ptr_size : 4;
		  else if (form == DW_FORM_GNU_ref_alt
			   || form == DW_FORM_ref_sup4)
		    die->die_size += 4;
		  else
		    {
		      if (unlikely (recompute))
			form = cu->cu_intracu_form;
		      if (likely (!recompute) || form == DW_FORM_ref_udata)
			{
			  obstack_ptr_grow (vec, die);
			  obstack_ptr_grow (vec, refd);
			}
		    }
		  t->attr[j].attr = reft->attr[i].attr;
		  t->attr[j++].form = form;
		  continue;
		default:
		  abort ();
		}

	      if (form == DW_FORM_block1)
		ptr += len;
	      t->attr[j].attr = reft->attr[i].attr;
	      t->attr[j].form = reft->attr[i].form;
	      if (reft->attr[i].form == DW_FORM_implicit_const)
		t->values[j] = reft->values[i];
	      j++;
	      die->die_size += ptr - orig_ptr;
	    }
	  t->nattr = j;
	}
    }
  else
    switch (die->die_tag)
      {
      case DW_TAG_partial_unit:
      case DW_TAG_compile_unit:
	t->nattr = 0;
	die->die_size = 0;
	if (origin == NULL)
	  break;
	refcu = die_cu (origin);
	if (refcu->cu_nfiles)
	  {
	    t->attr[0].attr = DW_AT_stmt_list;
	    t->attr[0].form = cu->cu_version < 4
			      ? DW_FORM_data4 : DW_FORM_sec_offset;
	    die->die_size += 4;
	    t->nattr++;
	  }
	if (uni_lang_p || cu->cu_die->die_tag == DW_TAG_compile_unit)
	  {
	    unsigned int lang_size = nr_bytes_for (cu->lang);
	    die->die_size += lang_size;
	    t->attr[t->nattr].attr = DW_AT_language;
	    switch (lang_size)
	      {
	      case 1:
		t->attr[t->nattr].form = DW_FORM_data1;
		break;
	      case 2:
		t->attr[t->nattr].form = DW_FORM_data2;
		break;
	      default:
		abort ();
	      }
	    t->nattr++;
	  }
	if (refcu->cu_comp_dir)
	  {
	    enum dwarf_form form;
	    unsigned char *ptr = get_AT (origin, DW_AT_comp_dir, &form);
	    assert (ptr && (form == DW_FORM_string
			    || form == DW_FORM_strp
			    || form == DW_FORM_line_strp));
	    if (form == DW_FORM_strp)
	      {
		if (unlikely (op_multifile || fi_multifile))
		  form = note_strp_offset2 (read_32 (ptr));
		die->die_size += 4;
	      }
	    else if (form == DW_FORM_line_strp)
	      die->die_size += 4;
	    else
	      die->die_size
		+= strlen (refcu->cu_comp_dir) + 1;
	    t->attr[t->nattr].attr = DW_AT_comp_dir;
	    t->attr[t->nattr].form = form;
	    t->nattr++;
	  }
	break;
      case DW_TAG_namespace:
      case DW_TAG_module:
	{
	  enum dwarf_form form;
	  unsigned char *ptr = get_AT (origin, DW_AT_name, &form);
	  assert (ptr && (form == DW_FORM_string
			  || form == DW_FORM_strp
			  || form == DW_FORM_line_strp));
	  if (form == DW_FORM_strp)
	    {
	      if (unlikely (op_multifile || fi_multifile))
		form = note_strp_offset2 (read_32 (ptr));
	      die->die_size = 4;
	    }
	  else if (form == DW_FORM_line_strp)
	    die->die_size += 4;
	  else
	    die->die_size = strlen ((char *) ptr) + 1;
	  t->attr[0].attr = DW_AT_name;
	  t->attr[0].form = form;
	  t->nattr = 1;
	  if (sib)
	    {
	      t->attr[1].attr = DW_AT_sibling;
	      t->attr[1].form = DW_FORM_ref4;
	      obstack_ptr_grow (vec, die);
	      obstack_ptr_grow (vec, sib);
	      t->nattr++;
	    }
	  break;
	}
      case DW_TAG_imported_unit:
	t->attr[0].attr = DW_AT_import;
	t->nattr = 1;
	if (die_cu (die->die_nextdup)->cu_kind == CU_ALT)
	  {
	    t->attr[0].form = dwarf_5 ? DW_FORM_ref_sup4 : DW_FORM_GNU_ref_alt;
	    die->die_size = 4;
	  }
	else
	  {
	    t->attr[0].form = DW_FORM_ref_addr;
	    die->die_size = cu->cu_version == 2 ? ptr_size : 4;
	  }
	break;
      default:
	abort ();
      }
  compute_abbrev_hash (t);
  slot = htab_find_slot_with_hash (h, t, t->hash,
				   recompute ? NO_INSERT : INSERT);
  if (slot == NULL)
    dwz_oom ();
  if (unlikely (recompute))
    assert (*slot);
  if (*slot)
    {
      if (likely (!recompute))
	((struct abbrev_tag *)*slot)->nusers++;
      die->u.p2.die_new_abbrev = (struct abbrev_tag *)*slot;
    }
  else
    {
      struct abbrev_tag *newt = pool_clone_abbrev (t);
      *slot = newt;
      die->u.p2.die_new_abbrev = newt;
    }
  (*ndies)++;
  if (ref != NULL && ref != die)
    {
      for (child = die->die_child, ref_child = ref->die_child;
	   child; child = child->die_sib, ref_child = ref_child->die_sib)
	if (build_abbrevs_for_die (h, cu, child, refcu, ref_child,
				   t, ndies, vec, recompute))
	  return 1;
    }
  else
    for (child = die->die_child; child; child = child->die_sib)
      if (build_abbrevs_for_die (h, cu, child, NULL, NULL, t, ndies, vec,
				 recompute))
	return 1;
  return 0;
}

/* Build new abbreviations for CU.  T, NDIES and VEC arguments like
   for build_abbrevs_for_die.  */
static int
build_abbrevs (dw_cu_ref cu, struct abbrev_tag *t, unsigned int *ndies,
	       struct obstack *vec)
{
  htab_t h = htab_try_create (50, abbrev_hash, abbrev_eq2, NULL);

  if (h == NULL)
    dwz_oom ();

  if (build_abbrevs_for_die (h, cu, cu->cu_die, NULL, NULL, t, ndies, vec,
			     false))
    {
      htab_delete (h);
      return 1;
    }

  cu->cu_new_abbrev = h;
  return 0;
}

/* Helper to record all abbrevs from the hash table into ob obstack
   vector.  Called through htab_traverse.  */
static int
list_abbrevs (void **slot, void *data)
{
  struct obstack *obp = (struct obstack *) data;
  obstack_ptr_grow (obp, *slot);
  return 1;
}

/* Comparison function for abbreviations.  Used for CUs that
   need 128 or more abbreviations.  Use lowest numbers (i.e. sort earlier)
   abbrevs used for typed DWARF stack referenced DIEs, then sort
   by decreasing number of users (abbrev numbers are uleb128 encoded,
   the bigger number of them that can be 1 byte encoded the better).  */
static int
abbrev_cmp (const void *p, const void *q)
{
  struct abbrev_tag *t1 = *(struct abbrev_tag **)p;
  struct abbrev_tag *t2 = *(struct abbrev_tag **)q;
  unsigned int i;

  if (t1->op_type_referenced && !t2->op_type_referenced)
    return -1;
  if (!t1->op_type_referenced && t2->op_type_referenced)
    return 1;
  if (t1->nusers > t2->nusers)
    return -1;
  if (t1->nusers < t2->nusers)
    return 1;
  /* The rest just so that we have a stable sort.  */
  if (t1->tag < t2->tag)
    return -1;
  if (t1->tag > t2->tag)
    return 1;
  if (t1->nattr < t2->nattr)
    return -1;
  if (t1->nattr > t2->nattr)
    return 1;
  if (t1->children && !t2->children)
    return -1;
  if (!t1->children && t2->children)
    return 1;
  for (i = 0; i < t1->nattr; i++)
    {
      if (t1->attr[i].attr < t2->attr[i].attr)
	return -1;
      if (t1->attr[i].attr > t2->attr[i].attr)
	return 1;
      if (t1->attr[i].form < t2->attr[i].form)
	return -1;
      if (t1->attr[i].form > t2->attr[i].form)
	return 1;
      if (t1->attr[i].form == DW_FORM_implicit_const)
	{
	  if (t1->values[i] < t2->values[i])
	    return -1;
	  if (t1->values[i] > t2->values[i])
	    return 1;
	}
    }
  return 0;
}

/* First phase of computation of u.p2.die_new_offset and
   new CU sizes.  */
static unsigned int
init_new_die_offsets (dw_die_ref die, unsigned int off,
		      unsigned int intracusize)
{
  dw_die_ref child;
  unsigned int i;
  struct abbrev_tag *t = die->u.p2.die_new_abbrev;
  if (wr_multifile ? die->die_no_multifile : die->die_remove)
    return off;
  die->u.p2.die_new_offset = off;
  if (likely (die->die_ref_seen == 0))
    {
      die->die_size += size_of_uleb128 (die->u.p2.die_new_abbrev->entry);
      die->u.p2.die_intracu_udata_size = 0;
      for (i = 0; i < t->nattr; ++i)
	switch (t->attr[i].form)
	  {
	  case DW_FORM_ref1:
	  case DW_FORM_ref2:
	  case DW_FORM_ref4:
	  case DW_FORM_ref_udata:
	    die->u.p2.die_intracu_udata_size += intracusize;
	    break;
	  default:
	    break;
	  }
      die->die_size += die->u.p2.die_intracu_udata_size;
    }
  off += die->die_size;
  for (child = die->die_child; child; child = child->die_sib)
    off = init_new_die_offsets (child, off, intracusize);
  if (die->die_child)
    off++;
  return off;
}

/* Second phase of computation of u.p2.die_new_offset and
   new CU sizes.  This step is called possibly many times,
   for deciding if DW_FORM_ref_udata is worthwhile.
   init_new_die_offsets starts with assuming each uleb128 will
   need maximum number of bytes for the CU of the given size,
   each new invocation of this function (except the last)
   will shrink one or more uleb128s.  Each shrinking can create
   new opportunities to shrink other uleb128s.  */
static unsigned int
update_new_die_offsets (dw_die_ref die, unsigned int off,
			dw_die_ref **intracuvec)
{
  dw_die_ref child;
  if (wr_multifile ? die->die_no_multifile : die->die_remove)
    return off;
  assert (off <= die->u.p2.die_new_offset);
  die->u.p2.die_new_offset = off;
  if ((*intracuvec)[0] == die)
    {
      unsigned int intracu_udata_size = 0;
      assert (die->u.p2.die_intracu_udata_size);
      while ((*intracuvec)[0] == die)
	{
	  intracu_udata_size
	    += size_of_uleb128 ((*intracuvec)[1]->u.p2.die_new_offset);
	  *intracuvec += 2;
	}
      assert (die->u.p2.die_intracu_udata_size >= intracu_udata_size);
      die->die_size -= die->u.p2.die_intracu_udata_size - intracu_udata_size;
      die->u.p2.die_intracu_udata_size = intracu_udata_size;
    }
  else
    assert (die->u.p2.die_intracu_udata_size == 0 || die->die_ref_seen);
  off += die->die_size;
  for (child = die->die_child; child; child = child->die_sib)
    off = update_new_die_offsets (child, off, intracuvec);
  if (die->die_child)
    off++;
  return off;
}

/* Final phase of computation of u.p2.die_new_offset.  Called when already
   decided what intra-CU form will be used.  Can return -1U if
   a problem is detected and the tool should give up.  */
static unsigned int
finalize_new_die_offsets (dw_cu_ref cu, dw_die_ref die, unsigned int off,
			  unsigned int intracusize, dw_die_ref **intracuvec)
{
  dw_die_ref child;
  unsigned int ref_seen = die->die_ref_seen;
  if (wr_multifile ? die->die_no_multifile : die->die_remove)
    return off;
  die->u.p2.die_new_offset = off;
  die->die_ref_seen = 0;
  /* As we aren't adjusting sizes of exprloc, if in the new layout
     a DIE referenced through DW_OP_call2 is placed after 64K into
     the CU, punt.  */
  if (die->die_op_call2_referenced && off >= 65536)
    return -1U;
  /* Similarly punt if
     DW_OP_GNU_{{regval,const,deref}_type,convert,reinterpret}
     references a DIE that needs more uleb128 bytes to encode
     the new offset compared to uleb128 bytes to encode the old offset.
     GCC emits DW_TAG_base_type dies referenced that way at the
     beginning of the CU and we try to preserve that, so this shouldn't
     trigger for GCC generated code.  */
  if (die->die_op_type_referenced
      && !wr_multifile
      && size_of_uleb128 (off)
	 > size_of_uleb128 (die->die_offset - cu->cu_offset))
    return -1U;
  if ((*intracuvec)[0] == die)
    {
      unsigned int intracu_udata_size = 0;
      assert (die->u.p2.die_intracu_udata_size);
      while ((*intracuvec)[0] == die)
	{
	  intracu_udata_size += intracusize;
	  *intracuvec += 2;
	}
      if (intracusize != 0)
	{
	  die->die_size
	    -= die->u.p2.die_intracu_udata_size - intracu_udata_size;
	  die->u.p2.die_intracu_udata_size = intracu_udata_size;
	}
    }
  else
    assert (die->u.p2.die_intracu_udata_size == 0 || ref_seen);
  off += die->die_size;
  for (child = die->die_child; child; child = child->die_sib)
    {
      off = finalize_new_die_offsets (cu, child, off, intracusize, intracuvec);
      if (off == -1U)
	return off;
    }
  if (die->die_child)
    off++;
  return off;
}

/* Comparison function, called through qsort, to sort CUs
   by increasing number of needed new abbreviations.  */
static int
cu_abbrev_cmp (const void *p, const void *q)
{
  dw_cu_ref cu1 = *(dw_cu_ref *)p;
  dw_cu_ref cu2 = *(dw_cu_ref *)q;
  unsigned int nabbrevs1 = htab_elements (cu1->cu_new_abbrev);
  unsigned int nabbrevs2 = htab_elements (cu2->cu_new_abbrev);

  if (nabbrevs1 < nabbrevs2)
    return -1;
  if (nabbrevs1 > nabbrevs2)
    return 1;
  /* The rest is just to get stable sort.  */
  if (cu1->cu_kind != CU_PU && cu2->cu_kind == CU_PU)
    return -1;
  if (cu1->cu_kind == CU_PU && cu2->cu_kind != CU_PU)
    return 1;
  if (cu1->cu_offset < cu2->cu_offset)
    return -1;
  if (cu1->cu_offset > cu2->cu_offset)
    return 1;
  return 0;
}

/* Compute new abbreviations for all CUs, size the new
   .debug_abbrev section and all new .debug_info CUs.  */
static int
compute_abbrevs (DSO *dso)
{
  unsigned long total_size = 0, types_size = 0, abbrev_size = 0;
  dw_cu_ref cu, *cuarr;
  struct abbrev_tag *t;
  unsigned int ncus, nlargeabbrevs = 0, i, laststart;

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "compute_abbrevs\n");
    }

  t = (struct abbrev_tag *)
      obstack_alloc (&ob2,
		     sizeof (*t)
		     + (max_nattr + 4) * sizeof (struct abbrev_attr)
		     + (max_nattr + 4) * sizeof (int64_t));
  t->values = (int64_t *) &t->attr[max_nattr + 4];
  for (cu = first_cu, ncus = 0; cu; cu = cu->cu_next)
    {
      unsigned int intracu, ndies = 0, tagsize = 0, nchildren = 0;
      unsigned int nabbrevs, diesize, cusize, off, intracusize;
      struct abbrev_tag **arr;
      dw_die_ref *intracuarr, *intracuvec;
      enum dwarf_form intracuform = DW_FORM_ref4;
      dw_die_ref child, *lastotr, child_next, *last;
      unsigned int headersz = (cu->cu_kind == CU_TYPES
			       ? 23 : (cu->cu_version >= 5 ? 12 : 11));

      if (unlikely (fi_multifile) && cu->cu_die->die_remove)
	continue;
      if (unlikely (low_mem) && cu->cu_kind != CU_PU)
	expand_children (cu->cu_die);
      ncus++;
      if (build_abbrevs (cu, t, &ndies, &ob2))
	return 1;
      nabbrevs = htab_elements (cu->cu_new_abbrev);
      htab_traverse (cu->cu_new_abbrev, list_abbrevs, &ob);
      assert (obstack_object_size (&ob) == nabbrevs * sizeof (void *));
      arr = (struct abbrev_tag **) obstack_finish (&ob);
      intracu = obstack_object_size (&ob2) / sizeof (void *) / 2;
      obstack_ptr_grow (&ob2, NULL);
      intracuarr = (dw_die_ref *) obstack_finish (&ob2);
      if (nabbrevs >= 128)
	{
	  unsigned int limit, uleb128_size;

	  for (child = cu->cu_die->die_child; child; child = child->die_sib)
	    if (child->die_op_type_referenced && !wr_multifile)
	      {
		child->u.p2.die_new_abbrev->op_type_referenced = 1;
		/* If the old offset was close to uleb128 boundary, ensure
		   that DW_TAG_compile_unit gets small abbrev number
		   as well.  */
		if (size_of_uleb128 (child->die_offset - cu->cu_offset)
		    < size_of_uleb128 (child->die_offset - cu->cu_offset + 1))
		  cu->cu_die->u.p2.die_new_abbrev->op_type_referenced = 1;
	      }
	  qsort (arr, nabbrevs, sizeof (*arr), abbrev_cmp);
	  for (i = 0, limit = 128, uleb128_size = 1; i < nabbrevs; i++)
	    {
	      if (i + 1 == limit)
		{
		  limit <<= 7;
		  uleb128_size++;
		}
	      arr[i]->entry = i + 1;
	      tagsize += arr[i]->nusers * uleb128_size;
	      if (arr[i]->children)
		nchildren += arr[i]->nusers;
	    }
	  nlargeabbrevs++;
	}
      else
	{
	  tagsize = ndies;
	  for (i = 0; i < nabbrevs; i++)
	    {
	      arr[i]->entry = i + 1;
	      if (arr[i]->children)
		nchildren += arr[i]->nusers;
	    }
	}

      /* Move all base types with die_op_type_reference
	 to front, to increase the likelyhood that the offset
	 will fit.  */
      for (last = &cu->cu_die->die_child, lastotr = last, child = *last;
	   child; child = child_next)
	{
	  child_next = child->die_sib;
	  if (child->die_op_type_referenced)
	    {
	      if (lastotr != last)
		{
		  child->die_sib = *lastotr;
		  *lastotr = child;
		  lastotr = &child->die_sib;
		  *last = child_next;
		  continue;
		}
	      lastotr = &child->die_sib;
	    }
	  last = &child->die_sib;
	}

      cu->u2.cu_largest_entry = nabbrevs;
      diesize = calc_sizes (cu->cu_die);
      cusize = headersz + tagsize + diesize + nchildren;
      intracusize = size_of_uleb128 (cusize + intracu);
      do
	{
	  i = size_of_uleb128 (cusize + intracu * intracusize);
	  if (i == intracusize)
	    break;
	  intracusize = i;
	}
      while (1);
      cu->initial_intracusize = intracusize;
      off = init_new_die_offsets (cu->cu_die, headersz, intracusize);
      do
	{
	  intracuvec = intracuarr;
	  i = update_new_die_offsets (cu->cu_die, headersz, &intracuvec);
	  assert (*intracuvec == NULL);
	  if (i == off)
	    break;
	  assert (i < off);
	  off = i;
	}
      while (1);
      if (cusize + intracu <= 256)
	{
	  intracuform = DW_FORM_ref1;
	  intracusize = 1;
	  cusize += intracu;
	}
      else if (cusize + intracu * 2 <= 65536)
	{
	  intracuform = DW_FORM_ref2;
	  intracusize = 2;
	  cusize += intracu * 2;
	}
      else
	{
	  cusize += intracu * 4;
	  intracusize = 4;
	}
      if (off <= cusize)
	{
	  intracuform = DW_FORM_ref_udata;
	  intracusize = 0;
	  cusize = off;
	}

      intracuvec = intracuarr;
      off = finalize_new_die_offsets (cu, cu->cu_die, headersz, intracusize,
				      &intracuvec);
      if (off == -1U)
	{
	  error (0, 0, "%s: DW_OP_call2 or typed DWARF stack referenced DIE"
		       " layed out at too big offset", dso->filename);
	  return 1;
	}
      assert (*intracuvec == NULL && off == cusize);
      cu->cu_intracu_form = intracuform;

      if (intracuform != DW_FORM_ref4)
	{
	  unsigned int j;
	  htab_empty (cu->cu_new_abbrev);
	  for (i = 0; i < nabbrevs; i++)
	    {
	      void **slot;
	      for (j = 0; j < arr[i]->nattr; j++)
		if (arr[i]->attr[j].form == DW_FORM_ref4)
		  arr[i]->attr[j].form = intracuform;
	      compute_abbrev_hash (arr[i]);
	      slot = htab_find_slot_with_hash (cu->cu_new_abbrev, arr[i],
					       arr[i]->hash, INSERT);
	      if (slot == NULL)
		dwz_oom ();
	      assert (slot != NULL && *slot == NULL);
	      *slot = arr[i];
	    }
	}
      obstack_free (&ob, (void *) arr);
      obstack_free (&ob2, (void *) intracuarr);
      if (cu->cu_kind == CU_TYPES)
	{
	  cu->cu_new_offset = types_size;
	  types_size += cusize;
	}
      else
	{
	  cu->cu_new_offset = (wr_multifile ? multi_info_off : 0) + total_size;
	  total_size += cusize;
	}

      if (unlikely (low_mem) && cu->cu_kind != CU_PU)
	collapse_children (cu, cu->cu_die);
    }
  if (wr_multifile)
    total_size += 11; /* See the end of write_info.  */
  obstack_free (&ob2, (void *) t);
  cuarr = (dw_cu_ref *) obstack_alloc (&ob2, ncus * sizeof (dw_cu_ref));
  for (cu = first_cu, i = 0; cu; cu = cu->cu_next)
    if (cu->u1.cu_new_abbrev_owner == NULL
	&& (likely (!fi_multifile)
	    || cu->cu_kind != CU_NORMAL
	    || !cu->cu_die->die_remove))
      cuarr[i++] = cu;
  assert (i == ncus);
  qsort (cuarr, ncus, sizeof (dw_cu_ref), cu_abbrev_cmp);
  /* For CUs with < 128 abbrevs, try to see if either all of the
     abbrevs are at < 128 positions in >= 128 abbrev CUs, or
     can be merged with some other small abbrev table to form
     a < 128 abbrev table.  */
  laststart = ncus - nlargeabbrevs;
  for (i = ncus - 1; i != -1U; i--)
    {
      struct abbrev_tag **arr;
      unsigned int nabbrevs, j, k, nattempts;

      if (cuarr[i]->u1.cu_new_abbrev_owner != NULL)
	continue;
      nabbrevs = htab_elements (cuarr[i]->cu_new_abbrev);
      htab_traverse (cuarr[i]->cu_new_abbrev, list_abbrevs, &ob2);
      assert (obstack_object_size (&ob2) == nabbrevs * sizeof (void *));
      arr = (struct abbrev_tag **) obstack_finish (&ob2);
      if (nabbrevs >= 128)
	{
	  nattempts = 0;
	  for (j = i + 1; j < ncus; j++)
	    {
	      unsigned int entry;
	      if (cuarr[j]->u1.cu_new_abbrev_owner)
		continue;
	      if (++nattempts == 100)
		break;
	      entry = cuarr[j]->u2.cu_largest_entry;
	      for (k = 0; k < nabbrevs; k++)
		{
		  struct abbrev_tag *t
		    = htab_find_with_hash (cuarr[j]->cu_new_abbrev,
					   arr[k], arr[k]->hash);
		  if (t == NULL)
		    {
		      ++entry;
		      if (size_of_uleb128 (entry)
			  != size_of_uleb128 (arr[k]->entry))
			break;
		    }
		  else if (size_of_uleb128 (t->entry)
			   != size_of_uleb128 (arr[k]->entry))
		    break;
		}
	      if (k != nabbrevs)
		continue;
	      entry = cuarr[j]->u2.cu_largest_entry;
	      for (k = 0; k < nabbrevs; k++)
		{
		  void **slot
		    = htab_find_slot_with_hash (cuarr[j]->cu_new_abbrev,
						arr[k], arr[k]->hash,
						INSERT);
		  if (slot == NULL)
		    dwz_oom ();
		  if (*slot != NULL)
		    arr[k]->entry = ((struct abbrev_tag *) *slot)->entry;
		  else
		    {
		      struct abbrev_tag *newt;
		      arr[k]->entry = ++entry;
		      newt = pool_clone_abbrev (arr[k]);
		      *slot = newt;
		    }
		}
	      cuarr[j]->u2.cu_largest_entry = entry;
	      cuarr[i]->u1.cu_new_abbrev_owner = cuarr[j];
	      break;
	    }
	  obstack_free (&ob2, (void *) arr);
	  continue;
	}
      /* Don't search all CUs, that might be too expensive.  So just search
	 100 of >= 128 abbrev tables, if there are more than 100, different
	 set each time.  We are looking for a full match (i.e. that
	 cuarr[i] abbrevs are a subset of cuarr[j] abbrevs, and all of them
	 are in the low positions.  */
      for (j = laststart, nattempts = -1U; nlargeabbrevs; j++)
	{
	  if (j == ncus)
	    j -= nlargeabbrevs;
	  if (nattempts != -1U && j == laststart)
	    break;
	  if (nattempts == -1U)
	    nattempts = 0;
	  if (cuarr[j]->u1.cu_new_abbrev_owner)
	    continue;
	  if (++nattempts == 100)
	    break;
	  for (k = 0; k < nabbrevs; k++)
	    {
	      struct abbrev_tag *t
		= htab_find_with_hash (cuarr[j]->cu_new_abbrev,
				       arr[k], arr[k]->hash);
	      if (t == NULL || t->entry >= 128)
		break;
	    }
	  if (k == nabbrevs)
	    {
	      for (k = 0; k < nabbrevs; k++)
		{
		  struct abbrev_tag *t
		    = htab_find_with_hash (cuarr[j]->cu_new_abbrev,
					   arr[k], arr[k]->hash);
		  arr[k]->entry = t->entry;
		}
	      cuarr[i]->u1.cu_new_abbrev_owner = cuarr[j];
	      break;
	    }
	}
      if (nlargeabbrevs > 100)
	laststart = j;
      if (cuarr[i]->u1.cu_new_abbrev_owner == NULL)
	{
	  unsigned int maxdups = 0, maxdupidx = 0;
	  /* Next search up to 100 of small abbrev CUs, looking
	     for best match.  */
	  nattempts = 0;
	  for (j = i + 1; j < ncus - nlargeabbrevs; j++)
	    {
	      unsigned int curdups = 0;
	      if (cuarr[j]->u1.cu_new_abbrev_owner)
		continue;
	      if (++nattempts == 100)
		break;
	      for (k = 0; k < nabbrevs; k++)
		{
		  struct abbrev_tag *t
		    = htab_find_with_hash (cuarr[j]->cu_new_abbrev,
					   arr[k], arr[k]->hash);
		  if (t != NULL)
		    curdups++;
		}
	      if (curdups > maxdups
		  && cuarr[j]->u2.cu_largest_entry - curdups + nabbrevs < 128)
		{
		  maxdups = curdups;
		  maxdupidx = j;
		  if (maxdups == nabbrevs)
		    break;
		}
	    }
	  if (maxdups)
	    {
	      unsigned int entry = cuarr[maxdupidx]->u2.cu_largest_entry;
	      j = maxdupidx;
	      for (k = 0; k < nabbrevs; k++)
		{
		  void **slot
		    = htab_find_slot_with_hash (cuarr[j]->cu_new_abbrev,
						arr[k], arr[k]->hash,
						INSERT);
		  if (slot == NULL)
		    dwz_oom ();
		  if (*slot != NULL)
		    arr[k]->entry = ((struct abbrev_tag *) *slot)->entry;
		  else
		    {
		      struct abbrev_tag *newt;
		      arr[k]->entry = ++entry;
		      newt = pool_clone_abbrev (arr[k]);
		      *slot = newt;
		    }
		}
	      cuarr[j]->u2.cu_largest_entry = entry;
	      cuarr[i]->u1.cu_new_abbrev_owner = cuarr[j];
	    }
	}
      obstack_free (&ob2, (void *) arr);
    }
  obstack_free (&ob2, (void *) t);
  for (cu = first_cu; cu; cu = cu->cu_next)
    {
      struct abbrev_tag **arr;
      unsigned int nabbrevs, j;

      if (unlikely (fi_multifile)
	  && cu->cu_kind == CU_NORMAL
	  && cu->cu_die->die_remove)
	continue;
      if (cu->u1.cu_new_abbrev_owner != NULL)
	{
	  cu->u2.cu_new_abbrev_offset = -1U;
	  if (cu->cu_new_abbrev)
	    htab_delete (cu->cu_new_abbrev);
	  cu->cu_new_abbrev = NULL;
	  continue;
	}
      cu->u2.cu_new_abbrev_offset
	= (wr_multifile ? multi_abbrev_off : 0) + abbrev_size;
      nabbrevs = htab_elements (cu->cu_new_abbrev);
      htab_traverse (cu->cu_new_abbrev, list_abbrevs, &ob);
      assert (obstack_object_size (&ob) == nabbrevs * sizeof (void *));
      arr = (struct abbrev_tag **) obstack_finish (&ob);
      for (i = 0; i < nabbrevs; i++)
	{
	  abbrev_size += size_of_uleb128 (arr[i]->entry);
	  abbrev_size += size_of_uleb128 (arr[i]->tag);
	  abbrev_size += 1;
	  for (j = 0; j < arr[i]->nattr; j++)
	    {
	      abbrev_size += size_of_uleb128 (arr[i]->attr[j].attr);
	      abbrev_size += size_of_uleb128 (arr[i]->attr[j].form);
	      if (arr[i]->attr[j].form == DW_FORM_implicit_const)
		abbrev_size += size_of_sleb128 (arr[i]->values[j]);
	    }
	  abbrev_size += 2;
	}
      abbrev_size += 1;
      obstack_free (&ob, (void *) arr);
    }
  for (cu = first_cu; cu; cu = cu->cu_next)
    if (unlikely (fi_multifile)
	  && cu->cu_kind == CU_NORMAL
	  && cu->cu_die->die_remove)
      continue;
    else if (cu->u2.cu_new_abbrev_offset == -1U)
      {
	dw_cu_ref owner = cu;
	unsigned int cu_new_abbrev_offset;
	while (owner->u1.cu_new_abbrev_owner != NULL)
	  owner = owner->u1.cu_new_abbrev_owner;
	cu_new_abbrev_offset = owner->u2.cu_new_abbrev_offset;
	owner = cu;
	while (owner->u1.cu_new_abbrev_owner != NULL)
	  {
	    owner->u2.cu_new_abbrev_offset = cu_new_abbrev_offset;
	    owner = owner->u1.cu_new_abbrev_owner;
	  }
      }
  debug_sections[DEBUG_INFO].new_size = total_size;
  debug_sections[DEBUG_ABBREV].new_size = abbrev_size;
  debug_sections[DEBUG_TYPES].new_size = types_size;
  return 0;
}

/* Comparison function, sort abbreviations by increasing
   entry value.  */
static int
abbrev_entry_cmp (const void *p, const void *q)
{
  struct abbrev_tag *t1 = *(struct abbrev_tag **)p;
  struct abbrev_tag *t2 = *(struct abbrev_tag **)q;

  if (t1->entry < t2->entry)
    return -1;
  if (t1->entry > t2->entry)
    return 1;
  return 0;
}

/* Construct the new .debug_abbrev section
   in malloced memory, store it as debug_sections[DEBUG_ABBREV].new_data.  */
static void
write_abbrev (void)
{
  dw_cu_ref cu;
  unsigned char *abbrev = malloc (debug_sections[DEBUG_ABBREV].new_size);
  unsigned char *ptr = abbrev;

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "write_abbrev\n");
    }

  if (abbrev == NULL)
    dwz_oom ();

  debug_sections[DEBUG_ABBREV].new_data = abbrev;
  for (cu = first_cu; cu; cu = cu->cu_next)
    {
      struct abbrev_tag **arr;
      unsigned int nabbrevs, i, j;

      if (unlikely (fi_multifile)
	  && cu->cu_kind == CU_NORMAL
	  && cu->cu_die->die_remove)
	continue;
      if (cu->u1.cu_new_abbrev_owner != NULL)
	continue;
      nabbrevs = htab_elements (cu->cu_new_abbrev);
      htab_traverse (cu->cu_new_abbrev, list_abbrevs, &ob);
      assert (obstack_object_size (&ob) == nabbrevs * sizeof (void *));
      arr = (struct abbrev_tag **) obstack_finish (&ob);
      qsort (arr, nabbrevs, sizeof (*arr), abbrev_entry_cmp);
      for (i = 0; i < nabbrevs; i++)
	{
	  write_uleb128 (ptr, arr[i]->entry);
	  write_uleb128 (ptr, arr[i]->tag);
	  *ptr++ = arr[i]->children ? DW_CHILDREN_yes : DW_CHILDREN_no;
	  for (j = 0; j < arr[i]->nattr; j++)
	    {
	      write_uleb128 (ptr, arr[i]->attr[j].attr);
	      write_uleb128 (ptr, arr[i]->attr[j].form);
	      if (arr[i]->attr[j].form == DW_FORM_implicit_const)
		write_sleb128 (ptr, arr[i]->values[j]);
	    }
	  *ptr++ = 0;
	  *ptr++ = 0;
	}
      *ptr++ = 0;
      obstack_free (&ob, (void *) arr);
      if (likely (!low_mem))
	{
	  htab_delete (cu->cu_new_abbrev);
	  cu->cu_new_abbrev = NULL;
	}
    }
  assert (abbrev + debug_sections[DEBUG_ABBREV].new_size == ptr);
}

/* Adjust DWARF expression starting at PTR, LEN bytes long, referenced by
   DIE, with REF being the original DIE.  */
static void
adjust_exprloc (dw_cu_ref cu, dw_die_ref die, dw_cu_ref refcu,
		dw_die_ref ref, unsigned char *ptr, size_t len)
{
  unsigned char *end = ptr + len, *orig_ptr = NULL;
  unsigned char op;
  uint32_t leni;
  GElf_Addr addr;
  dw_die_ref refd, refdt;

  while (ptr < end)
    {
      op = *ptr++;
      switch (op)
	{
	case DW_OP_addr:
	  ptr += ptr_size;
	  break;
	case DW_OP_deref:
	case DW_OP_dup:
	case DW_OP_drop:
	case DW_OP_over:
	case DW_OP_swap:
	case DW_OP_rot:
	case DW_OP_xderef:
	case DW_OP_abs:
	case DW_OP_and:
	case DW_OP_div:
	case DW_OP_minus:
	case DW_OP_mod:
	case DW_OP_mul:
	case DW_OP_neg:
	case DW_OP_not:
	case DW_OP_or:
	case DW_OP_plus:
	case DW_OP_shl:
	case DW_OP_shr:
	case DW_OP_shra:
	case DW_OP_xor:
	case DW_OP_eq:
	case DW_OP_ge:
	case DW_OP_gt:
	case DW_OP_le:
	case DW_OP_lt:
	case DW_OP_ne:
	case DW_OP_lit0 ... DW_OP_lit31:
	case DW_OP_reg0 ... DW_OP_reg31:
	case DW_OP_nop:
	case DW_OP_push_object_address:
	case DW_OP_form_tls_address:
	case DW_OP_call_frame_cfa:
	case DW_OP_stack_value:
	case DW_OP_GNU_push_tls_address:
	case DW_OP_GNU_uninit:
	  break;
	case DW_OP_const1u:
	case DW_OP_pick:
	case DW_OP_deref_size:
	case DW_OP_xderef_size:
	case DW_OP_const1s:
	  ++ptr;
	  break;
	case DW_OP_const2u:
	case DW_OP_const2s:
	case DW_OP_skip:
	case DW_OP_bra:
	  ptr += 2;
	  break;
	case DW_OP_call2:
	case DW_OP_call4:
	case DW_OP_GNU_parameter_ref:
	  if (op == DW_OP_call2)
	    addr = read_16 (ptr);
	  else
	    addr = read_32 (ptr);
	  refd = off_htab_lookup (refcu, refcu->cu_offset + addr);
	  assert (refd != NULL && !refd->die_remove);
	  if (op == DW_OP_call2)
	    {
	      assert (refd->u.p2.die_new_offset <= 65535);
	      ptr -= 2;
	      write_16 (ptr, refd->u.p2.die_new_offset);
	    }
	  else
	    {
	      ptr -= 4;
	      write_32 (ptr, refd->u.p2.die_new_offset);
	    }
	  break;
	case DW_OP_const4u:
	case DW_OP_const4s:
	  ptr += 4;
	  break;
	case DW_OP_call_ref:
	case DW_OP_GNU_implicit_pointer:
	case DW_OP_implicit_pointer:
	case DW_OP_GNU_variable_value:
	  addr = read_size (ptr, refcu->cu_version == 2 ? ptr_size : 4);
	  assert (cu->cu_version == refcu->cu_version);
	  refd = off_htab_lookup (NULL, addr);
	  assert (refd != NULL);
	  refdt = refd;
	  while (refdt->die_toplevel == 0)
	    refdt = refdt->die_parent;
	  if (refdt->die_dup && !refdt->die_op_type_referenced)
	    refd = die_find_dup (refdt, refdt->die_dup, refd);
	  write_size (ptr, cu->cu_version == 2 ? ptr_size : 4,
		      die_cu (refd)->cu_new_offset
		      + refd->u.p2.die_new_offset);
	  if (cu->cu_version == 2)
	    ptr += ptr_size;
	  else
	    ptr += 4;
	  if (op == DW_OP_GNU_implicit_pointer || op == DW_OP_implicit_pointer)
	    skip_leb128 (ptr);
	  break;
	case DW_OP_const8u:
	case DW_OP_const8s:
	  ptr += 8;
	  break;
	case DW_OP_constu:
	case DW_OP_plus_uconst:
	case DW_OP_regx:
	case DW_OP_piece:
	case DW_OP_consts:
	case DW_OP_breg0 ... DW_OP_breg31:
	case DW_OP_fbreg:
	  skip_leb128 (ptr);
	  break;
	case DW_OP_bregx:
	case DW_OP_bit_piece:
	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  break;
	case DW_OP_implicit_value:
	  leni = read_uleb128 (ptr);
	  ptr += leni;
	  break;
	case DW_OP_GNU_entry_value:
	case DW_OP_entry_value:
	  leni = read_uleb128 (ptr);
	  assert ((uint64_t) (end - ptr) >= leni);
	  adjust_exprloc (cu, die, refcu, ref, ptr, leni);
	  ptr += leni;
	  break;
	case DW_OP_GNU_convert:
	case DW_OP_convert:
	case DW_OP_GNU_reinterpret:
	case DW_OP_reinterpret:
	  orig_ptr = ptr;
	  addr = read_uleb128 (ptr);
	  if (addr == 0)
	    break;
	  goto typed_dwarf;
	case DW_OP_GNU_regval_type:
	case DW_OP_regval_type:
	  skip_leb128 (ptr);
	  orig_ptr = ptr;
	  addr = read_uleb128 (ptr);
	  goto typed_dwarf;
	case DW_OP_GNU_const_type:
	case DW_OP_const_type:
	  orig_ptr = ptr;
	  addr = read_uleb128 (ptr);
	  goto typed_dwarf;
	case DW_OP_GNU_deref_type:
	case DW_OP_deref_type:
	  ++ptr;
	  orig_ptr = ptr;
	  addr = read_uleb128 (ptr);
	typed_dwarf:
	  refd = off_htab_lookup (refcu, refcu->cu_offset + addr);
	  assert (refd != NULL && refd->die_op_type_referenced);
	  leni = ptr - orig_ptr;
	  assert (size_of_uleb128 (refd->u.p2.die_new_offset) <= leni);
	  ptr = orig_ptr;
	  write_uleb128 (ptr, refd->u.p2.die_new_offset);
	  /* If the new offset ends up being shorter uleb128
	     encoded than the old, pad it up to make it still valid,
	     but not shortest, uleb128.  Changing sizes of
	     exprloc would be a nightmare.  Another alternative would
	     be to pad with DW_OP_nop after the op.  */
	  if (ptr < orig_ptr + leni)
	    {
	      ptr[-1] |= 0x80;
	      while (ptr < orig_ptr + leni - 1)
		*ptr++ = 0x80;
	      *ptr++ = 0;
	    }
	  if (op == DW_OP_GNU_const_type || op == DW_OP_const_type)
	    ptr += *ptr + 1;
	  break;
	default:
	  abort ();
	}
    }
}

/* Write DW_TAG_unit_* DIE (with ORIGIN being the corresponding original DIE) to
   memory starting at PTR, return pointer after the DIE.  */
static unsigned char *
write_unit_die (unsigned char *ptr, dw_die_ref die, dw_die_ref origin)
{
  struct abbrev_tag *t = die->u.p2.die_new_abbrev;
  unsigned int i;

  for (i = 0; i < t->nattr; ++i)
    {
      struct abbrev_attr *attr = &t->attr[i];
      switch (attr->attr)
	{
	case DW_AT_stmt_list:
	  {
	    enum dwarf_form form;
	    unsigned char *p = get_AT (origin, DW_AT_stmt_list, &form);
	    assert (p && (form == DW_FORM_sec_offset
			  || form == DW_FORM_data4));
	    if (wr_multifile)
	      write_32 (ptr, multi_line_off);
	    else if (op_multifile)
	      write_32 (ptr, 0);
	    else
	      {
		memcpy (ptr, p, 4);
		ptr += 4;
	      }
	  }
	  break;
	case DW_AT_comp_dir:
	  {
	    enum dwarf_form form;
	    unsigned char *p = get_AT (origin, DW_AT_comp_dir, &form);
	    assert (p);
	    assert (form == attr->form
		    || (form == DW_FORM_strp
			&& (attr->form == DW_FORM_GNU_strp_alt
			    || attr->form == DW_FORM_strp_sup)));
	    if (form == DW_FORM_strp)
	      {
		if (unlikely (wr_multifile || op_multifile || fi_multifile))
		  {
		    unsigned int strp = lookup_strp_offset (read_32 (p));
		    write_32 (ptr, strp);
		  }
		else
		  {
		    memcpy (ptr, p, 4);
		    ptr += 4;
		  }
	      }
	    else if (form == DW_FORM_line_strp)
	      {
		memcpy (ptr, p, 4);
		ptr += 4;
	      }
	    else
	      {
		size_t len = strlen ((char *) p) + 1;
		memcpy (ptr, p, len);
		ptr += len;
	      }
	  }
	  break;
	case DW_AT_language:
	  {
	    enum dwarf_source_language lang = die_cu (die)->lang;
	    unsigned int lang_size = nr_bytes_for (lang);
	    write_size (ptr, lang_size, lang);
	    ptr += lang_size;
	  }
	  break;
	default:
	  assert (false);
	  break;
	}
    }

  return ptr;
}

/* Write DIE (with REF being the corresponding original DIE) to
   memory starting at PTR, return pointer after the DIE.  */
static unsigned char *
write_die (unsigned char *ptr, dw_cu_ref cu, dw_die_ref die,
	   dw_cu_ref refcu, dw_die_ref ref, unsigned int *die_count)
{
  uint64_t low_pc = 0;
  dw_die_ref child, sib = NULL, origin = NULL;
  struct abbrev_tag *t;

  if (wr_multifile ? die->die_no_multifile : die->die_remove)
    return ptr;
  if (die_count)
    (*die_count)++;
  if (die->die_offset == -1U)
    {
      if (ref != NULL)
	;
      else if (die_safe_nextdup (die) && die->die_nextdup->die_dup == die)
	{
	  ref = die->die_nextdup;
	  refcu = die_cu (ref);
	}
      if (ref == NULL)
	origin = die->die_nextdup;
    }
  else
    {
      ref = die;
      refcu = cu;
      if (wr_multifile
	  && (die->die_root || die->die_named_namespace))
	origin = die;
    }
  if (die->die_child && die->die_sib)
    for (sib = die->die_sib; sib; sib = sib->die_sib)
      if (wr_multifile ? !sib->die_no_multifile : !sib->die_remove)
	break;
  t = die->u.p2.die_new_abbrev;
  write_uleb128 (ptr, t->entry);
  if (ref != NULL && origin == NULL)
    {
      unsigned char *base
	= cu->cu_kind == CU_TYPES
	  ? debug_sections[DEBUG_TYPES].data
	  : debug_sections[DEBUG_INFO].data;
      unsigned char *inptr = base + ref->die_offset;
      struct abbrev_tag *reft = ref->die_abbrev;
      unsigned int i, j;

      skip_leb128 (inptr);
      for (i = 0, j = 0; i < reft->nattr; ++i)
	{
	  uint32_t form = reft->attr[i].form;
	  size_t len = 0;
	  uint64_t value;
	  unsigned char *orig_ptr = inptr;

	  while (form == DW_FORM_indirect)
	    form = read_uleb128 (inptr);

	  if (unlikely (wr_multifile || op_multifile)
	      && (reft->attr[i].attr == DW_AT_decl_file
		  || reft->attr[i].attr == DW_AT_call_file))
	    {
	      switch (form)
		{
		case DW_FORM_data1:
		  value = read_8 (inptr);
		  break;
		case DW_FORM_data2:
		  value = read_16 (inptr);
		  break;
		case DW_FORM_data4:
		  value = read_32 (inptr);
		  break;
		case DW_FORM_data8:
		  value = read_64 (inptr);
		  break;
		case DW_FORM_udata:
		  value = read_uleb128 (inptr);
		  break;
		case DW_FORM_sdata:
		  value = read_sleb128 (inptr);
		  break;
		case DW_FORM_implicit_const:
		  /* DW_FORM_implicit_const should have been updated
		     already when computing abbrevs.  */
		  j++;
		  continue;
		default: abort ();
		}
	      value = line_htab_lookup (refcu, value);
	      switch (t->attr[j].form)
		{
		  case DW_FORM_data1: write_8 (ptr, value); break;
		  case DW_FORM_data2: write_16 (ptr, value); break;
		  case DW_FORM_data4: write_32 (ptr, value); break;
		  case DW_FORM_data8: write_64 (ptr, value); break;
		  case DW_FORM_udata: write_uleb128 (ptr, value); break;
		  case DW_FORM_sdata: write_sleb128 (ptr, value); break;
		  default: abort ();
		}
	      j++;
	      continue;
	    }

	  if (unlikely (fi_multifile)
	      && (reft->attr[i].attr == DW_AT_GNU_macros
		  || reft->attr[i].attr == DW_AT_macros)
	      && alt_macro_htab != NULL)
	    {
	      struct macro_entry me, *m;

	      memcpy (ptr, orig_ptr, inptr - orig_ptr);
	      ptr += inptr - orig_ptr;
	      value = read_32 (inptr);
	      me.ptr = debug_sections[DEBUG_MACRO].data + value;
	      m = (struct macro_entry *)
		  htab_find_with_hash (macro_htab, &me, value);
	      write_32 (ptr, m->hash);
	      j++;
	      continue;
	    }

	  switch (form)
	    {
	    case DW_FORM_ref_addr:
	      {
		dw_die_ref refd, refdt;
		if (t->attr[j].form != DW_FORM_GNU_ref_alt
		    && t->attr[j].form != DW_FORM_ref_sup4)
		  {
		    memcpy (ptr, orig_ptr, inptr - orig_ptr);
		    ptr += inptr - orig_ptr;
		  }
		value = read_size (inptr, refcu->cu_version == 2
					  ? ptr_size : 4);
		inptr += refcu->cu_version == 2 ? ptr_size : 4;
		refd = off_htab_lookup (NULL, value);
		if (refd == NULL || refd->die_tag == 0)
		  error (1, 0, "Couldn't find DIE at DW_FORM_ref_addr offset"
			 " 0x%" PRIx64, value);
		assert (refd != NULL);
		refdt = refd;
		while (refdt->die_toplevel == 0)
		  refdt = refdt->die_parent;
		if (refdt->die_dup && !refdt->die_op_type_referenced)
		  {
		    refd = die_find_dup (refdt, refdt->die_dup, refd);
		    if (t->attr[j].form == DW_FORM_GNU_ref_alt
			|| t->attr[j].form == DW_FORM_ref_sup4)
		      {
			assert (die_cu (refd)->cu_kind == CU_ALT);
			write_32 (ptr, refd->die_offset);
			j++;
			continue;
		      }
		  }
		assert (refd->u.p2.die_new_offset
			&& t->attr[j].form != DW_FORM_GNU_ref_alt
			&& t->attr[j].form != DW_FORM_ref_sup4);
		value = die_cu (refd)->cu_new_offset
			+ refd->u.p2.die_new_offset;
		write_size (ptr, cu->cu_version == 2 ? ptr_size : 4,
			    value);
		ptr += cu->cu_version == 2 ? ptr_size : 4;
		if (unlikely (op_multifile))
		  assert (die_cu (refd)->cu_kind == CU_PU);
		j++;
		continue;
	      }
	    case DW_FORM_addr:
	      inptr += ptr_size;
	      if (reft->attr[i].attr == DW_AT_low_pc)
		low_pc = read_size (inptr - ptr_size, ptr_size);
	      if (reft->attr[i].attr == DW_AT_high_pc
		  && t->attr[j].form != reft->attr[i].form)
		{
		  uint64_t high_pc = read_size (inptr - ptr_size, ptr_size);
		  switch (t->attr[j].form)
		    {
		    case DW_FORM_udata:
		      write_uleb128 (ptr, high_pc - low_pc);
		      break;
		    case DW_FORM_data4:
		      write_32 (ptr, high_pc - low_pc);
		      break;
		    default:
		      abort ();
		    }
		  j++;
		  continue;
		}
	      break;
	    case DW_FORM_flag_present:
	    case DW_FORM_implicit_const:
	      break;
	    case DW_FORM_flag:
	    case DW_FORM_data1:
	      ++inptr;
	      break;
	    case DW_FORM_data2:
	      inptr += 2;
	      break;
	    case DW_FORM_data4:
	      if (reft->attr[i].attr == DW_AT_high_pc
		  && t->attr[j].form != reft->attr[i].form)
		{
		  uint32_t range_len = read_32 (inptr);
		  switch (t->attr[j].form)
		    {
		    case DW_FORM_udata:
		      write_uleb128 (ptr, range_len);
		      break;
		    default:
		      abort ();
		    }
		  j++;
		  continue;
		}
	      inptr += 4;
	      break;
	    case DW_FORM_sec_offset:
	      inptr += 4;
	      break;
	    case DW_FORM_data8:
	      if (reft->attr[i].attr == DW_AT_high_pc
		  && t->attr[j].form != reft->attr[i].form)
		{
		  uint64_t range_len = read_64 (inptr);
		  switch (t->attr[j].form)
		    {
		    case DW_FORM_udata:
		      write_uleb128 (ptr, range_len);
		      break;
		    case DW_FORM_data4:
		      write_32 (ptr, range_len);
		      break;
		    default:
		      abort ();
		    }
		  j++;
		  continue;
		}
	      inptr += 8;
	      break;
	    case DW_FORM_ref_sig8:
	      inptr += 8;
	      break;
	    case DW_FORM_data16:
	      inptr += 16;
	      break;
	    case DW_FORM_sdata:
	    case DW_FORM_udata:
	      skip_leb128 (inptr);
	      break;
	    case DW_FORM_strp:
	      if (unlikely (wr_multifile || op_multifile || fi_multifile))
		{
		  unsigned int strp = lookup_strp_offset (read_32 (inptr));
		  memcpy (ptr, orig_ptr, inptr - 4 - orig_ptr);
		  ptr += inptr - 4 - orig_ptr;
		  write_32 (ptr, strp);
		  j++;
		  continue;
		}
	      inptr += 4;
	      break;
	    case DW_FORM_line_strp:
	      inptr += 4;
	      break;
	    case DW_FORM_string:
	      inptr = (unsigned char *) strchr ((char *)inptr, '\0') + 1;
	      break;
	    case DW_FORM_indirect:
	      abort ();
	    case DW_FORM_block1:
	      len = *inptr++;
	      break;
	    case DW_FORM_block2:
	      len = read_16 (inptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_block4:
	      len = read_32 (inptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_block:
	      len = read_uleb128 (inptr);
	      form = DW_FORM_block1;
	      break;
	    case DW_FORM_exprloc:
	      len = read_uleb128 (inptr);
	      break;
	    case DW_FORM_ref1:
	    case DW_FORM_ref2:
	    case DW_FORM_ref4:
	    case DW_FORM_ref8:
	    case DW_FORM_ref_udata:
	      switch (form)
		{
		case DW_FORM_ref1: value = read_8 (inptr); break;
		case DW_FORM_ref2: value = read_16 (inptr); break;
		case DW_FORM_ref4: value = read_32 (inptr); break;
		case DW_FORM_ref8: value = read_64 (inptr); break;
		case DW_FORM_ref_udata: value = read_uleb128 (inptr); break;
		default: abort ();
		}
	      if (reft->attr[i].attr == DW_AT_sibling)
		{
		  if (j == t->nattr
		      || t->attr[j].attr != DW_AT_sibling)
		    continue;
		  assert (sib);
		  value = sib->u.p2.die_new_offset;
		}
	      else
		{
		  dw_die_ref refdt, refd
		    = off_htab_lookup (refcu, refcu->cu_offset + value);
		  assert (refd != NULL);
		  refdt = refd;
		  while (refdt->die_toplevel == 0)
		    refdt = refdt->die_parent;
		  if (refdt->die_dup && refdt->die_op_type_referenced
		      && cu->cu_kind != CU_PU)
		    {
		      if (cu == die_cu (refdt->die_dup))
			refd = die_find_dup (refdt, refdt->die_dup, refd);
		    }
		  else if (refdt->die_dup)
		    refd = die_find_dup (refdt, refdt->die_dup, refd);
		  if (t->attr[j].form == DW_FORM_GNU_ref_alt
		      || t->attr[j].form == DW_FORM_ref_sup4)
		    {
		      value = refd->die_offset;
		      assert (die_cu (refd)->cu_kind == CU_ALT);
		    }
		  else
		    {
		      dw_cu_ref refdcu = die_cu (refd);
		      value = refd->u.p2.die_new_offset;
		      assert (IMPLIES (cu->cu_kind == CU_PU,
				       die_cu (refd)->cu_kind == CU_PU));
		      assert (value && refdcu->cu_kind != CU_ALT);
		      if (t->attr[j].form == DW_FORM_ref_addr)
			{
			  value += refdcu->cu_new_offset;
			  if (unlikely (op_multifile))
			    assert (refdcu->cu_kind == CU_PU);
			}
		      else
			assert (refdcu == cu);
		    }
		}
	      switch (t->attr[j].form)
		{
		case DW_FORM_ref1: write_8 (ptr, value); break;
		case DW_FORM_ref2: write_16 (ptr, value); break;
		case DW_FORM_ref4: write_32 (ptr, value); break;
		case DW_FORM_ref_udata: write_uleb128 (ptr, value); break;
		case DW_FORM_ref_addr:
		  write_size (ptr, cu->cu_version == 2 ? ptr_size : 4,
			      value);
		  ptr += cu->cu_version == 2 ? ptr_size : 4;
		  break;
		case DW_FORM_GNU_ref_alt:
		case DW_FORM_ref_sup4:
		  write_32 (ptr, value);
		  break;
		case DW_FORM_ref_sup8:
		  write_64 (ptr, value);
		  break;
		default:
		  abort ();
		}
	      j++;
	      continue;
	    default:
	      abort ();
	    }

	  if (form == DW_FORM_block1 || form == DW_FORM_exprloc)
	    inptr += len;

	  memcpy (ptr, orig_ptr, inptr - orig_ptr);
	  ptr += inptr - orig_ptr;

	  /* Old DWARF uses blocks instead of exprlocs.  */
	  if (form == DW_FORM_block1 && cu->cu_version < 4)
	    switch (reft->attr[i].attr)
	      {
	      case DW_AT_frame_base:
	      case DW_AT_location:
	      case DW_AT_data_member_location:
	      case DW_AT_vtable_elem_location:
	      case DW_AT_byte_size:
	      case DW_AT_bit_offset:
	      case DW_AT_bit_size:
	      case DW_AT_string_length:
	      case DW_AT_lower_bound:
	      case DW_AT_return_addr:
	      case DW_AT_bit_stride:
	      case DW_AT_upper_bound:
	      case DW_AT_count:
	      case DW_AT_segment:
	      case DW_AT_static_link:
	      case DW_AT_use_location:
	      case DW_AT_allocated:
	      case DW_AT_associated:
	      case DW_AT_data_location:
	      case DW_AT_byte_stride:
	      case DW_AT_rank:
	      case DW_AT_call_value:
	      case DW_AT_call_target:
	      case DW_AT_call_target_clobbered:
	      case DW_AT_call_data_location:
	      case DW_AT_call_data_value:
	      case DW_AT_GNU_call_site_value:
	      case DW_AT_GNU_call_site_data_value:
	      case DW_AT_GNU_call_site_target:
	      case DW_AT_GNU_call_site_target_clobbered:
		adjust_exprloc (cu, die, refcu, ref, ptr - len, len);
	      default:
		break;
	      }
	  else if (form == DW_FORM_exprloc)
	    adjust_exprloc (cu, die, refcu, ref, ptr - len, len);
	  j++;
	}
      assert (j == t->nattr);
    }
  else
    switch (die->die_tag)
      {
      case DW_TAG_partial_unit:
      case DW_TAG_compile_unit:
	ptr = write_unit_die (ptr, die, origin);
	break;
      case DW_TAG_namespace:
      case DW_TAG_module:
	{
	  enum dwarf_form form;
	  unsigned char *p = get_AT (origin, DW_AT_name, &form);
	  assert (p && (form == t->attr[0].form
			|| (form == DW_FORM_strp
			    && (t->attr[0].form == DW_FORM_GNU_strp_alt
				|| t->attr[0].form == DW_FORM_strp_sup))));
	  if (form == DW_FORM_strp)
	    {
	      if (unlikely (wr_multifile || op_multifile || fi_multifile))
		{
		  unsigned int strp = lookup_strp_offset (read_32 (p));
		  write_32 (ptr, strp);
		}
	      else
		{
		  memcpy (ptr, p, 4);
		  ptr += 4;
		}
	    }
	  else if (form == DW_FORM_line_strp)
	    {
	      memcpy (ptr, p, 4);
	      ptr += 4;
	    }
	  else
	    {
	      size_t len = strlen ((char *) p) + 1;
	      memcpy (ptr, p, len);
	      ptr += len;
	    }
	  if (t->nattr > 1)
	    {
	      assert (sib);
	      switch (t->attr[1].form)
		{
		case DW_FORM_ref1:
		  write_8 (ptr, sib->u.p2.die_new_offset);
		  break;
		case DW_FORM_ref2:
		  write_16 (ptr, sib->u.p2.die_new_offset);
		  break;
		case DW_FORM_ref4:
		  write_32 (ptr, sib->u.p2.die_new_offset);
		  break;
		case DW_FORM_ref_udata:
		  write_uleb128 (ptr, sib->u.p2.die_new_offset);
		  break;
		default:
		  abort ();
		}
	    }
	  break;
	}
      case DW_TAG_imported_unit:
	refcu = die_cu (origin);
	if (t->attr[0].form == DW_FORM_GNU_ref_alt
	    || t->attr[0].form == DW_FORM_ref_sup4)
	  {
	    assert (refcu->cu_kind == CU_ALT);
	    write_32 (ptr, origin->die_offset);
	    break;
	  }
	assert (refcu->cu_kind != CU_ALT);
	write_size (ptr, cu->cu_version == 2 ? ptr_size : 4,
		    refcu->cu_new_offset
		    + origin->u.p2.die_new_offset);
	ptr += cu->cu_version == 2 ? ptr_size : 4;
	break;
      default:
	abort ();
      }
  if (ref != NULL && ref != die)
    {
      dw_die_ref ref_child;
      for (child = die->die_child, ref_child = ref->die_child;
	   child; child = child->die_sib, ref_child = ref_child->die_sib)
	ptr = write_die (ptr, cu, child, refcu, ref_child, die_count);
    }
  else
    for (child = die->die_child; child; child = child->die_sib)
      ptr = write_die (ptr, cu, child, NULL, NULL, die_count);
  if (die->die_child)
    write_8 (ptr, 0);
  return ptr;
}

/* Recompute abbrevs for CU.  If any children were collapsed during
   compute_abbrevs, their ->u.p2.die_new_abbrev and ->u.p2.die_new_offset
   fields are no longer available and need to be computed again.  */
static void
recompute_abbrevs (dw_cu_ref cu, unsigned int cu_size)
{
  unsigned int headersz = (cu->cu_kind == CU_TYPES
			   ? 23 : (cu->cu_version >= 5 ? 12 : 11));
  struct abbrev_tag *t;
  unsigned int ndies = 0, intracusize, off, i;
  dw_die_ref *intracuarr, *intracuvec;

  t = (struct abbrev_tag *)
      obstack_alloc (&ob2,
		     sizeof (*t)
		     + (max_nattr + 4) * sizeof (struct abbrev_attr)
		     + (max_nattr + 4) * sizeof (int64_t));
  t->values = (int64_t *) &t->attr[max_nattr + 4];

  build_abbrevs_for_die (cu->u1.cu_new_abbrev_owner
			 ? cu->u1.cu_new_abbrev_owner->cu_new_abbrev
			 : cu->cu_new_abbrev, cu, cu->cu_die, NULL, NULL, t,
			 &ndies, &ob2, true);

  obstack_ptr_grow (&ob2, NULL);
  intracuarr = (dw_die_ref *) obstack_finish (&ob2);
  if (cu->cu_intracu_form != DW_FORM_ref_udata)
    {
      switch (cu->cu_intracu_form)
	{
	case DW_FORM_ref1: intracusize = 1; break;
	case DW_FORM_ref2: intracusize = 2; break;
	case DW_FORM_ref4: intracusize = 4; break;
	default: abort ();
	}
      off = init_new_die_offsets (cu->cu_die, headersz, intracusize);
    }
  else
    {
      intracusize = cu->initial_intracusize;

      off = init_new_die_offsets (cu->cu_die, headersz, intracusize);
      do
	{
	  intracuvec = intracuarr;
	  i = update_new_die_offsets (cu->cu_die, headersz, &intracuvec);
	  assert (*intracuvec == NULL);
	  if (i == off)
	    break;
	  assert (i < off);
	  off = i;
	}
      while (1);

      intracuvec = intracuarr;
      off = finalize_new_die_offsets (cu, cu->cu_die, headersz, 0,
				      &intracuvec);
      assert (*intracuvec == NULL);
    }
  obstack_free (&ob2, (void *) t);
  assert (off == cu_size);
}

/* Construct new .debug_info section in malloced memory,
   store it to debug_sections[DEBUG_INFO].new_data.  */
static void
write_info (unsigned int *die_count)
{
  dw_cu_ref cu, cu_next;
  unsigned char *info = malloc (debug_sections[DEBUG_INFO].new_size);
  unsigned char *ptr = info;

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "write_info\n");
    }

  if (info == NULL)
    dwz_oom ();
  if (die_count)
    *die_count = 0;
  debug_sections[DEBUG_INFO].new_data = info;
  cu = first_cu;
  if (unlikely (fi_multifile))
    while (cu
	   && cu->cu_kind == CU_NORMAL
	   && cu->cu_die->die_remove)
      cu = cu->cu_next;
  for (; cu; cu = cu_next)
    {
      unsigned long next_off = debug_sections[DEBUG_INFO].new_size;
      /* Ignore .debug_types CUs.  */
      if (cu->cu_kind == CU_TYPES)
	break;
      cu_next = cu->cu_next;
      if (unlikely (fi_multifile))
	while (cu_next
	       && cu_next->cu_kind == CU_NORMAL
	       && cu_next->cu_die->die_remove)
	  cu_next = cu_next->cu_next;
      if (cu_next && cu_next->cu_kind == CU_TYPES)
	cu_next = NULL;
      if (cu_next)
	next_off = cu_next->cu_new_offset;
      else if (wr_multifile)
	next_off += multi_info_off - 11L;
      if (unlikely (low_mem)
	  && cu->cu_kind != CU_PU
	  && expand_children (cu->cu_die))
	recompute_abbrevs (cu, next_off - cu->cu_new_offset);
      /* Write CU header.  */
      write_32 (ptr, next_off - cu->cu_new_offset - 4);
      write_16 (ptr, cu->cu_version);
      if (cu->cu_version >= 5)
	{
	  *ptr++ = (cu->cu_die->die_tag == DW_TAG_compile_unit
		    ? DW_UT_compile : DW_UT_partial);
	  write_8 (ptr, ptr_size);
	}
      write_32 (ptr, cu->u2.cu_new_abbrev_offset);
      if (cu->cu_version < 5)
	write_8 (ptr, ptr_size);
      ptr = write_die (ptr, cu, cu->cu_die, NULL, NULL, die_count);
      assert (info + (next_off - (wr_multifile ? multi_info_off : 0)) == ptr);
      if (unlikely (low_mem) && cu->cu_kind != CU_PU)
	collapse_children (cu, cu->cu_die);
    }
  if (wr_multifile)
    {
      /* And terminate the contribution by the current object file.  */
      write_32 (ptr, 7);
      write_16 (ptr, 2);
      write_32 (ptr, 0);
      write_8 (ptr, ptr_size);
    }
  assert (info + debug_sections[DEBUG_INFO].new_size == ptr);
}

/* Adjust .debug_loc range determined by *SLOT, called through
   htab_traverse.  */
static int
adjust_loclist (void **slot, void *data)
{
  struct debug_loc_adjust *adj = (struct debug_loc_adjust *) *slot;
  unsigned char *ptr, *endsec;
  GElf_Addr low, high;
  size_t len;

  (void)data;

  ptr = debug_sections[DEBUG_LOC].new_data + adj->start_offset;
  endsec = ptr + debug_sections[DEBUG_LOC].size;
  while (ptr < endsec)
    {
      low = read_size (ptr, ptr_size);
      high = read_size (ptr + ptr_size, ptr_size);
      ptr += 2 * ptr_size;
      if (low == 0 && high == 0)
	break;

      if (low == ~ (GElf_Addr) 0 || (ptr_size == 4 && low == 0xffffffff))
	continue;

      len = read_16 (ptr);
      assert (ptr + len <= endsec);

      adjust_exprloc (adj->cu, adj->cu->cu_die, adj->cu, adj->cu->cu_die,
		      ptr, len);

      ptr += len;
    }

  return 1;
}

/* Adjust .debug_loclists range determined by *SLOT, called through
   htab_traverse.  */
static int
adjust_loclists (void **slot, void *data)
{
  struct debug_loc_adjust *adj = (struct debug_loc_adjust *) *slot;
  unsigned char *ptr, *endsec;
  size_t len = 0;

  (void)data;

  ptr = debug_sections[DEBUG_LOCLISTS].new_data + adj->start_offset;
  endsec = ptr + debug_sections[DEBUG_LOCLISTS].size;

again:
  while (ptr < endsec)
    {
      uint8_t lle = *ptr++;
      switch (lle)
	{
	case DW_LLE_end_of_list:
	  goto done;

	case DW_LLE_base_addressx:
	  skip_leb128 (ptr);
	  goto again;

	case DW_LLE_startx_endx:
	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  len = read_uleb128 (ptr);
	  break;

	case DW_LLE_startx_length:
	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  len = read_uleb128 (ptr);
	  break;

	case DW_LLE_offset_pair:
	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  len = read_uleb128 (ptr);
	  break;

	case DW_LLE_default_location:
	  len = read_uleb128 (ptr);
	  break;

	case DW_LLE_base_address:
	  ptr += ptr_size;
	  goto again;

	case DW_LLE_start_end:
	  ptr += 2 * ptr_size;
	  len = read_uleb128 (ptr);
	  break;

	case DW_LLE_start_length:
	  ptr += ptr_size;
	  skip_leb128 (ptr);
	  len = read_uleb128 (ptr);
	  break;

	case DW_LLE_GNU_view_pair:
	  /* Note we cannot check CU version here, but we'll get a
	     warning on the original parsing if CU version is not 5.*/
	  skip_leb128 (ptr);
	  skip_leb128 (ptr);
	  goto again;

	default:
	  error (0, 0, "unhandled location list entry 0x%x", lle);
	  return 1;
	}

      assert (ptr + len <= endsec);

      adjust_exprloc (adj->cu, adj->cu->cu_die, adj->cu, adj->cu->cu_die,
		      ptr, len);

      ptr += len;
    }

done:
  return 1;
}

/* Create new .debug_loc section in malloced memory if .debug_loc
   needs to be adjusted.  */
static void
write_loc (void)
{
  unsigned char *loc;
  if (loc_htab == NULL)
    return;
  loc = malloc (debug_sections[DEBUG_LOC].size);
  if (loc == NULL)
    dwz_oom ();
  memcpy (loc, debug_sections[DEBUG_LOC].data, debug_sections[DEBUG_LOC].size);
  debug_sections[DEBUG_LOC].new_data = loc;
  htab_traverse (loc_htab, adjust_loclist, NULL);
}

/* Create new .debug_loclists section in malloced memory if .debug_loclists
   needs to be adjusted.  */
static void
write_loclists (void)
{
  unsigned char *loc;
  if (loclists_htab == NULL)
    return;
  loc = malloc (debug_sections[DEBUG_LOCLISTS].size);
  if (loc == NULL)
    dwz_oom ();
  memcpy (loc, debug_sections[DEBUG_LOCLISTS].data,
	  debug_sections[DEBUG_LOCLISTS].size);
  debug_sections[DEBUG_LOCLISTS].new_data = loc;
  htab_traverse (loclists_htab, adjust_loclists, NULL);
}

/* Create new .debug_types section in malloced memory.  */
static void
write_types (void)
{
  dw_cu_ref cu;
  unsigned char *types, *ptr, *inptr;
  dw_die_ref ref;

  if (debug_sections[DEBUG_TYPES].data == NULL)
    return;
  types = malloc (debug_sections[DEBUG_TYPES].new_size);
  if (types == NULL)
    dwz_oom ();
  debug_sections[DEBUG_TYPES].new_data = types;
  ptr = types;
  for (cu = first_cu; cu; cu = cu->cu_next)
    {
      unsigned long next_off = debug_sections[DEBUG_TYPES].new_size;
      /* Ignore .debug_info CUs.  */
      if (cu->cu_kind != CU_TYPES)
	continue;
      if (cu->cu_next)
	next_off = cu->cu_next->cu_new_offset;
      if (unlikely (low_mem)
	  && expand_children (cu->cu_die))
	recompute_abbrevs (cu, next_off - cu->cu_new_offset);
      /* Write CU header.  */
      write_32 (ptr, next_off - cu->cu_new_offset - 4);
      write_16 (ptr, cu->cu_version);
      write_32 (ptr, cu->u2.cu_new_abbrev_offset);
      write_8 (ptr, ptr_size);
      inptr = debug_sections[DEBUG_TYPES].data + cu->cu_offset + 19;
      memcpy (ptr, inptr - 8, 8);
      ptr += 8;
      ref = off_htab_lookup (cu, cu->cu_offset + read_32 (inptr));
      assert (ref && die_safe_dup(ref) == NULL);
      write_32 (ptr, ref->u.p2.die_new_offset);
      ptr = write_die (ptr, cu, cu->cu_die, NULL, NULL, NULL);
      assert (types + next_off == ptr);
      if (unlikely (low_mem))
	collapse_children (cu, cu->cu_die);
    }
  assert (types + debug_sections[DEBUG_TYPES].new_size == ptr);
}

/* Construct new .debug_aranges section in malloced memory,
   store it to debug_sections[DEBUG_ARANGES].new_data.  */
static int
write_aranges (DSO *dso)
{
  dw_cu_ref cu, cufirst = NULL, cucur;
  unsigned char *aranges, *ptr, *end;

  if (debug_sections[DEBUG_ARANGES].data == NULL)
    return 0;

  aranges = malloc (debug_sections[DEBUG_ARANGES].size);
  if (aranges == NULL)
    dwz_oom ();
  memcpy (aranges, debug_sections[DEBUG_ARANGES].data,
	  debug_sections[DEBUG_ARANGES].size);
  debug_sections[DEBUG_ARANGES].new_data = aranges;
  ptr = aranges;
  end = aranges + debug_sections[DEBUG_ARANGES].size;
  for (cu = first_cu; cu; cu = cu->cu_next)
    if (cu->cu_kind != CU_PU)
      break;
  cufirst = cu;
  while (ptr < end)
    {
      unsigned int culen, value, cuoff;

      if (end - ptr < 12)
	{
	  error (0, 0, "%s: Corrupted .debug_aranges section",
		 dso->filename);
	  return 1;
	}
      culen = read_32 (ptr);
      if (culen >= 0xfffffff0)
	{
	  error (0, 0, "%s: 64-bit DWARF not supported", dso->filename);
	  return 1;
	}

      value = read_16 (ptr);
      if (value != 2)
	{
	  error (0, 0, "%s: DWARF version %d in .debug_aranges unhandled",
		 dso->filename, value);
	  return 1;
	}

      cuoff = read_32 (ptr);
      cucur = cu;
      /* Optimistically assume that .debug_aranges CU offsets only increase,
	 otherwise this might be too expensive and need a hash table.  */
      for (; cu; cu = cu->cu_next)
	{
	  if (cu->cu_kind == CU_TYPES)
	    {
	      cu = NULL;
	      break;
	    }
	  else if (cu->cu_offset == cuoff)
	    break;
	}
      if (cu == NULL)
	{
	  for (cu = cufirst; cu != cucur; cu = cu->cu_next)
	    if (cu->cu_offset == cuoff)
	      break;
	  if (cu == cucur)
	    {
	      error (0, 0, "%s: Couldn't find CU for .debug_aranges "
			   "offset 0x%x", dso->filename, cuoff);
	      return 1;
	    }
	}
      if (unlikely (fi_multifile)
	  && cu->cu_kind == CU_NORMAL
	  && cu->cu_die->die_remove)
	{
	  error (0, 0, "%s: Partial unit referenced in .debug_aranges",
		 dso->filename);
	  return 1;
	}
      ptr -= 4;
      write_32 (ptr, cu->cu_new_offset);
      ptr += culen - 6;
    }
  return 0;
}

/* Helper function of write_gdb_index, called through qsort.
   Sort an array of unsigned integer pairs, by increasing
   first integer.  The first integer is the TU offset
   in the .gdb_index TU table, the second is its index in
   the TU table from the start of that table.  */
static int
gdb_index_tu_cmp (const void *p, const void *q)
{
  unsigned int *t1 = (unsigned int *) p;
  unsigned int *t2 = (unsigned int *) q;

  if (t1[0] < t2[0])
    return -1;
  if (t1[0] > t2[0])
    return 1;

  if (t1[1] < t2[1])
    return -1;
  if (t1[1] > t2[1])
    return 1;
  return 0;
}

/* Construct new .gdb_index section in malloced memory
   if it needs adjustment.  */
static void
write_gdb_index (void)
{
  dw_cu_ref cu, cu_next, first_tu = NULL;
  unsigned char *gdb_index, *ptr, *inptr, *end;
  unsigned int ncus = 0, npus = 0, ntus = 0, ndelcus = 0, ver;
  unsigned int culistoff, cutypesoff, addressoff, symboloff, constoff;
  unsigned int *tuindices = NULL, tuidx = 0, *cumap = NULL, i, j, k;
  bool fail = false;

  debug_sections[GDB_INDEX].new_size = 0;
  if (likely (!op_multifile)
      && (debug_sections[GDB_INDEX].data == NULL
	  || debug_sections[GDB_INDEX].size < 0x18))
    return;
  inptr = (unsigned char *) debug_sections[GDB_INDEX].data;
  if (unlikely (op_multifile))
    ver = multi_gdb_index_ver;
  else
    ver = buf_read_ule32 (inptr);
  if (ver < 4 || ver > 8)
    return;

  for (cu = first_cu; cu; cu = cu->cu_next)
    if (cu->cu_kind == CU_PU)
      npus++;
    else if (cu->cu_kind == CU_NORMAL)
      {
	ncus++;
	if (unlikely (fi_multifile) && cu->cu_die->die_remove)
	  ndelcus++;
      }
    else if (cu->cu_kind == CU_TYPES)
      ntus++;

  /* Starting with version 7 CU indexes are limited to 24 bits,
     so if we have more CUs, give up.  */
  if (npus + ncus + ntus - ndelcus >= (1U << 24))
    return;

  if (unlikely (op_multifile))
    {
      assert (ncus == 0 && ntus == 0);
      debug_sections[GDB_INDEX].new_size
	= 0x18 + npus * 16 + 16;
      gdb_index = malloc (debug_sections[GDB_INDEX].new_size);
      if (gdb_index == NULL)
	dwz_oom ();
      debug_sections[GDB_INDEX].new_data = gdb_index;
      /* Write new header.  */
      buf_write_le32 (gdb_index + 0x00, ver);
      buf_write_le32 (gdb_index + 0x04, 0x18);
      buf_write_le32 (gdb_index + 0x08, 0x18 + npus * 16);
      buf_write_le32 (gdb_index + 0x0c, 0x18 + npus * 16);
      buf_write_le32 (gdb_index + 0x10, 0x18 + npus * 16);
      buf_write_le32 (gdb_index + 0x14, 0x18 + npus * 16 + 16);
      ptr = gdb_index + 0x18;
      /* Write new CU list.  */
      for (cu = first_cu; cu; cu = cu->cu_next)
	{
	  unsigned long next_off = debug_sections[DEBUG_INFO].new_size;
	  if (cu->cu_next)
	    next_off = cu->cu_next->cu_new_offset;
	  buf_write_le64 (ptr, cu->cu_new_offset);
	  buf_write_le64 (ptr + 8, next_off - cu->cu_new_offset);
	  ptr += 16;
	}
      /* Write an empty hash table (with two entries).  */
      memset (ptr, '\0', 16);
      return;
    }

  culistoff = buf_read_ule32 (inptr + 0x04);
  cutypesoff = buf_read_ule32 (inptr + 0x08);
  addressoff = buf_read_ule32 (inptr + 0x0c);
  symboloff = buf_read_ule32 (inptr + 0x10);
  constoff = buf_read_ule32 (inptr + 0x14);
  if (culistoff != 0x18
      || cutypesoff != 0x18 + ncus * 16
      || addressoff != cutypesoff + ntus * 24
      || symboloff < addressoff
      || ((symboloff - addressoff) % 20) != 0
      || constoff < symboloff
      || ((constoff - symboloff) & (constoff - symboloff - 1)) != 0
      || ((constoff - symboloff) & 7) != 0
      || debug_sections[GDB_INDEX].size < constoff)
    return;
  inptr += 0x18;
  if (ndelcus)
    cumap = (unsigned int *)
	    obstack_alloc (&ob2, ncus * sizeof (unsigned int));
  for (cu = first_cu, i = 0, j = 0; cu; cu = cu->cu_next)
    if (cu->cu_kind == CU_NORMAL)
      {
	if (buf_read_ule64 (inptr) != cu->cu_offset)
	  {
	    if (cumap)
	      obstack_free (&ob2, (void *) cumap);
	    return;
	  }
	inptr += 16;
	if (cumap)
	  {
	    if (cu->cu_die->die_remove)
	      cumap[i++] = -1U;
	    else
	      cumap[i++] = j++;
	  }
      }
    else if (cu->cu_kind == CU_TYPES)
      {
	if (tuindices == NULL)
	  {
	    tuindices = (unsigned int *)
			obstack_alloc (&ob2, ntus * 2 * sizeof (unsigned int));
	    first_tu = cu;
	  }
	tuindices[2 * tuidx] = buf_read_ule64 (inptr);
	tuindices[2 * tuidx + 1] = tuidx * 24;
	tuidx++;
	inptr += 24;
      }
  if (ntus)
    {
      qsort (tuindices, ntus, 2 * sizeof (unsigned int), gdb_index_tu_cmp);
      for (tuidx = 0, cu = first_tu; tuidx < ntus; tuidx++, cu = cu->cu_next)
	if (tuindices[2 * tuidx] != cu->cu_offset)
	  {
	    if (cumap)
	      obstack_free (&ob2, (void *) cumap);
	    else
	      obstack_free (&ob2, (void *) tuindices);
	    return;
	  }
    }

  if (multifile
      && !fi_multifile
      && !low_mem
      && multi_gdb_index_ver < ver)
    multi_gdb_index_ver = ver;

  debug_sections[GDB_INDEX].new_size
    = debug_sections[GDB_INDEX].size + npus * 16 - ndelcus * 16;
  gdb_index = malloc (debug_sections[GDB_INDEX].new_size);
  if (gdb_index == NULL)
    dwz_oom ();
  debug_sections[GDB_INDEX].new_data = gdb_index;
  /* Write new header.  */
  buf_write_le32 (gdb_index + 0x00, ver);
  buf_write_le32 (gdb_index + 0x04, culistoff);
  buf_write_le32 (gdb_index + 0x08, cutypesoff + npus * 16 - ndelcus * 16);
  buf_write_le32 (gdb_index + 0x0c, addressoff + npus * 16 - ndelcus * 16);
  buf_write_le32 (gdb_index + 0x10, symboloff + npus * 16 - ndelcus * 16);
  buf_write_le32 (gdb_index + 0x14, constoff + npus * 16 - ndelcus * 16);
  ptr = gdb_index + 0x18;
  /* Write new CU list.  */
  for (cu = first_cu; cu; cu = cu_next)
    {
      unsigned long next_off = debug_sections[DEBUG_INFO].new_size;
      if (cu->cu_kind == CU_TYPES)
	break;
      cu_next = cu->cu_next;
      if (unlikely (fi_multifile))
	{
	  while (cu_next
		 && cu_next->cu_kind == CU_NORMAL
		 && cu_next->cu_die->die_remove)
	    cu_next = cu_next->cu_next;
	  if (cu->cu_die->die_remove)
	    continue;
	}
      if (cu_next && cu_next->cu_kind != CU_TYPES)
	next_off = cu_next->cu_new_offset;
      buf_write_le64 (ptr, cu->cu_new_offset);
      buf_write_le64 (ptr + 8, next_off - cu->cu_new_offset);
      ptr += 16;
    }
  /* Write new TU list.  */
  for (tuidx = 0; cu; cu = cu->cu_next, tuidx++)
    {
      unsigned char *p;
      unsigned int tuoff = tuindices[2 * tuidx + 1];
      dw_die_ref ref;
      assert (cu->cu_kind == CU_TYPES);
      buf_write_le64 (ptr + tuoff, cu->cu_new_offset);
      p = debug_sections[DEBUG_TYPES].data + cu->cu_offset + 19;
      ref = off_htab_lookup (cu, cu->cu_offset + read_32 (p));
      assert (ref && ref->die_dup == NULL);
      buf_write_le64 (ptr + tuoff + 8, ref->u.p2.die_new_offset);
      p -= 12;
      buf_write_le64 (ptr + tuoff + 16, read_64 (p));
    }
  ptr += ntus * 24;
  end = inptr + (symboloff - addressoff);
  /* Copy address area, adjusting all CU indexes.  */
  while (inptr < end)
    {
      memcpy (ptr, inptr, 16);
      i = buf_read_ule32 (inptr + 16);
      if (cumap && i < ncus)
	{
	  if (cumap[i] == -1U)
	    fail = true;
	  i = cumap[i] + npus;
	}
      else
	i += npus - ndelcus;
      buf_write_le32 (ptr + 16, i);
      ptr += 20;
      inptr += 20;
    }
  /* Copy the symbol hash table.  */
  memcpy (ptr, inptr, constoff - symboloff);
  /* Clear the const pool initially.  */
  memset (ptr + (constoff - symboloff), '\0',
	  debug_sections[GDB_INDEX].size - constoff);
  ptr = ptr + (constoff - symboloff);
  end = inptr + (constoff - symboloff);
  /* Finally copy over const objects into the const pool, strings as is,
     CU vectors with CU indexes adjusted.  */
  while (inptr < end)
    {
      unsigned int name = buf_read_ule32 (inptr);
      unsigned int cuvec = buf_read_ule32 (inptr + 4);

      inptr += 8;
      if (name == 0 && cuvec == 0)
	continue;
      if (name > debug_sections[GDB_INDEX].size - constoff - 1
	  || cuvec > debug_sections[GDB_INDEX].size - constoff - 4)
	{
	fail:
	  free (gdb_index);
	  debug_sections[GDB_INDEX].new_size = 0;
	  return;
	}
      if (ptr[name] == '\0')
	{
	  unsigned char *strend = end + name;
	  while (*strend != '\0')
	    {
	      if (strend + 1
		  == end + (debug_sections[GDB_INDEX].size - constoff))
		goto fail;
	      strend++;
	    }
	  memcpy (ptr + name, end + name, strend + 1 - (end + name));
	}
      if (buf_read_ule32 (ptr + cuvec) == 0)
	{
	  unsigned int count = buf_read_ule32 (end + cuvec);
	  if (count * 4
	      > debug_sections[GDB_INDEX].size - constoff - cuvec - 4)
	    goto fail;
	  buf_write_le32 (ptr + cuvec, count);
	  for (i = 0; i < count; i++)
	    {
	      j = buf_read_ule32 (end + cuvec + (i + 1) * 4);
	      if (ver >= 7)
		k = j & ((1U << 24) - 1);
	      else
		k = j;
	      if (cumap && k < ncus)
		{
		  if (cumap[k] == -1U)
		    fail = true;
		  k = cumap[k] + npus;
		}
	      else
		k += npus - ndelcus;
	      if (ver >= 7)
		j = (j & (~0U << 24)) | k;
	      else
		j = k;
	      buf_write_le32 (ptr + cuvec + (i + 1) * 4, j);
	    }
	}
    }
  if (cumap)
    obstack_free (&ob2, (void *) cumap);
  else if (tuindices)
    obstack_free (&ob2, (void *) tuindices);
  if (fail)
    {
      free (debug_sections[GDB_INDEX].new_data);
      debug_sections[GDB_INDEX].new_data = NULL;
      debug_sections[GDB_INDEX].new_size = 0;
    }
}

/* Return a string from section SEC at offset OFFSET.  */
static const char *
strptr (DSO *dso, int sec, off_t offset)
{
  Elf_Scn *scn;
  Elf_Data *data;

  scn = dso->scn[sec];
  if (offset >= 0 && (GElf_Addr) offset < dso->shdr[sec].sh_size)
    {
      data = NULL;
      while ((data = elf_rawdata (scn, data)) != NULL)
	{
	  if (data->d_buf
	      && offset >= data->d_off
	      && offset < (off_t) (data->d_off + data->d_size))
	    return (const char *) data->d_buf + (offset - data->d_off);
	}
    }

  return NULL;
}

/* Initialize do_read_* and do_write_* callbacks based on
   ENDIANITY.  */
static void
init_endian (int endianity)
{
  if (endianity == ELFDATA2LSB)
    {
      do_read_16 = buf_read_ule16;
      do_read_32 = buf_read_ule32;
      do_read_64 = buf_read_ule64;
      do_write_16 = buf_write_le16;
      do_write_32 = buf_write_le32;
      do_write_64 = buf_write_le64;
    }
  else if (endianity == ELFDATA2MSB)
    {
      do_read_16 = buf_read_ube16;
      do_read_32 = buf_read_ube32;
      do_read_64 = buf_read_ube64;
      do_write_16 = buf_write_be16;
      do_write_32 = buf_write_be32;
      do_write_64 = buf_write_be64;
    }
  else
    abort ();
}

/* Read DWARF sections from DSO.  */
static int
read_dwarf (DSO *dso, bool quieter, unsigned int *die_count)
{
  Elf_Data *data;
  Elf_Scn *scn;
  int i, j;

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    if (! (dso->shdr[i].sh_flags & (SHF_ALLOC | SHF_WRITE | SHF_EXECINSTR))
	&& dso->shdr[i].sh_size)
      {
	const char *name = strptr (dso, dso->ehdr.e_shstrndx,
				   dso->shdr[i].sh_name);

	if (strncmp (name, ".debug_", sizeof (".debug_") - 1) == 0
	    || strcmp (name, ".gdb_index") == 0
	    || strcmp (name, ".gnu_debugaltlink") == 0)
	  {
	    if (dso->shdr[i].sh_flags & SHF_COMPRESSED)
	      {
		error (0, 0,
		       "%s: Found compressed %s section, not attempting dwz"
		       " compression",
		       dso->filename, name);
		return 1;
	      }
	    for (j = 0; debug_sections[j].name; ++j)
	      if (strcmp (name, debug_sections[j].name) == 0)
		{
		  if (debug_sections[j].data)
		    {
		      error (0, 0, "%s: Found two copies of %s section",
			     dso->filename, name);
		      return 1;
		    }

		  scn = dso->scn[i];
		  data = elf_rawdata (scn, NULL);
		  assert (data != NULL);
		  if (data->d_buf == NULL)
		    {
		      error (0, 0, "%s: Found empty %s section, not attempting"
			     " dwz compression", dso->filename, name);
		      return 1;
		    }
		  assert (elf_rawdata (scn, data) == NULL);
		  assert (data->d_off == 0);
		  assert (data->d_size == dso->shdr[i].sh_size);
		  debug_sections[j].data = data->d_buf;
		  debug_sections[j].size = data->d_size;
		  debug_sections[j].new_size = data->d_size;
		  debug_sections[j].sec = i;
		  break;
		}

	    if (debug_sections[j].name == NULL)
	      {
		error (0, 0, "%s: Unknown debugging section %s",
		       dso->filename, name);
		return 1;
	      }
	  }
      }

  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB
      || dso->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
    init_endian (dso->ehdr.e_ident[EI_DATA]);
  else
    {
      error (0, 0, "%s: Wrong ELF data encoding", dso->filename);
      return 1;
    }

  if (debug_sections[DEBUG_INFO].data == NULL
      && !rd_multifile)
    {
      if (!quieter)
	error (0, 0, "%s: .debug_info section not present",
	       dso->filename);
      return 3;
    }

  if (debug_sections[DEBUG_SUP].data != NULL && !(dwarf_5 && rd_multifile))
    {
      error (0, 0, "%s: .debug_sup section already present",
	     dso->filename);
      return 1;
    }

  if (debug_sections[GNU_DEBUGALTLINK].data != NULL)
    {
      error (0, 0, "%s: .gnu_debugaltlink section already present",
	     dso->filename);
      return 1;
    }

  int res;
  res = read_debug_info (dso, DEBUG_INFO, die_count);
  if (res == 0 && stats_p)
    print_parse_stats ();
  return res;
}

/* Open an ELF file NAME.  */
static DSO *
fdopen_dso (int fd, const char *name)
{
  Elf *elf = NULL;
  GElf_Ehdr ehdr;
  int i;
  DSO *dso = NULL;

  elf = elf_begin (fd, ELF_C_READ_MMAP, NULL);
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      goto error_out;
    }

  if (elf_kind (elf) != ELF_K_ELF)
    {
      error (0, 0, "\"%s\" is not an ELF file", name);
      goto error_out;
    }

  if (gelf_getehdr (elf, &ehdr) == NULL)
    {
      error (0, 0, "cannot get the ELF header: %s",
	     elf_errmsg (-1));
      goto error_out;
    }

  if (ehdr.e_type != ET_DYN && ehdr.e_type != ET_EXEC
      && (!rd_multifile || ehdr.e_type != ET_REL))
    {
      error (0, 0, "\"%s\" is not a shared library", name);
      goto error_out;
    }

  /* Allocate DSO structure.  */
  dso = (DSO *)
	malloc (sizeof(DSO) + ehdr.e_shnum * sizeof(GElf_Shdr)
		+ ehdr.e_shnum * sizeof(Elf_Scn *)
		+ strlen (name) + 1);
  if (!dso)
    {
      error (0, ENOMEM, "Could not open DSO");
      goto error_out;
    }

  elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT | ELF_F_PERMISSIVE);

  memset (dso, 0, sizeof(DSO));
  dso->elf = elf;
  dso->ehdr = ehdr;
  dso->scn = (Elf_Scn **) &dso->shdr[ehdr.e_shnum];

  for (i = 0; i < ehdr.e_shnum; ++i)
    {
      dso->scn[i] = elf_getscn (elf, i);
      gelf_getshdr (dso->scn[i], dso->shdr + i);
    }

  dso->filename = (const char *) &dso->scn[ehdr.e_shnum];
  strcpy ((char *) &dso->scn[ehdr.e_shnum], name);
  return dso;

error_out:
  free (dso);
  if (elf)
    elf_end (elf);
  if (fd != -1)
    close (fd);
  return NULL;
}

/* Implicit arg for compare_section_numbers.  Could be passed in as explicit arg
   when using qsort_r instead.  */
static DSO *compare_section_numbers_implicit_arg;

/* Helper function for sort_section_numbers.  */
static int
compare_section_numbers (const void *p1, const void *p2)
{
  DSO *dso = compare_section_numbers_implicit_arg;
  const int i1 = *(const int *)p1;
  const int i2 = *(const int *)p2;
  GElf_Off o1;
  GElf_Off o2;

  /* Keep element 0 at 0.  */
  if (i1 == 0 || i2 == 0)
    {
      if (i1 == i2)
	return 0;
      if (i1 == 0)
	return -1;
      if (i2 == 0)
	return 1;
    }

  /* Get file offsets.  */
  o1 = (i1 == dso->ehdr.e_shnum
	? dso->ehdr.e_shoff
	: dso->shdr[i1].sh_offset);
  o2 = (i2 == dso->ehdr.e_shnum
	? dso->ehdr.e_shoff
	: dso->shdr[i2].sh_offset);

  /* Compare file offsets.  */
  if (o1 < o2)
    return -1;
  if (o1 > o2)
    return 1;

  /* In case file offset is the same, keep the original relative order.  */
  if (i1 < i2)
    return -1;
  if (i1 > i2)
    return 1;

  return 0;
}

/* Sort SORTED_SECTION_NUMBERS in file offset order.  */
static void
sort_section_numbers (DSO *dso, unsigned int *sorted_section_numbers)
{
  unsigned int i;
  unsigned int nr_sections = dso->ehdr.e_shnum;

  /* Treat section header table as another section, with index
     dso->ehdr.e_shnum.  */
  nr_sections += 1;

  for (i = 0; i < nr_sections; ++i)
    sorted_section_numbers[i] = i;

  compare_section_numbers_implicit_arg = dso;
  qsort (sorted_section_numbers, nr_sections,
	 sizeof (sorted_section_numbers[0]), compare_section_numbers);
  compare_section_numbers_implicit_arg = NULL;

  assert (sorted_section_numbers[0] == 0);
}

/* Verify file offset and size of sections and section header table.  */
static void
verify_sections (DSO *dso, unsigned int *sorted_section_numbers,
		 GElf_Off *distance, int addsec, GElf_Off addsize,
		 GElf_Ehdr ehdr)
{
  int i, j;
  int prev, update_prev;
  GElf_Off offset, prev_offset, prev_size;
  GElf_Off section_header_table_size
    = dso->ehdr.e_shentsize * ehdr.e_shnum;

  prev = -1;
  for (i = 1; i < (dso->ehdr.e_shnum + 1); ++i, prev = update_prev)
    {
      j = sorted_section_numbers[i];

      if (j != dso->ehdr.e_shnum && dso->shdr[j].sh_type == SHT_NOBITS)
	{
	  update_prev = prev;
	  continue;
	}
      update_prev = j;

      if (prev == -1)
	continue;

      offset = (j == dso->ehdr.e_shnum
		? ehdr.e_shoff
		: dso->shdr[j].sh_offset);

      prev_offset = (prev == dso->ehdr.e_shnum
		     ? ehdr.e_shoff
		     : dso->shdr[prev].sh_offset);

      prev_size = (prev == dso->ehdr.e_shnum
		   ? section_header_table_size
		   : (dso->shdr[prev].sh_type == SHT_NOBITS
		      ? 0
		      : dso->shdr[prev].sh_size));

      if (distance != NULL)
	assert ((prev_offset + prev_size + distance[prev]
		 + (prev == addsec ? addsize : 0))
		== offset);
      else
	assert ((prev_offset + prev_size + (prev == addsec ? addsize : 0))
		<= offset);
    }
}

/* Calculate distance between sections and section header table.  */
static int
calculate_section_distance (DSO *dso, unsigned int *sorted_section_numbers,
			    GElf_Off *distance)
{
  int i, j;
  int prev, update_prev;
  GElf_Off offset, prev_offset, prev_size;
  GElf_Off section_header_table_size
    = dso->ehdr.e_shentsize * dso->ehdr.e_shnum;

  prev = -1;
  for (i = 1; i < (dso->ehdr.e_shnum + 1); ++i, prev = update_prev)
    {
      j = sorted_section_numbers[i];

      if (j != dso->ehdr.e_shnum && dso->shdr[j].sh_type == SHT_NOBITS)
	{
	  update_prev = prev;
	  continue;
	}
      update_prev = j;

      if (prev == -1)
	continue;

      offset = (j == dso->ehdr.e_shnum
		? dso->ehdr.e_shoff
		: dso->shdr[j].sh_offset);

      prev_offset = (prev == dso->ehdr.e_shnum
		     ? dso->ehdr.e_shoff
		     : dso->shdr[prev].sh_offset);

      prev_size = (prev == dso->ehdr.e_shnum
		   ? section_header_table_size
		   : dso->shdr[prev].sh_size);

      if (prev_offset + prev_size > offset)
	{
	  error (0, 0, "Section overlap detected");
	  if (prev == dso->ehdr.e_shnum)
	    error (0, 0, "Section header table: [0x%llx, 0x%llx)",
		   (unsigned long long)prev_offset,
		   (unsigned long long)(prev_offset + prev_size));
	  else
	    error (0, 0, "Section %d: [0x%llx, 0x%llx)", j,
		   (unsigned long long)prev_offset,
		   (unsigned long long)(prev_offset + prev_size));
	  if (j == dso->ehdr.e_shnum)
	    error (0, 0, "Section header table: 0x%llx",
		   (unsigned long long)offset);
	  else
	    error (0, 0, "Section %d: 0x%llx", j, (unsigned long long)offset);
	  return 1;
	}

      distance[prev] = offset - (prev_offset + prev_size);
    }

  verify_sections (dso, sorted_section_numbers, distance, -1, 0, dso->ehdr);

  return 0;
}

/* Store new ELF into FILE.  debug_sections array contains
   new_data/new_size pairs where needed.  */
static int
write_dso (DSO *dso, const char *file, struct stat *st, bool save_to_temp)
{
  Elf *elf = NULL;
  GElf_Ehdr ehdr;
  GElf_Off min_shoff = ~(GElf_Off) 0;
  char *e_ident;
  int fd, i, j, addsec = -1, ret;
  GElf_Off off, diff, addsize = 0;
  char *filename = NULL;
  GElf_Word shstrtabadd = 0;
  char *shstrtab = NULL;
  bool remove_sections[SECTION_COUNT];
  GElf_Off distance[dso->ehdr.e_shnum + 1];
  /* Array of sections and section header table sorted by file offset.  */
  unsigned int sorted_section_numbers[dso->ehdr.e_shnum + 1];
  GElf_Off old_sh_offset[dso->ehdr.e_shnum];

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "write_dso\n");
    }

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    old_sh_offset[i] = dso->shdr[i].sh_offset;

  memset (remove_sections, '\0', sizeof (remove_sections));
  ehdr = dso->ehdr;

  sort_section_numbers (dso, sorted_section_numbers);
  if (calculate_section_distance (dso, sorted_section_numbers, distance))
    return 1;

  for (i = 0; debug_sections[i].name; i++)
    if (debug_sections[i].new_size != debug_sections[i].size)
      {
	if (debug_sections[i].size == 0
	    && debug_sections[i].sec == 0)
	  {
	    unsigned int len;
	    if (addsec == -1)
	      for (j = 0; debug_sections[j].name; j++)
		if (debug_sections[j].new_size
		    && debug_sections[j].sec
		    && debug_sections[j].sec > addsec)
		  addsec = debug_sections[j].sec;
	    ehdr.e_shnum++;
	    if (ehdr.e_shoff < min_shoff)
	      min_shoff = ehdr.e_shoff;
	    for (j = 1; j < dso->ehdr.e_shnum; ++j)
	      {
		if (dso->shdr[j].sh_offset > ehdr.e_shoff)
		  dso->shdr[j].sh_offset += ehdr.e_shentsize;
		if (dso->shdr[j].sh_link > (unsigned int) addsec)
		  dso->shdr[j].sh_link++;
		if ((dso->shdr[j].sh_type == SHT_REL
		     || dso->shdr[j].sh_type == SHT_RELA
		     || (dso->shdr[j].sh_flags & SHF_INFO_LINK))
		    && dso->shdr[j].sh_info
		       > (unsigned int) addsec)
		  dso->shdr[j].sh_info++;
	      }
	    if (dso->ehdr.e_shstrndx > addsec)
	      ehdr.e_shstrndx++;
	    len = strlen (debug_sections[i].name) + 1;
	    dso->shdr[dso->ehdr.e_shstrndx].sh_size += len;
	    if (dso->shdr[dso->ehdr.e_shstrndx].sh_offset < min_shoff)
	      min_shoff = dso->shdr[dso->ehdr.e_shstrndx].sh_offset;
	    for (j = 1; j < dso->ehdr.e_shnum; ++j)
	      if (dso->shdr[j].sh_offset
		  > dso->shdr[dso->ehdr.e_shstrndx].sh_offset)
		dso->shdr[j].sh_offset += len;
	    if (ehdr.e_shoff > dso->shdr[dso->ehdr.e_shstrndx].sh_offset)
	      ehdr.e_shoff += len;
	    shstrtabadd += len;
	    diff = debug_sections[i].new_size;
	    addsize += diff;
	    off = dso->shdr[addsec].sh_offset;
	  }
	else
	  {
	    diff = (GElf_Off) debug_sections[i].new_size
		   - (GElf_Off) dso->shdr[debug_sections[i].sec].sh_size;
	    off = dso->shdr[debug_sections[i].sec].sh_offset;
	  }
	if (off < min_shoff)
	  min_shoff = off;
	for (j = 1; j < dso->ehdr.e_shnum; ++j)
	  if (dso->shdr[j].sh_offset > off)
	    dso->shdr[j].sh_offset += diff;
	if (ehdr.e_shoff > off)
	  ehdr.e_shoff += diff;
	dso->shdr[debug_sections[i].sec].sh_size
	  = debug_sections[i].new_size;
	if (debug_sections[i].new_size == 0)
	  {
	    remove_sections[i] = true;
	    ehdr.e_shnum--;
	    if (ehdr.e_shoff < min_shoff)
	      min_shoff = ehdr.e_shoff;
	    for (j = 1; j < dso->ehdr.e_shnum; ++j)
	      {
		if (dso->shdr[j].sh_offset > ehdr.e_shoff)
		  dso->shdr[j].sh_offset -= ehdr.e_shentsize;
		if (dso->shdr[j].sh_link
		    > (unsigned int) debug_sections[i].sec)
		  dso->shdr[j].sh_link--;
		if ((dso->shdr[j].sh_type == SHT_REL
		     || dso->shdr[j].sh_type == SHT_RELA
		     || (dso->shdr[j].sh_flags & SHF_INFO_LINK))
		    && dso->shdr[j].sh_info
		       > (unsigned int) debug_sections[i].sec)
		  dso->shdr[j].sh_info--;
	      }
	    if (dso->ehdr.e_shstrndx > debug_sections[i].sec)
	      ehdr.e_shstrndx--;
	  }
      }

  /* Verify that we did not change section layout, by checking that the
     distances between sections and section header table remained the same.  */
  verify_sections (dso, sorted_section_numbers, distance, addsec, addsize,
		   ehdr);

  if (min_shoff != ~(GElf_Off) 0)
    {
      for (j = 1; j < dso->ehdr.e_shnum; ++j)
	if (dso->shdr[j].sh_offset >= min_shoff
	    && dso->shdr[j].sh_addralign > 1
	    && (dso->shdr[j].sh_offset & (dso->shdr[j].sh_addralign - 1)) != 0)
	  break;
      if (j < dso->ehdr.e_shnum
	  || (ehdr.e_shoff >= min_shoff
	      && (ehdr.e_shoff & (ehdr.e_ident[EI_CLASS] == ELFCLASS64
				  ? 7 : 3)) != 0))
	{
	  /* Need to fix up sh_offset/e_shoff.  Punt if all the sections
	     >= min_shoff aren't non-ALLOC.  */
	  GElf_Off last_shoff = 0;
	  int k = -1;
	  int l;
	  for (l = 1; l <= dso->ehdr.e_shnum; ++l)
	    {
	      j = sorted_section_numbers[l];
	      if (j == dso->ehdr.e_shnum)
		continue;
	      else if (!last_shoff
		       && (dso->shdr[j].sh_offset < min_shoff
			   || (dso->shdr[j].sh_offset == min_shoff
			       && (dso->shdr[j].sh_size == 0
				   || dso->shdr[j].sh_type == SHT_NOBITS))))
		continue;
	      else if (dso->shdr[j].sh_type == SHT_NOBITS)
		continue;
	      else if ((dso->shdr[j].sh_flags & SHF_ALLOC) != 0)
		{
		  error (0, 0, "Allocatable section in %s after "
			 "non-allocatable ones", dso->filename);
		  return 1;
		}
	      else
		{
		  assert (dso->shdr[j].sh_offset >= last_shoff);

		  if (k == -1)
		    k = l;
		  last_shoff = dso->shdr[j].sh_offset + dso->shdr[j].sh_size;
		}
	    }
	  last_shoff = min_shoff;
	  for (l = k; l <= dso->ehdr.e_shnum; ++l)
	    {
	      j = sorted_section_numbers[l];
	      if (j == dso->ehdr.e_shnum)
		{
		  if (ehdr.e_ident[EI_CLASS] == ELFCLASS64)
		    ehdr.e_shoff = (last_shoff + 7) & -8;
		  else
		    ehdr.e_shoff = (last_shoff + 3) & -4;
		  last_shoff = ehdr.e_shoff + ehdr.e_shnum * ehdr.e_shentsize;
		  continue;
		}
	      /* Ignore SHT_NOBITS sections.  */
	      if (dso->shdr[j].sh_type == SHT_NOBITS)
		continue;
	      dso->shdr[j].sh_offset = last_shoff;
	      if (dso->shdr[j].sh_addralign > 1)
		dso->shdr[j].sh_offset
		  = (last_shoff + dso->shdr[j].sh_addralign - 1)
		    & ~(dso->shdr[j].sh_addralign - (GElf_Off) 1);
	      last_shoff = dso->shdr[j].sh_offset + dso->shdr[j].sh_size;
	      if (addsec != -1 && j == addsec)
		last_shoff += addsize;
	    }
	}
    }

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    if (dso->shdr[i].sh_type == SHT_NOBITS)
      dso->shdr[i].sh_offset = old_sh_offset[i];

  verify_sections (dso, sorted_section_numbers, NULL, addsec, addsize,
		   ehdr);

  if (shstrtabadd != 0)
    {
      shstrtab = (char *) malloc (dso->shdr[dso->ehdr.e_shstrndx].sh_size);
      if (shstrtab == NULL)
	{
	  error (0, ENOMEM, "Failed to adjust .shstrtab for %s",
		 dso->filename);
	  return 1;
	}
    }

  if (file == NULL)
    {
      size_t len = strlen (dso->filename);
      filename = alloca (len + sizeof (".#dwz#.XXXXXX"));
      memcpy (filename, dso->filename, len);
      memcpy (filename + len, ".#dwz#.XXXXXX", sizeof (".#dwz#.XXXXXX"));
      fd = mkstemp (filename);
      file = (const char *) filename;
      if (fd == -1)
	{
	  error (0, errno, "Failed to create temporary file for %s",
		 dso->filename);
	  free (shstrtab);
	  return 1;
	}
    }
  else
    {
      fd = open (file, O_RDWR | O_CREAT, 0600);
      if (fd == -1)
	{
	  error (0, errno, "Failed to open %s for writing", file);
	  free (shstrtab);
	  return 1;
	}
    }

  elf = elf_begin (fd, ELF_C_WRITE, NULL);
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      unlink (file);
      close (fd);
      free (shstrtab);
      return 1;
    }

  /* Some gelf_newehdr implementations don't return the resulting
     ElfNN_Ehdr, so we have to do it the hard way instead of:
     e_ident = (char *) gelf_newehdr (elf, gelf_getclass (dso->elf));  */
  switch (gelf_getclass (dso->elf))
    {
    case ELFCLASS32:
      e_ident = (char *) elf32_newehdr (elf);
      break;
    case ELFCLASS64:
      e_ident = (char *) elf64_newehdr (elf);
      break;
    default:
      e_ident = NULL;
      break;
    }

  if (e_ident == NULL
      /* This is here just for the gelfx wrapper, so that gelf_update_ehdr
	 already has the correct ELF class.  */
      || memcpy (e_ident, dso->ehdr.e_ident, EI_NIDENT) == NULL
      || gelf_update_ehdr (elf, &ehdr) == 0
      || gelf_newphdr (elf, ehdr.e_phnum) == 0)
    {
      error (0, 0, "Could not create new ELF headers");
      unlink (file);
      elf_end (elf);
      close (fd);
      free (shstrtab);
      return 1;
    }
  elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT | ELF_F_PERMISSIVE);
  for (i = 0; i < ehdr.e_phnum; ++i)
    {
      GElf_Phdr *phdr, phdr_mem;
      phdr = gelf_getphdr (dso->elf, i, &phdr_mem);
      gelf_update_phdr (elf, i, phdr);
    }

  for (i = 1; i < dso->ehdr.e_shnum; ++i)
    {
      Elf_Scn *scn;
      Elf_Data *data1, *data2;

      for (j = 0; debug_sections[j].name; j++)
	if (i == debug_sections[j].sec)
	  break;
      if (debug_sections[j].name && remove_sections[j])
	continue;
      scn = elf_newscn (elf);
      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
      gelf_update_shdr (scn, &dso->shdr[i]);
      data1 = elf_getdata (dso->scn[i], NULL);
      data2 = elf_newdata (scn);
      memcpy (data2, data1, sizeof (*data1));
      if (debug_sections[j].name
	  && debug_sections[j].new_data != NULL)
	{
	  data2->d_buf = debug_sections[j].new_data;
	  data2->d_size = dso->shdr[i].sh_size;
	}
      if (i == dso->ehdr.e_shstrndx && shstrtabadd)
	{
	  memcpy (shstrtab, data1->d_buf,
		  dso->shdr[dso->ehdr.e_shstrndx].sh_size
		  - shstrtabadd);
	  data2->d_buf = shstrtab;
	  data2->d_size = dso->shdr[i].sh_size;
	}
      if (i == addsec)
	{
	  GElf_Word sh_name = dso->shdr[dso->ehdr.e_shstrndx].sh_size
			      - shstrtabadd;
	  GElf_Shdr shdr;

	  off = dso->shdr[i].sh_offset + dso->shdr[i].sh_size;
	  for (j = 0; debug_sections[j].name; j++)
	    if (debug_sections[j].new_size
		&& debug_sections[j].size == 0
		&& debug_sections[j].sec == 0)
	      {
		scn = elf_newscn (elf);
		elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
		memset (&shdr, '\0', sizeof (shdr));
		shdr.sh_name = sh_name;
		sh_name += strlen (debug_sections[j].name) + 1;
		strcpy (shstrtab + shdr.sh_name, debug_sections[j].name);
		shdr.sh_type = SHT_PROGBITS;
		shdr.sh_offset = off;
		shdr.sh_size = debug_sections[j].new_size;
		shdr.sh_addralign = 1;
		off += shdr.sh_size;
		gelf_update_shdr (scn, &shdr);
		data2 = elf_newdata (scn);
		data2->d_buf = debug_sections[j].new_data;
		data2->d_type = ELF_T_BYTE;
		data2->d_version = EV_CURRENT;
		data2->d_size = shdr.sh_size;
		data2->d_off = 0;
		data2->d_align = 1;
	      }
	}
    }

  if (elf_update (elf, ELF_C_WRITE_MMAP) == -1)
    {
      error (0, 0, "%s: elf_update failed", dso->filename);
      unlink (file);
      elf_end (elf);
      close (fd);
      free (shstrtab);
      return 1;
    }

  if (elf_end (elf) < 0)
    {
      error (0, 0, "elf_end failed: %s", elf_errmsg (elf_errno ()));
      unlink (file);
      elf_end (elf);
      close (fd);
      free (shstrtab);
      return 1;
    }

  free (shstrtab);
  ret = fchown (fd, st->st_uid, st->st_gid);
  fchmod (fd, st->st_mode & 07777);
  close (fd);

  if (filename != NULL && rename (filename, dso->filename))
    {
      error (0, errno, "Failed to rename temporary file over %s",
	     dso->filename);
      unlink (file);
      /* | (ret & 1) to silence up __wur warning for fchown.  */
      return 1 | (ret & 1);
    }
  if (save_to_temp)
    {
      const char *prefix = "dwz.";
      size_t buf_len = strlen (prefix) + strlen (dso->filename) + 1;
      char *buf = (char *)alloca (buf_len);
      size_t offset = 0;
      strcpy (&buf[offset], prefix);
      offset += strlen (prefix);
      strcpy (&buf[offset], dso->filename);
      offset += strlen (dso->filename);
      assert (offset == buf_len - 1);
      assert (buf[offset] == '\0');
      unlink (buf);
      if (link (dso->filename, buf) != 0)
	{
	  error (0, errno, "Failed to link file: %s", dso->filename);
	  return 1;
	}
    }
  return 0;
}

/* Free memory and clear global variables.  */
static void
cleanup (void)
{
  dw_cu_ref cu;
  unsigned int i;

  for (cu = first_cu; cu; cu = cu->cu_next)
    {
      if (cu->cu_new_abbrev)
	htab_delete (cu->cu_new_abbrev);
      cu->cu_new_abbrev = NULL;
    }
  if (off_htab != NULL)
    {
      if (tracing)
	htab_report (off_htab, "off_htab final");
      htab_delete (off_htab);
    }
  off_htab = NULL;
  if (types_off_htab != NULL)
    htab_delete (types_off_htab);
  types_off_htab = NULL;
  if (loc_htab != NULL)
    htab_delete (loc_htab);
  loc_htab = NULL;
  if (loclists_htab != NULL)
    htab_delete (loclists_htab);
  loclists_htab = NULL;
  if (dup_htab != NULL)
    htab_delete (dup_htab);
  dup_htab = NULL;
  if (strp_htab != NULL)
    htab_delete (strp_htab);
  strp_htab = NULL;
  if (line_htab != NULL)
    htab_delete (line_htab);
  line_htab = NULL;
  if (macro_htab != NULL)
    htab_delete (macro_htab);
  macro_htab = NULL;
  if (meta_abbrev_htab != NULL)
    htab_delete (meta_abbrev_htab);
  meta_abbrev_htab = NULL;

  for (i = 0; i < SAVED_SECTIONS; ++i)
    {
      free (saved_new_data[i]);
      saved_new_data[i] = NULL;
    }

  obstack_free (&ob2, NULL);
  obstack_free (&ob, NULL);
  memset (&ob2, '\0', sizeof (ob2));
  memset (&ob, '\0', sizeof (ob2));
  die_nontoplevel_freelist = NULL;
  die_collapsed_child_freelist = NULL;
  pool_destroy ();
  first_cu = NULL;
  last_cu = NULL;
  ptr_size = 0;
  max_nattr = 0;
  do_read_16 = NULL;
  do_read_32 = NULL;
  do_read_64 = NULL;
  do_write_16 = NULL;
  do_write_32 = NULL;
  do_write_64 = NULL;
  edge_freelist = NULL;
  multifile_mode = 0;
  max_strp_off = 0;
  max_line_id = 0;
}

/* Propagate the die_no_multifile property along the duplicate chain of which
   DIE is a member.  If the property was changed on any die, set *CHANGED to
   true.  */
static void
propagate_multifile_duplicate_chain (dw_die_ref die, bool *changed)
{
  dw_die_ref dup = first_dup (die);
  if (!dup)
    return;

  while (dup && dup->die_offset == -1U)
    dup = dup->die_nextdup;
  if (dup != die)
    return;

  bool any_no_multifile = false;
  bool any_multifile = false;
  bool prop_needed = false;
  dw_die_ref d;
  for (d = dup; d && !prop_needed; d = d->die_nextdup)
    {
      if (d->die_no_multifile)
	any_no_multifile = true;
      else
	any_multifile = true;
      prop_needed = any_no_multifile && any_multifile;
    }
  if (!prop_needed)
    return;

  *changed = true;

  for (d = dup; d; d = d->die_nextdup)
    d->die_no_multifile = 1;
}

/* Propagate the die_no_multifile property backwards along the outgoing
   references of DIE, which is a member of CU and of the subtree of lower
   toplevel die TOP_DIE.  If the property was changed on any die, set *CHANGED
   to true.  */
static void
propagate_multifile_refs_backward (dw_cu_ref cu, dw_die_ref top_die,
				   dw_die_ref die, bool *changed)
{
  struct abbrev_tag *t = die->die_abbrev;
  unsigned int i;
  unsigned char *ptr;
  dw_die_ref child;

  if (die->die_offset == -1U)
    return;

  ptr = debug_sections[DEBUG_INFO].data + die->die_offset;
  skip_leb128 (ptr);
  for (i = 0; i < t->nattr; ++i)
    {
      uint32_t form = t->attr[i].form;
      uint64_t value;
      dw_die_ref ref, reft;

      while (form == DW_FORM_indirect)
	form = read_uleb128 (ptr);

      switch (form)
	{
	case DW_FORM_ref_addr:
	  value = read_size (ptr, cu->cu_version == 2 ? ptr_size : 4);
	  ptr += cu->cu_version == 2 ? ptr_size : 4;
	  ref = off_htab_lookup (cu, value);
	  goto finish_ref;
	  break;
	case DW_FORM_ref_udata:
	case DW_FORM_ref1:
	case DW_FORM_ref2:
	case DW_FORM_ref4:
	case DW_FORM_ref8:
	  switch (form)
	    {
	    case DW_FORM_ref_udata: value = read_uleb128 (ptr); break;
	    case DW_FORM_ref1: value = read_8 (ptr); break;
	    case DW_FORM_ref2: value = read_16 (ptr); break;
	    case DW_FORM_ref4: value = read_32 (ptr); break;
	    case DW_FORM_ref8: value = read_64 (ptr); break;
	    default: abort ();
	    }
	  if (t->attr[i].attr == DW_AT_sibling)
	    break;
	  ref = off_htab_lookup (cu, cu->cu_offset + value);
	finish_ref:
	  reft = ref;
	  while (!reft->die_root
		 && reft->die_parent->die_tag != DW_TAG_compile_unit
		 && reft->die_parent->die_tag != DW_TAG_partial_unit
		 && !reft->die_parent->die_named_namespace)
	    reft = reft->die_parent;
	  if (reft->die_root)
	    ;
	  else if (reft->die_ck_state == CK_KNOWN
		   && !top_die->die_no_multifile && reft->die_no_multifile)
	    {
	      top_die->die_no_multifile = 1;
	      *changed = true;
	    }
	  break;
	default:
	  ptr = skip_attr_no_dw_form_indirect (cu->cu_version, form, ptr);
	}
    }

  for (child = die->die_child; child; child = child->die_sib)
    propagate_multifile_refs_backward (cu, top_die, child, changed);
}

/* Do propagation of the die_no_multifile property that was not covered in
   checksum_die and checksum_ref_die.  */
static void
propagate_multifile (void)
{
  bool changed;
  dw_cu_ref cu;
  dw_die_ref die;

  changed = false;

  FOREACH_CU_NORMAL_LOW_TOPLEVEL_DIE (cu, die)
    propagate_multifile_duplicate_chain (die, &changed);

  if (!changed)
    return;

  do
    {
      changed = false;

      FOREACH_CU_NORMAL_LOW_TOPLEVEL_DIE (cu, die)
	propagate_multifile_refs_backward (cu, die, die, &changed);

      FOREACH_CU_NORMAL_LOW_TOPLEVEL_DIE (cu, die)
	propagate_multifile_duplicate_chain (die, &changed);
    }
  while (changed);
}

/* Returns true if DIE contains any toplevel children that can be
   potentially shared between different executables or shared libraries.  */
static bool
check_multifile (dw_die_ref die)
{
  dw_die_ref child;

  die->die_no_multifile = 1;
  for (child = die->die_child; child; child = child->die_sib)
    if (child->die_named_namespace)
      {
	if (check_multifile (child))
	  die->die_no_multifile = 0;
      }
    else if (child->die_offset == -1U)
      {
	if (child->die_nextdup && child->die_nextdup->die_dup == child)
	  {
	    if (child->die_nextdup->die_ck_state == CK_KNOWN
		&& child->die_nextdup->die_no_multifile == 0)
	      {
		child->die_no_multifile = 0;
		die->die_no_multifile = 0;
	      }
	    else
	      child->die_no_multifile = 1;
	  }
	else
	  child->die_no_multifile = 1;
      }
    else
      {
	child->die_op_type_referenced = 0;
	if (child->die_dup == NULL
	    && child->die_ck_state == CK_KNOWN
	    && child->die_no_multifile == 0)
	  die->die_no_multifile = 0;
	else
	  child->die_no_multifile = 1;
      }
  return die->die_no_multifile == 0;
}

/* Helper function for write_multifile_strp to sort strp_entry
   by increasing new_off.  */
static int
strp_off_cmp (const void *p, const void *q)
{
  struct strp_entry *s1 = *(struct strp_entry **)p;
  struct strp_entry *s2 = *(struct strp_entry **)q;
  if (s1->new_off < s2->new_off)
    return -1;
  if (s1->new_off > s2->new_off)
    return 1;
  return 0;
}

/* Write tail optimized strings into the temporary .debug_str file.  */
static int
write_multifile_strp (void)
{
  unsigned int count = htab_elements (strp_htab), i, buf_alloc, buf_size;
  struct strp_entry **arr = (struct strp_entry **)
			    obstack_alloc (&ob, count * sizeof (*arr));
  struct strp_entry **end = arr;
  unsigned char *buf;
  int ret = 0;

  htab_traverse (strp_htab, list_strp_entries, (void *) &end);
  assert (arr + count == end);
  qsort (arr, count, sizeof (struct strp_entry *), strp_off_cmp);
  buf_alloc = max_strp_off - debug_sections[DEBUG_STR].size;
  if (buf_alloc > 131072)
    buf_alloc = 131072;
  buf = (unsigned char *) obstack_alloc (&ob, buf_alloc);
  buf_size = 0;
  for (i = 0; i < count; i++)
    {
      unsigned char *p = debug_sections[DEBUG_STR].data + arr[i]->off;
      unsigned int len = strlen ((char *) p) + 1;
      if (buf_alloc - buf_size < len)
	{
	  if (buf_size
	      && write (multi_str_fd, buf, buf_size) != (ssize_t) buf_size)
	    {
	      ret = 1;
	      break;
	    }
	  buf_size = 0;
	  if (buf_alloc < len)
	    {
	      if (write (multi_str_fd, p, len) != (ssize_t) len)
		{
		  ret = 1;
		  break;
		}
	      continue;
	    }
	}
      memcpy (buf + buf_size, p, len);
      buf_size += len;
    }
  if (buf_size
      && ret == 0
      && write (multi_str_fd, buf, buf_size) != (ssize_t) buf_size)
    ret = 1;
  obstack_free (&ob, (void *) arr);
  return ret;
}

/* Hold some statistics on the line entries so we know whether to emit
   time and/or sizes.  Used by list_line_entries used by
   write_multifile_line.  */
struct line_stats
{
  struct line_entry ***end;
  bool has_time;
  bool has_size;
};

/* Helper to find the end of the line_htab entries and other stats.
   Called through htab_traverse.  */
static int
list_line_entries (void **slot, void *data)
{
  struct line_stats *stats = (struct line_stats *) data;
  struct line_entry *entry = (struct line_entry *) *slot;
  struct line_entry ***end = stats->end;
  **end = entry;
  (*end)++;
  if (entry->file->time != 0)
    stats->has_time = true;
  if (entry->file->size != 0)
    stats->has_size = true;
  return 1;
}

/* Helper function for write_multifile_strp to sort line_entry
   by increasing new_id.  */
static int
line_id_cmp (const void *p, const void *q)
{
  struct line_entry *s1 = *(struct line_entry **)p;
  struct line_entry *s2 = *(struct line_entry **)q;
  if (s1->new_id < s2->new_id)
    return -1;
  if (s1->new_id > s2->new_id)
    return 1;
  return 0;
}

/* Write a minimal .debug_line entry.  If not op_multifile, write it
   into the temporary .debug_line file (if line_htab is non-NULL, fill
   its directory and file table from it, otherwise emit an entry
   with no directories or files), if op_multifile, store the entry
   into debug_sections[DEBUG_LINE].new_data which it allocates.  */
static int
write_multifile_line (void)
{
  unsigned int filecnt = 0, dircnt = 0, filetbllen = 0, dirtbllen = 0;
  unsigned int header_len, len, i, j;
  unsigned char *line, *ptr;
  struct line_entry **filearr = NULL;
  struct line_stats line_stats;
  unsigned int *diridx = NULL, *dirarr = NULL;
  unsigned char buf[45]; /* Max header_len, see below.  */
  int ret = 0;

  line_stats.has_time = line_stats.has_size = false;
  if (line_htab)
    {
      struct line_entry **end;
      filecnt = htab_elements (line_htab);
      filearr = (struct line_entry **)
		obstack_alloc (&ob, filecnt * sizeof (*filearr));
      end = filearr;
      line_stats.end = &end;
      htab_traverse (line_htab, list_line_entries, (void *) &line_stats);
      assert (filearr + filecnt == end);
      diridx = (unsigned int *)
	       obstack_alloc (&ob, filecnt * sizeof (*diridx));
      qsort (filearr, filecnt, sizeof (struct line_entry *), line_id_cmp);
      for (i = 0; i < filecnt; i++)
	{
	  unsigned int direntrylen = 0;
	  const char *file = filearr[i]->file->file;
	  if (filearr[i]->file->dir == NULL)
	    {
	      const char *r = strrchr (file, '/'), *s;

	      j = 0;
	      direntrylen = r ? r - file : 0;
	      while (direntrylen && file[direntrylen - 1] == '/')
		direntrylen--;
	      if (direntrylen)
		{
		  direntrylen++;
		  for (j = 0; j < dircnt; j++)
		    if (filearr[dirarr[j]]->file->dir == NULL
			&& strncmp (filearr[dirarr[j]]->file->file,
				    file, direntrylen) == 0)
		      {
			s = filearr[dirarr[j]]->file->file + direntrylen;
			while (*s == '/')
			  s++;
			if (strchr (s, '/'))
			  continue;
			break;
		      }
		  j++;
		  file = r + 1;
		}
	    }
	  else
	    {
	      for (j = 0; j < dircnt; j++)
		if (filearr[dirarr[j]]->file->dir
		    && strcmp (filearr[dirarr[j]]->file->dir,
			       filearr[i]->file->dir) == 0)
		  break;
	      j++;
	      direntrylen = strlen (filearr[i]->file->dir) + 1;
	    }
	  if (j <= dircnt)
	    diridx[i] = j;
	  else
	    {
	      obstack_int_grow (&ob, i);
	      diridx[i] = ++dircnt;
	      dirarr = (unsigned int *) obstack_base (&ob);
	      dirtbllen += direntrylen;
	    }
	  filetbllen += strlen (file) + 1;
	  filetbllen += size_of_uleb128 (diridx[i]);
	  if (lowest_line_version < 5 || line_stats.has_time)
	    filetbllen += size_of_uleb128 (filearr[i]->file->time);
	  if (lowest_line_version < 5 || line_stats.has_size)
	    filetbllen += size_of_uleb128 (filearr[i]->file->size);
	}
      dirarr = (unsigned int *) obstack_finish (&ob);
    }

  /* standard .debug_line "header" length (both version 2 and 5):
     unit_length (4) + version (2) + header_length (4) +
     min_instr_length (1) + default_is_stmt (1) + line_base (1) +
     line_range (1) + opcode_base (1) = 15

     version 2 adds 2 bytes, one zero byte to terminate dir and file lists.

     version 5 adds at least 11 bytes, max_ops_per_instr (1) +
     address_size (1) + segment_size (1) + dir_entry_format_cnt (1) +
     format_pair (2), file_entry_format_cnt (1) + file_format_pairs
     (4). Plus dircnt (uleb128) + format_pair (2) if has_time +
     format_pair (2) if has_size) + filecnt (uleb128).

     version 5 also has 2 extra 6 byte "<dwz>" string entries for dir
     and file entry zero, plus one for the zero file entry dir idx.
  */
  header_len = 15;
  if (lowest_line_version < 5)
    header_len += 2;
  else
    {
      header_len += 11;
      header_len += size_of_uleb128 (dircnt + 1);
      header_len += size_of_uleb128 (filecnt + 1);
      if (line_stats.has_time)
	header_len += 2;
      if (line_stats.has_size)
	header_len += 2;
      header_len += 2 * 6 + 1;
    }
  len = header_len + filetbllen + dirtbllen;
  if (unlikely (op_multifile))
    {
      debug_sections[DEBUG_LINE].new_size = len;
      debug_sections[DEBUG_LINE].new_data = malloc (len);
      if (debug_sections[DEBUG_LINE].new_data == NULL)
	dwz_oom ();
      line = debug_sections[DEBUG_LINE].new_data;
    }
  else
    {
      if (multi_line_off + len < multi_line_off)
	{
	  if (line_htab)
	    obstack_free (&ob, (void *) filearr);
	  return 1;
	}

      if (len == header_len)
	{
	  line = buf;
	  assert (sizeof (buf) >= header_len);
	}
      else
	line = (unsigned char *) obstack_alloc (&ob, len);
    }
  ptr = line;
  write_32 (ptr, len - 4);	/* Total length.  */
  if (lowest_line_version < 5)
    write_16 (ptr, 2);		/* DWARF version.  */
  else
    {
      write_16 (ptr, 5);	/* DWARF version.  */
      write_8 (ptr, multi_ptr_size);	/* Address size.  */
      write_8 (ptr, 0);	       	/* Segment size.  */
    }
  write_32 (ptr,		/* Header length.  */
	    len - (lowest_line_version < 5 ? 10 : 12));
  write_8 (ptr, 1);		/* Minimum insn length.  */
  if (lowest_line_version >= 5)
    write_8 (ptr, 1);		/* Maximum ops per instr.  */
  write_8 (ptr, 1);		/* Default is_stmt.  */
  write_8 (ptr, 0);		/* Line base.  */
  write_8 (ptr, 1);		/* Line range.  */
  write_8 (ptr, 1);		/* Opcode base.  */

  if (lowest_line_version >= 5)
    {
      write_8 (ptr, 1);		/* Dir entry format count.  */
      write_uleb128 (ptr, DW_LNCT_path);
      write_uleb128 (ptr, DW_FORM_string);
      write_uleb128 (ptr, dircnt + 1); /* Dir cnt.  */
      memcpy (ptr, "<dwz>", 6);	/* Zero entry empty dir path.  */
      ptr += 6;
    }

  for (i = 0; i < dircnt; i++)
    {
      unsigned int l;
      if (filearr[dirarr[i]]->file->dir)
	{
	  l = strlen (filearr[dirarr[i]]->file->dir) + 1;
	  memcpy (ptr, filearr[dirarr[i]]->file->dir, l);
	}
      else
	{
	  const char *file = filearr[dirarr[i]]->file->file;
	  const char *r = strrchr (file, '/');

	  while (r && r > file && r[-1] == '/')
	    r--;
	  l = r - file + 1;
	  memcpy (ptr, file, l - 1);
	  ptr[l - 1] = '\0';
	}
      ptr += l;
    }
  if (lowest_line_version < 5)
    write_8 (ptr, 0);		/* Terminate dir table.  */
  else
    {
      unsigned int format_cnt = 2 + line_stats.has_size + line_stats.has_time;
      write_8 (ptr, format_cnt);	/* File entry format count.  */
      write_uleb128 (ptr, DW_LNCT_path);
      write_uleb128 (ptr, DW_FORM_string);
      write_uleb128 (ptr, DW_LNCT_directory_index);
      write_uleb128 (ptr, DW_FORM_udata);
      if (line_stats.has_time)
	{
	  write_uleb128 (ptr, DW_LNCT_timestamp);
	  write_uleb128 (ptr, DW_FORM_udata);
	}
      if (line_stats.has_size)
	{
	  write_uleb128 (ptr, DW_LNCT_size);
	  write_uleb128 (ptr, DW_FORM_udata);
	}
      write_uleb128 (ptr, filecnt + 1); /* File names cnt.  */
      memcpy (ptr, "<dwz>", 6);		/* Zero entry empty file path.  */
      ptr += 6;
      write_8 (ptr, 0);	       		/* Zero entry zero diridx.  */
      if (line_stats.has_time)
	write_8 (ptr, 0);
      if (line_stats.has_size)
	write_8 (ptr, 0);
    }

  for (i = 0; i < filecnt; i++)
    {
      const char *file = filearr[i]->file->file;
      unsigned int l;
      if (diridx[i] && filearr[i]->file->dir == NULL)
	file = strrchr (file, '/') + 1;
      l = strlen (file) + 1;
      memcpy (ptr, file, l);
      ptr += l;
      write_uleb128 (ptr, diridx[i]);
      if (lowest_line_version < 5 || line_stats.has_time)
	write_uleb128 (ptr, filearr[i]->file->time);
      if (lowest_line_version < 5 || line_stats.has_size)
	write_uleb128 (ptr, filearr[i]->file->size);
    }
  if (lowest_line_version < 5)
    write_8 (ptr, 0);		/* Terminate file table.  */
  assert (ptr == line + len);

  if (likely (!op_multifile))
    {
      if (write (multi_line_fd, line, len) != (ssize_t) len)
	ret = 1;
      else
	multi_line_off += len;
      if (line_htab)
	obstack_free (&ob, (void *) filearr);
      else if (line != buf)
	obstack_free (&ob, (void *) line);
    }
  else if (line_htab)
    obstack_free (&ob, (void *) filearr);
  return ret;
}

#if DEVEL
/* In struct dw_die we have a union u with fields p1 and p2.  The p1 field is
   used during phase 1, after which the space is reused for the p2 field
   during phase 2.  Clear the p2 field to get rid of values stored to p1
   during phase 1.  */
static int
clear_p2_field (void)
{
  dw_cu_ref cu;
  dw_die_ref die;

  FOREACH_DIE (cu, die)
    {
      assert (die->die_collapsed_child == 0);
      die->u.p2.die_new_abbrev = NULL;
      die->u.p2.die_new_offset = 0;
      die->u.p2.die_intracu_udata_size = 0;
    }

  return 0;
}
#endif

/* Helper structure for hardlink discovery.  */
struct file_result
{
  /* -3: Uninitialized.
     -2: Already processed under different name.
     -1: Ignore.
      0: Processed, changed.
      1: Processed, unchanged.  */
  int res;
  dev_t dev;
  ino_t ino;
  nlink_t nlink;
  size_t hardlink_to;
  unsigned int die_count;
  bool skip_multifile;
  bool low_mem_p;
};

/* Collect potentially shareable DIEs, strings and .debug_macro
   opcode sequences into temporary .debug_* files.  */
static int
write_multifile (DSO *dso, struct file_result *res)
{
  dw_cu_ref cu;
  bool any_cus = false;
  unsigned int i;
  int ret = 0;

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "write_multifile\n");
    }

  if (multi_ehdr.e_ident[0] == '\0')
    multi_ehdr = dso->ehdr;

  if (multifile_force_ptr_size && ptr_size != multifile_force_ptr_size)
    {
      error (0, 0, "File %s skipped for multi-file optimization, different"
	     " pointer size", dso->filename);
      res->skip_multifile = true;
      return 1;
    }
  else if (multi_ptr_size == 0)
    multi_ptr_size = ptr_size;
  else if (ptr_size != multi_ptr_size)
    {
      error (0, 0, "Multi-file optimization not allowed for different"
	     " pointer sizes");
      multifile = NULL;
      return 1;
    }
  else
    {
      /* Same ptr_size.  */
    }

  int endianity = (do_read_32 == buf_read_ule32
		   ? ELFDATA2LSB
		   : ELFDATA2MSB);
  if (multifile_force_endian && endianity != multifile_force_endian)
    {
      error (0, 0, "File %s skipped for multi-file optimization, different"
	     " endianity", dso->filename);
      res->skip_multifile = true;
      return 1;
    }
  else if (multi_endian == 0)
    multi_endian = endianity;
  else if (multi_endian != endianity)
    {
      error (0, 0, "Multi-file optimization not allowed for different"
	     " endianity");
      multifile = NULL;
      return 1;
    }
  else
    {
      /* Same endianity.  */
    }

#if DEVEL
  clear_p2_field ();
#endif

  for (i = 0; i < SAVED_SECTIONS; i++)
    {
      saved_new_data[i] = debug_sections[i].new_data;
      saved_new_size[i] = debug_sections[i].new_size;
      debug_sections[i].new_data = NULL;
      debug_sections[i].new_size = debug_sections[i].size;
    }
  propagate_multifile ();
  for (cu = first_cu; cu && cu->cu_kind != CU_TYPES; cu = cu->cu_next)
    {
      cu->u1.cu_new_abbrev_owner = NULL;
      cu->u2.cu_new_abbrev_offset = 0;
      cu->cu_new_offset = 0;
      any_cus |= check_multifile (cu->cu_die);
    }
  if (any_cus)
    {
      dw_cu_ref *cup;

      for (cup = &first_cu; *cup && (*cup)->cu_kind != CU_TYPES; )
	{
	  if ((*cup)->cu_new_abbrev)
	    htab_delete ((*cup)->cu_new_abbrev);

	  if ((*cup)->cu_die->die_no_multifile == 0)
	    cup = &(*cup)->cu_next;
	  else
	    *cup = (*cup)->cu_next;
	}
      *cup = NULL;
      multifile_mode = MULTIFILE_MODE_WR;
      if (tracing)
	fprintf (stderr, "Write-multifile %s\n", dso->filename);
      if (compute_abbrevs (NULL))
	ret = 1;
      else if (debug_sections[DEBUG_MACRO].data && read_macro (dso))
	ret = 1;
      else if ((unsigned int) (multi_info_off
			       + debug_sections[DEBUG_INFO].new_size)
	       < multi_info_off
	       || (unsigned int) (multi_abbrev_off
				  + debug_sections[DEBUG_ABBREV].new_size)
		  < multi_abbrev_off
	       || (unsigned int) (multi_str_off
				  + (max_strp_off ? max_strp_off
				     : debug_sections[DEBUG_ABBREV].size))
		  < multi_str_off
	       || (unsigned int) (multi_macro_off
				  + debug_sections[DEBUG_MACRO].new_size)
		  < multi_macro_off)
	{
	  error (0, 0, "Multifile temporary files too large");
	  multifile = NULL;
	  ret = 1;
	}
      else
	{
	  const char *mfile;
	  write_abbrev ();
	  write_info (NULL);
	  /* Any error in this is fatal for multifile handling of further
	     files.  */
	  mfile = multifile;
	  multifile = NULL;
	  if (write (multi_abbrev_fd, debug_sections[DEBUG_ABBREV].new_data,
		     debug_sections[DEBUG_ABBREV].new_size)
	      != (ssize_t) debug_sections[DEBUG_ABBREV].new_size
	      || write (multi_info_fd, debug_sections[DEBUG_INFO].new_data,
			debug_sections[DEBUG_INFO].new_size)
		 != (ssize_t) debug_sections[DEBUG_INFO].new_size
	      || write (multi_str_fd, debug_sections[DEBUG_STR].data,
			debug_sections[DEBUG_STR].size)
		 != (ssize_t) debug_sections[DEBUG_STR].size
	      || (debug_sections[DEBUG_MACRO].new_data
		  && write (multi_macro_fd,
			    debug_sections[DEBUG_MACRO].new_data,
			    debug_sections[DEBUG_MACRO].new_size)
		     != (ssize_t) debug_sections[DEBUG_MACRO].new_size)
	      || (strp_htab != NULL && write_multifile_strp ())
	      || write_multifile_line ())
	    {
	      error (0, 0, "Error writing multi-file temporary files");
	      ret = 1;
	    }
	  else
	    {
	      multi_info_off += debug_sections[DEBUG_INFO].new_size;
	      multi_abbrev_off += debug_sections[DEBUG_ABBREV].new_size;
	      multi_str_off += max_strp_off ? max_strp_off
			       : debug_sections[DEBUG_STR].size;
	      multi_macro_off += debug_sections[DEBUG_MACRO].new_size;
	      multifile = mfile;
	    }
	}
    }
  multifile_mode = 0;
  for (i = 0; i < SAVED_SECTIONS; i++)
    {
      free (debug_sections[i].new_data);
      debug_sections[i].new_data = saved_new_data[i];
      debug_sections[i].new_size = saved_new_size[i];
      saved_new_data[i] = NULL;
    }
  return ret;
}

/* During fi_multifile phase, see what DIEs in a partial unit
   contain no children worth keeping where all real DIEs have
   dups in the shared .debug_info section and what remains is
   just the DW_TAG_partial_unit, a single DW_TAG_imported_unit
   and perhaps some empty named namespaces.  Then all the
   references to that partial unit can be replaced by references
   to the shared partial unit DW_TAG_import_unit has been importing.  */
static bool
remove_empty_pu (dw_die_ref die)
{
  dw_die_ref child = die->die_child, dup = NULL;
  if (!die->die_named_namespace)
    {
      if (die->die_tag != DW_TAG_partial_unit
	  || child == NULL
	  || child->die_tag != DW_TAG_imported_unit
	  || child->die_offset != -1U)
	return false;
      if (die->die_abbrev->nattr > 2)
	return false;
      if (die->die_abbrev->nattr
	  && die->die_abbrev->attr[0].attr != DW_AT_stmt_list)
	return false;
      if (die->die_abbrev->nattr == 2
	  && die->die_abbrev->attr[1].attr != DW_AT_comp_dir)
	return false;
      dup = child->die_nextdup;
      child = child->die_sib;
    }
  else
    {
      if (die->die_abbrev->nattr > 2)
	return false;
      if (die->die_abbrev->nattr
	  && die->die_abbrev->attr[0].attr != DW_AT_name)
	return false;
      if (die->die_abbrev->nattr == 2
	  && die->die_abbrev->attr[1].attr != DW_AT_sibling)
	return false;
    }
  for (; child; child = child->die_sib)
    if (!child->die_named_namespace)
      {
	if (!child->die_remove)
	  /* Signal that DIE can't be removed, but
	     perhaps we could still remove_empty_pu
	     some named namespaces that are children of DIE.  */
	  dup = die;
	if (dup == NULL && die->die_named_namespace)
	  dup = child->die_dup->die_parent;
      }
    else if (!remove_empty_pu (child))
      return false;
    else if (dup == NULL && die->die_named_namespace)
      dup = child->die_dup->die_parent;
  if (dup == NULL || dup == die)
    return false;
  die->die_remove = 1;
  assert (dup->die_tag == die->die_tag);
  die->die_dup = dup;
  return true;
}

/* Call remove_empty_pu on all partial units.  */
static int
remove_empty_pus (void)
{
  dw_cu_ref cu;
  for (cu = first_cu; cu; cu = cu->cu_next)
    if (cu->cu_kind == CU_NORMAL
	&& cu->cu_die->die_tag == DW_TAG_partial_unit)
      remove_empty_pu (cu->cu_die);
  return 0;
}

/* Handle compression of a single file FILE.  If OUTFILE is
   non-NULL, the result will be stored into that file, otherwise
   the result will be written into a temporary file that is renamed
   over FILE.  */
static int
dwz (const char *file, const char *outfile, struct file_result *res)
{
  DSO *dso;
  int ret = 0, fd;
  unsigned int i;
  struct stat st;

  if (res->res == -1)
    return 1;

  res->res = -1;
  fd = open (file, O_RDONLY);
  if (fd < 0)
    {
      error (0, errno, "Failed to open input file %s", file);
      return 1;
    }
  if (fstat (fd, &st) < 0)
    {
      close (fd);
      error (0, errno, "Failed to stat input file %s", file);
      return 1;
    }

  res->res = 1;

  if (tracing)
    {
      fprintf (stderr, "Compressing %s", file);
      if (multifile_mode == 0)
	;
      else if (low_mem)
	fprintf (stderr, " in low-mem mode");
      else if (fi_multifile)
	fprintf (stderr, " in finalize-multifile mode");
      else
	abort ();
      fprintf (stderr, "\n");
    }

  dso = fdopen_dso (fd, file);
  if (dso == NULL)
    return 1;

  obstack_alloc_failed_handler = dwz_oom;
  if (setjmp (oom_buf))
    {
      error (0, ENOMEM, "%s: Could not allocate memory", dso->filename);

      cleanup ();
      ret = 1;
    }
  else
    {
      obstack_init (&ob);
      obstack_init (&ob2);

      unsigned int *die_count = multifile ? &res->die_count : NULL;
      ret = read_dwarf (dso, quiet && outfile == NULL, die_count);
      if (ret)
	cleanup ();
      else if (partition_dups ()
	       || create_import_tree ()
	       || (unlikely (fi_multifile)
		   && (remove_empty_pus ()
		       || read_macro (dso)))
	       || read_debug_info (dso, DEBUG_TYPES, NULL)
#if DEVEL
	       || clear_p2_field ()
#endif
	       || compute_abbrevs (dso)
	       || (unlikely (fi_multifile) && (finalize_strp (false), 0)))
	{
	  cleanup ();
	  ret = 1;
	}
      else if (!(ignore_size || force_p)
	       && ((debug_sections[DEBUG_INFO].new_size
		    + debug_sections[DEBUG_ABBREV].new_size
		    + debug_sections[DEBUG_STR].new_size
		    + debug_sections[DEBUG_MACRO].new_size
		    + debug_sections[DEBUG_TYPES].new_size)
		   >= (debug_sections[DEBUG_INFO].size
		       + debug_sections[DEBUG_ABBREV].size
		       + debug_sections[DEBUG_STR].size
		       + debug_sections[DEBUG_MACRO].size
		       + debug_sections[DEBUG_TYPES].size)))
	{
	  if (!quiet || outfile != NULL)
	    error (0, 0, "%s: DWARF compression not beneficial "
			 "- old size %ld new size %ld", dso->filename,
		   (unsigned long) (debug_sections[DEBUG_INFO].size
				    + debug_sections[DEBUG_ABBREV].size
				    + debug_sections[DEBUG_STR].size
				    + debug_sections[DEBUG_MACRO].size
				    + debug_sections[DEBUG_TYPES].size),
		   (unsigned long) (debug_sections[DEBUG_INFO].new_size
				    + debug_sections[DEBUG_ABBREV].new_size
				    + debug_sections[DEBUG_STR].new_size
				    + debug_sections[DEBUG_MACRO].new_size
				    + debug_sections[DEBUG_TYPES].new_size));

	  if (multifile && !fi_multifile && !low_mem)
	    write_multifile (dso, res);

	  cleanup ();
	  if (outfile != NULL)
	    ret = 1;
	}
      else if (write_aranges (dso))
	{
	failure:
	  cleanup ();
	  ret = 1;
	}
      else
	{
	  if (unlikely (fi_multifile))
	    {
	      size_t len;
	      const char *name = multifile_name;
	      enum debug_section_kind sec_kind;
	      unsigned char *ptr;
	      if (multifile_name == NULL)
		{
		  if (!multifile_relative)
		    name = multifile;
		  else
		    {
		      char *p1 = realpath (file, NULL);
		      char *p2 = realpath (multifile, NULL);
		      char *p3, *p4, *p5, *p6;
		      unsigned int dotdot = 0;
		      if (p1 == NULL || p2 == NULL)
			{
			  if (p1)
			    free (p1);
			  else if (p2)
			    free (p2);
			  error (0, 0, "Could not compute relative multifile "
				       "pathname from %s to %s",
				 file, multifile);
			  goto failure;
			}
		      p3 = p1;
		      p4 = p2;
		      do
			{
			  p5 = strchr (p3, '/');
			  p6 = strchr (p4, '/');
			  if (p5 == NULL
			      || p6 == NULL
			      || p5 - p3 != p6 - p4
			      || memcmp (p3, p4, p5 - p3) != 0)
			    break;
			  p3 = p5 + 1;
			  p4 = p6 + 1;
			}
		      while (1);
		      while (p5 != NULL)
			{
			  dotdot++;
			  p5 = strchr (p5 + 1, '/');
			}
		      len = strlen (p4);
		      p3 = (char *) malloc (dotdot * 3 + len + 1);
		      if (p3 == NULL)
			dwz_oom ();
		      p5 = p3;
		      while (dotdot)
			{
			  memcpy (p5, "../", 3);
			  p5 += 3;
			  dotdot--;
			}
		      memcpy (p5, p4, len + 1);
		      free (p1);
		      free (p2);
		      name = p3;
		    }
		}
	      len = strlen (name) + 1;
	      sec_kind = dwarf_5 ? DEBUG_SUP : GNU_DEBUGALTLINK;
	      debug_sections[sec_kind].new_size
		= len + 0x14 + (dwarf_5 ? 4 : 0);
	      debug_sections[sec_kind].new_data
		= malloc (debug_sections[sec_kind].new_size);
	      if (debug_sections[sec_kind].new_data == NULL)
		dwz_oom ();
	      ptr = debug_sections[sec_kind].new_data;
	      if (dwarf_5)
		{
		  write_16 (ptr, 5);
		  write_8 (ptr, 0);
		}
	      memcpy (ptr, name, len);
	      ptr += len;
	      if (dwarf_5)
		write_uleb128 (ptr, 0x14);
	      memcpy (ptr, multifile_sha1, 0x14);
	      if (name != multifile_name && name != multifile)
		free ((void *) name);
	      write_macro ();
	    }
	  write_abbrev ();
	  write_info (die_count);
	  if (unlikely (progress_p))
	    {
	      report_progress ();
	      fprintf (stderr, "write_loc\n");
	    }
	  write_loc ();
	  if (unlikely (progress_p))
	    {
	      report_progress ();
	      fprintf (stderr, "write_loclists\n");
	    }
	  write_loclists ();
	  if (unlikely (progress_p))
	    {
	      report_progress ();
	      fprintf (stderr, "write_types\n");
	    }
	  write_types ();
	  if (unlikely (progress_p))
	    {
	      report_progress ();
	      fprintf (stderr, "write_gdb_index\n");
	    }
	  write_gdb_index ();
	  /* These sections are optional and it is unclear
	     how to adjust them.  Just remove them.  */
	  debug_sections[DEBUG_PUBNAMES].new_data = NULL;
	  debug_sections[DEBUG_PUBNAMES].new_size = 0;
	  debug_sections[DEBUG_PUBTYPES].new_data = NULL;
	  debug_sections[DEBUG_PUBTYPES].new_size = 0;
	  debug_sections[DEBUG_GNU_PUBNAMES].new_data = NULL;
	  debug_sections[DEBUG_GNU_PUBNAMES].new_size = 0;
	  debug_sections[DEBUG_GNU_PUBTYPES].new_data = NULL;
	  debug_sections[DEBUG_GNU_PUBTYPES].new_size = 0;

	  if (multifile && !fi_multifile && !low_mem)
	    write_multifile (dso, res);

	  bool save_to_temp = save_temps && multifile && multifile_mode == 0;
	  cleanup ();

	  if (write_dso (dso, outfile, &st, save_to_temp))
	    ret = 1;
	  else
	    res->res = 0;

	  if (unlikely (progress_p))
	    report_progress ();
	}
    }

  for (i = 0; debug_sections[i].name; ++i)
    {
      debug_sections[i].data = NULL;
      debug_sections[i].size = 0;
      free (debug_sections[i].new_data);
      debug_sections[i].new_data = NULL;
      debug_sections[i].new_size = 0;
      debug_sections[i].sec = 0;
    }

  if (elf_end (dso->elf) < 0)
    {
      error (0, 0, "elf_end failed: %s", elf_errmsg (elf_errno ()));
      ret = 1;
    }
  close (fd);

  free (dso);
  if (ret == 3)
    {
      ret = (outfile != NULL) ? 1 : 0;
      res->res = -1;
    }
  return ret;
}

/* In order to free all malloced memory at the end of optimize_multifile,
   communicate .debug_str tail optimized offset list from optimize_multifile
   to read_multifile using an mmapped chunk of memory pointed by this
   variable.  */
static unsigned int *strp_tail_off_list;

/* Process temporary .debug_* files, see what can be beneficially shared
   and write a new ET_REL file, containing the shared .debug_* sections.  */
static int
optimize_multifile (unsigned int *die_count)
{
  DSO dsobuf, *dso;
  int fd = -1;
  volatile int vfd = -1;
  unsigned int i;
  Elf *elf = NULL;
  Elf *volatile velf = NULL;
  GElf_Shdr shdr;
  Elf_Scn *scn;
  Elf_Data *data;
  char *e_ident;
  const char shstrtab_gnu[]
    = "\0.shstrtab\0.note.gnu.build-id\0.gdb_index\0"
      ".debug_info\0.debug_abbrev\0.debug_line\0.debug_str\0.debug_macro";
  const char shstrtab_dwarf5[]
    = "\0.shstrtab\0.gdb_index\0"
      ".debug_info\0.debug_abbrev\0.debug_line\0.debug_str\0.debug_macro\0"
      ".debug_sup";
  const char *shstrtab;
  size_t shstrtab_len;
  const char *p;
  unsigned char note[0x24], *np, *supp;
  struct sha1_ctx ctx;

  if (multi_ehdr.e_ident[0] == '\0'
      || multi_ptr_size == 0
      || multi_endian == 0)
    return -1;

  if (multi_line_off == 0)
    {
      init_endian (multi_endian);
      if (write_multifile_line ())
	{
	  error (0, 0, "Error writing multi-file temporary files");
	  return -1;
	}
    }

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "optimize_multifile\n");
    }

  if (dwarf_5)
    {
      shstrtab = shstrtab_dwarf5;
      shstrtab_len = sizeof shstrtab_dwarf5;
    }
  else
    {
      shstrtab = shstrtab_gnu;
      shstrtab_len = sizeof shstrtab_gnu;
    }
  debug_sections[DEBUG_INFO].size = multi_info_off;
  debug_sections[DEBUG_INFO].data
    = (multi_info_off
       ? mmap (NULL, multi_info_off, PROT_READ, MAP_PRIVATE, multi_info_fd, 0)
       : NULL);
  debug_sections[DEBUG_ABBREV].size = multi_abbrev_off;
  debug_sections[DEBUG_ABBREV].data
    = (multi_abbrev_off
       ? mmap (NULL, multi_abbrev_off, PROT_READ, MAP_PRIVATE,
	       multi_abbrev_fd, 0)
       : NULL);
  debug_sections[DEBUG_LINE].size = multi_line_off;
  debug_sections[DEBUG_LINE].data
    = mmap (NULL, multi_line_off, PROT_READ, MAP_PRIVATE, multi_line_fd, 0);
  debug_sections[DEBUG_STR].size = multi_str_off;
  debug_sections[DEBUG_STR].data
    = multi_str_off
      ? mmap (NULL, multi_str_off, PROT_READ, MAP_PRIVATE, multi_str_fd, 0)
      : NULL;
  debug_sections[DEBUG_MACRO].size = multi_macro_off;
  debug_sections[DEBUG_MACRO].data
    = multi_macro_off
      ? mmap (NULL, multi_macro_off, PROT_READ, MAP_PRIVATE, multi_macro_fd, 0)
      : NULL;
  if (debug_sections[DEBUG_INFO].data == MAP_FAILED
      || debug_sections[DEBUG_ABBREV].data == MAP_FAILED
      || debug_sections[DEBUG_LINE].data == MAP_FAILED
      || debug_sections[DEBUG_STR].data == MAP_FAILED
      || debug_sections[DEBUG_MACRO].data == MAP_FAILED)
    {
      error (0, 0, "Error mmapping multi-file temporary files");
    fail:
      cleanup ();
      if (velf)
	elf_end (velf);
      if (vfd != -1)
	{
	  unlink (multifile);
	  close (vfd);
	}
      if (debug_sections[DEBUG_INFO].data != MAP_FAILED)
	munmap (debug_sections[DEBUG_INFO].data,
		debug_sections[DEBUG_INFO].size);
      if (debug_sections[DEBUG_ABBREV].data != MAP_FAILED)
	munmap (debug_sections[DEBUG_ABBREV].data,
		debug_sections[DEBUG_ABBREV].size);
      if (debug_sections[DEBUG_LINE].data != MAP_FAILED)
	munmap (debug_sections[DEBUG_LINE].data,
		debug_sections[DEBUG_LINE].size);
      if (debug_sections[DEBUG_STR].data != MAP_FAILED
	  && debug_sections[DEBUG_STR].data != NULL)
	munmap (debug_sections[DEBUG_STR].data,
		debug_sections[DEBUG_STR].size);
      if (debug_sections[DEBUG_MACRO].data != MAP_FAILED
	  && debug_sections[DEBUG_MACRO].data != NULL)
	munmap (debug_sections[DEBUG_MACRO].data,
		debug_sections[DEBUG_MACRO].size);
      return -1;
    }

  init_endian (multi_endian);
  ptr_size = multi_ptr_size;
  memset (&dsobuf, '\0', sizeof (dsobuf));
  dso = &dsobuf;
  dso->filename = multifile;
  if (tracing)
    fprintf (stderr, "Optimize-multifile\n");
  multifile_mode = MULTIFILE_MODE_OP;

  obstack_alloc_failed_handler = dwz_oom;
  if (unoptimized_multifile)
    {
      for (i = 0; i < SAVED_SECTIONS; i++)
	{
	  debug_sections[i].new_data = debug_sections[i].data;
	  debug_sections[i].new_size = debug_sections[i].size;
	}
    }
  else if (setjmp (oom_buf))
    {
      error (0, ENOMEM, "%s: Could not allocate memory", dso->filename);
      goto fail;
    }
  else
    {
      dw_cu_ref *cup;
      unsigned char *p, *q;
      unsigned int strp_count;

      obstack_init (&ob);
      obstack_init (&ob2);

      if (read_debug_info (dso, DEBUG_INFO, NULL)
	  || partition_dups ())
	goto fail;

#if DEVEL
      clear_p2_field ();
#endif

      for (cup = &first_cu; *cup && (*cup)->cu_kind == CU_PU;
	   cup = &(*cup)->cu_next)
	;

      *cup = NULL;

      strp_count = debug_sections[DEBUG_STR].size / 64;
      if (strp_count < 64)
	strp_count = 64;
      strp_htab = htab_try_create (strp_count,
				   strp_hash2, strp_eq2, NULL);
      if (strp_htab == NULL)
	dwz_oom ();

      for (p = debug_sections[DEBUG_STR].data;
	   p < debug_sections[DEBUG_STR].data + debug_sections[DEBUG_STR].size;
	   p = q + 1)
	{
	  void **slot;
	  struct strp_entry se;
	  hashval_t hash;

	  q = (unsigned char *) strchr ((char *) p, '\0');
	  hash = iterative_hash (p, q - p, 0);
	  se.off = p - debug_sections[DEBUG_STR].data;
	  se.new_off = hash & ~1U;
	  slot = htab_find_slot_with_hash (strp_htab, &se, se.new_off, INSERT);
	  if (slot == NULL)
	    dwz_oom ();
	  if (*slot == NULL)
	    {
	      struct strp_entry *s = pool_alloc (strp_entry, sizeof (*s));
	      *s = se;
	      *slot = (void *) s;
	    }
	  else
	    ((struct strp_entry *) *slot)->new_off |= 1;
	}

      if (first_cu != NULL)
	{
	  if (compute_abbrevs (dso))
	    goto fail;

	  strp_tail_off_list = finalize_strp (true);

	  write_abbrev ();
	  write_info (die_count);
	  write_gdb_index ();
	  if (write_multifile_line ())
	    goto fail;
	}
      else
	strp_tail_off_list = finalize_strp (true);

      if (debug_sections[DEBUG_MACRO].data)
	handle_macro ();
    }

  np = note;
  write_32 (np, sizeof ("GNU"));
  write_32 (np, 0x14);
  write_32 (np, NT_GNU_BUILD_ID);

  supp = NULL;
  if (dwarf_5)
    {
      debug_sections[DEBUG_SUP].new_size = 0x14 + 5;
      debug_sections[DEBUG_SUP].new_data
	= malloc (debug_sections[DEBUG_SUP].new_size);
      if (debug_sections[DEBUG_SUP].new_data == NULL)
	dwz_oom ();
      supp = debug_sections[DEBUG_SUP].new_data;
      write_16 (supp, 5);
      write_8 (supp, 1);
      write_8 (supp, 0);
      write_uleb128 (supp, 0x14);
    }

  cleanup ();
  fd = open (multifile, O_RDWR | O_CREAT, 0600);
  vfd = fd;
  if (fd < 0)
    {
      error (0, errno, "Failed to open multi-file common file %s", multifile);
      goto fail;
    }

  elf = elf_begin (fd, ELF_C_WRITE, NULL);
  velf = elf;
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      goto fail;
    }

  multi_ehdr.e_type = ET_REL;
  multi_ehdr.e_entry = 0;
  multi_ehdr.e_phoff = 0;
  multi_ehdr.e_phnum = 0;
  multi_ehdr.e_shoff = multi_ehdr.e_ehsize;
  multi_ehdr.e_shnum = 2;
  if (!dwarf_5)
    {
      multi_ehdr.e_shoff += 0x24;
      multi_ehdr.e_shnum++;
    }
  for (i = 0; debug_sections[i].name; i++)
    if (debug_sections[i].new_size)
      {
	multi_ehdr.e_shoff += debug_sections[i].new_size;
	multi_ehdr.e_shnum++;
      }
  multi_ehdr.e_shstrndx = multi_ehdr.e_shnum - 1;

  /* Some gelf_newehdr implementations don't return the resulting
     ElfNN_Ehdr, so we have to do it the hard way instead of:
     e_ident = (char *) gelf_newehdr (elf, gelf_getclass (dso->elf));  */
  switch (multi_ehdr.e_ident[EI_CLASS])
    {
    case ELFCLASS32:
      e_ident = (char *) elf32_newehdr (elf);
      multi_ehdr.e_shoff = (multi_ehdr.e_shoff + 3) & -4;
      break;
    case ELFCLASS64:
      e_ident = (char *) elf64_newehdr (elf);
      multi_ehdr.e_shoff = (multi_ehdr.e_shoff + 7) & -8;
      break;
    default:
      e_ident = NULL;
      break;
    }

  if (e_ident == NULL
      /* This is here just for the gelfx wrapper, so that gelf_update_ehdr
	 already has the correct ELF class.  */
      || memcpy (e_ident, multi_ehdr.e_ident, EI_NIDENT) == NULL
      || gelf_update_ehdr (elf, &multi_ehdr) == 0)
    {
      error (0, 0, "Could not create new ELF headers");
      goto fail;
    }
  elf_flagelf (elf, ELF_C_SET, ELF_F_LAYOUT | ELF_F_PERMISSIVE);

  sha1_init_ctx (&ctx);
  for (i = 0; debug_sections[i].name; i++)
    {
      if (debug_sections[i].new_size == 0)
	continue;
      sha1_process_bytes (debug_sections[i].new_data,
			  debug_sections[i].new_size, &ctx);
    }
  sha1_finish_ctx (&ctx, multifile_sha1);

  memcpy (np, "GNU", sizeof ("GNU"));
  memcpy (np + 4, multifile_sha1, 0x14);

  if (dwarf_5)
    memcpy (supp, multifile_sha1, 0x14);

  memset (&shdr, '\0', sizeof (shdr));
  shdr.sh_offset = multi_ehdr.e_ehsize;
  if (!dwarf_5)
    {
      shdr.sh_type = SHT_NOTE;
      shdr.sh_addralign = 4;
      shdr.sh_size = 0x24;
      scn = elf_newscn (elf);
      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
      shdr.sh_name = (strchr (shstrtab + 1, '\0') + 1) - shstrtab;
      gelf_update_shdr (scn, &shdr);
      data = elf_newdata (scn);
      data->d_buf = (char *) note;
      data->d_type = ELF_T_BYTE;
      data->d_version = EV_CURRENT;
      data->d_size = shdr.sh_size;
      data->d_off = 0;
      data->d_align = 1;
    }

  shdr.sh_type = SHT_PROGBITS;
  shdr.sh_offset += shdr.sh_size;
  shdr.sh_addralign = 1;
  for (i = 0; debug_sections[i].name; i++)
    {
      if (debug_sections[i].new_size == 0)
	continue;
      scn = elf_newscn (elf);
      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
      for (p = shstrtab + 1; p < shstrtab + shstrtab_len;
	   p = strchr (p, '\0') + 1)
	if (strcmp (p, debug_sections[i].name) == 0)
	  {
	    shdr.sh_name = p - shstrtab;
	    break;
	  }
      shdr.sh_size = debug_sections[i].new_size;
      if (i == DEBUG_STR)
	{
	  shdr.sh_flags = SHF_MERGE | SHF_STRINGS;
	  shdr.sh_entsize = 1;
	}
      else
	{
	  shdr.sh_flags = 0;
	  shdr.sh_entsize = 0;
	}
      gelf_update_shdr (scn, &shdr);
      data = elf_newdata (scn);
      data->d_buf = debug_sections[i].new_data;
      data->d_type = ELF_T_BYTE;
      data->d_version = EV_CURRENT;
      data->d_size = shdr.sh_size;
      data->d_off = 0;
      data->d_align = 1;
      shdr.sh_offset += shdr.sh_size;
    }
  scn = elf_newscn (elf);
  elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
  shdr.sh_name = 1;
  shdr.sh_offset = multi_ehdr.e_shoff
		   + multi_ehdr.e_shnum * multi_ehdr.e_shentsize;
  shdr.sh_size = shstrtab_len;
  shdr.sh_type = SHT_STRTAB;
  shdr.sh_flags = 0;
  shdr.sh_entsize = 0;
  gelf_update_shdr (scn, &shdr);
  data = elf_newdata (scn);
  data->d_buf = (char *) shstrtab;
  data->d_type = ELF_T_BYTE;
  data->d_version = EV_CURRENT;
  data->d_size = shdr.sh_size;
  data->d_off = 0;
  data->d_align = 1;

  if (elf_update (elf, ELF_C_WRITE_MMAP) == -1)
    {
      error (0, 0, "%s: elf_update failed", multifile);
      goto fail;
    }

  if (elf_end (elf) < 0)
    {
      error (0, 0, "elf_end failed: %s", elf_errmsg (elf_errno ()));
      goto fail;
    }

  fchmod (fd, 0644);

  if (dwarf_5)
    {
      free (debug_sections[DEBUG_SUP].new_data);
      debug_sections[DEBUG_SUP].new_data = NULL;
    }
  munmap (debug_sections[DEBUG_INFO].data, debug_sections[DEBUG_INFO].size);
  munmap (debug_sections[DEBUG_ABBREV].data,
	  debug_sections[DEBUG_ABBREV].size);
  munmap (debug_sections[DEBUG_LINE].data, debug_sections[DEBUG_LINE].size);
  if (debug_sections[DEBUG_STR].data)
    munmap (debug_sections[DEBUG_STR].data, debug_sections[DEBUG_STR].size);
  if (debug_sections[DEBUG_MACRO].data)
    munmap (debug_sections[DEBUG_MACRO].data,
	    debug_sections[DEBUG_MACRO].size);

  for (i = 0; debug_sections[i].name; ++i)
    {
      debug_sections[i].data = NULL;
      debug_sections[i].size = 0;
      if (!unoptimized_multifile)
	free (debug_sections[i].new_data);
      debug_sections[i].new_data = NULL;
      debug_sections[i].new_size = 0;
      debug_sections[i].sec = 0;
    }

  return fd;
}

/* Parse the .debug_* sections from shared ET_REL file written
   by optimize_multifile into data structures for fi_multifile
   phase.  */
static DSO *
read_multifile (int fd, unsigned int die_count)
{
  DSO *dso, *volatile ret;
  unsigned int i;

  if (unlikely (progress_p))
    {
      report_progress ();
      fprintf (stderr, "read_multifile\n");
    }

  if (tracing)
    fprintf (stderr, "Read-multifile\n");

  multifile_mode = MULTIFILE_MODE_RD;
  dso = fdopen_dso (fd, multifile);
  if (dso == NULL)
    {
      multifile_mode = 0;
      return NULL;
    }

  ret = dso;
  obstack_alloc_failed_handler = dwz_oom;
  if (setjmp (oom_buf))
    {
      error (0, ENOMEM, "%s: Could not allocate memory", dso->filename);

    fail:
      elf_end (dso->elf);
      close (fd);
      free (dso);
      ret = NULL;
      alt_off_htab = NULL;
    }
  else
    {
      obstack_init (&ob);
      obstack_init (&ob2);

      if (read_dwarf (dso, false, &die_count))
	goto fail;

      if (debug_sections[DEBUG_STR].size)
	{
	  unsigned char *p, *q;
	  unsigned int strp_count = debug_sections[DEBUG_STR].size / 64;
	  void **slot;
	  unsigned int *pi;

	  if (strp_count < 100)
	    strp_count = 100;
	  strp_htab = htab_try_create (strp_count, strp_hash3, strp_eq3, NULL);
	  if (strp_htab == NULL)
	    dwz_oom ();
	  for (p = debug_sections[DEBUG_STR].data;
	       p < debug_sections[DEBUG_STR].data
		   + debug_sections[DEBUG_STR].size; p = q)
	    {
	      q = (unsigned char *) strchr ((char *) p, '\0') + 1;
	      slot = htab_find_slot_with_hash (strp_htab, p,
					       iterative_hash (p, q - p - 1,
							       0), INSERT);
	      if (slot == NULL)
		dwz_oom ();
	      assert (*slot == NULL);
	      *slot = (void *) p;
	    }
	  if (strp_tail_off_list)
	    {
	      for (pi = strp_tail_off_list; *pi; pi++)
		{
		  p = debug_sections[DEBUG_STR].data + *pi;
		  q = (unsigned char *) strchr ((char *) p, '\0');
		  slot = htab_find_slot_with_hash (strp_htab, p,
						   iterative_hash (p, q - p,
								   0), INSERT);
		  if (slot == NULL)
		    dwz_oom ();
		  assert (*slot == NULL);
		  *slot = (void *) p;
		}
	      pi++;
	      munmap (strp_tail_off_list,
		      (char *) pi - (char *) strp_tail_off_list);
	    }
	}

      if (debug_sections[DEBUG_MACRO].data)
	handle_macro ();

      alt_strp_htab = strp_htab;
      strp_htab = NULL;
      alt_off_htab = off_htab;
      off_htab = NULL;
      alt_dup_htab = dup_htab;
      dup_htab = NULL;
      alt_macro_htab = macro_htab;
      macro_htab = NULL;
      alt_first_cu = first_cu;
      alt_pool = pool;
      pool = NULL;
      pool_next = NULL;
      pool_limit = NULL;
      alt_ob = ob;
      alt_ob2 = ob2;
      memset (&ob, '\0', sizeof (ob));
      memset (&ob2, '\0', sizeof (ob2));
      for (i = 0; i < SAVED_SECTIONS; i++)
	{
	  alt_data[i] = debug_sections[i].data;
	  alt_size[i] = debug_sections[i].size;
	}
    }

  cleanup ();

  for (i = 0; debug_sections[i].name; ++i)
    {
      debug_sections[i].data = NULL;
      debug_sections[i].size = 0;
      debug_sections[i].new_data = NULL;
      debug_sections[i].new_size = 0;
      debug_sections[i].sec = 0;
    }

  return ret;
}

/* Clear all die_nextdup fields among toplevel children
   of DIE.  */
static void
alt_clear_dups (dw_die_ref die)
{
  dw_die_ref child;
  assert (die->die_dup == NULL);
  die->die_nextdup = NULL;
  for (child = die->die_child; child; child = child->die_sib)
    {
      assert (child->die_dup == NULL);
      child->die_nextdup = NULL;
      if (child->die_named_namespace)
	alt_clear_dups (child);
    }
}

/* Create a temporary file using NAME.  Return the corresponding file
   descriptor if successful, otherwise return -1.  */
static int
make_temp_file (const char *name)
{
  const char *tmpdir = "/tmp/";
  const char *template_suffix = ".XXXXXX";
  int fd;
  size_t buf_len, offset, name_len;
  char *buf;

  if (save_temps)
    {
      FILE *f = fopen (name, "w+");
      if (f == NULL)
	fd = -1;
      else
	fd = fileno (f);
      return fd;
    }

  name_len = strlen (name);
  buf_len = (strlen (tmpdir)
	     + name_len
	     + strlen (template_suffix)
	     + 1);
  if (buf_len < name_len)
    return -1;
  buf = (char *)malloc (buf_len);
  if (buf == NULL)
    return -1;
  offset = 0;

  strcpy (&buf[offset], tmpdir);
  offset += strlen (tmpdir);

  strcpy (&buf[offset], name);
  offset += name_len;

  strcpy (&buf[offset], template_suffix);
  offset += strlen (template_suffix);

  assert (offset == buf_len - 1);
  assert (buf[offset] == '\0');

  fd = mkstemp (buf);
  if (fd == -1)
    goto done;

  /* Unlink the filename, such that the file is disposed of once the file
     descriptor is closed.  */
  unlink (buf);

 done:
  free (buf);
  return fd;
}

/* As dwz, but retry with MULTIFILE_MODE_LOW_MEM if the low_mem_die_limit
   is hit.  */
static int
dwz_with_low_mem (const char *file, const char *outfile,
		  struct file_result *res)
{
  int ret;

  res->low_mem_p = false;

  ret = (low_mem_die_limit == 0
	 ? 2
	 : dwz (file, outfile, res));

  if (ret == 2)
    {
      multifile_mode = MULTIFILE_MODE_LOW_MEM;
      res->low_mem_p = true;

      ret = dwz (file, outfile, res);
    }

  return ret;
}

/* Initialize struct file_result RES.  */
static void
init_file_result (struct file_result *res)
{
  res->die_count = 0;
  res->res = -3;
  res->skip_multifile = false;
  res->low_mem_p = false;
}

/* Dwarf-compress FILE.  If OUTFILE, write to result to OUTFILE, otherwise
   modify FILE.  */
static int
dwz_one_file (const char *file, const char *outfile)
{
  struct file_result res;

  if (stats_p)
    init_stats (file);

  init_file_result (&res);

  return dwz_with_low_mem (file, outfile, &res);
}

/* Detect which FILES are hardlinks, and mark those in RESA.  */
static bool
detect_hardlinks (int nr_files, char *files[], struct file_result *resa)
{
  bool found = false;
  int i;

  /* Try to open all files.  */
  for (i = 0; i < nr_files; i++)
    {
      struct file_result *res = &resa[i];
      int fd;
      struct stat st;

      const char *file = files[i];
      res->res = -1;

      fd = open (file, O_RDONLY);
      if (fd < 0)
	error (0, errno, "Failed to open input file %s", file);
      else if (fstat (fd, &st) < 0)
	error (0, errno, "Failed to stat input file %s", file);
      else
	{
	  res->res = 1;
	  res->dev = st.st_dev;
	  res->ino = st.st_ino;
	  res->nlink = st.st_nlink;
	}

      close (fd);
    }

  /* Detect hard links.  */
  for (i = 0; i < nr_files; i++)
    {
      struct file_result *res = &resa[i];
      size_t n;
      for (n = 0; &resa[n] != res; n++)
	if (resa[n].res >= 0
	    && resa[n].nlink > 1
	    && resa[n].dev == res->dev
	    && resa[n].ino == res->ino)
	  break;
      if (&resa[n] == res)
	continue;
      res->res = -2;
      res->hardlink_to = n;
      found = true;
    }

  return found;
}

/* Update the FILES marked as hardlink in RESA.  */
static void
update_hardlinks (int nr_files, char *files[], struct file_result *resa)
{
  int i;

  /* Update hardlinks.  */
  for (i = 0; i < nr_files; i++)
    {
      struct file_result *res = &resa[i];
      const char *file = files[i];
      size_t n;
      if (res->res != -2)
	continue;
      n = res->hardlink_to;

      /* If a hardlink to this has been processed before
	 and we didn't change it, just assume the same
	 state.  */
      if (resa[n].res == 1)
	{
	  if (tracing)
	    fprintf (stderr, "Skipping hardlink %s to unchanged file\n",
		     file);
	  continue;
	}

      /* If it changed, try to hardlink it again.  */
      if (resa[n].res == 0)
	{
	  size_t len = strlen (file);
	  char *filename = alloca (len + sizeof (".#dwz#.XXXXXX"));
	  int fd2;
	  if (tracing)
	    fprintf (stderr, "Updating hardlink %s to changed file\n",
		     file);
	  memcpy (filename, file, len);
	  memcpy (filename + len, ".#dwz#.XXXXXX",
		  sizeof (".#dwz#.XXXXXX"));
	  fd2 = mkstemp (filename);
	  if (fd2 >= 0)
	    {
	      close (fd2);
	      unlink (filename);
	      if (link (files[n], filename) == 0)
		{
		  if (rename (filename, file) == 0)
		    ;
		  else
		    unlink (filename);
		}
	    }
	}
    }
}

/* Encode child process exit status.  */
static int
encode_child_exit_status (int thisret, struct file_result *res)
{
  if (thisret == 0 && res->low_mem_p)
    thisret = 2;
  assert (thisret >= 0 && thisret <= 2);
  assert (res->res >= -3);
  thisret = thisret + ((res->res + 3) << 2);
  return thisret;
}

/* Decode child process exit status.  */
static int
decode_child_exit_status (int state, struct file_result *res)
{
  int ret;
  if (!WIFEXITED (state))
    error (1, 0, "Child dwz process got killed");
  ret = WEXITSTATUS (state) & 0x3;
  res->low_mem_p = false;
  if (ret == 2)
    {
      ret = 0;
      res->low_mem_p = true;
    }
  res->res = (int)((WEXITSTATUS (state) & ~0x3) >> 2) - 3;

  return ret;
}

/* Wait on child exit with PID, update PIDS and RES.  */
static int
wait_child_exit (pid_t pid, pid_t *pids, int nr_pids,
		 struct file_result *res)
{
  int state;
  pid_t got_pid = waitpid (pid, &state, 0);

  int i;
  for (i = 0; i < nr_pids; ++i)
    if (pids[i] == got_pid)
      {
	pids[i] = 0;
	break;
      }
  assert (i < nr_pids);

  return decode_child_exit_status (state, res);
}

/* Dwarf-compress FILES.  If HARDLINK, detect if some files are hardlinks and
   if so, dwarf-compress just one, and relink the others.  */
static int
dwz_files_1 (int nr_files, char *files[], bool hardlink,
	     struct file_result *resa)
{
  int ret = 0;
  int i;
  const char *file;
  int successcount = 0;

  for (i = 0; i < nr_files; ++i)
    init_file_result (&resa[i]);

  if (multifile)
    {
      multi_info_fd = make_temp_file ("dwz.debug_info");
      multi_abbrev_fd = make_temp_file ("dwz.debug_abbrev");
      multi_line_fd = make_temp_file ("dwz.debug_line");
      multi_str_fd = make_temp_file ("dwz.debug_str");
      multi_macro_fd = make_temp_file ("dwz.debug_macro");
      if (multi_info_fd == -1
	  || multi_abbrev_fd == -1
	  || multi_line_fd == -1
	  || multi_str_fd == -1
	  || multi_macro_fd == -1)
	{
	  error (0, 0, "Could not create multifile temporary files");
	  multifile = NULL;
	}
    }

  if (hardlink)
    hardlink = detect_hardlinks (nr_files, files, resa);

  int nr_forks = 0;
  if (max_forks > 1 && multifile == NULL)
    {
      pid_t pids[nr_files];
      for (i = 0; i < nr_files; i++)
	{
	  int thisret;
	  file = files[i];
	  struct file_result *res = &resa[i];
	  if (res->res == -2)
	    /* Skip hard links.  */
	    continue;

	  if (nr_forks == max_forks)
	    {
	      int thisret = wait_child_exit (-1, pids, i, res);
	      if (thisret == 1)
		ret = 1;
	      nr_forks--;
	    }

	  pid_t fork_res = fork ();
	  assert (fork_res != -1);
	  if (fork_res == 0)
	    {
	      thisret = dwz_with_low_mem (file, NULL, res);
	      return encode_child_exit_status (thisret, res);
	    }
	  else
	    {
	      pids[i] = fork_res;
	      nr_forks++;
	    }
	}
      for (i = 0; i < nr_files; i++)
	{
	  int thisret;
	  file = files[i];
	  struct file_result *res = &resa[i];
	  if (res->res == -2)
	    /* Skip hard links.  */
	    continue;
	  if (pids[i] == 0)
	    continue;
	  thisret = wait_child_exit (pids[i], &pids[i], 1, res);
	  if (thisret == 1)
	    ret = 1;
	}
    }
  else
    {
      for (i = 0; i < nr_files; i++)
	{
	  int thisret;
	  file = files[i];
	  struct file_result *res = &resa[i];
	  if (res->res == -2)
	    /* Skip hard links.  */
	    continue;
	  if (stats_p)
	    init_stats (file);
	  thisret = dwz_with_low_mem (file, NULL, res);
	  if (thisret == 1)
	    ret = 1;
	  else if (!res->low_mem_p && !res->skip_multifile && res->res >= 0)
	    successcount++;
	}
    }

  if (hardlink)
    update_hardlinks (nr_files, files, resa);

  if (multifile == NULL)
    return ret;

  if (successcount < 2)
    {
      error (0, 0, "Too few files for multifile optimization");
      return ret;
    }

  if (multi_info_off == 0 && multi_str_off == 0 && multi_macro_off == 0)
    {
      if (!quiet)
	error (0, 0, "No suitable DWARF found for multifile optimization");
      return ret;
    }

  unsigned int multifile_die_count = 0;
  int multi_fd = optimize_multifile (&multifile_die_count);
  DSO *dso;
  if (multi_fd == -1)
    return 1;

  dso = read_multifile (multi_fd, multifile_die_count);
  if (dso == NULL)
    ret = 1;
  else
    {
      for (i = 0; i < nr_files; i++)
	{
	  dw_cu_ref cu;
	  file = files[i];
	  if (stats_p)
	    init_stats (file);
	  multifile_mode = MULTIFILE_MODE_FI;
	  /* Don't process again files that couldn't
	     be processed successfully.  Also skip hard links.  */
	  if (resa[i].res == -1 || resa[i].res == -2
	      || resa[i].skip_multifile)
	    continue;
	  for (cu = alt_first_cu; cu; cu = cu->cu_next)
	    alt_clear_dups (cu->cu_die);
	  ret |= dwz (file, NULL, &resa[i]);
	}
      if (hardlink)
	update_hardlinks (nr_files, files, resa);
      elf_end (dso->elf);
      close (multi_fd);
      free (dso);
    }

  cleanup ();

  strp_htab = alt_strp_htab;
  off_htab = alt_off_htab;
  dup_htab = alt_dup_htab;
  macro_htab = alt_macro_htab;
  pool = alt_pool;
  ob = alt_ob;
  ob2 = alt_ob2;
  cleanup ();

  return ret;
}

/* Wrapper around dwz_files_1 that takes care of malloc and free of resa.  */
static int
dwz_files (int nr_files, char *files[], bool hardlink)
{
  int ret;
  struct file_result *resa
    = (struct file_result *) malloc ((nr_files) * sizeof (*resa));
  if (resa == NULL)
    error (1, ENOMEM, "failed to allocate result array");

  ret = dwz_files_1 (nr_files, files, hardlink, resa);

  free (resa);
  return ret;
}

int
main (int argc, char *argv[])
{
  int ret;
  const char *outfile;
  bool hardlink;
  int nr_files;
  char **files;

  if (elf_version (EV_CURRENT) == EV_NONE)
    error (1, 0, "library out of date");

  outfile = NULL;
  hardlink = false;
  parse_args (argc, argv, &hardlink, &outfile);
  nr_files = argc - optind;
  files = &argv[optind];

  if (nr_files <= 1)
    {
      const char *file = nr_files == 0 ? "a.out" : files[0];

      if (multifile != NULL)
	{
	  error (0, 0, "Too few files for multifile optimization");
	  multifile = NULL;
	}

      ret = dwz_one_file (file, outfile);
    }
  else
    {
      if (outfile != NULL)
	error (1, 0, "-o option not allowed for multiple files");

      ret = dwz_files (nr_files, files, hardlink);
    }

  if (stats_p)
    free (stats);

  return ret;
}
