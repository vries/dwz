/* Copyright (C) 2001-2012 Red Hat, Inc.
   Copyright (C) 2003 Free Software Foundation, Inc.
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
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <getopt.h>
#include <setjmp.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <obstack.h>

#include <gelf.h>
#include "dwarf2.h"
#include "hashtab.h"
#include "sha1.h"

#define DW_FORM_GNU_ref_alt	0x1f20
#define DW_FORM_GNU_strp_alt	0x1f21

#define DW_MACRO_GNU_define_indirect_alt	8
#define DW_MACRO_GNU_undef_indirect_alt		9
#define DW_MACRO_GNU_transparent_include_alt	10

#ifndef IGNORE_LOCUS
# define IGNORE_LOCUS 0
#endif

#if defined __GNUC__ && __GNUC__ >= 3
#define likely(x) __builtin_expect (!!(x), 1)
#define unlikely(x) __builtin_expect (!!(x), 0)
#else
#define likely(x) x
#define unlikely(x) x
#endif

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

static struct obstack alt_ob, alt_ob2;

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

/* Pointer size in the debug info, in bytes.  Only debug info
   with a single pointer size are handled.  */
static int ptr_size;

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
  return data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
}

static inline uint32_t
buf_read_ube32 (unsigned char *data)
{
  return data[3] | (data[2] << 8) | (data[1] << 16) | (data[0] << 24);
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
#define DEBUG_INFO		0
#define DEBUG_ABBREV		1
#define DEBUG_LINE		2
#define DEBUG_STR		3
#define DEBUG_MACRO		4
#define DEBUG_ARANGES		5
#define DEBUG_PUBNAMES		6
#define DEBUG_PUBTYPES		7
#define DEBUG_MACINFO		8
#define DEBUG_LOC		9
#define DEBUG_FRAME		10
#define DEBUG_RANGES		11
#define DEBUG_TYPES		12
#define DEBUG_GDB_SCRIPTS	13
#define GDB_INDEX		14
    { ".debug_info", NULL, NULL, 0, 0, 0 },
    { ".debug_abbrev", NULL, NULL, 0, 0, 0 },
    { ".debug_line", NULL, NULL, 0, 0, 0 },
    { ".debug_str", NULL, NULL, 0, 0, 0 },
    { ".debug_macro", NULL, NULL, 0, 0, 0 },
    { ".debug_aranges", NULL, NULL, 0, 0, 0 },
    { ".debug_pubnames", NULL, NULL, 0, 0, 0 },
    { ".debug_pubtypes", NULL, NULL, 0, 0, 0 },
    { ".debug_macinfo", NULL, NULL, 0, 0, 0 },
    { ".debug_loc", NULL, NULL, 0, 0, 0 },
    { ".debug_frame", NULL, NULL, 0, 0, 0 },
    { ".debug_ranges", NULL, NULL, 0, 0, 0 },
    { ".debug_types", NULL, NULL, 0, 0, 0 },
    { ".debug_gdb_scripts", NULL, NULL, 0, 0, 0 },
    { ".gdb_index", NULL, NULL, 0, 0, 0 },
    { NULL, NULL, NULL, 0, 0, 0 }
  };
#define SAVED_SECTIONS (DEBUG_MACRO + 1)
/* Pointers that might need cleaning up during write_multifile.  */
static unsigned char *saved_new_data[SAVED_SECTIONS];
static size_t saved_new_size[SAVED_SECTIONS];

static unsigned char *alt_data[SAVED_SECTIONS];
static size_t alt_size[SAVED_SECTIONS];

/* How many bytes of each of /tmp/dwz.debug_*.XXXXXX have we written
   already.  */
static unsigned int multi_info_off, multi_abbrev_off;
static unsigned int multi_line_off, multi_str_off;
static unsigned int multi_macro_off;
static int multi_info_fd = -1, multi_abbrev_fd = -1;
static int multi_line_fd = -1, multi_str_fd = -1;
static int multi_macro_fd = -1;

/* Copy of one of the input file's ehdr.  */
static GElf_Ehdr multi_ehdr;

static int multi_ptr_size;
static int multi_endian;

/* Phase of multifile handling.  */
#define MULTIFILE_MODE_WR	1
#define MULTIFILE_MODE_OP	2
#define MULTIFILE_MODE_RD	4
#define MULTIFILE_MODE_FI	8
static unsigned char multifile_mode;

/* True while in write_multifile.  */
#define wr_multifile (multifile_mode & MULTIFILE_MODE_WR)

/* True while in optimize_multifile.  */
#define op_multifile (multifile_mode & MULTIFILE_MODE_OP)

/* True while in read_multifile.  */
#define rd_multifile (multifile_mode & MULTIFILE_MODE_RD)

/* True while in finalize_multifile.  */
#define fi_multifile (multifile_mode & MULTIFILE_MODE_FI)

/* Filename if inter-file size optimization should be performed.  */
static const char *multifile;

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
  /* Attribute/form pairs.  */
  struct abbrev_attr attr[0];
};

typedef struct dw_die *dw_die_ref;
struct import_cu;

/* An entry from .debug_line file table.  */
struct dw_file
{
  char *dir;
  char *file;
  uint64_t time, size;
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
  struct dw_cu *cu_next;
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
  /* New abbreviation hash table.  */
  htab_t cu_new_abbrev;
  union dw_cu_u1
    {
      /* Pointer to another struct dw_cu that owns
	 cu_new_abbrev for this CU.  */
      struct dw_cu *cu_new_abbrev_owner;
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
  /* When op_multifile, record which object this came from here.
     The least significant bit is clear for partial units added
     by dwz, set for compilation units/partial units from original
     debug info.  */
  unsigned int cu_chunk;
};

/* Internal representation of a debugging information entry (DIE).
   This structure should be kept as small as possible,
   there are .debug_info sections with tens of millions of DIEs
   in them and this structure is allocated for each of them.  */
struct dw_die
{
  /* This field should be the first, otherwise die_dup and die_nextdup
     macros need adjustment.  Pointer to the CU this DIE is in or
     will be in.  */
  struct dw_cu *die_cu;
  /* Tree pointers, to parent, first child and pointer to next sibling.  */
  dw_die_ref die_parent, die_child, die_sib;
  /* Pointer to the old .debug_abbrev entry's internal representation.  */
  struct abbrev_tag *die_abbrev;
  /* Offset in old .debug_info from the start of the .debug_info section,
     -1U for newly created DIEs.  */
  unsigned int die_offset;
  /* Size of the DIE (abbrev number + attributes), not including children.
     In later phases this holds the new size as opposed to the old one.  */
  unsigned int die_size;
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
	     this one is CU relative, so die_cu->cu_new_offset needs
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

static unsigned char *pool, *pool_next, *pool_limit;

static unsigned char *alt_pool;

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
	|| t1->attr[i].form != t2->attr[i].form)
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
    }
}

/* Maximum number of attributes in a DIE.  */
static unsigned int max_nattr;

/* Parse a .debug_abbrev entry at PTR.  If !DEBUG_TYPES, return
   first abbrev htab style hash table, otherwise return cu->cu_new_abbrev
   style hash table (this is used for reading .debug_types abbreviations
   which we are not rewriting).  */
static htab_t
read_abbrev (DSO *dso, unsigned char *ptr, bool debug_types)
{
  htab_t h;
  unsigned int attr, form;
  struct abbrev_tag *t;
  void **slot;

  if (debug_types)
    h = htab_try_create (50, abbrev_hash, abbrev_eq2, NULL);
  else
    h = htab_try_create (50, abbrev_hash, abbrev_eq, NULL);
  if (h == NULL)
    dwz_oom ();

  while ((attr = read_uleb128 (ptr)) != 0)
    {
      unsigned int nattr = 0;
      unsigned char *p = ptr;

      read_uleb128 (p);
      p++;
      while (read_uleb128 (p) != 0)
	{
	  nattr++;
	  form = read_uleb128 (p);
	  if (form == 2
	      || (form > DW_FORM_flag_present && form != DW_FORM_ref_sig8))
	    {
	      error (0, 0, "%s: Unknown DWARF DW_FORM_%d", dso->filename, form);
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
		      sizeof (*t) + nattr * sizeof (struct abbrev_attr));
      t->entry = attr;
      t->hash = attr;
      t->nattr = 0;
      t->nusers = 0;
      t->tag = read_uleb128 (ptr);
      t->children = *ptr++ == DW_CHILDREN_yes;
      t->op_type_referenced = false;
      while ((attr = read_uleb128 (ptr)) != 0)
	{
	  form = read_uleb128 (ptr);
	  t->attr[t->nattr].attr = attr;
	  t->attr[t->nattr++].form = form;
	}
      read_uleb128 (ptr);
      if (t->nattr > max_nattr)
	max_nattr = t->nattr;
      if (debug_types)
	compute_abbrev_hash (t);
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

/* Read the directory and file table from .debug_line offset OFF,
   record it in CU.  */
static int
read_debug_line (DSO *dso, struct dw_cu *cu, uint32_t off)
{
  unsigned char *ptr = debug_sections[DEBUG_LINE].data, *dir, *file;
  unsigned char **dirt;
  unsigned char *endsec = ptr + debug_sections[DEBUG_LINE].size;
  unsigned char *endcu, *endprol;
  unsigned char opcode_base;
  unsigned int culen;
  uint32_t value, dirt_cnt, file_cnt;

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
  if (value < 2 || value > 4)
    {
      error (0, 0, "%s: DWARF version %d unhandled", dso->filename,
	     value);
      return 1;
    }

  endprol = ptr + 4;
  endprol += read_32 (ptr);
  if (endprol > endcu)
    {
      error (0, 0, "%s: .debug_line CU prologue does not fit into CU",
	     dso->filename);
      return 1;
    }

  opcode_base = ptr[4 + (value >= 4)];
  ptr = dir = ptr + 4 + (value >= 4) + opcode_base;

  /* dir table: */
  value = 1;
  while (*ptr != 0)
    {
      ptr = (unsigned char *) strchr ((char *)ptr, 0) + 1;
      ++value;
    }

  dirt = (unsigned char **) alloca (value * sizeof (unsigned char *));
  dirt[0] = NULL;
  dirt_cnt = 1;
  ptr = dir;
  while (*ptr != 0)
    {
      dirt[dirt_cnt++] = ptr;
      ptr = (unsigned char *) strchr ((char *)ptr, 0) + 1;
    }
  ptr++;

  /* file table: */
  file = ptr;
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

      read_uleb128 (ptr);
      read_uleb128 (ptr);
      file_cnt++;
    }

  cu->cu_nfiles = file_cnt;
  cu->cu_files = pool_alloc (dw_file, file_cnt * sizeof (struct dw_file));
  memset (cu->cu_files, 0, file_cnt * sizeof (struct dw_file));

  ptr = file;
  file_cnt = 0;
  while (*ptr != 0)
    {
      unsigned char *end;
      cu->cu_files[file_cnt].file = (char *) ptr;
      ptr = (unsigned char *) strchr ((char *)ptr, 0) + 1;
      end = ptr;
      value = read_uleb128 (ptr);

      if (value >= dirt_cnt)
	{
	  error (0, 0, "%s: Wrong directory table index %u",
		 dso->filename, value);
	  return 1;
	}

      cu->cu_files[file_cnt].dir = (char *) dirt[value];
      cu->cu_files[file_cnt].time = read_uleb128 (ptr);
      cu->cu_files[file_cnt].size = read_uleb128 (ptr);
      if (cu->cu_files[file_cnt].file[0] != '/'
	  && cu->cu_files[file_cnt].dir != NULL)
	{
	  size_t file_len = (char *) end - cu->cu_files[file_cnt].file;
	  size_t dir_len = strlen (cu->cu_files[file_cnt].dir);
	  if (dir_len)
	    {
	      obstack_grow (&ob, cu->cu_files[file_cnt].dir,
			    dir_len);
	      if (cu->cu_files[file_cnt].dir[dir_len - 1] != '/')
		obstack_1grow (&ob, '/');
	      obstack_grow (&ob, cu->cu_files[file_cnt].file,
			    file_len);
	      cu->cu_files[file_cnt].file
		= (char *) obstack_finish (&ob);
	      cu->cu_files[file_cnt].dir = NULL;
	    }
	}
      file_cnt++;
    }

  return 0;
}

/* Hash function for off_htab hash table.  */
static hashval_t
off_hash (const void *p)
{
  dw_die_ref die = (dw_die_ref) p;

  return die->die_offset;
}

/* Equality function for off_htab hash table.  */
static int
off_eq (const void *p, const void *q)
{
  return ((dw_die_ref) p)->die_offset == ((dw_die_ref) q)->die_offset;
}

/* Hash table to map die_offset values to struct dw_die pointers.  */
static htab_t off_htab;

static htab_t alt_off_htab;

/* Function to add DIE into the hash table (and create the hash table
   when not already created).  */
static int
off_htab_add_die (dw_die_ref die)
{
  void **slot;
  if (off_htab == NULL)
    {
      off_htab = htab_try_create (100000, off_hash, off_eq, NULL);
      if (off_htab == NULL)
	dwz_oom ();
      if (rd_multifile)
	alt_off_htab = off_htab;
    }

  slot = htab_find_slot (off_htab, die, INSERT);
  if (slot == NULL)
    dwz_oom ();
  assert (*slot == NULL);
  *slot = die;
  return 0;
}

/* For DIE_OFFSET return dw_die_ref whose die_offset field is equal
   to that value.  Return NULL if no DIE is at that position (buggy
   DWARF input?).  */
static dw_die_ref
off_htab_lookup (struct dw_cu *cu, unsigned int die_offset)
{
  struct dw_die die;
  die.die_offset = die_offset;
  if (unlikely (cu->cu_kind == CU_ALT))
    return (dw_die_ref) htab_find_with_hash (alt_off_htab, &die, die_offset);
  return (dw_die_ref) htab_find_with_hash (off_htab, &die, die_offset);
}

/* Return a pointer at which DIE's attribute AT is encoded, and fill in
   its form into *FORMP.  Return NULL if the attribute is not present.  */
static unsigned char *
get_AT (dw_die_ref die, enum dwarf_attribute at, enum dwarf_form *formp)
{
  struct abbrev_tag *t = die->die_abbrev;
  unsigned int i;
  unsigned char *ptr;
  if (unlikely (fi_multifile) && die->die_cu->cu_kind == CU_ALT)
    ptr = alt_data[DEBUG_INFO];
  else
    ptr = debug_sections[DEBUG_INFO].data;
  ptr += die->die_offset;
  read_uleb128 (ptr);
  for (i = 0; i < t->nattr; ++i)
    {
      uint32_t form = t->attr[i].form;
      size_t len = 0;

      while (form == DW_FORM_indirect)
	form = read_uleb128 (ptr);
      if (t->attr[i].attr == at)
	{
	  *formp = form;
	  return ptr;
	}
      switch (form)
	{
	case DW_FORM_ref_addr:
	  ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
	  break;
	case DW_FORM_addr:
	  ptr += ptr_size;
	  break;
	case DW_FORM_flag_present:
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
	  ptr += 4;
	  break;
	case DW_FORM_ref8:
	case DW_FORM_data8:
	case DW_FORM_ref_sig8:
	  ptr += 8;
	  break;
	case DW_FORM_sdata:
	case DW_FORM_ref_udata:
	case DW_FORM_udata:
	  read_uleb128 (ptr);
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
  return NULL;
}

/* Return an integer attribute AT of DIE.  Set *PRESENT to true
   if found.  */
static uint64_t
get_AT_int (dw_die_ref die, enum dwarf_attribute at, bool *present)
{
  enum dwarf_form form;
  unsigned char *ptr;
  ptr = get_AT (die, at, &form);
  *present = false;
  if (ptr == NULL)
    return 0;
  *present = true;
  switch (form)
    {
    case DW_FORM_ref_addr:
      return read_size (ptr, die->die_cu->cu_version == 2 ? ptr_size : 4);
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
	if (unlikely (fi_multifile) && die->die_cu->cu_kind == CU_ALT)
	  {
	    if (strp >= alt_size[DEBUG_STR])
	      return NULL;
	    return (char *) alt_data[DEBUG_STR] + strp;
	  }
	if (strp >= debug_sections[DEBUG_STR].size)
	  return NULL;
	return (char *) debug_sections[DEBUG_STR].data + strp;
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
	  ref = off_htab_lookup (die->die_cu, die->die_cu->cu_offset + addr);
	  if (ref == NULL)
	    {
	      error (0, 0, "%s: Couldn't find DIE referenced by DW_OP_%d",
		     dso->filename, op);
	      return 1;
	    }
	  if (op == DW_OP_call2)
	    ref->die_op_call2_referenced = 1;
	  if (ref->die_ck_state == CK_KNOWN)
	    {
	      ref->die_ck_state = CK_BAD;
	      while (ref->die_parent != NULL
		     && ref->die_parent->die_ck_state == CK_KNOWN)
		{
		  ref = ref->die_parent;
		  ref->die_ck_state = CK_BAD;
		}
	    }
	  else
	    ref->die_ck_state = CK_BAD;
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
	  addr = read_size (ptr, die->die_cu->cu_version == 2 ? ptr_size : 4);
	  if (die->die_cu->cu_version == 2)
	    ptr += ptr_size;
	  else
	    ptr += 4;
	  ref = off_htab_lookup (die->die_cu, addr);
	  if (ref == NULL)
	    {
	      error (0, 0, "%s: Couldn't find DIE referenced by DW_OP_%d",
		     dso->filename, op);
	      return 1;
	    }
	  die->die_ck_state = CK_BAD;
	  if (need_adjust)
	    *need_adjust = true;
	  if (op == DW_OP_GNU_implicit_pointer)
	    read_uleb128 (ptr);
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
	  read_uleb128 (ptr);
	  break;
	case DW_OP_bregx:
	case DW_OP_bit_piece:
	  read_uleb128 (ptr);
	  read_uleb128 (ptr);
	  break;
	case DW_OP_implicit_value:
	  {
	    uint32_t leni = read_uleb128 (ptr);
	    ptr += leni;
	  }
	  break;
	case DW_OP_GNU_entry_value:
	  {
	    uint32_t leni = read_uleb128 (ptr);
	    if ((uint64_t) (end - ptr) < leni)
	      {
		error (0, 0, "%s: DWARF DW_OP_GNU_entry_value with too large"
		       " length", dso->filename);
		return 1;
	      }
	    if (read_exprloc (dso, die, ptr, leni, need_adjust))
	      return 1;
	    ptr += leni;
	  }
	  break;
	case DW_OP_GNU_convert:
	case DW_OP_GNU_reinterpret:
	  addr = read_uleb128 (ptr);
	  if (addr == 0)
	    break;
	  goto typed_dwarf;
	case DW_OP_GNU_regval_type:
	  read_uleb128 (ptr);
	  addr = read_uleb128 (ptr);
	  goto typed_dwarf;
	case DW_OP_GNU_const_type:
	  addr = read_uleb128 (ptr);
	  ptr += *ptr + 1;
	  goto typed_dwarf;
	case DW_OP_GNU_deref_type:
	  ++ptr;
	  addr = read_uleb128 (ptr);
	typed_dwarf:
	  ref = off_htab_lookup (die->die_cu, die->die_cu->cu_offset + addr);
	  if (ref == NULL)
	    {
	      error (0, 0, "%s: Couldn't find DIE referenced by DW_OP_%d",
		     dso->filename, op);
	      return 1;
	    }
	  ref->die_op_type_referenced = 1;
	  die->die_ck_state = CK_BAD;
	  if (need_adjust)
	    *need_adjust = true;
	  break;
	default:
	  error (0, 0, "%s: Unknown DWARF DW_OP_%d", dso->filename, op);
	  return 1;
	}
    }
  if (die->die_ck_state != CK_BAD)
    die->u.p1.die_hash = iterative_hash (end - len, len, die->u.p1.die_hash);
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
  struct dw_cu *cu;
};
ALIGN_STRUCT (debug_loc_adjust)

/* Hash table and obstack for recording .debug_loc adjustment ranges.  */
static htab_t loc_htab;

/* Hash function for loc_htab.  */
static hashval_t
loc_hash (const void *p)
{
  struct debug_loc_adjust *a = (struct debug_loc_adjust *)p;

  return a->end_offset;
}

/* Equality function for loc_htab.  */
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
read_loclist (DSO *dso, dw_die_ref die, GElf_Addr offset)
{
  unsigned char *ptr, *endsec;
  GElf_Addr low, high;
  size_t len;
  bool need_adjust = false;

  die->die_ck_state = CK_BAD;
  ptr = debug_sections[DEBUG_LOC].data;
  if (ptr == NULL)
    {
      error (0, 0, "%s: loclistptr attribute, yet no .debug_loc section",
	     dso->filename);
      return 1;
    }
  if (offset >= debug_sections[DEBUG_LOC].size)
    {
      error (0, 0,
	     "%s: loclistptr offset %Ld outside of .debug_loc section",
	     dso->filename, (long long) offset);
      return 1;
    }
  endsec = ptr + debug_sections[DEBUG_LOC].size;
  ptr += offset;
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

      if (read_exprloc (dso, die, ptr, len, &need_adjust))
	return 1;

      ptr += len;
    }

  if (need_adjust)
    {
      struct debug_loc_adjust adj, *a;
      void **slot;

      adj.start_offset = offset;
      adj.end_offset = ptr - debug_sections[DEBUG_LOC].data;
      adj.cu = die->die_cu;
      if (loc_htab == NULL)
	{
	  loc_htab = htab_try_create (50, loc_hash, loc_eq, NULL);
	  if (loc_htab == NULL)
	    dwz_oom ();
	}
      slot = htab_find_slot_with_hash (loc_htab, &adj, adj.end_offset, INSERT);
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
	  error (0, 0, "%s: can't adjust .debug_loc section because multiple "
		       "CUs refer to it", dso->filename);
	  return 1;
	}
      else if (((struct debug_loc_adjust *)*slot)->start_offset > offset)
	((struct debug_loc_adjust *)*slot)->start_offset = offset;
    }

  return 0;
}

/* This function computes u.p1.die_hash and die_ck_state of DIE.
   u.p1.die_hash is an iterative hash of the die_tag, for all its attributes
   except DW_AT_sibling the attribute code, for non-reference class
   attributes or DW_FORM_ref_addr attributes the value of the attribute
   (magic for DW_AT_*_file), for reference class attributes that point
   into the subtree of TOP_DIE ref->u.p1.die_enter - top_die->u.p1.die_enter
   (note, other references are intentionally ignored here) and hashes
   of all its children.  die_ck_state is set to CK_BAD if the die is
   unsuitable for moving into a partial unit (contains code references
   or other reasons).  TOP_DIE is initially NULL when DW_TAG_*_unit or
   die_named_namespace dies are walked.  */
static int
checksum_die (DSO *dso, dw_die_ref top_die, dw_die_ref die)
{
  unsigned short s;
  struct abbrev_tag *t;
  unsigned int i;
  unsigned char *ptr;
  dw_die_ref child;

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
  read_uleb128 (ptr);
  s = die->die_tag;
  die->u.p1.die_hash = iterative_hash_object (s, die->u.p1.die_hash);
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
	case DW_AT_GNU_macros:
	  if (die->die_parent)
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
	  if ((die->die_cu->cu_version < 4 && form == DW_FORM_data4)
	      || form == DW_FORM_sec_offset)
	    {
	      if (read_loclist (dso, die, read_32 (ptr)))
		return 1;
	      ptr = old_ptr;
	      break;
	    }
	  else if (die->die_cu->cu_version < 4 && form == DW_FORM_data8)
	    {
	      if (read_loclist (dso, die, read_64 (ptr)))
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
	    default:
	      error (0, 0, "%s: Unhandled DW_FORM_%d for DW_AT_%d",
		     dso->filename, form, t->attr[i].attr);
	      return 1;
	    }
	  if (handled)
	    {
	      unsigned char *new_ptr = ptr;
	      ptr = old_ptr;
	      if (value > die->die_cu->cu_nfiles)
		{
		  error (0, 0, "%s: Invalid DW_AT_%d file number %d",
			 dso->filename, t->attr[i].attr, (int) value);
		  return 1;
		}
	      if (value == 0)
		handled = false;
	      else if (!IGNORE_LOCUS && die->die_ck_state != CK_BAD)
		{
		  struct dw_file *cu_file = &die->die_cu->cu_files[value - 1];
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
		  else if (cu_file->file[0] == '<'
			   && cu_file->file[file_len - 1] == '>'
			   && strchr (cu_file->file, '/') == NULL
			   && i + 1 < t->nattr
			   && t->attr[i + 1].attr
			      == (t->attr[i].attr == DW_AT_decl_file
				  ? DW_AT_decl_line : DW_AT_call_line)
			   && t->attr[i + 1].form == DW_FORM_data1
			   && *new_ptr == 0)
		    break;
		  if (die->die_cu->cu_comp_dir
		      && (cu_file->dir ? cu_file->dir[0]
				       : cu_file->file[0]) != '/')
		    die->u.p1.die_hash
		      = iterative_hash (die->die_cu->cu_comp_dir,
					strlen (die->die_cu->cu_comp_dir) + 1,
					die->u.p1.die_hash);
		}
	    }
	  break;
	case DW_AT_decl_line:
	case DW_AT_decl_column:
	case DW_AT_call_line:
	case DW_AT_call_column:
	  if (IGNORE_LOCUS)
	    handled = true;
	  break;
	default:
	  break;
	}

      switch (form)
	{
	case DW_FORM_ref_addr:
	  if (unlikely (op_multifile || rd_multifile))
	    {
	      dw_die_ref ref;

	      value = read_size (ptr, die->die_cu->cu_version == 2
				      ? ptr_size : 4);
	      ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
	      if (die->die_ck_state != CK_BAD)
		{
		  s = t->attr[i].attr;
		  die->u.p1.die_hash
		    = iterative_hash_object (s, die->u.p1.die_hash);
		}
	      ref = off_htab_lookup (die->die_cu, value);
	      if (ref == NULL)
		{
		  error (0, 0, "%s: Couldn't find DIE referenced by DW_AT_%d",
			 dso->filename, t->attr[i].attr);
		  return 1;
		}
	      assert (die->die_cu != ref->die_cu
		      && (die->die_cu->cu_chunk | 1)
			 == (ref->die_cu->cu_chunk | 1));
	      handled = true;
	      break;
	    }
	  die->die_no_multifile = 1;
	  ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
	  break;
	case DW_FORM_addr:
	  die->die_no_multifile = 1;
	  ptr += ptr_size;
	  break;
	case DW_FORM_flag_present:
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
	case DW_FORM_ref_sig8:
	  die->die_no_multifile = 1;
	  ptr += 8;
	  break;
	case DW_FORM_sdata:
	case DW_FORM_udata:
	  read_uleb128 (ptr);
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
		= off_htab_lookup (die->die_cu,
				   die->die_cu->cu_offset + value);
	      if (ref == NULL)
		{
		  error (0, 0, "%s: Couldn't find DIE referenced by DW_AT_%d",
			 dso->filename, t->attr[i].attr);
		  return 1;
		}
	      if (die->die_ck_state != CK_BAD)
		{
		  s = t->attr[i].attr;
		  die->u.p1.die_hash
		    = iterative_hash_object (s, die->u.p1.die_hash);
		}
	      if (top_die
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
	  len = read_uleb128 (ptr);
	  form = DW_FORM_block1;
	  break;
	case DW_FORM_exprloc:
	  len = read_uleb128 (ptr);
	  break;
	default:
	  abort ();
	}

      if (form == DW_FORM_block1)
	{
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
	  ptr += len;
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
	  ptr += len;
	}
      if (!handled && die->die_ck_state != CK_BAD)
	{
	  s = t->attr[i].attr;
	  die->u.p1.die_hash = iterative_hash_object (s, die->u.p1.die_hash);
	  die->u.p1.die_hash
	    = iterative_hash (old_ptr, ptr - old_ptr, die->u.p1.die_hash);
	}
    }

  for (child = die->die_child; child; child = child->die_sib)
    if (checksum_die (dso, top_die ? top_die
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
	    die->die_no_multifile
	      |= child->die_no_multifile;
	  }
	else
	  die->die_ck_state = CK_BAD;
      }
  if (die->die_ck_state == CK_BEING_COMPUTED)
    die->die_ck_state = CK_KNOWN;

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
checksum_ref_die (dw_die_ref top_die, dw_die_ref die, unsigned int *second_idx,
		  hashval_t *second_hash)
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
	  if (unlikely (op_multifile || rd_multifile))
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
      read_uleb128 (ptr);
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
	      if (unlikely (op_multifile || rd_multifile))
		{
		  value = read_size (ptr, die->die_cu->cu_version == 2
					  ? ptr_size : 4);
		  ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
		  assert (t->attr[i].attr != DW_AT_sibling);
		  if (top_die == NULL)
		    break;
		  ref = off_htab_lookup (die->die_cu, value);
		  goto finish_ref;
		}
	      ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
	      break;
	    case DW_FORM_addr:
	      ptr += ptr_size;
	      break;
	    case DW_FORM_flag_present:
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
	      ptr += 4;
	      break;
	    case DW_FORM_data8:
	    case DW_FORM_ref_sig8:
	      ptr += 8;
	      break;
	    case DW_FORM_sdata:
	    case DW_FORM_udata:
	      read_uleb128 (ptr);
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
	      ref = off_htab_lookup (die->die_cu,
				     die->die_cu->cu_offset + value);
	      if (ref->u.p1.die_enter >= top_die->u.p1.die_enter
		  && ref->u.p1.die_exit <= top_die->u.p1.die_exit)
		break;
	    finish_ref:
	      reft = ref;
	      while (reft->die_parent != NULL
		     && reft->die_parent->die_tag != DW_TAG_compile_unit
		     && reft->die_parent->die_tag != DW_TAG_partial_unit
		     && !reft->die_parent->die_named_namespace)
		reft = reft->die_parent;
	      if (reft->die_ck_state != CK_KNOWN || reft->die_parent == NULL)
		top_die->die_ck_state = CK_BAD;
	      else
		{
		  unsigned int r = checksum_ref_die (reft, reft, second_idx,
						     second_hash);
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
    for (child = die->die_child; child; child = child->die_sib)
      {
	unsigned int r
	  = checksum_ref_die (top_die ? top_die
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
	  if (minidx != -1U)
	    {
	      idx = 0;
	      checksum_ref_die (arr[minidx], arr[minidx], &idx, &ref_hash);
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
		  checksum_ref_die (arr[i], arr[i], NULL,
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

/* Return 1 if DIE1 and DIE2 match.  TOP_DIE1 and TOP_DIE2
   is the corresponding ultimate parent with die_toplevel
   set.  u.p1.die_hash and u.p1.die_ref_hash hashes should
   hopefully ensure that in most cases this function actually
   just verifies matching.  */
static int
die_eq_1 (dw_die_ref top_die1, dw_die_ref top_die2,
	  dw_die_ref die1, dw_die_ref die2)
{
  struct abbrev_tag *t1, *t2;
  unsigned int i, j;
  unsigned char *ptr1, *ptr2;
  dw_die_ref ref1, ref2;
  dw_die_ref child1, child2;

#define FAIL goto fail
  if (die1 == die2 || die_safe_dup (die2) == die1)
    return 1;
  if (die1->u.p1.die_hash != die2->u.p1.die_hash
      || die1->u.p1.die_ref_hash != die2->u.p1.die_ref_hash
      || die1->die_tag != die2->die_tag
      || die1->die_cu == die2->die_cu
      || die1->u.p1.die_exit - die1->u.p1.die_enter
	 != die2->u.p1.die_exit - die2->u.p1.die_enter
      || die_safe_dup (die2) != NULL
      || die1->die_ck_state != CK_KNOWN
      || die2->die_ck_state != CK_KNOWN
      || die1->die_toplevel != die2->die_toplevel)
    return 0;
  assert (die1->die_parent != NULL
	  && die2->die_parent != NULL);

  t1 = die1->die_abbrev;
  t2 = die2->die_abbrev;
  if (likely (!fi_multifile))
    {
      ptr1 = debug_sections[DEBUG_INFO].data + die1->die_offset;
      ptr2 = debug_sections[DEBUG_INFO].data + die2->die_offset;
    }
  else
    {
      if (die1->die_cu->cu_kind == CU_ALT)
	ptr1 = alt_data[DEBUG_INFO];
      else
	ptr1 = debug_sections[DEBUG_INFO].data;
      ptr1 += die1->die_offset;
      if (die2->die_cu->cu_kind == CU_ALT)
	ptr2 = alt_data[DEBUG_INFO];
      else
	ptr2 = debug_sections[DEBUG_INFO].data;
      ptr2 += die2->die_offset;
    }
  read_uleb128 (ptr1);
  read_uleb128 (ptr2);
  i = 0;
  j = 0;
  if (die1->die_toplevel)
    {
      for (ref1 = die1->die_parent, ref2 = die2->die_parent;
	   ref1 && ref2; ref1 = ref1->die_parent, ref2 = ref2->die_parent)
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
	}
      if (ref1 == NULL || ref2 == NULL)
	return 0;
      /* For each toplevel die seen, record optimistically
	 that we expect them to match, to avoid recursing
	 on it again.  If non-match is determined later,
	 die_eq wrapper undoes this (which is why the DIE
	 pointer is added to the vector).  */
      die2->die_dup = die1;
      if (!die2->die_op_type_referenced)
	die2->die_remove = 1;
      die2->die_nextdup = die1->die_nextdup;
      die1->die_nextdup = die2;
      obstack_ptr_grow (&ob, die2);
    }
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
	    case DW_FORM_ref_udata: read_uleb128 (ptr1); break;
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
	    case DW_FORM_ref_udata: read_uleb128 (ptr2); break;
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
	    default: abort ();
	    }
	  switch (form2)
	    {
	    case DW_FORM_data1: value2 = read_8 (ptr2); break;
	    case DW_FORM_data2: value2 = read_16 (ptr2); break;
	    case DW_FORM_data4: value2 = read_32 (ptr2); break;
	    case DW_FORM_data8: value2 = read_64 (ptr2); break;
	    case DW_FORM_udata: value2 = read_uleb128 (ptr2); break;
	    default: abort ();
	    }
	  if (IGNORE_LOCUS)
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
		= &die1->die_cu->cu_files[value1 - 1];
	      struct dw_file *cu_file2
		= &die2->die_cu->cu_files[value2 - 1];
	      unsigned int file_len;

	      if (cu_file1->time != cu_file2->time
		  || cu_file1->size != cu_file2->size
		  || strcmp (cu_file1->file, cu_file2->file))
		FAIL;

	      file_len = strlen (cu_file1->file);
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
	      else if (cu_file1->file[0] == '<'
		       && cu_file1->file[file_len - 1] == '>'
		       && strchr (cu_file1->file, '/') == NULL
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
		  if (die1->die_cu->cu_comp_dir != NULL)
		    {
		      if (die2->die_cu->cu_comp_dir == NULL
			  || strcmp (die1->die_cu->cu_comp_dir,
				     die2->die_cu->cu_comp_dir))
			FAIL;
		    }
		  else if (die2->die_cu->cu_comp_dir != NULL)
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
	  if (IGNORE_LOCUS)
	    old_ptr1 = NULL;
	  break;
	default:
	  break;
	}

      switch (form1)
	{
	case DW_FORM_ref_addr:
	  if (likely (!op_multifile && !rd_multifile))
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
	      if (likely (!op_multifile && !rd_multifile))
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
	case DW_FORM_sdata:
	case DW_FORM_udata:
	  read_uleb128 (ptr1);
	  read_uleb128 (ptr2);
	  break;
	case DW_FORM_strp:
	  if (unlikely (op_multifile || rd_multifile || fi_multifile))
	    {
	      value1 = read_32 (ptr1);
	      value2 = read_32 (ptr2);
	      if (fi_multifile)
		{
		  if (strcmp ((char *) (die1->die_cu->cu_kind == CU_ALT
					? alt_data[DEBUG_STR]
					: debug_sections[DEBUG_STR].data)
			      + value1,
			      (char *) (die2->die_cu->cu_kind == CU_ALT
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
	  if (likely (!op_multifile && !rd_multifile))
	    {
	      ptr1 += die1->die_cu->cu_version == 2 ? ptr_size : 4;
	      ptr2 += die2->die_cu->cu_version == 2 ? ptr_size : 4;
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
	      value1 = read_size (ptr1, die1->die_cu->cu_version == 2
					? ptr_size : 4)
		       - die1->die_cu->cu_offset;
	      ptr1 += die1->die_cu->cu_version == 2 ? ptr_size : 4;
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
	  ref1 = off_htab_lookup (die1->die_cu,
				  die1->die_cu->cu_offset + value1);
	  switch (form2)
	    {
	    case DW_FORM_ref_addr:
	      value2 = read_size (ptr2, die2->die_cu->cu_version == 2
					? ptr_size : 4)
		       - die2->die_cu->cu_offset;
	      ptr2 += die2->die_cu->cu_version == 2 ? ptr_size : 4;
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
	  ref2 = off_htab_lookup (die2->die_cu,
				  die2->die_cu->cu_offset + value2);
	  assert (ref1 != NULL && ref2 != NULL);
	  if (ref1->die_cu == top_die1->die_cu
	      && ref1->u.p1.die_enter >= top_die1->u.p1.die_enter
	      && ref1->u.p1.die_exit <= top_die1->u.p1.die_exit)
	    {
	      /* A reference into a subdie of the DIE being compared.  */
	      if (ref2->die_cu != top_die2->die_cu
		  || ref1->u.p1.die_enter - top_die1->u.p1.die_enter
		     != ref2->u.p1.die_enter - top_die2->u.p1.die_enter
		  || top_die1->u.p1.die_exit - ref1->u.p1.die_exit
		     != top_die2->u.p1.die_exit - ref2->u.p1.die_exit)
		FAIL;
	    }
	  else
	    {
	      dw_die_ref reft1 = ref1, reft2 = ref2;
	      while (reft1->die_toplevel == 0)
		reft1 = reft1->die_parent;
	      while (reft2->die_toplevel == 0)
		reft2 = reft2->die_parent;
	      if (ref1->u.p1.die_enter - reft1->u.p1.die_enter
		  != ref2->u.p1.die_enter - reft2->u.p1.die_enter)
		FAIL;
	      /* If reft1 (die1 or whatever refers to it is already
		 in the hash table) already has a dup, follow to that
		 dup.  Don't do the same for reft2, {{top_,}die,reft,child}2
		 should always be from the current CU (or for
		 op_multifile from the current chunk of CUs).  */
	      if (reft1->die_dup)
		reft1 = reft1->die_dup;
	      if (die_eq_1 (reft1, reft2, reft1, reft2) == 0)
		FAIL;
	    }
	  i++;
	  j++;
	  continue;
	default:
	  abort ();
	}

      if ((!IGNORE_LOCUS || old_ptr1)
	  && (ptr1 - old_ptr1 != ptr2 - old_ptr2
	      || memcmp (old_ptr1, old_ptr2, ptr1 - old_ptr1)))
	FAIL;
      i++;
      j++;
    }

  for (child1 = die1->die_child, child2 = die2->die_child;
       child1 && child2;
       child1 = child1->die_sib, child2 = child2->die_sib)
    if (die_eq_1 (top_die1, top_die2, child1, child2) == 0)
      FAIL;

  if (child1 || child2)
    {
    fail:
      return 0;
    }

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
  if (die1->die_cu->cu_offset < die2->die_cu->cu_offset)
    ret = die_eq_1 (die1, die2, die1, die2);
  else
    ret = die_eq_1 (die2, die1, die2, die1);
  count = obstack_object_size (&ob) / sizeof (void *);
  arr = (dw_die_ref *) obstack_finish (&ob);
  if (!ret)
    for (i = count; i;)
      {
	dw_die_ref die = arr[--i]->die_dup;
	die->die_nextdup = arr[i]->die_nextdup;
	arr[i]->die_nextdup = NULL;
	arr[i]->die_dup = NULL;
	arr[i]->die_remove = 0;
      }
  obstack_free (&ob, (void *) arr);
  return ret;
}

static int
die_eq2 (const void *p, const void *q)
{
  dw_die_ref die1 = (dw_die_ref) p;
  dw_die_ref die2 = (dw_die_ref) q;
  dw_die_ref *arr;
  unsigned int i, count;
  int ret;

  if (die1->u.p1.die_hash != die2->u.p1.die_hash
      || die1->u.p1.die_ref_hash != die2->u.p1.die_ref_hash)
    return 0;
  if (die1->die_cu->cu_kind == CU_ALT)
    {
      if (die2->die_cu->cu_kind != CU_ALT)
	ret = die_eq_1 (die1, die2, die1, die2);
      else
	return 0;
    }
  else if (die2->die_cu->cu_kind == CU_ALT)
    ret = die_eq_1 (die2, die1, die2, die1);
  else
    return 0;
  count = obstack_object_size (&ob) / sizeof (void *);
  arr = (dw_die_ref *) obstack_finish (&ob);
  if (!ret)
    for (i = count; i;)
      {
	dw_die_ref die = arr[--i]->die_dup;
	die->die_nextdup = arr[i]->die_nextdup;
	arr[i]->die_nextdup = NULL;
	arr[i]->die_dup = NULL;
	arr[i]->die_remove = 0;
      }
  obstack_free (&ob, (void *) arr);
  return ret;
}

/* Hash table for finding of matching toplevel DIEs (and all
   its children together with it).  */
static htab_t dup_htab;

static htab_t alt_dup_htab;

/* First CU, start of the linked list of CUs, and the tail
   of that list.  Initially this contains just the original
   CUs, later on newly created partial units are added
   to the beginning of the list and optionally .debug_types
   CUs are added to its tail.  */
static struct dw_cu *first_cu, *last_cu;

static struct dw_cu *alt_first_cu;

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

/* Walk toplevel DIEs in tree rooted by PARENT, and see if they
   match previously processed DIEs.  */
static int
find_dups (dw_die_ref parent)
{
  void **slot;
  dw_die_ref child;

  for (child = parent->die_child; child; child = child->die_sib)
    {
      if (child->die_ck_state == CK_KNOWN)
	{
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
	if (find_dups (child))
	  return 1;
    }
  return 0;
}

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

#ifdef DEBUG_DUMP_DIES
/* Debugging helper function to dump hash values to stdout.  */
static void
dump_dies (int depth, dw_die_ref die)
{
  dw_die_ref child;
  const char *name = get_AT_string (die, DW_AT_name);
  printf ("%*s %x %c %x %x %s\n", depth, "", die->die_offset,
	  die->die_ck_state == CK_KNOWN ? 'O' : 'X',
	  (unsigned) die->u.p1.die_hash,
	  (unsigned) die->u.p1.die_ref_hash, name ? name : "");
  for (child = die->die_child; child; child = child->die_sib)
    dump_dies (depth + 1, child);
}
#endif

static htab_t strp_htab;
static unsigned int max_strp_off;

static htab_t alt_strp_htab;

struct strp_entry
{
  unsigned int off;
  unsigned int new_off;
};
ALIGN_STRUCT (strp_entry)

/* Hash function in strp_htab.  */
static hashval_t
strp_hash (const void *p)
{
  struct strp_entry *s = (struct strp_entry *)p;

  return s->off;
}

/* Equality function in strp_htab.  */
static int
strp_eq (const void *p, const void *q)
{
  struct strp_entry *s1 = (struct strp_entry *)p;
  struct strp_entry *s2 = (struct strp_entry *)q;

  return s1->off == s2->off;
}

/* Hash function in strp_htab.  */
static hashval_t
strp_hash2 (const void *p)
{
  struct strp_entry *s = (struct strp_entry *)p;

  return s->new_off & ~1U;
}

/* Equality function in strp_htab.  */
static int
strp_eq2 (const void *p, const void *q)
{
  struct strp_entry *s1 = (struct strp_entry *)p;
  struct strp_entry *s2 = (struct strp_entry *)q;

  return strcmp ((char *) debug_sections[DEBUG_STR].data + s1->off,
		 (char *) debug_sections[DEBUG_STR].data + s2->off) == 0;
}

/* Hash function in strp_htab.  */
static hashval_t
strp_hash3 (const void *p)
{
  return iterative_hash (p, strlen (p), 0);
}

/* Equality function in strp_htab.  */
static int
strp_eq3 (const void *p, const void *q)
{
  return strcmp (p, q) == 0;
}

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
	    return DW_FORM_GNU_strp_alt;
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

static unsigned int *
finalize_strp (bool build_tail_offset_list)
{
  unsigned int count, new_count, i, *tail_offset_list = NULL;
  unsigned int strp_index = 0, tail_offset_list_count = 0, k;
  struct strp_entry **arr, **end;
  unsigned char *p;

  if (strp_htab == NULL)
    return NULL;
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
  strp_htab = htab_try_create (new_count, strp_hash3, strp_eq3, NULL);
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

#define MARK_REFS_FOLLOW_DUPS	1
#define MARK_REFS_RETURN_VAL	2

/* Mark all DIEs referenced from DIE by setting die_ref_seen to 1,
   unless already marked.  */
static bool
mark_refs (dw_die_ref top_die, dw_die_ref die, int mode)
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
      ptr = debug_sections[DEBUG_INFO].data + die->die_offset;
      read_uleb128 (ptr);
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
		  value = read_size (ptr, die->die_cu->cu_version == 2
					  ? ptr_size : 4);
		  ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
		  assert (t->attr[i].attr != DW_AT_sibling);
		  ref = off_htab_lookup (die->die_cu, value);
		  goto finish_ref;
		}
	      ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
	      break;
	    case DW_FORM_addr:
	      ptr += ptr_size;
	      break;
	    case DW_FORM_flag_present:
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
	      ptr += 4;
	      break;
	    case DW_FORM_data8:
	    case DW_FORM_ref_sig8:
	      ptr += 8;
	      break;
	    case DW_FORM_sdata:
	    case DW_FORM_udata:
	      read_uleb128 (ptr);
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
	      ref = off_htab_lookup (die->die_cu,
				     die->die_cu->cu_offset + value);
	      if (ref->u.p1.die_enter >= top_die->u.p1.die_enter
		  && ref->u.p1.die_exit <= top_die->u.p1.die_exit)
		break;
	    finish_ref:
	      reft = ref;
	      while (reft->die_parent != NULL
		     && reft->die_parent->die_tag != DW_TAG_compile_unit
		     && reft->die_parent->die_tag != DW_TAG_partial_unit
		     && !reft->die_parent->die_named_namespace)
		reft = reft->die_parent;
	      if ((mode & MARK_REFS_FOLLOW_DUPS) && reft->die_dup != NULL)
		{
		  reft = reft->die_dup;
		  if (reft->die_cu->cu_kind == CU_PU)
		    break;
		}
	      if (reft->die_ref_seen == 0)
		{
		  if ((mode & MARK_REFS_RETURN_VAL))
		    return false;
		  reft->die_ref_seen = 1;
		  mark_refs (reft, reft, mode);
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
    if (!mark_refs (top_die, child, mode))
      return false;
  return true;
}

static dw_die_ref die_nontoplevel_freelist;

static void
remove_dies (dw_die_ref die)
{
  dw_die_ref child, next;
  void **slot;
  for (child = die->die_child; child; child = next)
    {
      next = child->die_sib;
      remove_dies (child);
    }
  slot = htab_find_slot_with_hash (off_htab, die, die->die_offset,
				   NO_INSERT);
  if (slot != NULL)
    htab_clear_slot (off_htab, slot);
  if (die->die_toplevel == 0)
    {
      memset (die, '\0', offsetof (struct dw_die, die_dup));
      die->die_sib = die_nontoplevel_freelist;
      die_nontoplevel_freelist = die->die_sib;
    }
  else
    die->die_child = NULL;
}

static void
remove_unneeded (dw_die_ref die, unsigned int phase)
{
  dw_die_ref child;
  for (child = die->die_child; child; child = child->die_sib)
    {
      if (child->die_named_namespace)
	{
	  remove_unneeded (child, phase);
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
	    if (child->die_dup == NULL)
	      mark_refs (child, child, 0);
	    break;
	  case 2:
	    if (child->die_ref_seen == 0)
	      remove_dies (child);
	    else
	      child->die_ref_seen = 0;
	    break;
	  }
    }
}

/* First phase of the DWARF compression.  Parse .debug_info section,
   for each CU in it construct internal represetnation for the CU
   and its DIE tree, compute checksums of DIEs and look for duplicates.  */
static int
read_debug_info (DSO *dso)
{
  unsigned char *ptr, *endcu, *endsec;
  unsigned int value;
  htab_t abbrev = NULL;
  unsigned int last_abbrev_offset = 0;
  unsigned int last_debug_line_off = 0;
  struct dw_file *cu_files = NULL;
  unsigned int cu_nfiles = 0;
  bool note_strp_forms = multifile != NULL && !op_multifile && !rd_multifile;
  struct abbrev_tag tag, *t;
  unsigned int cu_chunk = 0;
  struct dw_cu *cu_tail = NULL;

  if (!fi_multifile)
    {
      dup_htab = htab_try_create (100000, die_hash,
				  rd_multifile ? die_eq2 : die_eq, NULL);
      if (dup_htab == NULL)
	dwz_oom ();
    }

  ptr = debug_sections[DEBUG_INFO].data;
  endsec = ptr + debug_sections[DEBUG_INFO].size;
  while (ptr < endsec)
    {
      unsigned int cu_offset = ptr - debug_sections[DEBUG_INFO].data;
      unsigned int tick = 0, culen;
      int cu_version;
      struct dw_cu *cu;
      dw_die_ref *diep, parent, die;
      bool present;
      unsigned int debug_line_off;

      if (ptr + 11 > endsec)
	{
	  error (0, 0, "%s: .debug_info CU header too small", dso->filename);
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
	  error (0, 0, "%s: .debug_info too small", dso->filename);
	  goto fail;
	}

      cu_version = read_16 (ptr);
      if (cu_version < 2 || cu_version > 4)
	{
	  error (0, 0, "%s: DWARF version %d unhandled", dso->filename,
		 cu_version);
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

      if (unlikely (op_multifile) && ptr == endcu)
	{
	  if ((cu_chunk++ & 1) == 1)
	    {
	      struct dw_cu *cuf = cu_tail ? cu_tail->cu_next : first_cu;
	      /* Inside of optimize_multifile, DIE hashes are computed
		 only after all the CUs from a particular DSO or
		 executable have been parsed, as we follow
		 DW_FORM_ref_addr then.  */
	      for (cu = cuf; cu; cu = cu->cu_next)
		if (checksum_die (dso, NULL, cu->cu_die))
		  goto fail;

	      for (cu = cuf; cu; cu = cu->cu_next)
		checksum_ref_die (NULL, cu->cu_die, NULL, NULL);

#ifdef DEBUG_DUMP_DIES
	      for (cu = cuf; cu; cu = cu->cu_next)
		dump_dies (0, cu->cu_die);
#endif

	      for (cu = cuf; cu; cu = cu->cu_next)
		if (find_dups (cu->cu_die))
		  goto fail;

	      for (cu = cuf; cu; cu = cu->cu_next)
		remove_unneeded (cu->cu_die, 0);
	      for (cu = cuf; cu; cu = cu->cu_next)
		remove_unneeded (cu->cu_die, 1);
	      for (cu = cuf; cu; cu = cu->cu_next)
		remove_unneeded (cu->cu_die, 2);

	      cu_tail = last_cu;
	    }
	  continue;
	}

      if (abbrev == NULL || value != last_abbrev_offset)
	{
	  if (abbrev)
	    htab_delete (abbrev);
	  abbrev = read_abbrev (dso, debug_sections[DEBUG_ABBREV].data + value,
				false);
	  if (abbrev == NULL)
	    goto fail;
	}
      last_abbrev_offset = value;

      cu = pool_alloc (dw_cu, sizeof (struct dw_cu));
      memset (cu, '\0', sizeof (*cu));
      cu->cu_kind = rd_multifile ? CU_ALT : CU_NORMAL;
      cu->cu_offset = cu_offset;
      cu->cu_version = cu_version;
      cu->cu_chunk = cu_chunk;
      diep = &cu->cu_die;
      parent = NULL;
      if (first_cu == NULL)
	first_cu = last_cu = cu;
      else
	{
	  last_cu->cu_next = cu;
	  last_cu = cu;
	}

      while (ptr < endcu)
	{
	  unsigned int i;
	  unsigned int die_offset = ptr - debug_sections[DEBUG_INFO].data;

	  tag.entry = read_uleb128 (ptr);
	  if (tag.entry == 0)
	    {
	      if (parent)
		{
		  diep = &parent->die_sib;
		  parent->u.p1.die_exit = tick++;
		  parent = parent->die_parent;
		}
	      else
		diep = NULL;
	      continue;
	    }
	  if (diep == NULL)
	    {
	      error (0, 0, "%s: Wrong .debug_info DIE tree", dso->filename);
	      goto fail;
	    }
	  t = htab_find_with_hash (abbrev, &tag, tag.entry);
	  if (t == NULL)
	    {
	      error (0, 0, "%s: Could not find DWARF abbreviation %d",
		     dso->filename, tag.entry);
	      goto fail;
	    }
	  if (parent == NULL
	      || parent->die_parent == NULL
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
	  die->die_cu = cu;
	  die->die_parent = parent;
	  die->u.p1.die_enter = tick;
	  die->u.p1.die_exit = tick++;
	  if (t->children)
	    {
	      diep = &die->die_child;
	      parent = die;
	    }
	  else
	    diep = &die->die_sib;
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
	      switch (form)
		{
		case DW_FORM_ref_addr:
		  ptr += cu->cu_version == 2 ? ptr_size : 4;
		  break;
		case DW_FORM_addr:
		  ptr += ptr_size;
		  break;
		case DW_FORM_flag_present:
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
		  ptr += 4;
		  break;
		case DW_FORM_ref8:
		case DW_FORM_data8:
		case DW_FORM_ref_sig8:
		  ptr += 8;
		  break;
		case DW_FORM_sdata:
		case DW_FORM_ref_udata:
		case DW_FORM_udata:
		  read_uleb128 (ptr);
		  break;
		case DW_FORM_strp:
		  if (t->attr[i].attr == DW_AT_name
		      && (die->die_tag == DW_TAG_namespace
			  || die->die_tag == DW_TAG_module)
		      && die->die_parent != NULL
		      && (die->die_parent->die_parent == NULL
			  || die->die_parent->die_named_namespace))
		    die->die_named_namespace = 1;
		  if (note_strp_forms)
		    note_strp_offset (read_32 (ptr));
		  else
		    ptr += 4;
		  break;
		case DW_FORM_string:
		  ptr = (unsigned char *) strchr ((char *)ptr, '\0') + 1;
		  if (t->attr[i].attr == DW_AT_name
		      && (die->die_tag == DW_TAG_namespace
			  || die->die_tag == DW_TAG_module)
		      && die->die_parent != NULL
		      && (die->die_parent->die_parent == NULL
			  || die->die_parent->die_named_namespace))
		    die->die_named_namespace = 1;
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
		  error (0, 0, "%s: Unknown DWARF DW_FORM_%d",
			 dso->filename, form);
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

		  if (t->attr[i].attr > DW_AT_linkage_name
		      && (t->attr[i].attr < DW_AT_MIPS_fde
			  || t->attr[i].attr > DW_AT_MIPS_has_inlines)
		      && (t->attr[i].attr < DW_AT_sf_names
			  || t->attr[i].attr > DW_AT_body_end)
		      && (t->attr[i].attr < DW_AT_GNU_call_site_value
			  || t->attr[i].attr > DW_AT_GNU_call_site_target_clobbered))
		    {
		      error (0, 0, "%s: Unknown DWARF DW_AT_%d with block DW_FORM",
			     dso->filename, t->attr[i].attr);
		      goto fail;
		    }

		  ptr += len;
		}
	    }
	  die->die_size = (ptr - debug_sections[DEBUG_INFO].data)
			  - die_offset;
	  if (off_htab_add_die (die))
	    goto fail;
	}

      if (cu->cu_die == NULL
	  || (cu->cu_die->die_tag != DW_TAG_compile_unit
	      && cu->cu_die->die_tag != DW_TAG_partial_unit)
	  || cu->cu_die->die_sib != NULL)
	{
	  error (0, 0, "%s: .debug_info section chunk doesn't contain a single"
			" compile_unit or partial_unit", dso->filename);
	  goto fail;
	}

      cu->cu_comp_dir = get_AT_string (cu->cu_die, DW_AT_comp_dir);
      debug_line_off = get_AT_int (cu->cu_die, DW_AT_stmt_list, &present);
      if (present)
	{
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

      if (likely (!op_multifile && !rd_multifile && !fi_multifile))
	{
	  if (checksum_die (dso, NULL, cu->cu_die))
	    goto fail;
	  checksum_ref_die (NULL, cu->cu_die, NULL, NULL);

#ifdef DEBUG_DUMP_DIES
	  dump_dies (0, cu->cu_die);
#endif

	  if (find_dups (cu->cu_die))
	    goto fail;
	}
    }

  if (abbrev)
    htab_delete (abbrev);

  if (unlikely (rd_multifile || fi_multifile))
    {
      struct dw_cu *cu;

      /* Inside of read_multifile, DIE hashes are computed
	 only after all the PUs are parsed, as we follow
	 DW_FORM_ref_addr then.  */
      for (cu = first_cu; cu; cu = cu->cu_next)
	if (checksum_die (dso, NULL, cu->cu_die))
	  goto fail;

      for (cu = first_cu; cu; cu = cu->cu_next)
	checksum_ref_die (NULL, cu->cu_die, NULL, NULL);

#ifdef DEBUG_DUMP_DIES
      for (cu = first_cu; cu; cu = cu->cu_next)
	dump_dies (0, cu->cu_die);
#endif

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

  htab_delete (dup_htab);
  dup_htab = NULL;
  return 0;
fail:
  if (abbrev)
    htab_delete (abbrev);
  htab_delete (dup_htab);
  dup_htab = NULL;
  return 1;
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
  struct dw_cu *last_cu1 = NULL, *last_cu2 = NULL;
  for (ref1 = die1, ref2 = die2;;
       ref1 = ref1->die_nextdup, ref2 = ref2->die_nextdup)
    {
      while (ref1 && ref1->die_cu == last_cu1)
	ref1 = ref1->die_nextdup;
      while (ref2 && ref2->die_cu == last_cu2)
	ref2 = ref2->die_nextdup;
      if (ref1 == NULL || ref2 == NULL)
	break;
      last_cu1 = ref1->die_cu;
      last_cu2 = ref2->die_cu;
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
	  if (unlikely (op_multifile))
	    {
	      /* Due to the if (die1->die_cu == die2->die_cu) return 0;
		 in die_eq_1, the first pass might actually not detect
		 some dups when the compiler did a bad job.  Reject
		 those here, because otherwise we would fail on assertions
		 later on.  */
	      unsigned int cu_chunk = child->die_cu->cu_chunk & ~1U;
	      dw_die_ref dup;
	      for (dup = child->die_nextdup; dup; dup = dup->die_nextdup)
		if ((dup->die_cu->cu_chunk & ~1U) != cu_chunk)
		  break;
	      if (dup == NULL)
		continue;
	    }
	  obstack_ptr_grow (vec, child);
	}
      else if (child->die_named_namespace)
	partition_find_dups (vec, child);
    }
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
  new_die->die_cu = parent->die_cu;
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

/* Helper function of partition_dups_1.  Decide what DIEs matching in multiple
   CUs might be worthwhile to be moved into partial units, construct those
   partial units.  */
static bool
partition_dups_1 (dw_die_ref *arr, size_t vec_size,
		  struct dw_cu **first_partial_cu,
		  struct dw_cu **last_partial_cu,
		  bool second_phase)
{
  size_t i, j;
  bool ret = false;
  for (i = 0; i < vec_size; i = j)
    {
      dw_die_ref ref;
      size_t cnt = 0, size = 0, k, orig_size, new_size, namespaces = 0;
      unsigned int force = 0;
      if (arr[i]->die_dup != NULL)
	{
	  j = i + 1;
	  continue;
	}
      for (j = i + 1; j < vec_size; j++)
	{
	  dw_die_ref ref1, ref2;
	  struct dw_cu *last_cu1 = NULL, *last_cu2 = NULL;
	  size_t this_cnt = 0;
	  for (ref1 = arr[i], ref2 = arr[j];;
	       ref1 = ref1->die_nextdup, ref2 = ref2->die_nextdup)
	    {
	      while (ref1 && ref1->die_cu == last_cu1)
		ref1 = ref1->die_nextdup;
	      while (ref2 && ref2->die_cu == last_cu2)
		ref2 = ref2->die_nextdup;
	      if (ref1 == NULL || ref2 == NULL)
		break;
	      last_cu1 = ref1->die_cu;
	      last_cu2 = ref2->die_cu;
	      if (last_cu1 != last_cu2)
		break;
	      else
		this_cnt++;
	    }
	  if (ref1 || ref2)
	    break;
	  cnt = this_cnt;
	}
      if (cnt == 0)
	{
	  struct dw_cu *last_cu1 = NULL;
	  for (ref = arr[i];; ref = ref->die_nextdup)
	    {
	      while (ref && ref->die_cu == last_cu1)
		ref = ref->die_nextdup;
	      if (ref == NULL)
		break;
	      last_cu1 = ref->die_cu;
	      cnt++;
	    }
	}
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
      if (second_phase && force && force < j - k)
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
		&& !mark_refs (arr[k], arr[k], (MARK_REFS_FOLLOW_DUPS
						| MARK_REFS_RETURN_VAL)))
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
		    if (!mark_refs (arr[k], arr[k], (MARK_REFS_FOLLOW_DUPS
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
	 21 (also child end byte), plus in each CU referencing it
	 DW_TAG_imported_unit with DW_AT_import attribute
	 (5 or 9 bytes (the latter for DWARF2 and ptr_size 8)).
	 For DW_TAG_namespace or DW_TAG_module needed as
	 parents of the DIEs conservatively assume 10 bytes
	 for the abbrev index, DW_AT_name attribute and
	 DW_AT_sibling attribute and child end.  */
      new_size = size + 21
		 + (arr[i]->die_cu->cu_version == 2
		    ? 1 + ptr_size : 5) * cnt + 10 * namespaces;
      if (!second_phase)
	force = orig_size > new_size;
      if (force)
	{
	  dw_die_ref die, *diep;
	  struct dw_cu *partial_cu = pool_alloc (dw_cu, sizeof (struct dw_cu));
	  memset (partial_cu, '\0', sizeof (*partial_cu));
	  partial_cu->cu_kind = CU_PU;
	  partial_cu->cu_offset = *last_partial_cu == NULL
				  ? 0 : (*last_partial_cu)->cu_offset + 1;
	  partial_cu->cu_version = arr[i]->die_cu->cu_version;
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
	  die->die_cu = partial_cu;
	  die->die_nextdup = arr[i]->die_cu->cu_die;
	  die->die_size = 9;
	  diep = &die->die_child;
	  for (k = i; k < j; k++)
	    {
	      dw_die_ref child;
	      if (second_phase && !arr[k]->die_ref_seen)
		continue;
	      child = copy_die_tree (die, arr[k]);
	      for (ref = arr[k]->die_nextdup; ref; ref = ref->die_nextdup)
		ref->die_dup = child;
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
		      namespc->die_cu = partial_cu;
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
		  next = ref->die_nextdup;
		  ref->die_dup = NULL;
		  ref->die_nextdup = NULL;
		  ref->die_remove = 0;
		}
	    }
	}
    }
  return ret;
}

/* Decide what DIEs matching in multiple CUs might be worthwhile
   to be moved into partial units, construct those partial units.  */
static int
partition_dups (void)
{
  struct dw_cu *cu, *first_partial_cu = NULL, *last_partial_cu = NULL;
  size_t vec_size, i;
  unsigned char *to_free;

  if (unlikely (fi_multifile))
    return 0;

  to_free = obstack_alloc (&ob2, 1);
  for (cu = first_cu; cu; cu = cu->cu_next)
    partition_find_dups (&ob2, cu->cu_die);
  vec_size = obstack_object_size (&ob2) / sizeof (void *);
  if (vec_size != 0)
    {
      dw_die_ref *arr = (dw_die_ref *) obstack_finish (&ob2);
      qsort (arr, vec_size, sizeof (dw_die_ref), partition_cmp);
      if (partition_dups_1 (arr, vec_size, &first_partial_cu,
			    &last_partial_cu, false))
	{
	  for (i = 0; i < vec_size; i++)
	    arr[i]->die_ref_seen = arr[i]->die_dup != NULL;
	  for (i = 0; i < vec_size; i++)
	    if (arr[i]->die_dup != NULL)
	      mark_refs (arr[i], arr[i], MARK_REFS_FOLLOW_DUPS);
	  partition_dups_1 (arr, vec_size, &first_partial_cu,
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
  struct dw_cu *cu;
  /* Linked list of incoming resp. outgoing edges.  */
  struct import_edge *incoming, *outgoing;
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
  /* Flag used during PU merging, set for PUs already considered
     for merging for the given first PU.  */
  bool seen;
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

/* Remove edges in linked list EP that refer to CUS, which
   is an array of CUCOUNT CUs/PUs.  If ADD is true, additionally
   add a new edge at the end of the linked list and return it.  */
static struct import_edge *
remove_import_edges (struct import_edge **ep, struct import_cu **cus,
		     unsigned int cucount, bool add)
{
  unsigned int i = 0;
  struct import_edge *e, *efirst = NULL;
  while (*ep)
    if (i < cucount && (*ep)->icu == cus[i])
      {
	e = *ep;
	*ep = e->next;
	if (efirst == NULL)
	  efirst = e;
	else
	  {
	    e->next = edge_freelist;
	    edge_freelist = e;
	  }
	i++;
	if (i == cucount && !add)
	  return NULL;
      }
    else
      ep = &(*ep)->next;
  assert (i == cucount);
  *ep = efirst;
  efirst->next = NULL;
  return efirst;
}

#ifdef DEBUG_VERIFY_EDGES
/* Helper function for debugging create_import_tree.  Verify
   various invariants for CU/PU IPU.  */
static void
verify_edges_1 (struct import_cu *ipu, unsigned int *ic, unsigned int *oc)
{
  struct import_edge *e1, *e2;
  unsigned int last_idx = 0, count;
  for (e1 = ipu->incoming, count = 0; e1; e1 = e1->next)
    {
      assert (count == 0 || e1->icu->idx > last_idx);
      last_idx = e1->icu->idx;
      count++;
      for (e2 = e1->icu->outgoing; e2; e2 = e2->next)
	if (e2->icu == ipu)
	  break;
      assert (e2);
    }
  assert (ipu->incoming_count == count);
  for (e1 = ipu->outgoing, count = 0; e1; e1 = e1->next)
    {
      assert (count == 0 || e1->icu->idx > last_idx);
      last_idx = e1->icu->idx;
      count++;
      for (e2 = e1->icu->incoming; e2; e2 = e2->next)
	if (e2->icu == ipu)
	  break;
      assert (e2);
    }
  assert (ipu->outgoing_count == count);
  *ic += ipu->incoming_count;
  *oc += ipu->outgoing_count;
}

/* Helper function for debugging create_import_tree.  Call verify_edges_1
   on all CUs and PUs.  */
void
verify_edges (struct import_cu **ipus, unsigned int npus, unsigned int ncus)
{
  struct import_cu *ipu;
  unsigned int i, ic = 0, oc = 0;
  for (ipu = ipus[0]; ipu; ipu = ipu->next)
    verify_edges_1 (ipu, &ic, &oc);
  for (i = 0; i < ncus; i++)
    verify_edges_1 (ipus[i + npus], &ic, &oc);
  assert (ic == oc);
}
#endif

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
  struct dw_cu *pu, *cu, *last_partial_cu = NULL;
  unsigned int i, new_pu_version = 2, min_cu_version, npus, ncus;
  struct import_cu **ipus, *ipu, *icu;
  unsigned int cu_off;
  unsigned int puidx;
  struct import_cu *last_pu, *pu_freelist = NULL;
  unsigned char *to_free;
  /* size doesn't count anything already created before this
     function (partial units etc.) or already preexisting, just
     initially the cumulative sizes of DW_TAG_imported_unit DIEs
     that would need to be added, and if some new DW_TAG_partial_unit
     CUs are going to be created as a result of this routine, that size
     too.  DW_TAG_imported_unit has size 5 (for DWARF3+) or 1 + ptr_size
     (DWARF2), DW_TAG_partial_unit has size 13 (11 CU header + 1 byte
     abbrev number + 1 byte child end).  */
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
      struct dw_cu *prev_cu;

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
      for (die = rdie->die_nextdup, prev_cu = NULL;
	   die; die = die->die_nextdup)
	{
	  if (die->die_cu == prev_cu)
	    continue;
	  ipu->incoming_count++;
	  size += 1 + (die->die_cu->cu_version == 2 ? ptr_size : 4);
	  prev_cu = die->die_cu;
	}
      ipu->incoming = (struct import_edge *)
		       obstack_alloc (&ob2,
				      ipu->incoming_count
				      * sizeof (*ipu->incoming));
      for (die = rdie->die_nextdup, i = 0, prev_cu = NULL;
	   die; die = die->die_nextdup)
	{
	  if (die->die_cu == prev_cu)
	    continue;
	  icu = die->die_cu->u1.cu_icu;
	  if (icu == NULL)
	    {
	      icu = (struct import_cu *)
		    obstack_alloc (&ob2, sizeof (*ipu));
	      memset (icu, 0, sizeof (*icu));
	      icu->cu = die->die_cu;
	      die->die_cu->u1.cu_icu = icu;
	    }
	  ipu->incoming[i++].icu = icu;
	  icu->outgoing_count++;
	  prev_cu = die->die_cu;
	}
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
  /* Now, for the above constructed bipartite graph, find K x,2 components
     where x >= 5 (for DWARF3 and above or ptr_size 4, for DWARF2 and
     ptr_size 8 it can be even x == 4) and add a new PU node, where all
     CUs from the component will point to the new PU node and that new PU
     will point to all the destination PUs.  In theory with DWARF2
     and ptr_size 1 we could need x >= 9.  */
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
		      pusrc[srccount] = e3->icu;
		      cost += edge_cost;
		      if (!edge_cost)
			cost += pusrc[srccount]->cu->cu_version == 2
				? 1 + ptr_size : 5;
		      srccount++;
		      if ((dstcount - 1) * cost
			  > 13 + dstcount * new_edge_cost)
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
			      remove_import_edges (&pusrc[j]->outgoing, pudst,
						   dstcount, true)->icu = npu;
			      pusrc[j]->outgoing_count -= dstcount - 1;
			    }
			  for (j = 0; j < dstcount; j++)
			    {
			      remove_import_edges (&pudst[j]->incoming, pusrc,
						   srccount, true)->icu = npu;
			      pudst[j]->incoming_count -= srccount - 1;
			    }
			  npu->incoming = edge_freelist;
			  for (j = 0, e4 = npu->incoming; j < srccount; j++)
			    {
			      e4->icu = pusrc[j];
			      if (j == srccount - 1)
				{
				  edge_freelist = e4->next;
				  e4->next = NULL;
				  ep = &e4->next;
				}
			      else
				e4 = e4->next;
			    }
			  npu->outgoing = edge_freelist;
			  for (j = 0, e4 = npu->outgoing; j < dstcount; j++)
			    {
			      e4->icu = pudst[j];
			      if (j == dstcount - 1)
				{
				  edge_freelist = e4->next;
				  e4->next = NULL;
				}
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
		      remove_import_edges (&pusrc[srccount]->outgoing, pudst,
					   dstcount, true)->icu = npu;
		      pusrc[srccount]->outgoing_count -= dstcount - 1;
		      for (j = 0; j < dstcount; j++)
			{
			  remove_import_edges (&pudst[j]->incoming,
					       pusrc + srccount, 1, false);
			  pudst[j]->incoming_count--;
			}
		      *ep = edge_freelist;
		      edge_freelist = edge_freelist->next;
		      npu->incoming_count++;
		      (*ep)->icu = pusrc[srccount];
		      (*ep)->next = NULL;
		      ep = &(*ep)->next;
		      size -= (dstcount - 1) * cost;
		    }
		}
	    }
	}
    }
  /* Try to merge PUs which have the same set of referrers if
     beneficial, or if one PU has a subset of referrers of the
     other, attempt to replace all the incoming edges from the
     referrers intersection to the PU with larger number of
     incoming edges by an edge from the other PU.  */
  for (ipu = ipus[0]; ipu; ipu = ipu->next)
    {
      struct import_edge *e1, *e2, *e3, *e4, **e1p, **ep;
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

	      if (ipu2->idx <= ipu->idx || ipu2->seen)
		continue;
	      ipu2->seen = true;
	      maybe_subset = (e1 == ipu->incoming
			      && ipu->incoming_count <= ipu2->incoming_count);
	      maybe_superset = ipu->incoming_count >= ipu2->incoming_count;
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
		  if (size_dec > size_inc)
		    {
		      struct import_cu **ipup;
		      for (e4 = ipu2->incoming, ep = NULL; e4; e4 = e4->next)
			{
			  remove_import_edges (&e4->icu->outgoing, &ipu2, 1,
					       false);
			  e4->icu->outgoing_count--;
			  ep = &e4->next;
			}
		      *ep = edge_freelist;
		      edge_freelist = ipu2->incoming;
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
		  for (e3 = ipusub->incoming, ep = &ipusup->incoming;
		       e3; e3 = e3->next)
		    {
		      remove_import_edges (&e3->icu->outgoing, &ipusup, 1,
					   false);
		      e3->icu->outgoing_count--;
		      while ((*ep)->icu != e3->icu)
			ep = &(*ep)->next;
		      e4 = *ep;
		      *ep = e4->next;
		      e4->next = edge_freelist;
		      edge_freelist = e4;
		    }
		  for (ep = &ipusub->outgoing; *ep; ep = &(*ep)->next)
		    if ((*ep)->icu->idx >= ipusup->idx)
		      break;
		  assert (*ep == NULL || (*ep)->icu != ipusup);
		  e4 = edge_freelist;
		  edge_freelist = edge_freelist->next;
		  e4->icu = ipusup;
		  e4->next = *ep;
		  *ep = e4;
		  ipusub->outgoing_count++;
		  for (ep = &ipusup->incoming; *ep; ep = &(*ep)->next)
		    if ((*ep)->icu->idx >= ipusub->idx)
		      break;
		  assert (*ep == NULL || (*ep)->icu != ipusub);
		  e4 = edge_freelist;
		  edge_freelist = edge_freelist->next;
		  e4->icu = ipusup;
		  e4->next = *ep;
		  *ep = e4;
		  ipusup->incoming_count -= ipusub->incoming_count - 1;
		  size -= size_dec - size_inc;
		  if (ipusup == ipu)
		    break;
		}
	    }
	}
      for (icu = ipu->next; icu; icu = icu->next)
	icu->seen = false;
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
      struct dw_cu *partial_cu = pool_alloc (dw_cu, sizeof (struct dw_cu));
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
      die->die_cu = partial_cu;
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
	  die->die_cu = cu;
	  die->die_nextdup = e->icu->cu->cu_die;
	  die->die_parent = die->die_cu->cu_die;
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

/* Record abbreviations referenced from .debug_types section.
   .debug_types sections aren't rewritten, so the abbrevs need
   to stay as is.  */
static int
read_debug_types (DSO *dso)
{
  unsigned char *ptr, *endcu, *endsec;
  htab_t abbrev;
  unsigned int value, last_abbrev_offset = -1U;

  ptr = debug_sections[DEBUG_TYPES].data;
  if (ptr == NULL)
    return 0;
  endsec = ptr + debug_sections[DEBUG_TYPES].size;
  while (ptr < endsec)
    {
      unsigned int cu_offset = ptr - debug_sections[DEBUG_TYPES].data, culen;
      int cu_version;
      struct dw_cu *cu;

      if (ptr + 23 > endsec)
	{
	  error (0, 0, "%s: .debug_types CU header too small", dso->filename);
	  return 1;
	}

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
	  error (0, 0, "%s: .debug_types too small", dso->filename);
	  return 1;
	}

      cu_version = read_16 (ptr);
      if (cu_version < 2 || cu_version > 4)
	{
	  error (0, 0, "%s: DWARF version %d unhandled", dso->filename,
		 cu_version);
	  return 1;
	}

      value = read_32 (ptr);
      if (value >= debug_sections[DEBUG_ABBREV].size)
	{
	  if (debug_sections[DEBUG_ABBREV].data == NULL)
	    error (0, 0, "%s: .debug_abbrev not present", dso->filename);
	  else
	    error (0, 0, "%s: DWARF CU abbrev offset too large",
		   dso->filename);
	  return 1;
	}

      if (cu_offset && last_abbrev_offset == value)
	abbrev = NULL;
      else
	{
	  abbrev = read_abbrev (dso, debug_sections[DEBUG_ABBREV].data + value,
				true);
	  if (abbrev == NULL)
	    return 1;
	  last_abbrev_offset = value;
	}

      cu = pool_alloc (dw_cu, sizeof (struct dw_cu));
      memset (cu, '\0', sizeof (*cu));
      cu->cu_kind = CU_TYPES;
      cu->cu_new_abbrev = abbrev;
      cu->cu_offset = cu_offset;
      cu->cu_version = cu_version;
      if (abbrev == NULL)
	{
	  cu->u1.cu_new_abbrev_owner = last_cu->u1.cu_new_abbrev_owner;
	  if (cu->u1.cu_new_abbrev_owner == NULL)
	    cu->u1.cu_new_abbrev_owner = last_cu;
	}
      if (first_cu == NULL)
	first_cu = last_cu = cu;
      else
	{
	  last_cu->cu_next = cu;
	  last_cu = cu;
	}
      ptr = endcu;
    }

  return 0;
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

static htab_t line_htab;
static unsigned int max_line_id;

struct line_entry
{
  struct dw_file *file;
  unsigned int hash;
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

static unsigned int
line_htab_lookup (struct dw_cu *cu, unsigned int id)
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

static htab_t macro_htab;

static htab_t alt_macro_htab;

struct macro_entry
{
  unsigned char *ptr;
  unsigned int hash;
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
	case DW_MACRO_GNU_define:
	case DW_MACRO_GNU_undef:
	  read_uleb128 (p1);
	  p1 = (unsigned char *) strchr ((char *) p1, '\0') + 1;
	  break;
	case DW_MACRO_GNU_define_indirect:
	case DW_MACRO_GNU_undef_indirect:
	  read_uleb128 (p1);
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
      if (version != 4)
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
	    case DW_MACRO_GNU_define:
	    case DW_MACRO_GNU_undef:
	      read_uleb128 (ptr);
	      ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
	      break;
	    case DW_MACRO_GNU_start_file:
	      read_uleb128 (ptr);
	      read_uleb128 (ptr);
	      can_share = false;
	      break;
	    case DW_MACRO_GNU_end_file:
	      can_share = false;
	      break;
	    case DW_MACRO_GNU_define_indirect:
	    case DW_MACRO_GNU_undef_indirect:
	      read_uleb128 (ptr);
	      strp = read_32 (ptr);
	      note_strp_offset (strp);
	      if (wr_multifile)
		{
		  break;
		}
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
	    case DW_MACRO_GNU_transparent_include:
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
	    case DW_MACRO_GNU_define:
	    case DW_MACRO_GNU_undef:
	      read_uleb128 (ptr);
	      ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
	      break;
	    case DW_MACRO_GNU_start_file:
	      read_uleb128 (ptr);
	      read_uleb128 (ptr);
	      can_share = false;
	      break;
	    case DW_MACRO_GNU_end_file:
	      can_share = false;
	      break;
	    case DW_MACRO_GNU_define_indirect:
	    case DW_MACRO_GNU_undef_indirect:
	      read_uleb128 (ptr);
	      ptr += 4;
	      break;
	    case DW_MACRO_GNU_transparent_include:
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
		case DW_MACRO_GNU_define:
		case DW_MACRO_GNU_undef:
		  read_uleb128 (ptr);
		  ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
		  break;
		case DW_MACRO_GNU_define_indirect:
		case DW_MACRO_GNU_undef_indirect:
		  read_uleb128 (ptr);
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
	case DW_MACRO_GNU_define:
	case DW_MACRO_GNU_undef:
	  read_uleb128 (p);
	  p = (unsigned char *) strchr ((char *) p, '\0') + 1;
	  break;
	case DW_MACRO_GNU_define_indirect:
	case DW_MACRO_GNU_undef_indirect:
	  read_uleb128 (p);
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
	    case DW_MACRO_GNU_define:
	    case DW_MACRO_GNU_undef:
	      read_uleb128 (ptr);
	      ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
	      break;
	    case DW_MACRO_GNU_define_indirect:
	    case DW_MACRO_GNU_undef_indirect:
	      read_uleb128 (ptr);
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
	    case DW_MACRO_GNU_define:
	    case DW_MACRO_GNU_undef:
	      read_uleb128 (ptr);
	      ptr = (unsigned char *) strchr ((char *) ptr, '\0') + 1;
	      break;
	    case DW_MACRO_GNU_start_file:
	      read_uleb128 (ptr);
	      read_uleb128 (ptr);
	      break;
	    case DW_MACRO_GNU_end_file:
	      break;
	    case DW_MACRO_GNU_define_indirect:
	    case DW_MACRO_GNU_undef_indirect:
	      memcpy (dst, s, ptr - 1 - s);
	      dst += ptr - 1 - s;
	      s = ptr - 1;
	      read_uleb128 (ptr);
	      strp = read_32 (ptr);
	      if (note_strp_offset2 (strp) == DW_FORM_GNU_strp_alt)
		{
		  *dst = op == DW_MACRO_GNU_define_indirect
			 ? DW_MACRO_GNU_define_indirect_alt
			 : DW_MACRO_GNU_undef_indirect_alt;
		  dst++;
		  s++;
		}
	      memcpy (dst, s, ptr - 4 - s);
	      dst += ptr - 4 - s;
	      write_32 (dst, lookup_strp_offset (strp));
	      s = ptr;
	      break;
	    case DW_MACRO_GNU_transparent_include:
	      memcpy (dst, s, ptr - 1 - s);
	      dst += ptr - 1 - s;
	      me.ptr = debug_sections[DEBUG_MACRO].data + read_32 (ptr);
	      m = (struct macro_entry *)
		  htab_find_with_hash (macro_htab, &me,
				       me.ptr
				       - debug_sections[DEBUG_MACRO].data);
	      if (m->len)
		*dst = DW_MACRO_GNU_transparent_include_alt;
	      else
		*dst = DW_MACRO_GNU_transparent_include;
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
build_abbrevs_for_die (htab_t h, dw_die_ref die, dw_die_ref ref,
		       struct abbrev_tag *t, unsigned int *ndies,
		       struct obstack *vec)
{
  dw_die_ref child, ref_child, sib = NULL, origin = NULL;
  unsigned int i, j;
  uint64_t low_pc = 0;
  void **slot;

  die->u.p2.die_new_abbrev = NULL;
  die->u.p2.die_new_offset = 0;
  die->u.p2.die_intracu_udata_size = 0;

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
	ref = die->die_nextdup;
      if (ref == NULL)
	origin = die->die_nextdup;
    }
  else
    {
      ref = die;
      if (wr_multifile
	  && (die->die_parent == NULL || die->die_named_namespace))
	origin = die;
    }
  if (die->die_child && die->die_sib)
    for (sib = die->die_sib; sib; sib = sib->die_sib)
      if (wr_multifile ? !sib->die_no_multifile : !sib->die_remove)
	break;
  if (ref != NULL && origin == NULL)
    {
      unsigned char *ptr = debug_sections[DEBUG_INFO].data
			   + ref->die_offset;
      struct abbrev_tag *reft = ref->die_abbrev;

      read_uleb128 (ptr);
      /* No longer count the abbrev uleb128 size in die_size.
	 We'll add it back after determining the new abbrevs.  */
      if (unlikely (wr_multifile || op_multifile || fi_multifile))
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
	    case DW_FORM_addr:
	      if (reft->attr[i].attr == DW_AT_high_pc
		  && die->die_cu->cu_version >= 4)
		i = -2U;
	      break;
	    default:
	      break;
	    }
      if (i != -1U)
	{
	  die->die_size -= ptr
			   - (debug_sections[DEBUG_INFO].data
			      + ref->die_offset);
	  /* If there are no references, size stays the same
	     and no need to walk the actual attribute values.  */
	  for (i = 0; i < reft->nattr; i++)
	    {
	      t->attr[i].attr = reft->attr[i].attr;
	      t->attr[i].form = reft->attr[i].form;
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
	      uint64_t value;
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
		    default:
		      error (0, 0, "Unhandled DW_FORM_%d for DW_AT_%d",
			     form, reft->attr[i].attr);
		      return 1;
		    }
		  value = line_htab_lookup (ref->die_cu, value);
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
		  else
		    {
		      form = DW_FORM_data4;
		      die->die_size += 4;
		    }
		  t->attr[j].attr = reft->attr[i].attr;
		  t->attr[j++].form = form;
		  continue;
		}

	      if (unlikely (fi_multifile)
		  && reft->attr[i].attr == DW_AT_GNU_macros
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
		      error (0, 0, "Unhandled DW_FORM_%d for DW_AT_GNU_macros",
			     form);
		      return 1;
		    }
		  me.ptr = debug_sections[DEBUG_MACRO].data + value;
		  m = (struct macro_entry *)
		    htab_find_with_hash (macro_htab, &me, value);
		  if (m->len)
		    {
		      error (0, 0, "DW_AT_GNU_macros referencing "
				   "transparent include");
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
					 ref->die_cu->cu_version == 2
					 ? ptr_size : 4);
		      ptr += ref->die_cu->cu_version == 2 ? ptr_size : 4;
		      refd = off_htab_lookup (ref->die_cu, value);
		      assert (refd != NULL);
		      refdt = refd;
		      while (refdt->die_toplevel == 0)
			refdt = refdt->die_parent;
		      if (refdt->die_dup
			  && !refdt->die_op_type_referenced
			  && refdt->die_dup->die_cu->cu_kind == CU_ALT)
			{
			  t->attr[j].attr = reft->attr[i].attr;
			  t->attr[j++].form = DW_FORM_GNU_ref_alt;
			  die->die_size += 4;
			  continue;
			}
		      break;
		    }
		  ptr += ref->die_cu->cu_version == 2 ? ptr_size : 4;
		  break;
		case DW_FORM_addr:
		  ptr += ptr_size;
		  if (reft->attr[i].attr == DW_AT_low_pc
		      && die->die_cu->cu_version >= 4)
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
			  if (sz <= 4 && sz < (unsigned) ptr_size)
			    nform = DW_FORM_udata;
			  else if (ptr_size > 4
				   && high_pc - low_pc <= 0xffffffff)
			    {
			      nform = DW_FORM_data4;
			      sz = 4;
			    }
			  else if (sz < (unsigned) ptr_size)
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
		case DW_FORM_ref_sig8:
		  ptr += 8;
		  break;
		case DW_FORM_sdata:
		case DW_FORM_udata:
		  read_uleb128 (ptr);
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
		      refd = off_htab_lookup (ref->die_cu,
					      ref->die_cu->cu_offset + value);
		      assert (refd != NULL);
		      refdt = refd;
		      while (refdt->die_toplevel == 0)
			refdt = refdt->die_parent;
		      if (refdt->die_dup && refdt->die_op_type_referenced)
			{
			  if (die->die_cu == refd->die_cu)
			    form = DW_FORM_ref4;
			  else if (die->die_cu == refdt->die_dup->die_cu)
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
			  if (die->die_cu == refd->die_cu)
			    form = DW_FORM_ref4;
			  else if (refd->die_cu->cu_kind == CU_ALT)
			    form = DW_FORM_GNU_ref_alt;
			  else
			    form = DW_FORM_ref_addr;
			}
		    }
		  if (form == DW_FORM_ref_addr)
		    die->die_size += die->die_cu->cu_version == 2 ? ptr_size : 4;
		  else if (form == DW_FORM_GNU_ref_alt)
		    die->die_size += 4;
		  else
		    {
		      obstack_ptr_grow (vec, die);
		      obstack_ptr_grow (vec, refd);
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
	      t->attr[j++].form = reft->attr[i].form;
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
	if (origin->die_cu->cu_nfiles)
	  {
	    t->attr[0].attr = DW_AT_stmt_list;
	    t->attr[0].form = die->die_cu->cu_version < 4
			      ? DW_FORM_sec_offset : DW_FORM_data4;
	    die->die_size += 4;
	    t->nattr++;
	  }
	if (origin->die_cu->cu_comp_dir)
	  {
	    enum dwarf_form form;
	    unsigned char *ptr = get_AT (origin, DW_AT_comp_dir, &form);
	    assert (ptr && (form == DW_FORM_string || form == DW_FORM_strp));
	    if (form == DW_FORM_strp)
	      {
		if (unlikely (op_multifile || fi_multifile))
		  form = note_strp_offset2 (read_32 (ptr));
		die->die_size += 4;
	      }
	    else
	      die->die_size
		= strlen (origin->die_cu->cu_comp_dir) + 1;
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
	  assert (ptr && (form == DW_FORM_string || form == DW_FORM_strp));
	  if (form == DW_FORM_strp)
	    {
	      if (unlikely (op_multifile || fi_multifile))
		form = note_strp_offset2 (read_32 (ptr));
	      die->die_size = 4;
	    }
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
	if (die->die_nextdup->die_cu->cu_kind == CU_ALT)
	  {
	    t->attr[0].form = DW_FORM_GNU_ref_alt;
	    die->die_size = 4;
	  }
	else
	  {
	    t->attr[0].form = DW_FORM_ref_addr;
	    die->die_size = die->die_cu->cu_version == 2 ? ptr_size : 4;
	  }
	break;
      default:
	abort ();
      }
  compute_abbrev_hash (t);
  slot = htab_find_slot_with_hash (h, t, t->hash, INSERT);
  if (slot == NULL)
    dwz_oom ();
  if (*slot)
    {
      ((struct abbrev_tag *)*slot)->nusers++;
      die->u.p2.die_new_abbrev = (struct abbrev_tag *)*slot;
    }
  else
    {
      struct abbrev_tag *newt
	= pool_alloc (abbrev_tag,
		      sizeof (*newt) + t->nattr * sizeof (struct abbrev_attr));
      memcpy (newt, t,
	      sizeof (*newt) + t->nattr * sizeof (struct abbrev_attr));
      *slot = newt;
      die->u.p2.die_new_abbrev = newt;
    }
  (*ndies)++;
  if (ref != NULL && ref != die)
    {
      for (child = die->die_child, ref_child = ref->die_child;
	   child; child = child->die_sib, ref_child = ref_child->die_sib)
	if (build_abbrevs_for_die (h, child, ref_child, t, ndies, vec))
	  return 1;
    }
  else
    for (child = die->die_child; child; child = child->die_sib)
      if (build_abbrevs_for_die (h, child, NULL, t, ndies, vec))
	return 1;
  return 0;
}

/* Build new abbreviations for CU.  T, NDIES and VEC arguments like
   for build_abbrevs_for_die.  */
static int
build_abbrevs (struct dw_cu *cu, struct abbrev_tag *t, unsigned int *ndies,
	       struct obstack *vec)
{
  htab_t h = htab_try_create (50, abbrev_hash, abbrev_eq2, NULL);

  if (h == NULL)
    dwz_oom ();

  if (build_abbrevs_for_die (h, cu->cu_die, NULL, t, ndies, vec))
    return 1;

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

/* Helper function to find abbrev with highest abbrev number,
   called through htab_traverse.  */
static int
find_max_abbrev_entry (void **slot, void *info)
{
  struct abbrev_tag *t = (struct abbrev_tag *) *slot;
  unsigned int *largest = (unsigned int *) info;
  if (t->entry > *largest)
    *largest = t->entry;
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
  die->die_size += size_of_uleb128 (die->u.p2.die_new_abbrev->entry);
  die->u.p2.die_intracu_udata_size = 0;
  for (i = 0; i < t->nattr; ++i)
    if (t->attr[i].form == DW_FORM_ref4)
      die->u.p2.die_intracu_udata_size += intracusize;
  die->die_size += die->u.p2.die_intracu_udata_size;
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
    assert (die->u.p2.die_intracu_udata_size == 0);
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
finalize_new_die_offsets (dw_die_ref die, unsigned int off,
			  unsigned int intracusize, dw_die_ref **intracuvec)
{
  dw_die_ref child;
  if (wr_multifile ? die->die_no_multifile : die->die_remove)
    return off;
  die->u.p2.die_new_offset = off;
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
	 > size_of_uleb128 (die->die_offset - die->die_cu->cu_offset))
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
    assert (die->u.p2.die_intracu_udata_size == 0);
  off += die->die_size;
  for (child = die->die_child; child; child = child->die_sib)
    {
      off = finalize_new_die_offsets (child, off, intracusize, intracuvec);
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
  struct dw_cu *cu1 = *(struct dw_cu **)p;
  struct dw_cu *cu2 = *(struct dw_cu **)q;
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
  unsigned long total_size = 0, abbrev_size = 0;
  struct dw_cu *cu, **cuarr;
  struct abbrev_tag *t;
  unsigned int ncus, nlargeabbrevs = 0, i, laststart;
  unsigned char *to_free = obstack_alloc (&ob2, 1);
  bool saw_cu_normal = false;

  t = (struct abbrev_tag *)
      obstack_alloc (&ob2,
		     sizeof (*t)
		     + (max_nattr + 4) * sizeof (struct abbrev_attr));
  for (cu = first_cu, ncus = 0; cu; cu = cu->cu_next)
    {
      unsigned int intracu, ndies = 0, tagsize = 0, nchildren = 0;
      unsigned int nabbrevs, diesize, cusize, off, intracusize;
      struct abbrev_tag **arr;
      dw_die_ref *intracuarr, *intracuvec;
      enum dwarf_form intracuform = DW_FORM_ref4;
      dw_die_ref child, *lastotr, child_next, *last;

      if (cu->cu_kind == CU_TYPES)
	{
	  if (cu->u1.cu_new_abbrev_owner != NULL)
	    continue;
	  ncus++;
	  if (htab_elements (cu->cu_new_abbrev) >= 128)
	    nlargeabbrevs++;
	  cu->u2.cu_largest_entry = 0;
	  htab_traverse (cu->cu_new_abbrev, find_max_abbrev_entry,
			 &cu->u2.cu_largest_entry);
	  continue;
	}
      if (unlikely (fi_multifile) && cu->cu_die->die_remove)
	continue;
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
      cusize = 11 + tagsize + diesize + nchildren;
      intracusize = size_of_uleb128 (cusize + intracu);
      do
	{
	  i = size_of_uleb128 (cusize + intracu * intracusize);
	  if (i == intracusize)
	    break;
	  intracusize = i;
	}
      while (1);
      off = init_new_die_offsets (cu->cu_die, 11, intracusize);
      do
	{
	  intracuvec = intracuarr;
	  i = update_new_die_offsets (cu->cu_die, 11, &intracuvec);
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
      off = finalize_new_die_offsets (cu->cu_die, 11, intracusize,
				      &intracuvec);
      if (off == -1U)
	{
	  error (0, 0, "%s: DW_OP_call2 or typed DWARF stack referenced DIE"
		       " layed out at too big offset", dso->filename);
	  return 1;
	}
      assert (*intracuvec == NULL && off == cusize);

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
      if (wr_multifile && cu->cu_kind == CU_NORMAL && !saw_cu_normal)
	{
	  total_size += 11;
	  saw_cu_normal = true;
	}
      cu->cu_new_offset = (wr_multifile ? multi_info_off : 0) + total_size;
      total_size += cusize;
    }
  if (wr_multifile)
    total_size += saw_cu_normal ? 11 : 22;
  obstack_free (&ob2, (void *) t);
  cuarr = (struct dw_cu **) obstack_alloc (&ob2,
					   ncus * sizeof (struct dw_cu *));
  for (cu = first_cu, i = 0; cu; cu = cu->cu_next)
    if (cu->u1.cu_new_abbrev_owner == NULL
	&& (likely (!fi_multifile)
	    || cu->cu_kind != CU_NORMAL
	    || !cu->cu_die->die_remove))
      cuarr[i++] = cu;
  assert (i == ncus);
  qsort (cuarr, ncus, sizeof (struct dw_cu *), cu_abbrev_cmp);
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
		  /* We aren't rewriting .debug_types section, merely
		     adjusting .debug_abbrev offsets into it, so the
		     assigned entry values for .debug_types section
		     can't change.  */
		  if (cuarr[i]->cu_kind == CU_TYPES)
		    {
		      if (t == NULL || t->entry != arr[k]->entry)
			break;
		    }
		  else if (t == NULL)
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
		      newt = pool_alloc (abbrev_tag,
					 sizeof (*newt)
					 + arr[k]->nattr
					   * sizeof (struct abbrev_attr));
		      memcpy (newt, arr[k],
			      sizeof (*newt)
			      + arr[k]->nattr * sizeof (struct abbrev_attr));
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
	      /* We aren't rewriting .debug_types section, merely adjusting
		 .debug_abbrev offsets into it, so the assigned entry
		 values for .debug_types section can't change.  */
	      if (cuarr[i]->cu_kind == CU_TYPES && t->entry != arr[k]->entry)
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
		  /* We aren't rewriting .debug_types section, merely adjusting
		     .debug_abbrev offsets into it, so the assigned entry
		     values for .debug_types section can't change.  */
		  if (cuarr[i]->cu_kind == CU_TYPES
		      && (t == NULL || t->entry != arr[k]->entry))
		    {
		      curdups = 0;
		      break;
		    }
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
		      newt = pool_alloc (abbrev_tag,
					 sizeof (*newt)
					 + arr[k]->nattr
					   * sizeof (struct abbrev_attr));
		      memcpy (newt, arr[k],
			      sizeof (*newt)
			      + arr[k]->nattr * sizeof (struct abbrev_attr));
		      *slot = newt;
		    }
		}
	      cuarr[j]->u2.cu_largest_entry = entry;
	      cuarr[i]->u1.cu_new_abbrev_owner = cuarr[j];
	    }
	}
      obstack_free (&ob2, (void *) arr);
    }
  obstack_free (&ob2, to_free);
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
	struct dw_cu *owner = cu;
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
  struct dw_cu *cu;
  unsigned char *abbrev = malloc (debug_sections[DEBUG_ABBREV].new_size);
  unsigned char *ptr = abbrev;

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
	    }
	  *ptr++ = 0;
	  *ptr++ = 0;
	}
      *ptr++ = 0;
      obstack_free (&ob, (void *) arr);
      htab_delete (cu->cu_new_abbrev);
      cu->cu_new_abbrev = NULL;
    }
  assert (abbrev + debug_sections[DEBUG_ABBREV].new_size == ptr);
}

/* Adjust DWARF expression starting at PTR, LEN bytes long, referenced by
   DIE, with REF being the original DIE.  */
static void
adjust_exprloc (dw_die_ref die, dw_die_ref ref, unsigned char *ptr, size_t len)
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
	  refd = off_htab_lookup (ref->die_cu,
				  ref->die_cu->cu_offset + addr);
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
	  addr = read_size (ptr, ref->die_cu->cu_version == 2 ? ptr_size : 4);
	  assert (die->die_cu->cu_version == ref->die_cu->cu_version);
	  refd = off_htab_lookup (ref->die_cu, addr);
	  assert (refd != NULL);
	  refdt = refd;
	  while (refdt->die_toplevel == 0)
	    refdt = refdt->die_parent;
	  if (refdt->die_dup && !refdt->die_op_type_referenced)
	    refd = die_find_dup (refdt, refdt->die_dup, refd);
	  write_size (ptr, die->die_cu->cu_version == 2 ? ptr_size : 4,
		      refd->die_cu->cu_new_offset
		      + refd->u.p2.die_new_offset);
	  if (die->die_cu->cu_version == 2)
	    ptr += ptr_size;
	  else
	    ptr += 4;
	  if (op == DW_OP_GNU_implicit_pointer)
	    read_uleb128 (ptr);
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
	  read_uleb128 (ptr);
	  break;
	case DW_OP_bregx:
	case DW_OP_bit_piece:
	  read_uleb128 (ptr);
	  read_uleb128 (ptr);
	  break;
	case DW_OP_implicit_value:
	  leni = read_uleb128 (ptr);
	  ptr += leni;
	  break;
	case DW_OP_GNU_entry_value:
	  leni = read_uleb128 (ptr);
	  assert ((uint64_t) (end - ptr) >= leni);
	  adjust_exprloc (die, ref, ptr, leni);
	  ptr += leni;
	  break;
	case DW_OP_GNU_convert:
	case DW_OP_GNU_reinterpret:
	  orig_ptr = ptr;
	  addr = read_uleb128 (ptr);
	  if (addr == 0)
	    break;
	  goto typed_dwarf;
	case DW_OP_GNU_regval_type:
	  read_uleb128 (ptr);
	  orig_ptr = ptr;
	  addr = read_uleb128 (ptr);
	  goto typed_dwarf;
	case DW_OP_GNU_const_type:
	  orig_ptr = ptr;
	  addr = read_uleb128 (ptr);
	  goto typed_dwarf;
	case DW_OP_GNU_deref_type:
	  ++ptr;
	  orig_ptr = ptr;
	  addr = read_uleb128 (ptr);
	typed_dwarf:
	  refd = off_htab_lookup (ref->die_cu,
				  ref->die_cu->cu_offset + addr);
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
	  if (op == DW_OP_GNU_const_type)
	    ptr += *ptr + 1;
	  break;
	default:
	  abort ();
	}
    }
}

/* Write DIE (with REF being the corresponding original DIE) to
   memory starting at PTR, return pointer after the DIE.  */
static unsigned char *
write_die (unsigned char *ptr, dw_die_ref die, dw_die_ref ref)
{
  uint64_t low_pc = 0;
  dw_die_ref child, sib = NULL, origin = NULL;
  struct abbrev_tag *t;

  if (wr_multifile ? die->die_no_multifile : die->die_remove)
    return ptr;
  if (die->die_offset == -1U)
    {
      if (ref != NULL)
	;
      else if (die_safe_nextdup (die) && die->die_nextdup->die_dup == die)
	ref = die->die_nextdup;
      if (ref == NULL)
	origin = die->die_nextdup;
    }
  else
    {
      ref = die;
      if (wr_multifile
	  && (die->die_parent == NULL || die->die_named_namespace))
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
      unsigned char *inptr = debug_sections[DEBUG_INFO].data
			     + ref->die_offset;
      struct abbrev_tag *reft = ref->die_abbrev;
      unsigned int i, j;

      read_uleb128 (inptr);
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
		case DW_FORM_data1: value = read_8 (inptr); break;
		case DW_FORM_data2: value = read_16 (inptr); break;
		case DW_FORM_data4: value = read_32 (inptr); break;
		case DW_FORM_data8: value = read_64 (inptr); break;
		case DW_FORM_udata: value = read_uleb128 (inptr); break;
		default: abort ();
		}
	      value = line_htab_lookup (ref->die_cu, value);
	      switch (t->attr[j].form)
		{
		case DW_FORM_data1: write_8 (ptr, value); break;
		case DW_FORM_data2: write_16 (ptr, value); break;
		case DW_FORM_data4: write_32 (ptr, value); break;
		default: abort ();
		}
	      j++;
	      continue;
	    }

	  if (unlikely (fi_multifile)
	      && reft->attr[i].attr == DW_AT_GNU_macros
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
		if (t->attr[j].form != DW_FORM_GNU_ref_alt)
		  {
		    memcpy (ptr, orig_ptr, inptr - orig_ptr);
		    ptr += inptr - orig_ptr;
		  }
		value = read_size (inptr, ref->die_cu->cu_version == 2
					  ? ptr_size : 4);
		inptr += ref->die_cu->cu_version == 2 ? ptr_size : 4;
		refd = off_htab_lookup (ref->die_cu, value);
		assert (refd != NULL);
		refdt = refd;
		while (refdt->die_toplevel == 0)
		  refdt = refdt->die_parent;
		if (refdt->die_dup && !refdt->die_op_type_referenced)
		  {
		    refd = die_find_dup (refdt, refdt->die_dup, refd);
		    if (t->attr[j].form == DW_FORM_GNU_ref_alt)
		      {
			assert (refd->die_cu->cu_kind == CU_ALT);
			write_32 (ptr, refd->die_offset);
			j++;
			continue;
		      }
		  }
		assert (refd->u.p2.die_new_offset
			&& t->attr[j].form != DW_FORM_GNU_ref_alt);
		value = refd->die_cu->cu_new_offset
			+ refd->u.p2.die_new_offset;
		write_size (ptr, die->die_cu->cu_version == 2 ? ptr_size : 4,
			    value);
		ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
		if (unlikely (op_multifile))
		  assert (refd->die_cu->cu_kind == CU_PU);
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
	      break;
	    case DW_FORM_flag:
	    case DW_FORM_data1:
	      ++inptr;
	      break;
	    case DW_FORM_data2:
	      inptr += 2;
	      break;
	    case DW_FORM_data4:
	    case DW_FORM_sec_offset:
	      inptr += 4;
	      break;
	    case DW_FORM_data8:
	    case DW_FORM_ref_sig8:
	      inptr += 8;
	      break;
	    case DW_FORM_sdata:
	    case DW_FORM_udata:
	      read_uleb128 (inptr);
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
		    = off_htab_lookup (ref->die_cu,
				       ref->die_cu->cu_offset + value);
		  assert (refd != NULL);
		  refdt = refd;
		  while (refdt->die_toplevel == 0)
		    refdt = refdt->die_parent;
		  if (refdt->die_dup && refdt->die_op_type_referenced)
		    {
		      if (die->die_cu == refdt->die_dup->die_cu)
			refd = die_find_dup (refdt, refdt->die_dup, refd);
		    }
		  else if (refdt->die_dup)
		    refd = die_find_dup (refdt, refdt->die_dup, refd);
		  if (t->attr[j].form == DW_FORM_GNU_ref_alt)
		    {
		      value = refd->die_offset;
		      assert (refd->die_cu->cu_kind == CU_ALT);
		    }
		  else
		    {
		      value = refd->u.p2.die_new_offset;
		      assert (value && refd->die_cu->cu_kind != CU_ALT);
		      if (t->attr[j].form == DW_FORM_ref_addr)
			{
			  value += refd->die_cu->cu_new_offset;
			  if (unlikely (op_multifile))
			    assert (refd->die_cu->cu_kind == CU_PU);
			}
		      else
			assert (refd->die_cu == die->die_cu);
		    }
		}
	      switch (t->attr[j].form)
		{
		case DW_FORM_ref1: write_8 (ptr, value); break;
		case DW_FORM_ref2: write_16 (ptr, value); break;
		case DW_FORM_ref4: write_32 (ptr, value); break;
		case DW_FORM_ref_udata: write_uleb128 (ptr, value); break;
		case DW_FORM_ref_addr:
		  write_size (ptr, die->die_cu->cu_version == 2 ? ptr_size : 4,
			      value);
		  ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
		  break;
		case DW_FORM_GNU_ref_alt: write_32 (ptr, value); break;
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

	  if (form == DW_FORM_block1)
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
	      case DW_AT_GNU_call_site_value:
	      case DW_AT_GNU_call_site_data_value:
	      case DW_AT_GNU_call_site_target:
	      case DW_AT_GNU_call_site_target_clobbered:
		adjust_exprloc (die, ref, ptr - len, len);
	      default:
		break;
	      }
	  else if (form == DW_FORM_exprloc)
	    adjust_exprloc (die, ref, ptr - len, len);
	  j++;
	}
      assert (j == t->nattr);
    }
  else
    switch (die->die_tag)
      {
      case DW_TAG_partial_unit:
      case DW_TAG_compile_unit:
	if (t->nattr == 0)
	  break;
	if (t->attr[0].attr == DW_AT_stmt_list)
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
	if (t->attr[t->nattr - 1].attr == DW_AT_comp_dir)
	  {
	    enum dwarf_form form;
	    unsigned char *p = get_AT (origin, DW_AT_comp_dir, &form);
	    assert (p);
	    assert (form == t->attr[t->nattr - 1].form
		    || (form == DW_FORM_strp
			&& t->attr[t->nattr - 1].form
			   == DW_FORM_GNU_strp_alt));
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
	    else
	      {
		size_t len = strlen ((char *) p) + 1;
		memcpy (ptr, p, len);
		ptr += len;
	      }
	  }
	break;
      case DW_TAG_namespace:
      case DW_TAG_module:
	{
	  enum dwarf_form form;
	  unsigned char *p = get_AT (origin, DW_AT_name, &form);
	  assert (p && (form == t->attr[0].form
			|| (form == DW_FORM_strp
			    && t->attr[0].form == DW_FORM_GNU_strp_alt)));
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
	if (t->attr[0].form == DW_FORM_GNU_ref_alt)
	  {
	    assert (die->die_nextdup->die_cu->cu_kind == CU_ALT);
	    write_32 (ptr, die->die_nextdup->die_offset);
	    break;
	  }
	assert (die->die_nextdup->die_cu->cu_kind != CU_ALT);
	write_size (ptr, die->die_cu->cu_version == 2 ? ptr_size : 4,
		    die->die_nextdup->die_cu->cu_new_offset
		    + die->die_nextdup->u.p2.die_new_offset);
	ptr += die->die_cu->cu_version == 2 ? ptr_size : 4;
	break;
      default:
	abort ();
      }
  if (ref != NULL && ref != die)
    {
      dw_die_ref ref_child;
      for (child = die->die_child, ref_child = ref->die_child;
	   child; child = child->die_sib, ref_child = ref_child->die_sib)
	ptr = write_die (ptr, child, ref_child);
    }
  else
    for (child = die->die_child; child; child = child->die_sib)
      ptr = write_die (ptr, child, NULL);
  if (die->die_child)
    write_8 (ptr, 0);
  return ptr;
}

/* Construct new .debug_info section in malloced memory,
   store it to debug_sections[DEBUG_INFO].new_data.  */
static void
write_info (void)
{
  struct dw_cu *cu, *cu_next;
  unsigned char *info = malloc (debug_sections[DEBUG_INFO].new_size);
  unsigned char *ptr = info;
  bool saw_cu_normal = false;

  if (info == NULL)
    dwz_oom ();
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
      if (wr_multifile && !saw_cu_normal && cu->cu_kind == CU_NORMAL)
	{
	  /* Emit a barrier separating CU_PUs from CU_NORMAL.  */
	  write_32 (ptr, 7);
	  write_16 (ptr, 2);
	  write_32 (ptr, 0);
	  write_8 (ptr, ptr_size);
	  saw_cu_normal = true;
	}
      cu_next = cu->cu_next;
      if (unlikely (fi_multifile))
	while (cu_next
	       && cu_next->cu_kind == CU_NORMAL
	       && cu_next->cu_die->die_remove)
	  cu_next = cu_next->cu_next;
      if (cu_next && cu_next->cu_kind == CU_TYPES)
	cu_next = NULL;
      if (cu_next)
	{
	  next_off = cu_next->cu_new_offset;
	  if (wr_multifile && !saw_cu_normal
	      && cu_next->cu_kind == CU_NORMAL)
	    next_off -= 11L;
	}
      else if (wr_multifile)
	next_off += multi_info_off - (saw_cu_normal ? 11L : 22L);
      /* Write CU header.  */
      write_32 (ptr, next_off - cu->cu_new_offset - 4);
      write_16 (ptr, cu->cu_version);
      write_32 (ptr, cu->u2.cu_new_abbrev_offset);
      write_8 (ptr, ptr_size);
      ptr = write_die (ptr, cu->cu_die, NULL);
      assert (info + (next_off - (wr_multifile ? multi_info_off : 0)) == ptr);
    }
  if (wr_multifile)
    {
      unsigned int i;
      /* And terminate the contribution by the current object file.  */
      for (i = 0; i < (saw_cu_normal ? 1 : 2); i++)
	{
	  write_32 (ptr, 7);
	  write_16 (ptr, 2);
	  write_32 (ptr, 0);
	  write_8 (ptr, ptr_size);
	}
    }
  assert (info + debug_sections[DEBUG_INFO].new_size == ptr);
}

/* Adjust .debug_loc range determined by *SLOT, called through
   htab_traverse.  */
static int
adjust_loclist (void **slot, void *data __attribute__((unused)))
{
  struct debug_loc_adjust *adj = (struct debug_loc_adjust *) *slot;
  unsigned char *ptr, *endsec;
  GElf_Addr low, high;
  size_t len;

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

      adjust_exprloc (adj->cu->cu_die, adj->cu->cu_die, ptr, len);

      ptr += len;
    }

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

/* Create new .debug_types section in malloced memory if abbrev
   offsets in .debug_types need to be adjusted.  */
static void
write_types (void)
{
  struct dw_cu *cu;
  unsigned char *types, *ptr;

  if (debug_sections[DEBUG_TYPES].data == NULL)
    return;
  types = malloc (debug_sections[DEBUG_TYPES].size);
  if (types == NULL)
    dwz_oom ();
  debug_sections[DEBUG_TYPES].new_data = types;
  memcpy (types, debug_sections[DEBUG_TYPES].data,
	  debug_sections[DEBUG_TYPES].size);
  for (cu = first_cu; cu; cu = cu->cu_next)
    {
      /* Ignore .debug_info CUs.  */
      if (cu->cu_kind != CU_TYPES)
	continue;
      ptr = types + cu->cu_offset + 6;
      write_32 (ptr, cu->u2.cu_new_abbrev_offset);
    }
}

/* Construct new .debug_aranges section in malloced memory,
   store it to debug_sections[DEBUG_ARANGES].new_data.  */
static int
write_aranges (DSO *dso)
{
  struct dw_cu *cu, *cufirst = NULL, *cucur;
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

/* Construct new .gdb_index section in malloced memory
   if it needs adjustment.  */
static void
write_gdb_index (void)
{
  struct dw_cu *cu;
  unsigned char *gdb_index, *ptr, *inptr, *end;
  unsigned int ncus = 0, npus = 0, ver;
  unsigned int culistoff, cutypesoff, addressoff, symboloff, constoff;

  debug_sections[GDB_INDEX].new_size = 0;
  if (debug_sections[GDB_INDEX].data == NULL
      || debug_sections[GDB_INDEX].size < 0x18)
    return;
  inptr = (unsigned char *) debug_sections[GDB_INDEX].data;
  ver = buf_read_ule32 (inptr);
  if (ver < 4 || ver > 6)
    return;

  if (unlikely (fi_multifile))
    return;

  for (cu = first_cu; cu; cu = cu->cu_next)
    if (cu->cu_kind == CU_PU)
      npus++;
    else if (cu->cu_kind == CU_NORMAL)
      ncus++;
    else if (cu->cu_kind == CU_TYPES)
      break;
  culistoff = buf_read_ule32 (inptr + 0x04);
  cutypesoff = buf_read_ule32 (inptr + 0x08);
  addressoff = buf_read_ule32 (inptr + 0x0c);
  symboloff = buf_read_ule32 (inptr + 0x10);
  constoff = buf_read_ule32 (inptr + 0x14);
  if (culistoff != 0x18
      || cutypesoff != 0x18 + ncus * 16
      || addressoff < cutypesoff
      || ((addressoff - cutypesoff) % 24) != 0
      || symboloff < addressoff
      || ((symboloff - addressoff) % 20) != 0
      || constoff < symboloff
      || ((constoff - symboloff) & (constoff - symboloff - 1)) != 0
      || ((constoff - symboloff) & 7) != 0
      || debug_sections[GDB_INDEX].size < constoff)
    return;
  inptr += 0x18;
  for (cu = first_cu; cu; cu = cu->cu_next)
    if (cu->cu_kind == CU_NORMAL)
      {
	if (buf_read_ule64 (inptr) != cu->cu_offset)
	  return;
	inptr += 16;
      }

  debug_sections[GDB_INDEX].new_size
    = debug_sections[GDB_INDEX].size + npus * 16;
  gdb_index = malloc (debug_sections[GDB_INDEX].new_size);
  if (gdb_index == NULL)
    dwz_oom ();
  debug_sections[GDB_INDEX].new_data = gdb_index;
  /* Write new header.  */
  buf_write_le32 (gdb_index + 0x00, ver);
  buf_write_le32 (gdb_index + 0x04, culistoff);
  buf_write_le32 (gdb_index + 0x08, cutypesoff + npus * 16);
  buf_write_le32 (gdb_index + 0x0c, addressoff + npus * 16);
  buf_write_le32 (gdb_index + 0x10, symboloff + npus * 16);
  buf_write_le32 (gdb_index + 0x14, constoff + npus * 16);
  ptr = gdb_index + 0x18;
  /* Write new CU list.  */
  for (cu = first_cu; cu; cu = cu->cu_next)
    {
      unsigned long next_off = debug_sections[DEBUG_INFO].new_size;
      if (cu->cu_kind == CU_TYPES)
	break;
      if (cu->cu_next && cu->cu_next->cu_kind != CU_TYPES)
	next_off = cu->cu_next->cu_new_offset;
      buf_write_le64 (ptr, cu->cu_new_offset);
      buf_write_le64 (ptr + 8, next_off - cu->cu_new_offset);
      ptr += 16;
    }
  /* Copy types CU list unmodified.  */
  memcpy (ptr, inptr, addressoff - cutypesoff);
  ptr += addressoff - cutypesoff;
  inptr += addressoff - cutypesoff;
  end = inptr + (symboloff - addressoff);
  /* Copy address area, adjusting all CU indexes.  */
  while (inptr < end)
    {
      memcpy (ptr, inptr, 16);
      buf_write_le32 (ptr + 16, buf_read_ule32 (inptr + 16) + npus);
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
	  unsigned int count = buf_read_ule32 (end + cuvec), i;
	  if (count * 4
	      > debug_sections[GDB_INDEX].size - constoff - cuvec - 4)
	    goto fail;
	  buf_write_le32 (ptr + cuvec, count);
	  for (i = 0; i < count; i++)
	    buf_write_le32 (ptr + cuvec + 4 + i,
			    buf_read_ule32 (end + cuvec + 4 + i) + npus);
	}
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

/* Read DWARF sections from DSO.  */
static int
read_dwarf (DSO *dso)
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
	    || strcmp (name, ".gdb_index") == 0)
	  {
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
		  assert (data != NULL && data->d_buf != NULL);
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

  if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2LSB)
    {
      do_read_16 = buf_read_ule16;
      do_read_32 = buf_read_ule32;
      do_read_64 = buf_read_ule64;
      do_write_16 = buf_write_le16;
      do_write_32 = buf_write_le32;
      do_write_64 = buf_write_le64;
    }
  else if (dso->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)
    {
      do_read_16 = buf_read_ube16;
      do_read_32 = buf_read_ube32;
      do_read_64 = buf_read_ube64;
      do_write_16 = buf_write_be16;
      do_write_32 = buf_write_be32;
      do_write_64 = buf_write_be64;
    }
  else
    {
      error (0, 0, "%s: Wrong ELF data enconding", dso->filename);
      return 1;
    }

  if (debug_sections[DEBUG_PUBTYPES].data != NULL)
    {
      error (0, 0, "%s: .debug_pubtypes adjusting unimplemented",
	     dso->filename);
      return 1;
    }
  if (debug_sections[DEBUG_PUBNAMES].data != NULL)
    {
      error (0, 0, "%s: .debug_pubnames adjusting unimplemented",
	     dso->filename);
      return 1;
    }

  if (debug_sections[DEBUG_INFO].data == NULL)
    {
      error (0, 0, "%s: .debug_info section not present",
	     dso->filename);
      return 1;
    }

  if (read_debug_info (dso))
    return 1;

  return 0;
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

/* Store new ELF into FILE.  debug_sections array contains
   new_data/new_size pairs where needed.  */
static int
write_dso (DSO *dso, const char *file, struct stat *st)
{
  Elf *elf = NULL;
  GElf_Ehdr ehdr;
  char *e_ident;
  int fd, i, j;
  GElf_Off off, diff;
  char *filename = NULL;
  bool remove_gdb_index = false;

  ehdr = dso->ehdr;
  if (multi_ehdr.e_ident[0] == '\0')
    multi_ehdr = ehdr;

  for (i = 0; debug_sections[i].name; i++)
    if (debug_sections[i].new_size != debug_sections[i].size)
      {
	diff = (GElf_Off) debug_sections[i].new_size
	       - (GElf_Off) dso->shdr[debug_sections[i].sec].sh_size;
	off = dso->shdr[debug_sections[i].sec].sh_offset;
	for (j = 1; j < dso->ehdr.e_shnum; ++j)
	  if (dso->shdr[j].sh_offset > off)
	    dso->shdr[j].sh_offset += diff;
	if (ehdr.e_shoff > off)
	  ehdr.e_shoff += diff;
	dso->shdr[debug_sections[i].sec].sh_size
	  = debug_sections[i].new_size;
	if (i == GDB_INDEX
	    && debug_sections[i].new_size == 0)
	  {
	    remove_gdb_index = true;
	    ehdr.e_shnum--;
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
	    if (ehdr.e_shstrndx > debug_sections[i].sec)
	      ehdr.e_shstrndx--;
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
	  return 1;
	}
    }
  else
    {
      fd = open (file, O_RDWR | O_CREAT, 0600);
      if (fd == -1)
	{
	  error (0, errno, "Failed to open %s for writing", file);
	  return 1;
	}
    }

  elf = elf_begin (fd, ELF_C_WRITE, NULL);
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      unlink (file);
      close (fd);
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

      if (remove_gdb_index
	  && i == debug_sections[GDB_INDEX].sec)
	continue;
      scn = elf_newscn (elf);
      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
      gelf_update_shdr (scn, &dso->shdr[i]);
      data1 = elf_getdata (dso->scn[i], NULL);
      data2 = elf_newdata (scn);
      memcpy (data2, data1, sizeof (*data1));
      for (j = 0; debug_sections[j].name; j++)
	if (i == debug_sections[j].sec)
	  {
	    if (debug_sections[j].new_data != NULL)
	      {
		data2->d_buf = debug_sections[j].new_data;
		data2->d_size = dso->shdr[i].sh_size;
	      }
	    break;
	  }
    }

  if (elf_update (elf, ELF_C_WRITE_MMAP) == -1)
    {
      error (0, 0, "%s: elf_update failed", dso->filename);
      unlink (file);
      elf_end (elf);
      close (fd);
      return 1;
    }

  if (elf_end (elf) < 0)
    {
      error (0, 0, "elf_end failed: %s\n", elf_errmsg (elf_errno ()));
      unlink (file);
      elf_end (elf);
      close (fd);
      return 1;
    }

  fchown (fd, st->st_uid, st->st_gid);
  fchmod (fd, st->st_mode & 07777);
  close (fd);

  if (filename != NULL && rename (filename, dso->filename))
    {
      error (0, errno, "Failed to rename temporary file over %s",
	     dso->filename);
      unlink (file);
    }
  return 0;
}

/* Free memory and clear global variables.  */
static void
cleanup (void)
{
  struct dw_cu *cu;
  unsigned int i;

  for (cu = first_cu; cu; cu = cu->cu_next)
    {
      if (cu->cu_new_abbrev)
	htab_delete (cu->cu_new_abbrev);
      cu->cu_new_abbrev = NULL;
    }
  if (off_htab != NULL)
    htab_delete (off_htab);
  off_htab = NULL;
  if (loc_htab != NULL)
    {
      htab_delete (loc_htab);
      loc_htab = NULL;
    }
  if (dup_htab != NULL)
    htab_delete (dup_htab);
  dup_htab = NULL;
  if (strp_htab != NULL)
    htab_delete (strp_htab);
  strp_htab = NULL;
  if (line_htab != NULL)
    htab_delete (line_htab);
  line_htab = NULL;

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

/* Helper to record all strp_entry entries from strp_htab.
   Called through htab_traverse.  */
static int
list_line_entries (void **slot, void *data)
{
  struct line_entry ***end = (struct line_entry ***) data;
  **end = (struct line_entry *) *slot;
  (*end)++;
  return 1;
}

/* Helper function for write_multifile_strp to sort strp_entry
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

static int
write_multifile_line (void)
{
  unsigned int filecnt = 0, dircnt = 0, filetbllen = 0, dirtbllen = 0;
  unsigned int len, i, j;
  unsigned char *line, *ptr;
  struct line_entry **filearr = NULL;
  unsigned int *diridx = NULL, *dirarr = NULL;
  int ret = 0;

  if (line_htab)
    {
      struct line_entry **end;
      filecnt = htab_elements (line_htab);
      filearr = (struct line_entry **)
		obstack_alloc (&ob, filecnt * sizeof (*filearr));
      end = filearr;
      htab_traverse (line_htab, list_line_entries, (void *) &end);
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
	  filetbllen += size_of_uleb128 (filearr[i]->file->time);
	  filetbllen += size_of_uleb128 (filearr[i]->file->size);
	}
      dirarr = (unsigned int *) obstack_finish (&ob);
    }

  len = 17 + filetbllen + dirtbllen;
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

      line = (unsigned char *) obstack_alloc (&ob, len);
    }
  ptr = line;
  write_32 (ptr, len - 4);	/* Total length.  */
  write_16 (ptr, 2);		/* DWARF version.  */
  write_32 (ptr, len - 10);	/* Header length.  */
  write_8 (ptr, 1);		/* Minimum insn length.  */
  write_8 (ptr, 1);		/* Default is_stmt.  */
  write_8 (ptr, 0);		/* Line base.  */
  write_8 (ptr, 1);		/* Line range.  */
  write_8 (ptr, 1);		/* Opcode base.  */
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
  write_8 (ptr, 0);		/* Terminate dir table.  */
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
      write_uleb128 (ptr, filearr[i]->file->time);
      write_uleb128 (ptr, filearr[i]->file->size);
    }
  write_8 (ptr, 0);		/* Terminate file table.  */
  assert (ptr == line + len);

  if (likely (!op_multifile))
    {
      if (write (multi_line_fd, line, len) != (ssize_t) len)
	ret = 1;
      else
	multi_line_off += len;
      obstack_free (&ob, line_htab ? (void *) filearr : (void *) line);
    }
  else if (line_htab)
    obstack_free (&ob, (void *) filearr);
  return ret;
}

static int
write_multifile (DSO *dso)
{
  struct dw_cu *cu;
  bool any_cus = false;
  unsigned int i;
  int ret = 0;

  if ((multi_ptr_size && ptr_size != multi_ptr_size)
      || (multi_endian
	  && multi_endian != (do_read_32 == buf_read_ule32
			      ? ELFDATA2LSB : ELFDATA2MSB)))
    {
      error (0, 0, "Multi-file optimization not allowed for different"
		   "pointer sizes or endianity");
      multifile = NULL;
      return 1;
    }
  multi_ptr_size = ptr_size;
  multi_endian = do_read_32 == buf_read_ule32 ? ELFDATA2LSB : ELFDATA2MSB;

  for (i = 0; i < SAVED_SECTIONS; i++)
    {
      saved_new_data[i] = debug_sections[i].new_data;
      saved_new_size[i] = debug_sections[i].new_size;
      debug_sections[i].new_data = NULL;
      debug_sections[i].new_size = debug_sections[i].size;
    }
  for (cu = first_cu; cu && cu->cu_kind != CU_TYPES; cu = cu->cu_next)
    {
      cu->u1.cu_new_abbrev_owner = NULL;
      cu->u2.cu_new_abbrev_offset = 0;
      cu->cu_new_offset = 0;
      any_cus |= check_multifile (cu->cu_die);
    }
  if (any_cus)
    {
      struct dw_cu **cup;

      for (cup = &first_cu; *cup && (*cup)->cu_kind != CU_TYPES; )
	if ((*cup)->cu_die->die_no_multifile == 0)
	  cup = &(*cup)->cu_next;
	else
	  *cup = (*cup)->cu_next;
      *cup = NULL;
      multifile_mode = MULTIFILE_MODE_WR;
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
	  write_info ();
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
	      || (line_htab != NULL && write_multifile_line ()))
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

static int
remove_empty_pus (void)
{
  struct dw_cu *cu;
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
dwz (const char *file, const char *outfile)
{
  DSO *dso;
  int ret = 0, fd;
  unsigned int i;
  struct stat st;

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

      if (read_dwarf (dso)
	  || partition_dups ()
	  || create_import_tree ()
	  || (unlikely (fi_multifile)
	      && (remove_empty_pus ()
		  || read_macro (dso)))
	  || read_debug_types (dso)
	  || compute_abbrevs (dso)
	  || (unlikely (fi_multifile) && (finalize_strp (false), 0)))
	{
	  cleanup ();
	  ret = 1;
	}
      else if (debug_sections[DEBUG_INFO].new_size
	       + debug_sections[DEBUG_ABBREV].new_size
	       + debug_sections[DEBUG_STR].new_size
	       + debug_sections[DEBUG_MACRO].new_size
	       >= debug_sections[DEBUG_INFO].size
		  + debug_sections[DEBUG_ABBREV].size
		  + debug_sections[DEBUG_STR].size
		  + debug_sections[DEBUG_MACRO].size)
	{
	  error (0, 0, "%s: DWARF compression not beneficial "
		       "- old size %ld new size %ld", dso->filename,
		 (unsigned long) (debug_sections[DEBUG_INFO].size
				  + debug_sections[DEBUG_ABBREV].size
				  + debug_sections[DEBUG_STR].size
				  + debug_sections[DEBUG_MACRO].size),
		 (unsigned long) (debug_sections[DEBUG_INFO].new_size
				  + debug_sections[DEBUG_ABBREV].new_size
				  + debug_sections[DEBUG_STR].new_size
				  + debug_sections[DEBUG_MACRO].new_size));

	  if (multifile && !fi_multifile)
	    write_multifile (dso);

	  cleanup ();
	  if (outfile != NULL)
	    ret = 1;
	}
      else if (write_aranges (dso))
	{
	  cleanup ();
	  ret = 1;
	}
      else
	{
	  if (unlikely (fi_multifile))
	    write_macro ();
	  write_abbrev ();
	  write_info ();
	  write_loc ();
	  write_types ();
	  write_gdb_index ();

	  if (multifile && !fi_multifile)
	    write_multifile (dso);

	  cleanup ();

	  if (write_dso (dso, outfile, &st))
	    ret = 1;
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
      error (0, 0, "elf_end failed: %s\n", elf_errmsg (elf_errno ()));
      ret = 1;
    }
  close (fd);

  free (dso);
  return ret;
}

static unsigned int *strp_tail_off_list;

static int
optimize_multifile (void)
{
  DSO dsobuf, *dso;
  int fd = -1;
  unsigned int i;
  Elf *elf = NULL;
  GElf_Shdr shdr;
  Elf_Scn *scn;
  Elf_Data *data;
  char *e_ident;
  const char shstrtab[]
    = "\0.shstrtab\0.note.gnu.build-id\0"
      ".debug_info\0.debug_abbrev\0.debug_line\0.debug_str\0.debug_macro";
  const char *p;
  unsigned char note[0x24], *np;
  struct sha1_ctx ctx;

  if (multi_ehdr.e_ident[0] == '\0'
      || multi_ptr_size == 0
      || multi_endian == 0)
    return -1;

  if ((multi_line_off == 0 && write_multifile_line ()))
    {
      error (0, 0, "Error writing multi-file temporary files");
      return -1;
    }

  debug_sections[DEBUG_INFO].size = multi_info_off;
  debug_sections[DEBUG_INFO].data
    = mmap (NULL, multi_info_off, PROT_READ, MAP_PRIVATE, multi_info_fd, 0);
  debug_sections[DEBUG_ABBREV].size = multi_abbrev_off;
  debug_sections[DEBUG_ABBREV].data
    = mmap (NULL, multi_abbrev_off, PROT_READ, MAP_PRIVATE,
	    multi_abbrev_fd, 0);
  debug_sections[DEBUG_LINE].size = multi_line_off;
  debug_sections[DEBUG_LINE].data
    = mmap (NULL, multi_line_off, PROT_READ, MAP_PRIVATE, multi_line_fd, 0);
  debug_sections[DEBUG_STR].size = multi_str_off;
  debug_sections[DEBUG_STR].data
    = mmap (NULL, multi_str_off, PROT_READ, MAP_PRIVATE, multi_str_fd, 0);
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
      if (elf)
	elf_end (elf);
      if (fd != -1)
	{
	  unlink (multifile);
	  close (fd);
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
      if (debug_sections[DEBUG_STR].data != MAP_FAILED)
	munmap (debug_sections[DEBUG_STR].data,
		debug_sections[DEBUG_STR].size);
      if (debug_sections[DEBUG_MACRO].data != MAP_FAILED
	  && debug_sections[DEBUG_MACRO].data != NULL)
	munmap (debug_sections[DEBUG_MACRO].data,
		debug_sections[DEBUG_MACRO].size);
      return -1;
    }

  if (multi_endian == ELFDATA2LSB)
    {
      do_read_16 = buf_read_ule16;
      do_read_32 = buf_read_ule32;
      do_read_64 = buf_read_ule64;
      do_write_16 = buf_write_le16;
      do_write_32 = buf_write_le32;
      do_write_64 = buf_write_le64;
    }
  else if (multi_endian == ELFDATA2MSB)
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
  ptr_size = multi_ptr_size;
  memset (&dsobuf, '\0', sizeof (dsobuf));
  dso = &dsobuf;
  dso->filename = multifile;
  multifile_mode = MULTIFILE_MODE_OP;

  obstack_alloc_failed_handler = dwz_oom;
#ifdef DEBUG_OP_MULTIFILE
  if (1)
    {
      for (i = 0; i < SAVED_SECTIONS; i++)
	{
	  debug_sections[i].new_data = debug_sections[i].data;
	  debug_sections[i].new_size = debug_sections[i].size;
	}
    }
  else
#endif
  if (setjmp (oom_buf))
    {
      error (0, ENOMEM, "%s: Could not allocate memory", dso->filename);
      goto fail;
    }
  else
    {
      struct dw_cu **cup;
      unsigned char *p, *q;

      obstack_init (&ob);
      obstack_init (&ob2);

      if (read_debug_info (dso)
	  || partition_dups ())
	goto fail;

      for (cup = &first_cu; *cup && (*cup)->cu_kind == CU_PU;
	   cup = &(*cup)->cu_next)
	;

      *cup = NULL;

      strp_htab = htab_try_create (debug_sections[DEBUG_STR].size / 64,
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
	  write_info ();
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

  cleanup ();
  fd = open (multifile, O_RDWR | O_CREAT, 0600);
  if (fd < 0)
    {
      error (0, errno, "Failed to open multi-file common file %s", multifile);
      goto fail;
    }

  elf = elf_begin (fd, ELF_C_WRITE, NULL);
  if (elf == NULL)
    {
      error (0, 0, "cannot open ELF file: %s", elf_errmsg (-1));
      goto fail;
    }

  multi_ehdr.e_type = ET_REL;
  multi_ehdr.e_entry = 0;
  multi_ehdr.e_phoff = 0;
  multi_ehdr.e_phnum = 0;
  multi_ehdr.e_shoff = multi_ehdr.e_ehsize + 0x24;
  multi_ehdr.e_shnum = 3;
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

  memset (&shdr, '\0', sizeof (shdr));
  shdr.sh_type = SHT_NOTE;
  shdr.sh_offset = multi_ehdr.e_ehsize;
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

  shdr.sh_type = SHT_PROGBITS;
  shdr.sh_offset += shdr.sh_size;
  shdr.sh_addralign = 1;
  for (i = 0; debug_sections[i].name; i++)
    {
      if (debug_sections[i].new_size == 0)
	continue;
      scn = elf_newscn (elf);
      elf_flagscn (scn, ELF_C_SET, ELF_F_DIRTY);
      for (p = shstrtab + 1; p < shstrtab + sizeof (shstrtab);
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
  shdr.sh_size = sizeof (shstrtab);
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
      error (0, 0, "elf_end failed: %s\n", elf_errmsg (elf_errno ()));
      goto fail;
    }

  fchmod (fd, 0644);

  munmap (debug_sections[DEBUG_INFO].data, debug_sections[DEBUG_INFO].size);
  munmap (debug_sections[DEBUG_ABBREV].data,
	  debug_sections[DEBUG_ABBREV].size);
  munmap (debug_sections[DEBUG_LINE].data, debug_sections[DEBUG_LINE].size);
  munmap (debug_sections[DEBUG_STR].data, debug_sections[DEBUG_STR].size);
  if (debug_sections[DEBUG_MACRO].data)
    munmap (debug_sections[DEBUG_MACRO].data,
	    debug_sections[DEBUG_MACRO].size);

  for (i = 0; debug_sections[i].name; ++i)
    {
      debug_sections[i].data = NULL;
      debug_sections[i].size = 0;
#ifndef DEBUG_OP_MULTIFILE
      free (debug_sections[i].new_data);
#endif
      debug_sections[i].new_data = NULL;
      debug_sections[i].new_size = 0;
      debug_sections[i].sec = 0;
    }

  return fd;
}

static DSO *
read_multifile (int fd)
{
  DSO *dso, *volatile ret;
  unsigned int i;

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
    }
  else
    {
      obstack_init (&ob);
      obstack_init (&ob2);

      if (read_dwarf (dso))
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

/* Options for getopt_long.  */
static struct option dwz_options[] =
{
  { "help",	no_argument,	   0, 0 },
  { "output",	required_argument, 0, 'o' },
  { "multifile",required_argument, 0, 'm' },
};

/* Print usage and exit.  */
static void
usage (void)
{
  error (1, 0, "Usage:\n  dwz [FILES]\n  dwz -o OUTFILE FILE\n"
	       "  dwz -m COMMONFILE FILES");
}

int
main (int argc, char *argv[])
{
  const char *outfile = NULL;
  int ret = 0;
  int i;

  if (elf_version (EV_CURRENT) == EV_NONE)
    error (1, 0, "library out of date\n");

  while (1)
    {
      int option_index;
      int c = getopt_long (argc, argv, "m:o:", dwz_options, &option_index);
      if (c == -1)
	break;
      switch (c)
	{
	default:
	  usage ();
	  break;

	case 'o':
	  outfile = optarg;
	  break;

	case 'm':
	  multifile = optarg;
	  break;
	}
    }

  if (multifile && argc - optind <= 1)
    error (1, 0, "-m option only allowed with more than one file");
  if (optind == argc)
    ret = dwz ("a.out", outfile);
  else if (optind + 1 == argc)
    ret = dwz (argv[optind], outfile);
  else
    {
      if (outfile != NULL)
	error (1, 0, "-o option not allowed for multiple files");
      if (multifile)
	{
	  char buf[sizeof "/tmp/dwz.debug_abbrev.XXXXXX"];
	  strcpy (buf, "/tmp/dwz.debug_info.XXXXXX");
	  multi_info_fd = mkstemp (buf);
	  if (multi_info_fd != -1)
	    unlink (buf);
	  strcpy (buf, "/tmp/dwz.debug_abbrev.XXXXXX");
	  multi_abbrev_fd = mkstemp (buf);
	  if (multi_abbrev_fd != -1)
	    unlink (buf);
	  strcpy (buf, "/tmp/dwz.debug_line.XXXXXX");
	  multi_line_fd = mkstemp (buf);
	  if (multi_line_fd != -1)
	    unlink (buf);
	  strcpy (buf, "/tmp/dwz.debug_str.XXXXXX");
	  multi_str_fd = mkstemp (buf);
	  if (multi_str_fd != -1)
	    unlink (buf);
	  strcpy (buf, "/tmp/dwz.debug_macro.XXXXXX");
	  multi_macro_fd = mkstemp (buf);
	  if (multi_macro_fd != -1)
	    unlink (buf);
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
      for (i = optind; i < argc; i++)
	ret |= dwz (argv[i], NULL);
      if (multifile)
	{
	  int multi_fd = optimize_multifile ();
	  DSO *dso;
	  if (multi_fd == -1)
	    return 1;
	  dso = read_multifile (multi_fd);
	  if (dso == NULL)
	    ret = 1;
	  else
	    {
	      for (i = optind; i < argc; i++)
		{
		  struct dw_cu *cu;
		  multifile_mode = MULTIFILE_MODE_FI;
		  for (cu = alt_first_cu; cu; cu = cu->cu_next)
		    alt_clear_dups (cu->cu_die);
		  ret |= dwz (argv[i], NULL);
		}
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
	}
    }

  return ret;
}
