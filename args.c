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
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <error.h>
#include <gelf.h>
#include <sys/sysinfo.h>

#include "args.h"

#include "util.h"

#if DEVEL
int tracing;
int ignore_size;
int ignore_locus;
int dump_checksum_p;
int dump_dies_p;
int dump_dups_p;
int dump_pus_p;
int verify_dups_p;
int verify_edge_freelist;
int stats_p;
int checksum_cycle_opt = 1;
int skip_producers_p;
#endif

int unoptimized_multifile;
int save_temps;
int verify_edges_p;
int dump_edges_p;
int partition_dups_opt;
int progress_p;
int progress_mem_p;
int import_opt_p = 1;
int force_p;
int max_forks = -1;

enum deduplication_mode deduplication_mode = dm_inter_cu;

int uni_lang_p = 0;
int gen_cu_p = 0;

enum die_count_methods die_count_method = estimate;

int odr = 0;
enum odr_mode odr_mode = ODR_LINK;

/* Filename if inter-file size optimization should be performed.  */
const char *multifile;

/* Argument of -M option, i.e. preferred name that should be stored
   into the .gnu_debugaltlink or .debug_sup section.  */
const char *multifile_name;

/* True if -r option is present, i.e. .gnu_debugaltlink or .debug_sup section
   should contain a filename relative to the directory in which
   the particular file is present.  */
bool multifile_relative;

/* Pointer size of multifile.  */
int multifile_force_ptr_size;
/* Endianity of multifile.  */
int multifile_force_endian;

/* True if DWARF 5 .debug_sup and DW_FORM_ref_sup4 / DW_FORM_strp_sup
   should be used instead of the GNU extensions .gnu_debugaltlink
   and DW_FORM_GNU_ref_alt / DW_FORM_GNU_strp_alt etc.  */
bool dwarf_5;

/* True if -q option has been passed.  */
bool quiet;

/* Number of DIEs, above which dwz retries processing
   in low_mem mode (and give up on multifile optimizing
   the file in question).  */
unsigned int low_mem_die_limit = 10000000;

/* Number of DIEs, above which dwz gives up processing
   input altogether.  */
unsigned int max_die_limit = 50000000;

/* Phase of multifile handling.  */
unsigned char multifile_mode;

static int die_count_method_parsed;
static int deduplication_mode_parsed;
static int odr_mode_parsed;
static int skip_producer_parsed;

/* Options for getopt_long.  */
static struct option dwz_options[] =
{
  { "help",		 no_argument,	    0, '?' },
  { "output",		 required_argument, 0, 'o' },
  { "multifile",	 required_argument, 0, 'm' },
  { "quiet",		 no_argument,	    0, 'q' },
  { "hardlink",		 no_argument,	    0, 'h' },
  { "low-mem-die-limit", required_argument, 0, 'l' },
  { "max-die-limit",	 required_argument, 0, 'L' },
  { "multifile-name",	 required_argument, 0, 'M' },
  { "relative",		 no_argument,	    0, 'r' },
  { "version",		 no_argument,	    0, 'v' },
  { "import-optimize",
			 no_argument,	    &import_opt_p, 1 },
  { "no-import-optimize",
			 no_argument,	    &import_opt_p, 0 },
  { "dwarf-5",		 no_argument,	    0, '5' },
#if DEVEL
  { "devel-trace",	 no_argument,	    &tracing, 1 },
  { "devel-progress",	 no_argument,	    &progress_p, 1 },
  { "devel-progress-mem",no_argument,	    &progress_mem_p, 1 },
  { "devel-ignore-size", no_argument,	    &ignore_size, 1 },
  { "devel-ignore-locus",no_argument,	    &ignore_locus, 1 },
  { "devel-force",	 no_argument,	    &force_p, 1 },
  { "devel-save-temps",  no_argument,	    &save_temps, 1 },
  { "devel-dump-checksum",
			 no_argument,	    &dump_checksum_p, 1 },
  { "devel-dump-dies",  no_argument,	    &dump_dies_p, 1 },
  { "devel-dump-dups",  no_argument,	    &dump_dups_p, 1 },
  { "devel-dump-pus",  no_argument,	    &dump_pus_p, 1 },
  { "devel-unoptimized-multifile",
			 no_argument,	    &unoptimized_multifile, 1 },
  { "devel-verify-edges",no_argument,	    &verify_edges_p, 1 },
  { "devel-verify-dups", no_argument,	    &verify_dups_p, 1 },
  { "devel-dump-edges",  no_argument,	    &dump_edges_p, 1 },
  { "devel-partition-dups-opt",
			 no_argument,	    &partition_dups_opt, 1 },
  { "devel-die-count-method",
			 required_argument, &die_count_method_parsed, 1 },
  { "devel-stats",	 no_argument,	    &stats_p, 1 },
  { "devel-deduplication-mode",
			 required_argument, &deduplication_mode_parsed, 1 },
  { "devel-uni-lang",
			 no_argument,	    &uni_lang_p, 1 },
  { "devel-no-uni-lang",
			 no_argument,	    &uni_lang_p, 0 },
  { "devel-gen-cu",
			 no_argument,	    &gen_cu_p, 1 },
  { "devel-no-gen-cu",
			 no_argument,	    &gen_cu_p, 0 },
  { "devel-checksum-cycle-opt",
			 no_argument,	    &checksum_cycle_opt, 1 },
  { "devel-no-checksum-cycle-opt",
			 no_argument,	    &checksum_cycle_opt, 0 },
  { "devel-skip-producer",
			 required_argument, &skip_producer_parsed, 1},
#endif
  { "odr",		 no_argument,	    &odr, 1 },
  { "no-odr",		 no_argument,	    &odr, 0 },
  { "odr-mode",		 required_argument, &odr_mode_parsed, 1 },
  { "multifile-pointer-size",
			 required_argument, 0, 'p' },
  { "multifile-endian",
			 required_argument, 0, 'e' },
  { "jobs",		 required_argument, 0, 'j' },
  { NULL,		 no_argument,	    0, 0 }
};

/* Struct describing various usage aspects of a command line option.  */
struct option_help
{
  const char *short_name;
  const char *long_name;
  const char *argument;
  const char *default_value;
  const char *msg;
};

/* Describe common command line options.  */
static struct option_help dwz_common_options_help[] =
{
  { "q", "quiet", NULL, NULL,
    "Silence up the most common messages." },
  { "l", "low-mem-die-limit", "<COUNT|none>", "10 million DIEs",
    "Handle files larger than this limit using a slower and more memory"
    " usage friendly mode and don't optimize those files in multifile mode." },
  { "L", "max-die-limit", "<COUNT|none>", "50 million DIEs",
    "Don't optimize files larger than this limit." },
  { NULL, "odr", NULL, NULL,
    NULL },
  { NULL, "no-odr", NULL, "Disabled",
    "Enable/disable one definition rule optimization." },
  { NULL, "odr-mode", "<basic|link>", "link",
    "Set aggressiveness level of one definition rule optimization." },
  { NULL, "import-optimize", NULL, NULL,
    NULL },
  { NULL, "no-import-optimize", NULL, "Enabled",
    "Enable/disable optimization that reduces the number of"
    " DW_TAG_imported_unit DIEs." }
};

/* Describe single-file command line options.  */
static struct option_help dwz_single_file_options_help[] =
{
  { "o", "output", "OUTFILE", NULL,
    "Place the output in OUTFILE." }
};

#if NATIVE_ENDIAN_VAL == ELFDATA2MSB
#define NATIVE_ENDIAN "big"
#elif NATIVE_ENDIAN_VAL == ELFDATA2LSB
#define NATIVE_ENDIAN "little"
#else
#define NATIVE_ENDIAN "not available"
#endif

/* Describe mult-file command line options.  */
static struct option_help dwz_multi_file_options_help[] =
{
  { "h", "hardlink", NULL, NULL,
    "Handle hardlinked files as one file." },
  { "m", "multifile", "COMMONFILE", NULL,
    "Enable multifile optimization, placing common DIEs in multifile"
    " COMMONFILE." },
  { "M", "multifile-name", "NAME", NULL,
    "Set .gnu_debugaltlink or .debug_sup in files to NAME." },
  { "r", "relative", NULL, NULL,
    "Set .gnu_debugaltlink in files to relative path from file directory"
    " to multifile." },
  { "5", "dwarf-5", NULL, NULL,
    "Emit DWARF 5 standardized supplementary object files instead of"
    " GNU extension .debug_altlink." },
  { "p", "multifile-pointer-size", "<SIZE|auto|native>", "auto",
     "Set pointer size of multifile, in number of bytes."
    " Native pointer size is " XSTR (NATIVE_POINTER_SIZE) "." },
  { "e", "multifile-endian", "<l|b|auto|native>", "auto",
    "Set endianity of multifile."
    " Native endianity is " NATIVE_ENDIAN "." },
  { "j", "jobs", "<n>", "number of processors / 2",
    "Process <n> files in parallel." }
};

/* Describe misc command line options.  */
static struct option_help dwz_misc_options_help[] =
{
  { "v", "version", NULL, NULL,
    "Display dwz version information." },
  { "?", "help", NULL, NULL,
    "Display this information." }
};

/* Print LEN spaces to STREAM.  */
static void
do_indent (FILE *stream, unsigned int len)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    fprintf (stream, " ");
}

/* Print MSG to STREAM, indenting to INDENT and wrapping at LIMIT.
   Assume starting position is at INDENT.  */
static void
wrap (FILE *stream, unsigned int indent, unsigned int limit, const char *msg)
{
  unsigned int len = indent;
  const char *s = msg;
  while (true)
    {
      const char *e = strchr (s, ' ');
      unsigned int word_len;
      if (e == NULL)
	word_len = strlen (s);
      else
	word_len = e - s;
      if (word_len == 0)
	return;

      if (len + 1 /* space */ + word_len > limit)
	{
	  fprintf (stream, "\n");
	  do_indent (stream ,indent);
	  len = indent;
	}
      else if (len > indent)
	{
	  fprintf (stream, " ");
	  len += 1;
	}

      if (e != NULL)
	{
	  const char *i;
	  for (i = s; i < e; ++i)
	    fprintf (stream, "%c", *i);
	}
      else
	fprintf (stream, "%s", s);
      len += word_len;

      if (e == NULL)
	break;

      s = e + 1;
    }
}

/* Print OPTIONS_HELP of length H to STREAM, indenting to help message to
   INDENT an wrapping at LIMIT.  */
static void
print_options_help (FILE *stream, struct option_help *options_help, unsigned int n,
		    unsigned int indent, unsigned int limit)
{
  unsigned len;
  const char *s;
  unsigned int i;

  for (i = 0; i <  n; ++i)
    {
      len = 0;

      fprintf (stream, "  ");
      len += 2;

      s = options_help[i].short_name;
      if (s)
	{
	  fprintf (stream, "-%s", s);
	  len += 2;
	}

      s = options_help[i].long_name;
      if (len == 4)
	{
	  fprintf (stream, ", ");
	  len += 2;
	}
      fprintf (stream, "--%s", s);
      len += 2 + strlen (s);

      s = options_help[i].argument;
      if (s)
	{
	  fprintf (stream, " %s", s);
	  len += 1 + strlen (s);
	}

      s = options_help[i].msg;
      if (s)
	{
	  assert (IMPLIES (strlen (s) > 0, s[strlen (s) - 1] == '.'));
	  if (len > indent)
	    {
	      fprintf (stream, "\n");
	      do_indent (stream, indent);
	    }
	  else
	    do_indent (stream, indent - len);
	  len = indent;

	  wrap (stream, indent, limit, s);
	}
      fprintf (stream, "\n");

      s = options_help[i].default_value;
      if (s)
	{
	  do_indent (stream, indent);
	  fprintf (stream, "Default value: %s.\n", s);
	}
    }
}

/* Print usage and exit.  */
static void
usage (int failing)
{
  unsigned int n, i;
  unsigned int indent, limit;
  FILE *stream = failing ? stderr : stdout;
  const char *header_lines[] = {
    "dwz [common options] [-h] [-m COMMONFILE] [-M NAME | -r] [-5]",
    "    [-p <SIZE|auto|native>] [-e <l|b|auto|native>] [-j N] [FILES]",
    "dwz [common options] -o OUTFILE FILE",
    "dwz [ -v | -? ]"
  };
  unsigned int nr_header_lines
    = sizeof (header_lines) / sizeof (*header_lines);

  fprintf (stream, "Usage:\n");
  for (i = 0; i < nr_header_lines; ++i)
    fprintf (stream, "  %s\n", header_lines[i]);

  indent = 30;
  limit = 80;
  fprintf (stream, "Common options:\n");
  n = (sizeof (dwz_common_options_help)
       / sizeof (dwz_common_options_help[0]));
  print_options_help (stream, dwz_common_options_help, n, indent, limit);

  fprintf (stream, "Single-file options:\n");
  n = (sizeof (dwz_single_file_options_help)
       / sizeof (dwz_single_file_options_help[0]));
  print_options_help (stream, dwz_single_file_options_help, n, indent, limit);

  fprintf (stream, "Multi-file options:\n");
  n = (sizeof (dwz_multi_file_options_help)
       / sizeof (dwz_multi_file_options_help[0]));
  print_options_help (stream, dwz_multi_file_options_help, n, indent, limit);

  fprintf (stream, "Miscellaneous options:\n");
  n = (sizeof (dwz_misc_options_help)
       / sizeof (dwz_misc_options_help[0]));
  print_options_help (stream, dwz_misc_options_help, n, indent, limit);

#if DEVEL
  fprintf (stream, "Development options:\n");
  fprintf (stream, "%s",
	   ("  --devel-trace\n"
	    "  --devel-progress\n"
	    "  --devel-progress-mem\n"
	    "  --devel-stats\n"
	    "  --devel-ignore-size\n"
	    "  --devel-ignore-locus\n"
	    "  --devel-force\n"
	    "  --devel-save-temps\n"
	    "  --devel-dump-checksum\n"
	    "  --devel-dump-dies\n"
	    "  --devel-dump-dups\n"
	    "  --devel-dump-pus\n"
	    "  --devel-unoptimized-multifile\n"
	    "  --devel-verify-dups\n"
	    "  --devel-verify-edges\n"
	    "  --devel-dump-edges\n"
	    "  --devel-partition-dups-opt\n"
	    "  --devel-die-count-method\n"
	    "  --devel-deduplication-mode={none,intra-cu,inter-cu}\n"
	    "  --devel-uni-lang / --devel-no-uni-lang\n"
	    "  --devel-gen-cu / --devel-no-gen-cu\n"
	    "  --devel-skip-producer <producer>\n"));
#endif

  exit (failing);
}

/* Print version and exit.  */
static void
version (void)
{
  printf ("dwz version " DWZ_VERSION "\n"
	  "Copyright (C) " RH_YEARS " Red Hat, Inc.\n"
	  "Copyright (C) " FSF_YEARS " Free Software Foundation, Inc.\n"
	  "Copyright (C) " SUSE_YEARS " SUSE LLC.\n"
	  "This program is free software; you may redistribute it under the terms of\n"
	  "the GNU General Public License version 3 or (at your option) any later version.\n"
	  "This program has absolutely no warranty.\n");
  exit (0);
}

static const char **skip_producers;
static size_t skip_producers_size;
static size_t nr_skip_producers;

static void
add_skip_producer (const char *producer)
{
  size_t alloc_size;
  if (skip_producers == NULL)
    {
      skip_producers_size = 10;
      alloc_size = skip_producers_size * sizeof (const char *);
      skip_producers = malloc (alloc_size);
    }
  else if (nr_skip_producers == skip_producers_size)
    {
      skip_producers_size += 10;
      alloc_size = skip_producers_size * sizeof (const char *);
      skip_producers = realloc (skip_producers, alloc_size);
    }

  skip_producers[nr_skip_producers] = producer;
  nr_skip_producers++;
}

bool
skip_producer (const char *producer)
{
  size_t i;

  if (producer == NULL)
    return false;

  for (i = 0; i < nr_skip_producers; ++i)
    {
      const char *skip = skip_producers[i];
      if (strncmp (skip, producer, strlen (skip)) == 0)
	return true;
    }

  return false;
}

/* Parse command line arguments in ARGV.  */
void
parse_args (int argc, char *argv[], bool *hardlink, const char **outfile)
{
  unsigned long l;
  char *end;

  while (1)
    {
      int option_index = -1;
      int c = getopt_long (argc, argv, "m:o:qhl:L:M:r?v5p:e:j:", dwz_options,
			   &option_index);
      if (c == -1)
	break;
      switch (c)
	{
	default:
	case '?':
	  usage (option_index == -1);
	  break;

	case 0:
	  /* Option handled by getopt_long.  */
	  if (die_count_method_parsed)
	    {
	      die_count_method_parsed = 0;
	      if (strcmp (optarg, "none") == 0)
		{
		  die_count_method = none;
		  break;
		}
	      if (strcmp (optarg, "estimate") == 0)
		{
		  die_count_method = estimate;
		  break;
		}
	      error (1, 0, "invalid argument --devel-die-count-method %s",
		     optarg);
	    }
	  if (deduplication_mode_parsed)
	    {
	      deduplication_mode_parsed = 0;
	      if (strcmp (optarg, "none") == 0)
		{
		  deduplication_mode = dm_none;
		  break;
		}
	      if (strcmp (optarg, "intra-cu") == 0)
		{
		  deduplication_mode = dm_intra_cu;
		  break;
		}
	      if (strcmp (optarg, "inter-cu") == 0)
		{
		  deduplication_mode = dm_inter_cu;
		  break;
		}
	      error (1, 0, "invalid argument --devel-deduplication-mode %s",
		     optarg);
	    }
	  if (odr_mode_parsed)
	    {
	      odr_mode_parsed = 0;
	      if (strcmp (optarg, "basic") == 0)
		{
		  odr_mode = ODR_BASIC;
		  break;
		}
	      if (strcmp (optarg, "link") == 0)
		{
		  odr_mode = ODR_LINK;
		  break;
		}
	      error (1, 0, "invalid argument --odr-mode %s",
		     optarg);
	    }
	  if (skip_producer_parsed)
	    {
	      skip_producer_parsed = 0;
	      add_skip_producer (optarg);

#if DEVEL
	      skip_producers_p = 1;
#endif
	    }
	  break;

	case 'o':
	  *outfile = optarg;
	  break;

	case 'm':
	  multifile = optarg;
	  break;

	case 'q':
	  quiet = true;
	  break;

	case 'h':
	  *hardlink = true;
	  break;

	case 'M':
	  multifile_name = optarg;
	  break;

	case 'r':
	  multifile_relative = true;
	  break;

	case 'l':
	  if (strcmp (optarg, "none") == 0)
	    {
	      low_mem_die_limit = -1U;
	      break;
	    }
	  l = strtoul (optarg, &end, 0);
	  if (*end != '\0' || optarg == end || (unsigned int) l != l)
	    error (1, 0, "invalid argument -l %s", optarg);
	  low_mem_die_limit = l;
	  break;

	case 'L':
	  if (strcmp (optarg, "none") == 0)
	    {
	      max_die_limit = -1U;
	      break;
	    }
	  l = strtoul (optarg, &end, 0);
	  if (*end != '\0' || optarg == end || (unsigned int) l != l)
	    error (1, 0, "invalid argument -L %s", optarg);
	  max_die_limit = l;
	  break;

	case '5':
	  dwarf_5 = true;
	  break;

	case 'p':
	  if (strcmp (optarg, "auto") == 0)
	    {
	      multifile_force_ptr_size = 0;
	      break;
	    }
	  if (strcmp (optarg, "native") == 0)
	    {
	      multifile_force_ptr_size = NATIVE_POINTER_SIZE;
	      break;
	    }
	  l = strtoul (optarg, &end, 0);
	  if (*end != '\0' || optarg == end || (unsigned int) l != l)
	    error (1, 0, "invalid argument -l %s", optarg);
	  multifile_force_ptr_size = l;
	  break;

	case 'e':
	  if (strcmp (optarg, "auto") == 0)
	    {
	      multifile_force_endian = 0;
	      break;
	    }
	  if (strcmp (optarg, "native") == 0)
	    {
	      switch (NATIVE_ENDIAN_VAL)
		{
		case ELFDATA2MSB:
		case ELFDATA2LSB:
		  multifile_force_endian = NATIVE_ENDIAN_VAL;
		  break;
		default:
		  error (1, 0, "Cannot determine native endian");
		}
	      break;
	    }
	  if (strlen (optarg) != 1)
	    error (1, 0, "invalid argument -l %s", optarg);
	  switch (optarg[0])
	    {
	    case 'l':
	    case 'L':
	      multifile_force_endian = ELFDATA2LSB;
		break;
	    case 'b':
	    case 'B':
	      multifile_force_endian = ELFDATA2MSB;
		break;
	    default:
	      error (1, 0, "invalid argument -l %s", optarg);
	    }
	  break;

	case 'v':
	  version ();
	  break;

	case 'j':
	  l = strtoul (optarg, &end, 0);
	  if (*end != '\0' || optarg == end || (unsigned int) l != l)
	    error (1, 0, "invalid argument -j %s", optarg);
	  max_forks = l;
	  break;
	}
    }

  if (progress_mem_p)
    progress_p = 1;

  /* Specifying a low-mem die-limit that is larger than or equal to the
     max die-limit has the effect of disabling low-mem mode.  Make this
     explicit by setting it to the 'none' value.  */
  if (low_mem_die_limit != -1U
      && low_mem_die_limit >= max_die_limit)
    low_mem_die_limit = -1U;

  if (multifile_relative && multifile_name)
    error (1, 0, "-M and -r options can't be specified together");

  if (max_forks == -1)
    {
      long nprocs = get_nprocs ();
      /* Be conservative on max forks: 4 procs may be actually be 4 SMT
	 threads with only 2 cores.  */
      max_forks = nprocs / 2;
    }
}
