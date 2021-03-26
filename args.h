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

#if DEVEL
extern int tracing;
extern int ignore_size;
extern int ignore_locus;
extern int dump_checksum_p;
extern int dump_dies_p;
extern int dump_dups_p;
extern int dump_pus_p;
extern int verify_dups_p;
extern int verify_edge_freelist;
extern int stats_p;
extern int checksum_cycle_opt;
extern int skip_producers_p;
#else
#define tracing 0
#define ignore_size 0
#define ignore_locus 0
#define dump_checksum_p 0
#define dump_dies_p 0
#define dump_dups_p 0
#define dump_pus_p 0
#define verify_dups_p 0
#define stats_p 0
#define checksum_cycle_opt 1
#define skip_producers_p 0
#endif

extern int unoptimized_multifile;
extern int save_temps;
extern int verify_edges_p;
extern int dump_edges_p;
extern int partition_dups_opt;
extern int progress_p;
extern int progress_mem_p;
extern int import_opt_p;
extern int force_p;
extern int max_forks;

enum deduplication_mode
{
  dm_none,
  dm_intra_cu,
  dm_inter_cu
};
extern enum deduplication_mode deduplication_mode;

extern int uni_lang_p;
extern int gen_cu_p;

enum die_count_methods
{
  none,
  estimate
};
extern enum die_count_methods die_count_method;

extern int odr;
enum odr_mode { ODR_BASIC, ODR_LINK };
extern enum odr_mode odr_mode;

extern const char *multifile;
extern const char *multifile_name;
extern bool multifile_relative;
extern int multifile_force_ptr_size;
extern int multifile_force_endian;

extern unsigned char multifile_mode;

extern bool dwarf_5;

extern bool quiet;

extern unsigned int low_mem_die_limit;
extern unsigned int max_die_limit;

extern void parse_args (int, char *[], bool *, const char **);
extern bool skip_producer (const char *producer);
