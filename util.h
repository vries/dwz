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
extern struct stats *stats;

extern void report_progress (void);
extern void init_stats (const char *);
extern void print_parse_stats (void);
extern void print_dups_stats (void);
extern void print_part_stats (void);
extern void htab_report (htab_t, const char *);
extern void dump_die (dw_die_ref);
extern void dump_dups (dw_die_ref);
extern void dump_dies (int, dw_die_ref);
