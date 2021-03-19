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

#include <stdio.h>
#include <stddef.h>
#include <sys/times.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "hashtab.h"
#include "util.h"
#include "args.h"

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

void
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

struct stats *stats;

/* Initialize stats struct.  */
void
init_stats (const char *file)
{
  if (stats == NULL)
    stats = (struct stats *)malloc (sizeof (*stats));
  memset (stats, 0, sizeof (*stats));
  stats->file = file;
}

/* Print stats struct, parsing statistics.  */
void
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
void
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

void
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

/* Print hash table statistics for hash table HTAB with message string MSG.  */
void
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
