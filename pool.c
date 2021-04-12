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

/* Big pool allocator.  obstack isn't efficient, because it aligns everything
   too much, and allocates too small chunks.  All these objects are only freed
   together.  */

#include <stddef.h>
#include <stdlib.h>
#include <inttypes.h>

#include "pool.h"

/* Pointer to the start of the current pool chunk, current first free byte
   in the chunk and byte after the end of the current pool chunk.  */

static unsigned char *pool, *pool_next, *pool_limit;

extern void dwz_oom (void);

/* Allocate SIZE bytes with ALIGN bytes alignment from the pool.  */
void *
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

/* Finalize a pool and return it.  */
unsigned char *
finalize_pool (void)
{
  unsigned char *ret = pool;
  pool = NULL;
  pool_next = NULL;
  pool_limit = NULL;
  return ret;
}

/* Free pool P.  */
static void
pool_destroy_1 (unsigned char *p)
{
  while (p)
    {
      void *elem = (void *) p;
      p = *(unsigned char **) p;
      free (elem);
    }
}

/* Free pool P, or the current pool if NULL.  */
void
pool_destroy (unsigned char *p)
{
  if (p != NULL)
    {
      pool_destroy_1 (p);
      return;
    }

  pool_destroy_1 (pool);
  pool = NULL;
  pool_next = NULL;
  pool_limit = NULL;
}
