/* Various iterators.

   Copyright (C) 2019 SUSE LLC.

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


/* CU iterators.  */

#define FOREACH_CU(CU)				\
  for (CU = first_cu; CU; CU = CU->cu_next)

#define FOREACH_CU_PU(CU)						\
  for (CU = first_cu; CU && CU->cu_kind == CU_PU; CU = CU->cu_next)

#define FOREACH_CU_NORMAL(CU)						\
  for (CU = first_cu; CU && CU->cu_kind != CU_TYPES; CU = CU->cu_next)	\
    if (CU->cu_kind == CU_NORMAL)

#define FOREACH_CU_TYPES(CU)			\
  for (CU = first_cu; CU; CU = CU->cu_next)	\
    if (CU->cu_kind == CU_TYPES)		\

/* Function that describes a depth-first traversal path visiting all dies.  */

static inline dw_die_ref FORCE_INLINE
next_die (dw_die_ref die)
{
  if (die->die_child != NULL)
    return die->die_child;

  while (1)
    {
      if (die->die_sib != NULL)
	return die->die_sib;

      if (die->die_root)
	return NULL;

      die = die->die_parent;
    }
}

/* Function that describes a depth-first traversal path visiting all toplevel
   dies.  */

static inline dw_die_ref FORCE_INLINE
next_toplevel_die (dw_die_ref die)
{
  if (die->die_child != NULL && die->die_child->die_toplevel)
    return die->die_child;

  while (1)
    {
      if (die->die_sib != NULL && die->die_sib->die_toplevel)
	return die->die_sib;

      if (die->die_root)
	return NULL;

      die = die->die_parent;
    }
}

/* DIE_IN_CU iterators.  */

#define FOREACH_DIE_IN_CU(DIE, CU)			\
  for (DIE = CU->cu_die; DIE; DIE = next_die (DIE))

#define FOREACH_TOPLEVEL_DIE_IN_CU(DIE, CU)			\
  for (DIE = CU->cu_die; DIE; DIE = next_toplevel_die (DIE))

#define FOREACH_LOW_TOPLEVEL_DIE_IN_CU(DIE, CU)		\
  FOREACH_TOPLEVEL_DIE_IN_CU (DIE, CU)			\
    if (!(die->die_root || die->die_named_namespace))

/* DIE iterators.  */

#define FOREACH_DIE(CU, DIE)			\
  FOREACH_CU (CU)				\
    FOREACH_DIE_IN_CU (DIE, CU)

#define FOREACH_TOPLEVEL_DIE(CU, DIE)		\
  FOREACH_CU (CU)				\
    FOREACH_TOPLEVEL_DIE_IN_CU (DIE, CU)

#define FOREACH_LOW_TOPLEVEL_DIE(CU, DIE)	\
  FOREACH_CU (CU)				\
    FOREACH_LOW_TOPLEVEL_DIE_IN_CU (DIE, CU)

#define FOREACH_CU_PU_TOPLEVEL_DIE(CU, DIE)	\
  FOREACH_CU_PU (CU)				\
    FOREACH_TOPLEVEL_DIE_IN_CU (DIE, CU)

#define FOREACH_CU_NORMAL_TOPLEVEL_DIE(CU, DIE)	\
  FOREACH_CU_NORMAL (CU)			\
    FOREACH_TOPLEVEL_DIE_IN_CU (DIE, CU)

#define FOREACH_CU_TYPES_TOPLEVEL_DIE(CU, DIE)	\
  FOREACH_CU_TYPES (CU)				\
    FOREACH_TOPLEVEL_DIE_IN_CU (DIE, CU)

#define FOREACH_CU_PU_LOW_TOPLEVEL_DIE(CU, DIE)	\
  FOREACH_CU_PU (CU)				\
    FOREACH_LOW_TOPLEVEL_DIE_IN_CU (DIE, CU)

#define FOREACH_CU_NORMAL_LOW_TOPLEVEL_DIE(CU, DIE)	\
  FOREACH_CU_NORMAL (CU)				\
    FOREACH_LOW_TOPLEVEL_DIE_IN_CU (DIE, CU)

#define FOREACH_CU_TYPES_LOW_TOPLEVEL_DIE(CU, DIE)	\
  FOREACH_CU_TYPES (CU)					\
    FOREACH_LOW_TOPLEVEL_DIE_IN_CU (DIE, CU)
