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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <obstack.h>
#include <limits.h>

#include "args.h"
#include "import-tree.h"
#include "dwz.h"

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
struct import_edge *edge_freelist;

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
int
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
