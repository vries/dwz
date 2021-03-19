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

extern char *get_AT_string (dw_die_ref, enum dwarf_attribute);
extern uint64_t get_AT_int (dw_die_ref, enum dwarf_attribute, bool *,
			    enum dwarf_form *);
extern dw_die_ref off_htab_lookup (dw_cu_ref, unsigned int);
