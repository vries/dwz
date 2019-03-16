# Generated using gdb/testsuite/gdb.python/py-section-script.c from repo
# git://sourceware.org/git/binutils-gdb.git.
	
	.file	"py-section-script.c"
	.text
.Ltext0:
#APP
	.pushsection ".debug_gdb_scripts", "S",%progbits
.byte 1
.asciz "py-section-script.py"
.popsection

	.pushsection ".debug_gdb_scripts", "S",%progbits
.byte 1
.asciz "py-section-script.py"
.popsection

	.pushsection ".debug_gdb_scripts", "S",%progbits
.byte 4
.ascii "gdb.inlined-script\n"
.ascii "class test_cmd (gdb.Command):\n"
.ascii "  def __init__ (self):\n"
.ascii "    super (test_cmd, self).__init__ (\"test-cmd\", gdb.COMMAND_OBSCURE)\n"
.ascii "  def invoke (self, arg, from_tty):\n"
.ascii "    print (\"test-cmd output, arg = %s\" % arg)\n"
.ascii "test_cmd ()\n"
.byte 0
.popsection

	.pushsection ".debug_gdb_scripts", "S",%progbits
.byte 4
.ascii "gdb.inlined-script\n"
.ascii "class test_cmd (gdb.Command):\n"
.ascii "  def __init__ (self):\n"
.ascii "    super (test_cmd, self).__init__ (\"test-cmd\", gdb.COMMAND_OBSCURE)\n"
.ascii "  def invoke (self, arg, from_tty):\n"
.ascii "    print (\"test-cmd output, arg = %s\" % arg)\n"
.ascii "test_cmd ()\n"
.byte 0
.popsection

#NO_APP
	.globl	init_ss
	.type	init_ss, @function
init_ss:
.LFB0:
	.file 1 "py-section-script.c"
	# py-section-script.c:76
	.loc 1 76 0
	.cfi_startproc
# BLOCK 2 seq:0
# PRED: ENTRY (FALLTHRU)
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	movl	%edx, -16(%rbp)
	# py-section-script.c:77
	.loc 1 77 0
	movq	-8(%rbp), %rax
	movl	-12(%rbp), %edx
	movl	%edx, (%rax)
	# py-section-script.c:78
	.loc 1 78 0
	movq	-8(%rbp), %rax
	movl	-16(%rbp), %edx
	movl	%edx, 4(%rax)
	# py-section-script.c:79
	.loc 1 79 0
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
# SUCC: EXIT [100.0%] 
	ret
	.cfi_endproc
.LFE0:
	.size	init_ss, .-init_ss
	.globl	main
	.type	main, @function
main:
.LFB1:
	# py-section-script.c:83
	.loc 1 83 0
	.cfi_startproc
# BLOCK 2 seq:0
# PRED: ENTRY (FALLTHRU)
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	# py-section-script.c:86
	.loc 1 86 0
	leaq	-8(%rbp), %rax
	movl	$2, %edx
	movl	$1, %esi
	movq	%rax, %rdi
	call	init_ss
	# py-section-script.c:88
	.loc 1 88 0
	movl	$0, %eax
	# py-section-script.c:89
	.loc 1 89 0
	leave
	.cfi_def_cfa 7, 8
# SUCC: EXIT [100.0%] 
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0xc8	# Length of Compilation Unit Info
	.value	0x4	# DWARF version number
	.long	.Ldebug_abbrev0	# Offset Into Abbrev. Section
	.byte	0x8	# Pointer Size (in bytes)
	.uleb128 0x1	# (DIE (0xb) DW_TAG_compile_unit)
	.long	.LASF2	# DW_AT_producer: "GNU C11 7.3.1 20180323 [gcc-7-branch revision 258812] -mtune=generic -march=x86-64 -g"
	.byte	0xc	# DW_AT_language
	.long	.LASF3	# DW_AT_name: "py-section-script.c"
	.long	.LASF4	# DW_AT_comp_dir: "/home/vries/gdb_versions/devel"
	.quad	.Ltext0	# DW_AT_low_pc
	.quad	.Letext0-.Ltext0	# DW_AT_high_pc
	.long	.Ldebug_line0	# DW_AT_stmt_list
	.uleb128 0x2	# (DIE (0x2d) DW_TAG_structure_type)
	.ascii "ss\0"	# DW_AT_name
	.byte	0x8	# DW_AT_byte_size
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x44	# DW_AT_decl_line
	.long	0x4d	# DW_AT_sibling
	.uleb128 0x3	# (DIE (0x38) DW_TAG_member)
	.ascii "a\0"	# DW_AT_name
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x46	# DW_AT_decl_line
	.long	0x4d	# DW_AT_type
	.byte	0	# DW_AT_data_member_location
	.uleb128 0x3	# (DIE (0x42) DW_TAG_member)
	.ascii "b\0"	# DW_AT_name
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x47	# DW_AT_decl_line
	.long	0x4d	# DW_AT_type
	.byte	0x4	# DW_AT_data_member_location
	.byte	0	# end of children of DIE 0x2d
	.uleb128 0x4	# (DIE (0x4d) DW_TAG_base_type)
	.byte	0x4	# DW_AT_byte_size
	.byte	0x5	# DW_AT_encoding
	.ascii "int\0"	# DW_AT_name
	.uleb128 0x5	# (DIE (0x54) DW_TAG_subprogram)
			# DW_AT_external
	.long	.LASF0	# DW_AT_name: "main"
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x52	# DW_AT_decl_line
	.long	0x4d	# DW_AT_type
	.quad	.LFB1	# DW_AT_low_pc
	.quad	.LFE1-.LFB1	# DW_AT_high_pc
	.uleb128 0x1	# DW_AT_frame_base
	.byte	0x9c	# DW_OP_call_frame_cfa
			# DW_AT_GNU_all_tail_call_sites
	.long	0x83	# DW_AT_sibling
	.uleb128 0x6	# (DIE (0x75) DW_TAG_variable)
	.ascii "ss\0"	# DW_AT_name
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x54	# DW_AT_decl_line
	.long	0x2d	# DW_AT_type
	.uleb128 0x2	# DW_AT_location
	.byte	0x91	# DW_OP_fbreg
	.sleb128 -24
	.byte	0	# end of children of DIE 0x54
	.uleb128 0x7	# (DIE (0x83) DW_TAG_subprogram)
			# DW_AT_external
	.long	.LASF1	# DW_AT_name: "init_ss"
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x4b	# DW_AT_decl_line
			# DW_AT_prototyped
	.quad	.LFB0	# DW_AT_low_pc
	.quad	.LFE0-.LFB0	# DW_AT_high_pc
	.uleb128 0x1	# DW_AT_frame_base
	.byte	0x9c	# DW_OP_call_frame_cfa
			# DW_AT_GNU_all_call_sites
	.long	0xc5	# DW_AT_sibling
	.uleb128 0x8	# (DIE (0xa0) DW_TAG_formal_parameter)
	.ascii "s\0"	# DW_AT_name
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x4b	# DW_AT_decl_line
	.long	0xc5	# DW_AT_type
	.uleb128 0x2	# DW_AT_location
	.byte	0x91	# DW_OP_fbreg
	.sleb128 -24
	.uleb128 0x8	# (DIE (0xac) DW_TAG_formal_parameter)
	.ascii "a\0"	# DW_AT_name
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x4b	# DW_AT_decl_line
	.long	0x4d	# DW_AT_type
	.uleb128 0x2	# DW_AT_location
	.byte	0x91	# DW_OP_fbreg
	.sleb128 -28
	.uleb128 0x8	# (DIE (0xb8) DW_TAG_formal_parameter)
	.ascii "b\0"	# DW_AT_name
	.byte	0x1	# DW_AT_decl_file (py-section-script.c)
	.byte	0x4b	# DW_AT_decl_line
	.long	0x4d	# DW_AT_type
	.uleb128 0x2	# DW_AT_location
	.byte	0x91	# DW_OP_fbreg
	.sleb128 -32
	.byte	0	# end of children of DIE 0x83
	.uleb128 0x9	# (DIE (0xc5) DW_TAG_pointer_type)
	.byte	0x8	# DW_AT_byte_size
	.long	0x2d	# DW_AT_type
	.byte	0	# end of children of DIE 0xb
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1	# (abbrev code)
	.uleb128 0x11	# (TAG: DW_TAG_compile_unit)
	.byte	0x1	# DW_children_yes
	.uleb128 0x25	# (DW_AT_producer)
	.uleb128 0xe	# (DW_FORM_strp)
	.uleb128 0x13	# (DW_AT_language)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3	# (DW_AT_name)
	.uleb128 0xe	# (DW_FORM_strp)
	.uleb128 0x1b	# (DW_AT_comp_dir)
	.uleb128 0xe	# (DW_FORM_strp)
	.uleb128 0x11	# (DW_AT_low_pc)
	.uleb128 0x1	# (DW_FORM_addr)
	.uleb128 0x12	# (DW_AT_high_pc)
	.uleb128 0x7	# (DW_FORM_data8)
	.uleb128 0x10	# (DW_AT_stmt_list)
	.uleb128 0x17	# (DW_FORM_sec_offset)
	.byte	0
	.byte	0
	.uleb128 0x2	# (abbrev code)
	.uleb128 0x13	# (TAG: DW_TAG_structure_type)
	.byte	0x1	# DW_children_yes
	.uleb128 0x3	# (DW_AT_name)
	.uleb128 0x8	# (DW_FORM_string)
	.uleb128 0xb	# (DW_AT_byte_size)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3a	# (DW_AT_decl_file)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3b	# (DW_AT_decl_line)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x1	# (DW_AT_sibling)
	.uleb128 0x13	# (DW_FORM_ref4)
	.byte	0
	.byte	0
	.uleb128 0x3	# (abbrev code)
	.uleb128 0xd	# (TAG: DW_TAG_member)
	.byte	0	# DW_children_no
	.uleb128 0x3	# (DW_AT_name)
	.uleb128 0x8	# (DW_FORM_string)
	.uleb128 0x3a	# (DW_AT_decl_file)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3b	# (DW_AT_decl_line)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x49	# (DW_AT_type)
	.uleb128 0x13	# (DW_FORM_ref4)
	.uleb128 0x38	# (DW_AT_data_member_location)
	.uleb128 0xb	# (DW_FORM_data1)
	.byte	0
	.byte	0
	.uleb128 0x4	# (abbrev code)
	.uleb128 0x24	# (TAG: DW_TAG_base_type)
	.byte	0	# DW_children_no
	.uleb128 0xb	# (DW_AT_byte_size)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3e	# (DW_AT_encoding)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3	# (DW_AT_name)
	.uleb128 0x8	# (DW_FORM_string)
	.byte	0
	.byte	0
	.uleb128 0x5	# (abbrev code)
	.uleb128 0x2e	# (TAG: DW_TAG_subprogram)
	.byte	0x1	# DW_children_yes
	.uleb128 0x3f	# (DW_AT_external)
	.uleb128 0x19	# (DW_FORM_flag_present)
	.uleb128 0x3	# (DW_AT_name)
	.uleb128 0xe	# (DW_FORM_strp)
	.uleb128 0x3a	# (DW_AT_decl_file)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3b	# (DW_AT_decl_line)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x49	# (DW_AT_type)
	.uleb128 0x13	# (DW_FORM_ref4)
	.uleb128 0x11	# (DW_AT_low_pc)
	.uleb128 0x1	# (DW_FORM_addr)
	.uleb128 0x12	# (DW_AT_high_pc)
	.uleb128 0x7	# (DW_FORM_data8)
	.uleb128 0x40	# (DW_AT_frame_base)
	.uleb128 0x18	# (DW_FORM_exprloc)
	.uleb128 0x2116	# (DW_AT_GNU_all_tail_call_sites)
	.uleb128 0x19	# (DW_FORM_flag_present)
	.uleb128 0x1	# (DW_AT_sibling)
	.uleb128 0x13	# (DW_FORM_ref4)
	.byte	0
	.byte	0
	.uleb128 0x6	# (abbrev code)
	.uleb128 0x34	# (TAG: DW_TAG_variable)
	.byte	0	# DW_children_no
	.uleb128 0x3	# (DW_AT_name)
	.uleb128 0x8	# (DW_FORM_string)
	.uleb128 0x3a	# (DW_AT_decl_file)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3b	# (DW_AT_decl_line)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x49	# (DW_AT_type)
	.uleb128 0x13	# (DW_FORM_ref4)
	.uleb128 0x2	# (DW_AT_location)
	.uleb128 0x18	# (DW_FORM_exprloc)
	.byte	0
	.byte	0
	.uleb128 0x7	# (abbrev code)
	.uleb128 0x2e	# (TAG: DW_TAG_subprogram)
	.byte	0x1	# DW_children_yes
	.uleb128 0x3f	# (DW_AT_external)
	.uleb128 0x19	# (DW_FORM_flag_present)
	.uleb128 0x3	# (DW_AT_name)
	.uleb128 0xe	# (DW_FORM_strp)
	.uleb128 0x3a	# (DW_AT_decl_file)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3b	# (DW_AT_decl_line)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x27	# (DW_AT_prototyped)
	.uleb128 0x19	# (DW_FORM_flag_present)
	.uleb128 0x11	# (DW_AT_low_pc)
	.uleb128 0x1	# (DW_FORM_addr)
	.uleb128 0x12	# (DW_AT_high_pc)
	.uleb128 0x7	# (DW_FORM_data8)
	.uleb128 0x40	# (DW_AT_frame_base)
	.uleb128 0x18	# (DW_FORM_exprloc)
	.uleb128 0x2117	# (DW_AT_GNU_all_call_sites)
	.uleb128 0x19	# (DW_FORM_flag_present)
	.uleb128 0x1	# (DW_AT_sibling)
	.uleb128 0x13	# (DW_FORM_ref4)
	.byte	0
	.byte	0
	.uleb128 0x8	# (abbrev code)
	.uleb128 0x5	# (TAG: DW_TAG_formal_parameter)
	.byte	0	# DW_children_no
	.uleb128 0x3	# (DW_AT_name)
	.uleb128 0x8	# (DW_FORM_string)
	.uleb128 0x3a	# (DW_AT_decl_file)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x3b	# (DW_AT_decl_line)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x49	# (DW_AT_type)
	.uleb128 0x13	# (DW_FORM_ref4)
	.uleb128 0x2	# (DW_AT_location)
	.uleb128 0x18	# (DW_FORM_exprloc)
	.byte	0
	.byte	0
	.uleb128 0x9	# (abbrev code)
	.uleb128 0xf	# (TAG: DW_TAG_pointer_type)
	.byte	0	# DW_children_no
	.uleb128 0xb	# (DW_AT_byte_size)
	.uleb128 0xb	# (DW_FORM_data1)
	.uleb128 0x49	# (DW_AT_type)
	.uleb128 0x13	# (DW_FORM_ref4)
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.long	0x2c	# Length of Address Ranges Info
	.value	0x2	# DWARF Version
	.long	.Ldebug_info0	# Offset of Compilation Unit Info
	.byte	0x8	# Size of Address
	.byte	0	# Size of Segment Descriptor
	.value	0	# Pad to 16 byte boundary
	.value	0
	.quad	.Ltext0	# Address
	.quad	.Letext0-.Ltext0	# Length
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF2:
	.string	"GNU C11 7.3.1 20180323 [gcc-7-branch revision 258812] -mtune=generic -march=x86-64 -g"
.LASF3:
	.string	"py-section-script.c"
.LASF0:
	.string	"main"
.LASF4:
	.string	"/home/vries/gdb_versions/devel"
.LASF1:
	.string	"init_ss"
	.ident	"GCC: (SUSE Linux) 7.3.1 20180323 [gcc-7-branch revision 258812]"
	.section	.note.GNU-stack,"",@progbits
