/* This was generated using git://sourceware.org/git/binutils-gdb.git
   repository, file gdb/testsuite/gdb.dwarf2/implptr-64bit.exp.  */
        .section .debug_info
.Lcu1_begin:
        .4byte        .Lcu1_end - .Lcu1_start
.Lcu1_start:
        .2byte        2                 /* Version */
        .4byte        .Labbrev1_begin   /* Abbrevs */
        .byte        8                  /* Pointer size */
        .uleb128        2               /* Abbrev (DW_TAG_compile_unit) */
        .ascii        "GNU C 4.4.3\0"
        .sleb128        0x0001
        .ascii        "1.c\0"
.Llabel3:
        .uleb128        3               /* Abbrev (DW_TAG_base_type) */
        .sleb128        4
        .sleb128        0x5
        .ascii        "int\0"
.Llabel1:
        .uleb128        4               /* Abbrev (DW_TAG_structure_type) */
        .ascii        "s\0"
        .sleb128        4
        .uleb128        5               /* Abbrev (DW_TAG_member) */
        .ascii        "f\0"
        .4byte        .Llabel3 - .Lcu1_begin
        .byte        0
        .byte        0x0                /* Terminate children */
.Llabel4:
        .uleb128        6               /* Abbrev (DW_TAG_pointer_type) */
        .sleb128        8
        .4byte        .Llabel1 - .Lcu1_begin
.Llabel2:
        .uleb128        7               /* Abbrev (DW_TAG_variable) */
        .ascii        "v\0"
        .uleb128        .Lexpr_end6 - .Lexpr_start5/* expression */
.Lexpr_start5:
        .byte        0x9e               /* DW_OP_implicit_value */
        .uleb128        .Lvalue_end8 - .Lvalue_start7
.Lvalue_start7:
        .byte        0x1
        .byte        0x1
        .byte        0x1
        .byte        0x1
.Lvalue_end8:
.Lexpr_end6:
        .8byte        .Llabel1 - .Lcu1_begin
        .uleb128        8               /* Abbrev (DW_TAG_subprogram) */
        .ascii        "main\0"
        .8byte        main
        .8byte        main+0x100
        .8byte        .Llabel3
        .byte        1
        .uleb128        9               /* Abbrev (DW_TAG_variable) */
        .ascii        "p\0"
        .uleb128        .Lexpr_end10 - .Lexpr_start9/* expression */
.Lexpr_start9:
        .byte        0xf2               /* DW_OP_GNU_implicit_pointer */
        .8byte        .Llabel2
        .sleb128        0
.Lexpr_end10:
        .8byte        .Llabel4 - .Lcu1_begin
        .byte        0x0                /* Terminate children */
        .byte        0x0                /* Terminate children */
.Lcu1_end:
        .section .debug_abbrev
.Labbrev1_begin:
        .uleb128        2               /* Abbrev start */
        .uleb128        0x11            /* DW_TAG_compile_unit */
        .byte        1                  /* has_children */
        .uleb128        0x25            /* DW_AT_producer */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x13            /* DW_AT_language */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        3               /* Abbrev start */
        .uleb128        0x24            /* DW_TAG_base_type */
        .byte        0                  /* has_children */
        .uleb128        0x0b            /* DW_AT_byte_size */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .uleb128        0x3e            /* DW_AT_encoding */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        4               /* Abbrev start */
        .uleb128        0x13            /* DW_TAG_structure_type */
        .byte        1                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x0b            /* DW_AT_byte_size */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        5               /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0b            /* DW_FORM_data1 */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        6               /* Abbrev start */
        .uleb128        0x0f            /* DW_TAG_pointer_type */
        .byte        0                  /* has_children */
        .uleb128        0x0b            /* DW_AT_byte_size */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        7               /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x14            /* DW_FORM_ref8 */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        8               /* Abbrev start */
        .uleb128        0x2e            /* DW_TAG_subprogram */
        .byte        1                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x11            /* DW_AT_low_pc */
        .uleb128        0x01            /* DW_FORM_addr */
        .uleb128        0x12            /* DW_AT_high_pc */
        .uleb128        0x01            /* DW_FORM_addr */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x10            /* DW_FORM_ref_addr */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        9               /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x14            /* DW_FORM_ref8 */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
