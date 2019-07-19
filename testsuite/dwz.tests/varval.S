# Generated using gdb/testsuite/gdb.dwarf2/varval.exp from repo
# git://sourceware.org/git/binutils-gdb.git.
        .section .debug_info
.Lcu1_begin:
        .4byte        .Lcu1_end - .Lcu1_start
.Lcu1_start:
        .2byte        4                 /* Version */
        .4byte        .Labbrev1_begin   /* Abbrevs */
        .byte        8                  /* Pointer size */
        .uleb128        2               /* Abbrev (DW_TAG_compile_unit) */
        .sleb128        0x0004
.Llabel1:
        .uleb128        3               /* Abbrev (DW_TAG_base_type) */
        .uleb128        4
        .sleb128        0x5
        .ascii        "int\0"
.Llabel2:
        .uleb128        4               /* Abbrev (DW_TAG_pointer_type) */
        .4byte        .Llabel1 - .Lcu1_begin
.Llabel4:
        .uleb128        5               /* Abbrev (DW_TAG_variable) */
        .ascii        "var_a\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .byte        1
        .uleb128        .Lexpr_end16 - .Lexpr_start15/* expression */
.Lexpr_start15:
        .byte        0x03               /* DW_OP_addr */
        .8byte        var_a
.Lexpr_end16:
.Llabel12:
        .uleb128        6               /* Abbrev (DW_TAG_variable) */
        .4byte        .Llabel1 - .Lcu1_begin
        .byte        1
.Llabel5:
        .uleb128        7               /* Abbrev (DW_TAG_variable) */
        .ascii        "var_b\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .byte        1
        .uleb128        .Lexpr_end18 - .Lexpr_start17/* expression */
.Lexpr_start17:
        .byte        0x03               /* DW_OP_addr */
        .8byte        var_b
.Lexpr_end18:
.Llabel6:
        .uleb128        8               /* Abbrev (DW_TAG_variable) */
        .ascii        "var_c\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .byte        1
        .sleb128        53
.Llabel7:
        .uleb128        9               /* Abbrev (DW_TAG_variable) */
        .ascii        "var_p\0"
        .4byte        .Llabel2 - .Lcu1_begin
        .byte        1
        .uleb128        .Lexpr_end20 - .Lexpr_start19/* expression */
.Lexpr_start19:
        .byte        0x03               /* DW_OP_addr */
        .8byte        var_p
.Lexpr_end20:
.Llabel3:
        .uleb128        10              /* Abbrev (DW_TAG_structure_type) */
        .sleb128        8*4
        .uleb128        11              /* Abbrev (DW_TAG_member) */
        .ascii        "a\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        0*4
        .uleb128        12              /* Abbrev (DW_TAG_member) */
        .ascii        "b\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        1*4
        .uleb128        13              /* Abbrev (DW_TAG_member) */
        .ascii        "c\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        2*4
        .uleb128        14              /* Abbrev (DW_TAG_member) */
        .ascii        "d\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        3*4
        .uleb128        15              /* Abbrev (DW_TAG_member) */
        .ascii        "e\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        4*4
        .uleb128        16              /* Abbrev (DW_TAG_member) */
        .ascii        "f\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        5*4
        .uleb128        17              /* Abbrev (DW_TAG_member) */
        .ascii        "g\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        6*4
        .uleb128        18              /* Abbrev (DW_TAG_member) */
        .ascii        "h\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        7*4
        .byte        0x0                /* Terminate children */
.Llabel10:
        .uleb128        19              /* Abbrev (DW_TAG_variable) */
        .ascii        "var_s\0"
        .4byte        .Llabel3 - .Lcu1_begin
        .byte        1
        .uleb128        .Lexpr_end22 - .Lexpr_start21/* expression */
.Lexpr_start21:
        .byte        0x03               /* DW_OP_addr */
        .8byte        var_s
.Lexpr_end22:
.Llabel11:
        .uleb128        20              /* Abbrev (DW_TAG_variable) */
        .ascii        "var_untyped\0"
        .byte        1
        .uleb128        .Lexpr_end24 - .Lexpr_start23/* expression */
.Lexpr_start23:
        .byte        0x03               /* DW_OP_addr */
        .8byte        var_b
.Lexpr_end24:
        .uleb128        21              /* Abbrev (DW_TAG_subprogram) */
        .ascii        "main\0"
        .8byte        main_label - 4
        .8byte        main_label - 4 + 11
        .4byte        .Llabel1 - .Lcu1_begin
        .byte        1
.Llabel9:
        .uleb128        22              /* Abbrev (DW_TAG_variable) */
        .ascii        "varval\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        .Lexpr_end26 - .Lexpr_start25/* expression */
.Lexpr_start25:
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel4
        .byte        0x9f               /* DW_OP_stack_value */
.Lexpr_end26:
.Llabel14:
        .uleb128        23              /* Abbrev (DW_TAG_variable) */
        .ascii        "varval2\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        .Lexpr_end28 - .Lexpr_start27/* expression */
.Lexpr_start27:
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel12
        .byte        0x9f               /* DW_OP_stack_value */
.Lexpr_end28:
.Llabel13:
        .uleb128        24              /* Abbrev (DW_TAG_variable) */
        .4byte        .Llabel12 - .Lcu1_begin
        .uleb128        .Lexpr_end30 - .Lexpr_start29/* expression */
.Lexpr_start29:
        .byte        0x03               /* DW_OP_addr */
        .8byte        var_a
.Lexpr_end30:
        .uleb128        25              /* Abbrev (DW_TAG_variable) */
        .ascii        "constval\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        .Lexpr_end32 - .Lexpr_start31/* expression */
.Lexpr_start31:
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel6
        .byte        0x9f               /* DW_OP_stack_value */
.Lexpr_end32:
        .uleb128        26              /* Abbrev (DW_TAG_variable) */
        .ascii        "mixedval\0"
        .4byte        .Llabel1 - .Lcu1_begin
        .uleb128        .Lexpr_end34 - .Lexpr_start33/* expression */
.Lexpr_start33:
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel6
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel5
        .byte        0x1b               /* DW_OP_div */
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel9
        .byte        0x22               /* DW_OP_plus */
        .byte        0x12               /* DW_OP_dup */
        .byte        0x22               /* DW_OP_plus */
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel9
        .byte        0x1c               /* DW_OP_minus */
        .byte        0x9f               /* DW_OP_stack_value */
.Lexpr_end34:
        .uleb128        27              /* Abbrev (DW_TAG_variable) */
        .ascii        "pointerval\0"
        .4byte        .Llabel2 - .Lcu1_begin
        .uleb128        .Lexpr_end36 - .Lexpr_start35/* expression */
.Lexpr_start35:
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel7
        .byte        0x9f               /* DW_OP_stack_value */
.Lexpr_end36:
        .uleb128        28              /* Abbrev (DW_TAG_variable) */
        .ascii        "structval\0"
        .4byte        .Llabel3 - .Lcu1_begin
        .uleb128        .Lexpr_end38 - .Lexpr_start37/* expression */
.Lexpr_start37:
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel10
        .byte        0x9f               /* DW_OP_stack_value */
.Lexpr_end38:
        .uleb128        29              /* Abbrev (DW_TAG_variable) */
        .ascii        "untypedval\0"
        .uleb128        .Lexpr_end40 - .Lexpr_start39/* expression */
.Lexpr_start39:
        .byte        0xfd               /* DW_OP_GNU_variable_value */
        .4byte        .Llabel11
        .byte        0x9f               /* DW_OP_stack_value */
.Lexpr_end40:
        .byte        0x0                /* Terminate children */
        .byte        0x0                /* Terminate children */
.Lcu1_end:
        .section .debug_abbrev
.Labbrev1_begin:
        .uleb128        2               /* Abbrev start */
        .uleb128        0x11            /* DW_TAG_compile_unit */
        .byte        1                  /* has_children */
        .uleb128        0x13            /* DW_AT_language */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        3               /* Abbrev start */
        .uleb128        0x24            /* DW_TAG_base_type */
        .byte        0                  /* has_children */
        .uleb128        0x0b            /* DW_AT_byte_size */
        .uleb128        0x0f            /* DW_FORM_udata */
        .uleb128        0x3e            /* DW_AT_encoding */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        4               /* Abbrev start */
        .uleb128        0x0f            /* DW_TAG_pointer_type */
        .byte        0                  /* has_children */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        5               /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        6               /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        7               /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        8               /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .uleb128        0x1c            /* DW_AT_const_value */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        9               /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        10              /* Abbrev start */
        .uleb128        0x13            /* DW_TAG_structure_type */
        .byte        1                  /* has_children */
        .uleb128        0x0b            /* DW_AT_byte_size */
        .uleb128        0x0d            /* DW_FORM_sdata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        11              /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0f            /* DW_FORM_udata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        12              /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0f            /* DW_FORM_udata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        13              /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0f            /* DW_FORM_udata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        14              /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0f            /* DW_FORM_udata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        15              /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0f            /* DW_FORM_udata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        16              /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0f            /* DW_FORM_udata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        17              /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0f            /* DW_FORM_udata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        18              /* Abbrev start */
        .uleb128        0x0d            /* DW_TAG_member */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x38            /* DW_AT_data_member_location */
        .uleb128        0x0f            /* DW_FORM_udata */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        19              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        20              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        21              /* Abbrev start */
        .uleb128        0x2e            /* DW_TAG_subprogram */
        .byte        1                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x11            /* DW_AT_low_pc */
        .uleb128        0x01            /* DW_FORM_addr */
        .uleb128        0x12            /* DW_AT_high_pc */
        .uleb128        0x01            /* DW_FORM_addr */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x3f            /* DW_AT_external */
        .uleb128        0x0c            /* DW_FORM_flag */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        22              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        23              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        24              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x31            /* DW_AT_abstract_origin */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        25              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        26              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        27              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        28              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x49            /* DW_AT_type */
        .uleb128        0x13            /* DW_FORM_ref4 */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .uleb128        29              /* Abbrev start */
        .uleb128        0x34            /* DW_TAG_variable */
        .byte        0                  /* has_children */
        .uleb128        0x03            /* DW_AT_name */
        .uleb128        0x08            /* DW_FORM_string */
        .uleb128        0x02            /* DW_AT_location */
        .uleb128        0x09            /* SPECIAL_expr */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
        .byte        0x0                /* Terminator */
