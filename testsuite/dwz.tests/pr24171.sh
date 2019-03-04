cp $execs/dw2-restrict 1
cp $execs/dw2-restrict 2

if dwz -m 3 1 2 2>dwz.err; status=$?; then
    true
fi

if ! grep -q "DW_AT_stmt_list not DW_FORM_sec_offset or DW_FORM_data4" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 1 ]

rm -f 1 2 dwz.err
