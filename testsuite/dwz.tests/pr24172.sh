cp $execs/dw2-skip-prologue 1

if dwz 1 2>dwz.err; status=$?; then
    true
fi

if ! grep -q "locexpr length .* exceeds .debug_loc section" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 1 ]

rm -f 1 dwz.err
