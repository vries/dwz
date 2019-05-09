cp $execs/start 1
cp 1 2

if dwz -m 3 1 2 2> dwz.err; status=$?; then
    true
fi

if ! grep -q "No suitable DWARF found for multifile optimization" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 0 ]

rm -f 1 2 3 dwz.err
