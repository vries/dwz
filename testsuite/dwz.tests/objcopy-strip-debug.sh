objcopy --strip-debug $execs/hello 1

cp 1 1.saved

if dwz 1 2>dwz.err; status=$?; then
    true
fi

if ! grep -q "\.debug_info section not present" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 0 ]

cmp 1 1.saved

if dwz 1 -o 2 2>dwz.err; status=$?; then
    true
fi

if ! grep -q "\.debug_info section not present" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 1 ]
[ ! -f 2 ]

rm -f 1 1.saved dwz.err
