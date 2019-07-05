exec=$execs/hello
cp $exec 1
objcopy --compress-debug-sections 1
if cmp -s $exec 1; then
    exit 77
fi

if dwz 1 2>dwz.err; status=$?; then
   true
fi

if grep -q "DWARF version 0 unhandled" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 1 ]

rm -f 1 dwz.err
