cp $execs/hello 1
objcopy --compress-debug-sections 1
if dwz 1 2>dwz.err; status=$?; then
   true
fi

if grep -q "DWARF version 0 unhandled" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 1 ]

rm -f 1 dwz.err
