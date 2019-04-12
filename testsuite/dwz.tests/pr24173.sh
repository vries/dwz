cp $execs/py-section-script 1

eu-strip -g -f 1.debug 1

if dwz 1.debug 2>dwz.err; status=$?; then
    true
fi

if ! grep -q "Found empty .debug_gdb_scripts section, not attempting dwz compression" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 1 ]

rm -f 1 1.debug dwz.err
