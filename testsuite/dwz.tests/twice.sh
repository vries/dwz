cp $execs/hello 1

dwz 1

smaller-than.sh 1 $execs/hello

cp 1 1.saved

if dwz 1 2>dwz.err; status=$?; then
    true
fi

if ! grep -q "DWARF compression not beneficial" dwz.err; then
    cat dwz.err
    exit 1
fi

if [ $(grep -qv "DWARF compression not beneficial" dwz.err \
	   | wc -l) -gt 0 ]; then
    cat dwz.err
    exit 1
fi

[ $status -eq 0 ]

cmp 1 1.saved

rm -f 1 1.saved dwz.err
