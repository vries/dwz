cp ../hello 1
cp 1 2

dwz 1 2

smaller-than.sh 1 ../hello
smaller-than.sh 2 ../hello

cp 1 1.saved
cp 2 2.saved

if dwz -m 3 1 2 2>dwz.err; status=$?; then
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

if [ $status -eq 1 ]; then
    # PR24354
    true
else
    [ $status -eq 0 ]
fi

cmp 1 1.saved

rm -f 1 1.saved 2 2.saved dwz.err
