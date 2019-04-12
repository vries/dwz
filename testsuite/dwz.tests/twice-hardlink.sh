cp $execs/hello 1
ln 1 2

dwz -h 1 2

smaller-than.sh 1 $execs/hello

hardlinks-p.sh 1 2

cp 1 1.saved

if dwz -h 1 2 2>dwz.err; status=$?; then
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

rm -f 1 1.saved 2 2.saved dwz.err

if [ -f 2.#dwz#.* ]; then
    echo "PR24275 workaround used" > dwz.info
    rm -f 2.#dwz#.*
fi
