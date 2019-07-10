cp ../hello 1

objcopy --only-keep-debug 1 1.debug
objcopy --strip-debug 1 1.stripped

cp 1.debug 2.debug

if dwz -m 3 1.debug 2.debug 2> dwz.err; status=$?; then
    true
fi

rm 2.debug

if grep -q "dwz: Section overlap detected" dwz.err; then
    exit 77
fi

[ $status -eq 0 ]

eu-unstrip 1.stripped 1.debug -o 1.unstripped

smaller-than.sh 1.unstripped 1

rm -f 1 1.debug 1.stripped 1.unstripped 3 dwz.err
