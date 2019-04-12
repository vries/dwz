cp $execs/hello 1

if dwz -x 1 2> dwz.err; status=$?; then
    true
fi

[ $status -eq 1 ]

grep -q ": invalid option -- 'x'" dwz.err
grep -q "Usage:" dwz.err

cmp 1 $execs/hello

if dwz --x 1 2> dwz.err; status=$?; then
    true
fi

[ $status -eq 1 ]

grep -q ": unrecognized option '--x'" dwz.err
grep -q "Usage:" dwz.err

cmp 1 $execs/hello

rm -f 1 dwz.err
