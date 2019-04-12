cp $execs/hello 1

if dwz -? 1 2> dwz.err; status=$?; then
    true
fi

[ $status -eq 1 ]

grep -q "Usage:" dwz.err

cmp 1 $execs/hello

rm -f 1 dwz.err
