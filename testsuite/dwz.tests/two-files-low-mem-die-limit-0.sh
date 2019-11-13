cp $execs/hello 1
cp 1 2

$execs/dwz-for-test \
    -l0 \
    --devel-trace \
    1 2 \
    2> dwz.err

if egrep -q "Compressing (1|2)$" dwz.err; then
    exit 1
fi

rm -f 1 2 dwz.err
