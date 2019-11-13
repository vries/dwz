cp $execs/hello 1

$execs/dwz-for-test \
    -lnone \
    --devel-trace \
    1 \
    2> dwz.err

if grep -q "Compressing 1 in low-mem mode" dwz.err; then
    exit 1
fi

rm -f 1 dwz.err
