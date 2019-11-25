cp $execs/hello 1

count=$(readelf -wi 1 \
	    | grep '(DW_TAG' \
	    | wc -l)
limit=$count

$execs/dwz-for-test \
    -l$limit \
    --devel-trace \
    1 \
    2> dwz.err

if grep -q "Compressing 1 in low-mem mode" dwz.err; then
    exit 1
fi

rm -f 1 dwz.err
