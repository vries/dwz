cp $execs/hello 1
cp 1 2

count=$(readelf -wi 1 \
	    | grep '(DW_TAG' \
	    | wc -l)
limit=$count

if $execs/dwz-for-test \
       -l$limit \
       --devel-trace \
       -m 3 1 2 \
       2> dwz.err; status=$?; then
    true
fi

if grep -q "Hit low-mem die-limit" dwz.err; then
    exit 1
fi

[ $status -eq 0 ]

rm -f 1 2 3 dwz.err
