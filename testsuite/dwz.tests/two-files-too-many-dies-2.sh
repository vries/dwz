cp $execs/hello 1
cp $execs/dwz-for-test 2

limit=$(readelf -wi 2 \
	    | grep '(DW_TAG' \
	    | wc -l)
limit=$((limit - 1))

if dwz -L$limit 2 1 2>dwz.err; status=$?; then
    true
fi

if [ $status -eq 0 ]; then
    echo "PR24301 workaround used" > dwz.info
else
    [ $status -eq 1 ]
fi

smaller-than.sh 1 $execs/hello
cmp 2 $execs/dwz-for-test

rm -f 1 2 dwz.err
