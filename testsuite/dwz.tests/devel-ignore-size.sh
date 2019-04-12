cp $execs/min 1

cnt=$(readelf -wi 1 \
	    | grep '(DW_TAG_partial_unit' \
	    | wc -l)

[ $cnt -eq 0 ]

 $execs/dwz-for-test 1 2>/dev/null

cnt=$(readelf -wi 1 \
	    | grep '(DW_TAG_partial_unit' \
	    | wc -l)

[ $cnt -eq 0 ]

cp $execs/min 1

 $execs/dwz-for-test --devel-ignore-size 1

cnt=$(readelf -wi 1 \
	    | grep '(DW_TAG_partial_unit' \
	    | wc -l)

[ $cnt -gt 0 ]

rm -f 1
