cp ../two-typedef 1

cnt=$(readelf -wi 1 \
	    | grep 'DW_AT_name.*: aaa' \
	    | wc -l)

[ $cnt -eq 2 ]

dwz 1 2>/dev/null

cnt=$(readelf -wi 1 \
	    | grep 'DW_AT_name.*: aaa' \
	    | wc -l)

[ $cnt -eq 2 ]

cp ../two-typedef 1

dwz --devel-ignore-locus --devel-ignore-size 1

cnt=$(readelf -wi 1 \
	    | grep 'DW_AT_name.*: aaa' \
	    | wc -l)

[ $cnt -eq 1 ]

rm -f 1
