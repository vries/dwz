cp ../min 1
cp 1 2

dwz -m 3 1 2

cnt=$(readelf -S 3 | grep "\.debug_info" | wc -l)
[ $cnt -eq 0 ]

smaller-than.sh 1 ../min
smaller-than.sh 2 ../min

[ "$(gnu-debugaltlink-name.sh 1)" = "3" ]
[ "$(gnu-debugaltlink-name.sh 2)" = "3" ]

rm -f 1 2 3
