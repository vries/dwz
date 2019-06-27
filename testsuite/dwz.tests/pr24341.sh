cp $execs/min 1
cp 1 2

dwz -m 3 1 2

cnt=$(readelf -S 3 | grep "\.debug_info" | wc -l)
if [ $cnt -ne 0 ]; then
    exit 77
fi

smaller-than.sh 1 $execs/min
smaller-than.sh 2 $execs/min

[ "$(gnu-debugaltlink-name.sh 1)" = "3" ]
[ "$(gnu-debugaltlink-name.sh 2)" = "3" ]

rm -f 1 2 3
