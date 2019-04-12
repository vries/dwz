cp $execs/hello 1

gdb-add-index 1

readelf -S 1 | grep -q '\.gdb_index'

dwz 1 -o 2

readelf -S 2 | grep -q '\.gdb_index'

smaller-than.sh 2 1

rm -f 1 2
