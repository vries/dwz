cp $execs/no-multifile-prop 1
cp 1 2

$execs/dwz-for-test -m 3 1 2 --devel-ignore-size

rm -f 1 2 3
