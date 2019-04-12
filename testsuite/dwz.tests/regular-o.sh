cp $execs/hello 1

dwz 1 -o 2

cmp 1 $execs/hello

smaller-than.sh 2 1

rm -f 1 2
