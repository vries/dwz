cp $execs/hello 1
ln 1 2

dwz -h 1 2

smaller-than.sh 1 $execs/hello
smaller-than.sh 2 $execs/hello

hardlinks-p.sh 1 2

rm -f 1 2
