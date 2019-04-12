cp $execs/hello 1
cp $execs/hello 2

dwz -m $(pwd -P)/3 -r 1 2

smaller-than.sh 1 $execs/hello
smaller-than.sh 2 $execs/hello

[ "$(gnu-debugaltlink-name.sh 1)" = "3" ]
[ "$(gnu-debugaltlink-name.sh 2)" = "3" ]

rm -f 1 2 3
