exec=../testsuite/dwz.tests/execs/hello-ld-2.26.1

cp $exec 1
cp 1 2

dwz -m 3 1 2

smaller-than.sh 1 $exec
smaller-than.sh 2 $exec

[ "$(gnu-debugaltlink-name.sh 1)" = "3" ]
[ "$(gnu-debugaltlink-name.sh 2)" = "3" ]

rm -f 1 2 3
