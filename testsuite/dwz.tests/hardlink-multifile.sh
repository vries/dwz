cp ../hello 1
ln 1 2
cp ../hello 3

dwz -h -m 4 1 2 3

hardlinks-p.sh 1 2

smaller-than.sh 1 ../hello
smaller-than.sh 3 ../hello

[ "$(gnu-debugaltlink-name.sh 1)" = "4" ]
[ "$(gnu-debugaltlink-name.sh 3)" = "4" ]

rm -f 1 2 3 4
