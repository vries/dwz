cp $execs/hello 1
cp $execs/hello 2

eu-strip 1 -o 1.stripped -f 1.debug
eu-strip 2 -o 2.stripped -f 2.debug

dwz -m 3 1.debug 2.debug

eu-unstrip 1.stripped 1.debug -o 1.unstripped
eu-unstrip 2.stripped 2.debug -o 2.unstripped

smaller-than.sh 1.unstripped 1
smaller-than.sh 2.unstripped 2

[ "$(gnu-debugaltlink-name.sh 1.unstripped)" = "3" ]
[ "$(gnu-debugaltlink-name.sh 2.unstripped)" = "3" ]

rm -f 1 1.debug 1.stripped 1.unstripped 2 2.debug 2.stripped 2.unstripped 3
