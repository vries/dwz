cp $execs/hello 1

eu-strip 1 -o 1.stripped -f 1.debug

dwz 1.debug

eu-unstrip 1.stripped 1.debug -o 1.unstripped

smaller-than.sh 1.unstripped 1

rm -f 1 1.debug 1.stripped 1.unstripped
