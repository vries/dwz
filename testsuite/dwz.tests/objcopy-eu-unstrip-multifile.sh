cp ../hello 1

objcopy --only-keep-debug 1 1.debug
objcopy --strip-debug 1 1.stripped

cp 1.debug 2.debug

dwz -m 3 1.debug 2.debug

rm 2.debug

eu-unstrip 1.stripped 1.debug -o 1.unstripped

smaller-than.sh 1.unstripped 1

rm -f 1 1.debug 1.stripped 1.unstripped 3
