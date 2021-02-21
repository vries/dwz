cp $execs/hello 1

dwz -v 1 > dwz.out 2> /dev/null

grep -q "dwz version" dwz.out

cmp 1 $execs/hello

rm -f 1 dwz.out
