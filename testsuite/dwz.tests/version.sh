cp ../hello 1

dwz -v 1 2> dwz.err

grep -q "dwz version" dwz.err

cmp 1 ../hello

rm -f 1 dwz.err
