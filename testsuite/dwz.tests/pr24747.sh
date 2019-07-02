exec=$execs/start-gold

cp $exec 1

dwz 1

smaller-than.sh 1 $exec

rm -f 1
