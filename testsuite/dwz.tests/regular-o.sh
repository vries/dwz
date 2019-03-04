#!/bin/sh

set -e

cp ../hello 1

dwz 1 -o 2

cmp 1 ../hello

smaller-than.sh 2 1

ls=$(ls)
ls=$(echo $ls)
[ "$ls" = "1 2" ]

rm -f 1 2
