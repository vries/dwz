#!/bin/sh

set -e

cp ../hello 1
ln 1 2

dwz -h 1 2

smaller-than.sh 1 ../hello
smaller-than.sh 2 ../hello

hl="$(find -samefile 1 | sort)"
hl="$(echo $hl)"
[ "$hl" = "./1 ./2" ]

rm -f 1 2
