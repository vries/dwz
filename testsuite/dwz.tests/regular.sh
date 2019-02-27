#!/bin/sh

set -e

cp ../hello 1

dwz 1

smaller-than.sh 1 ../hello

[ $(ls) = "1" ]

rm -f 1
