#!/bin/sh

set -e

cp ../hello 1
cp ../hello 2

dwz -m 3 -M /xxx/yyy/3 1 2

smaller-than.sh 1 ../hello
smaller-than.sh 2 ../hello

[ "$(gnu-debugaltlink-name.sh 1)" = "/xxx/yyy/3" ]
[ "$(gnu-debugaltlink-name.sh 2)" = "/xxx/yyy/3" ]

rm -f 1 2 3
