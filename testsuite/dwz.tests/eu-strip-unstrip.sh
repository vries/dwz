#!/bin/sh

set -e

cp ../hello 1

eu-strip 1 -o 1.stripped -f 1.debug

dwz 1.debug

eu-unstrip 1.stripped 1.debug -o 1.unstripped

smaller-than.sh 1.unstripped 1

ls=$(ls)
ls=$(echo $ls)
[ "$ls" = "1 1.debug 1.stripped 1.unstripped" ]

rm -f 1 1.debugged 1.stripped 1.unstripped
