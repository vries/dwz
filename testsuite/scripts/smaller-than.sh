#!/bin/sh

f1=$1
f2=$2

s1=$(ls -l $f1 | awk '{print $5}')
s2=$(ls -l $f2 | awk '{print $5}')

if [ $s1 -ge $s2 ]; then
    exit 1
fi

exit 0
