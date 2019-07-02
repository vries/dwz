#!/bin/sh

exec=$execs/implptr-64bit-d2o4a8r8t0

pointer_sizes=$(readelf -wi $exec \
		    | grep "Pointer Size:" \
		    | sort -u \
		    | wc -l)

if [ $pointer_sizes -ne 1 ]; then
    exit 77
fi

cp $exec 1
cp 1 2

dwz -m 3 1 2

smaller-than.sh 1 $exec
smaller-than.sh 2 $exec

[ "$(gnu-debugaltlink-name.sh 1)" = "3" ]
[ "$(gnu-debugaltlink-name.sh 2)" = "3" ]

rm -f 1 2 3
