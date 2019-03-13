#!/bin/sh

if ! readelf -S $1 | grep -q '\.gnu_debugaltlink'; then
    exit
fi

readelf \
    --string-dump=.gnu_debugaltlink \
    $1 \
    | grep -a '\[[ 	]*0\]' \
    | sed 's/.*0\]  //'
