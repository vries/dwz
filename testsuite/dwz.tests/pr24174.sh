#!/bin/sh

set -e

cp ../hello 1
objcopy --compress-debug-sections 1
if dwz 1 2>dwz.err; status=$?; then
   true
fi

if grep -q "DWARF version 0 unhandled" dwz.err; then
    exit 1
fi

[ $status -eq 1 ]

rm -f 1 dwz.err
