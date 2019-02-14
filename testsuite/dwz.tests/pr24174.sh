#!/bin/sh

set -e

cp ../hello 1
objcopy --compress-debug-sections 1
if dwz 1 2>dwz.err; status=$?; then
   true
fi

grep "DWARF version 0 unhandled" dwz.err || true
rm -f dwz.err

[ $status -eq 1 ]

[ $(ls) = "1" ]

rm -f 1
