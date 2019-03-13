#!/bin/sh

set -e

objcopy --strip-debug ../hello 1

cp 1 1.saved

if dwz 1 2>dwz.err; status=$?; then
    true
fi

[ $status -eq 1 ]

if ! grep -q "\.debug_info section not present" dwz.err; then
    exit 1
fi

cmp 1 1.saved

rm -f 1 1.saved dwz.err
