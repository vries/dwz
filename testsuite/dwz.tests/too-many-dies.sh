#!/bin/sh

set -e

cp ../hello 1

if dwz -L0 1 2>/dev/null; then exit 1; fi

cmp 1 ../hello

rm -f 1
