#!/bin/sh

hardlinks=$(find -samefile "$1")

for f in "$@"; do
    found=false
    for hl in $hardlinks; do
	if [ "$hl" = "./$f" ]; then
	    found=true
	    break
	fi
    done
    if ! $found; then
	exit 1
    fi
done
