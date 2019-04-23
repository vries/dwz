#!/bin/sh

src="$1"
dst="$2"

if [ ! -d $src ]; then
    exit 0
fi

files=$(cd $src; find -name "*.xz")

for f in $files; do
    df=$(echo $f \
	     | sed 's/\.xz$//')
    if [ -f $dst/$df ]; then
	continue
    fi
    cp $src/$f $dst/$f
    xz -d $dst/$f
done
