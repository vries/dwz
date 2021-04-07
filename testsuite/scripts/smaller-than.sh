#!/bin/bash

f1=$1
f2=$2

section_size ()
{
    local f="$1"
    local section="$2"

    local s
    s=$(readelf -S -W $f \
	    | grep "\.debug_$section" \
	    | sed 's/.*\.debug_//' \
	    | awk '{print $5}')

    if [ "$s" = "" ]; then
       echo 0
       return
    fi

    # Convert hex to decimal.
    s=$(printf "%d" $((16#$s)))

    echo $s
}

size ()
{
    local f="$1"

    local total=0
    local section
    for section in info abbrev str macro types; do
	total=$(($total + $(section_size $f $section)))
    done

    echo $total
}

s1=$(size $f1)
s2=$(size $f2)

if [ $s1 -ge $s2 ]; then
    exit 1
fi

exit 0
