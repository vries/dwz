#!/bin/bash

f="$1"

size=$(readelf -WS "$f" \
	   | egrep "[ \t]\.debug_info" \
	   | sed 's/.*\.debug_info//' \
	   | awk '{print $4}')
size=$((16#$size))

nr_dies=$(readelf -wi "$f" \
	      | grep -c ': Abbrev Number.*(DW_TAG')

res=$(echo "scale=2; $size / $nr_dies" \
	  | bc)
echo -e "$res\tsize: $size\tnr_dies: $nr_dies"
