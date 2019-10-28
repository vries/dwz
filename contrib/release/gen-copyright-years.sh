#!/bin/bash

this=$(basename $0)

max ()
{
    local a
    a=$1
    local b
    b=$2

    if [ "$a" = "" ]; then
	echo "$b"
	return
    elif [ "$b" = "" ]; then
	echo "$a"
	return
    fi

    if [ $a -gt $b ]; then
        echo "$a"
    else
        echo "$b"
    fi
}

min ()
{
    local a
    a="$1"
    local b
    b="$2"

    if [ "$a" = "" ]; then
	echo "$b"
	return
    elif [ "$b" = "" ]; then
	echo "$a"
	return
    fi

    if [ $a -lt $b ]; then
        echo "$a"
    else
        echo "$b"
    fi
}

print_range () {
    local a
    a="$1"
    local b
    b="$2"

    if [ "$a" = "$b" ]; then
	echo "$a"
	return
    fi
    echo "$a-$b"
}

process_line ()
{
    local line
    line="$1"

    fsf=false
    rh=false
    suse=false;

    if echo "$line" \
	    | grep -q "Free Software Foundation, Inc\."; then
	fsf=true
	who=fsf
	line=$(echo "$line" \
		   | sed 's/Free Software Foundation, Inc\.//')
    elif echo "$line" \
	    | grep -q "Red Hat, Inc\."; then
	rh=true
	who=rh
	line=$(echo "$line" \
		   | sed 's/Red Hat, Inc\.//')
    elif echo "$line" \
	    | grep -q "SUSE LLC\."; then
	suse=true
	who=suse
	line=$(echo "$line" \
		   | sed 's/SUSE LLC\.//')
    else
	echo "error: unknown copyright: $line"
	exit 1
    fi

    line=$(echo "$line" \
	       | sed 's/[,-]/ /g')
    max_year=$(echo "$line" \
		   | sed 's/ /\n/g' \
		   | grep -v '^$' \
		   | sort -n -r \
		   | head -n 1)
    min_year=$(echo "$line" \
		   | sed 's/ /\n/g' \
		   | grep -v '^$' \
		   | sort -n \
		   | head -n 1)

    if $fsf; then
	fsf_max=$(max "$fsf_max" "$max_year")
	fsf_min=$(min "$fsf_min" "$min_year")
    elif $rh; then
	rh_max=$(max "$rh_max" "$max_year")
	rh_min=$(min "$rh_min" "$min_year")
    elif $suse; then
	suse_max=$(max "$suse_max" "$max_year")
	suse_min=$(min "$suse_min" "$min_year")
    fi
}

main ()
{
    if ! git status --ignored 2>&1 \
	   | grep -q "nothing to commit, working tree clean"; then
	echo "Git tree not clean"
	exit 1
    fi

    local tmp
    tmp=$(mktemp)

    for f in *.c *.h *.def; do
	if ! grep -q "Copyright (C)" $f; then
	    echo "error: found file without copyright marker: $f"
	    exit 1
	fi

	echo processing file: $f

	grep -v '"' $f \
	    | awk -f contrib/release/copyright-lines.awk \
		  > $tmp

	while read line; do
	    line=$(echo "$line" \
		       | sed 's/  */ /g')
	    line=$(echo "$line" \
		       | sed 's/.*Copyright (C) *//')
	    echo "Processing line: $line"
	    process_line "$line"
	done < $tmp
    done

    rm -f $tmp

    echo "-DFSF_YEARS='\"$(print_range $fsf_min $fsf_max)\"'" \
	 > COPYRIGHT_YEARS
    echo "-DRH_YEARS='\"$(print_range $rh_min $rh_max)\"'" \
	 >> COPYRIGHT_YEARS
    echo "-DSUSE_YEARS='\"$(print_range $suse_min $suse_max)\"'" \
	 >> COPYRIGHT_YEARS
}

main "$@"
