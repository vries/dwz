exec=$execs/varval

pointer_sizes=$(readelf -wi $exec \
		    | grep "Pointer Size:" \
		    | sort -u \
		    | wc -l)

if [ $pointer_sizes -ne 1 ]; then
    exit 77
fi

cp $exec 1
cp 1 2

dwz -m 3 1 2

if [ -f 3 ]; then
    readelf -wi 3 > READELF.3
    if grep -q var_c READELF.3; status=$?; then
	true
    fi
    [ $status -ne 0 ]
fi

rm -f 1 2 3 READELF.3
