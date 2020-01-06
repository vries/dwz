if ! $execs/dwz-for-test --odr -v 2>/dev/null; then
    exit 77
fi

cp $execs/def-decl 1

verify-dwarf.sh 1

cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*ao_ref" || true)
[ $cnt -eq 4 ]

$execs/dwz-for-test --odr 1 --devel-ignore-size

verify-dwarf.sh 1

cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*ao_ref" || true)
[ $cnt -eq 3 ]

rm -f 1
