if ! $execs/dwz-for-test --odr -v 2>/dev/null; then
    exit 77
fi

cp $execs/odr-class-ns 1

verify-dwarf.sh 1

aaa=$(readelf -wi 1 | grep -c 'DW_AT_name.*:.*aaa')
[ $aaa -eq 2 ]

bbb=$(readelf -wi 1 | grep -c 'DW_AT_name.*:.*bbb')
[ $bbb -eq 2 ]

ccc=$(readelf -wi 1 | grep -c 'DW_AT_name.*:.*ccc')
[ $ccc -eq 2 ]

$execs/dwz-for-test --odr 1

aaa=$(readelf -wi 1 | grep -c 'DW_AT_name.*:.*aaa')
[ $aaa -eq 1 ]

bbb=$(readelf -wi 1 | grep -c 'DW_AT_name.*:.*bbb')
[ $bbb -eq 1 ]

ccc=$(readelf -wi 1 | grep -c 'DW_AT_name.*:.*ccc')
[ $ccc -eq 1 ]

rm -f 1
