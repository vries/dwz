if ! $execs/dwz-for-test --odr -v 2>/dev/null; then
    exit 77
fi

cp $execs/odr-struct 1

for name in aaa bbb ccc; do
    cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*$name" || true)
    [ $cnt -eq 2 ]
done

for name in member_one member_two member_three member_four; do
    cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*$name" || true)
    case $name in
	member_one|member_two)
	    [ $cnt -eq 2 ]
	    ;;
	member_three|member_four)
	    [ $cnt -eq 1 ]
	    ;;
	esac
done

decl_cnt=$(readelf -wi 1 | grep -c "DW_AT_declaration" || true)

$execs/dwz-for-test --odr 1

verify-dwarf.sh 1

for name in aaa bbb ccc; do
    cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*$name" || true)
    [ $cnt -eq 1 ]
done

for name in member_one member_two member_three member_four; do
    cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*$name" || true)
    [ $cnt -eq 1 ]
done

# We expect two decls to be removed, for bbb and ccc.
expected_decl_cnt=$(($decl_cnt - 2))
decl_cnt=$(readelf -wi 1 | grep -c "DW_AT_declaration" || true)
[ $expected_decl_cnt -eq $decl_cnt ]

rm -f 1
