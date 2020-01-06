if ! $execs/dwz-for-test --odr -v 2>/dev/null; then
    exit 77
fi

cp $execs/odr-loc 1

for name in aaa bbb ccc; do
    cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*$name" || true)
    [ $cnt -eq 2 ]
done

$execs/dwz-for-test --odr 1

verify-dwarf.sh 1

for name in aaa bbb ccc; do
    cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*$name" || true)
    case $name in
	aaa)
	    [ $cnt -eq 2 ]
	    ;;
	*)
	    [ $cnt -eq 1 ]
	    ;;
    esac
done

cp $execs/odr-loc 1

$execs/dwz-for-test --odr --devel-ignore-locus 1

verify-dwarf.sh 1

for name in aaa bbb ccc; do
    cnt=$(readelf -wi 1 | grep -c "DW_AT_name.*:.*$name" || true)
    [ $cnt -eq 1 ]
done

rm -f 1
