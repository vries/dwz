exec=$execs/testsuite/dwz.tests/execs/hello-leap-15.0

cp $exec 1
cp 1 2

dwz -m 3 1 2

readelf -w 1 > READELF 2>/dev/null

offsets=$(grep '(DW_TAG_partial_unit' READELF \
	      | awk '{print $1}' \
	      | sed 's/.*<//;s/>.*//')
for off in $offsets; do
    imports=$(grep -c "DW_AT_import.*0x$off" READELF || true)
    [ $imports -gt 0 ]
done

rm -f 1 2 3 READELF
