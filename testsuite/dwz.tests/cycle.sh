readelf_flags=""
if readelf -h 2>&1 | grep -q "\-wN,"; then
    readelf_flags=-wN
fi

cp $execs/cycle 1

# Using mode 3 in checksum_die_ref.
$execs/dwz-for-test 1 -o 1.z --devel-dump-dies 2> DUMP.1
rm -f 1.z

# Skipping mode 3 in checksum_die_ref.
$execs/dwz-for-test 1 -o 1.z --devel-dump-dies --devel-no-checksum-cycle-opt 2> DUMP.2
rm -f 1.z

# Verify that mode 3 and mode 4 have different checksums.
grep " s structure_type" DUMP.1 > LINE.1
grep " s structure_type" DUMP.2 > LINE.2
! diff -q LINE.1 LINE.2
rm -f DUMP.1 DUMP.2 LINE.1 LINE.2

# Verify that dwz actually works with --devel-no-checksum-cycle-opt.
cp 1 2
$execs/dwz-for-test -m 3 1 2 --devel-no-checksum-cycle-opt --devel-ignore-size

cnt=$(readelf -wi 3 | grep -c "DW_AT_name.*: s$")
[ $cnt -eq 1 ]

cnt=$(readelf -wi $readelf_flags 1 | grep -c "DW_AT_name.*: s$" || true)
[ $cnt -eq 0 ]

rm -f 1 2 3
