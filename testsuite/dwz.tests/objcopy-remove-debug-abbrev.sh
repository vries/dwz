objcopy --remove-section=.debug_abbrev $execs/hello 1

cp 1 1.saved

if dwz 1 2>dwz.err; status=$?; then
    true
fi

if ! grep -q "\.debug_abbrev not present" dwz.err; then
    cat dwz.err
    exit 1
fi

[ $status -eq 1 ]

cmp 1 1.saved

rm -f 1 1.saved dwz.err
