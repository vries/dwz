cp ../hello 1

objcopy --only-keep-debug 1 1.debug
objcopy --strip-debug 1 1.stripped

if ! eu-unstrip 1.stripped 1.debug -o 1.unstripped; then
    exit 77
fi
rm 1.unstripped

if dwz 1.debug 2> dwz.err; status=$?; then
    true
fi

if grep -q "dwz: Section overlap detected" dwz.err; then
    exit 77
fi

[ $status -eq 0 ]

version=$(eu-unstrip --version | head -n 1 | cut -d ' ' -f3)
major=$(echo $version | sed 's%\..*%%')
minor=$(echo $version | sed 's%.*\.%%')
if [ $major -gt 0 ] || [ $minor -ge 168 ]; then
    true
else
    exit 77
fi

eu-unstrip 1.stripped 1.debug -o 1.unstripped

# An unstripped exec can end up larger than the original (PR elfutils/24809).
#smaller-than.sh 1.unstripped 1

rm -f 1 1.debug 1.stripped 1.unstripped dwz.err
