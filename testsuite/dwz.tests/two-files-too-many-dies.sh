cp ../hello 1
cp 1 2
if dwz -L0 1 2 2>dwz.err; status=$?; then
    true
fi

if ! grep -q "Too many DIEs, not optimizing" dwz.err; then
    cat dwz.err
    exit 1
fi

if [ $status -eq 0 ]; then
    echo "PR24301 workaround used" > dwz.info
else
    [ $status -eq 1 ]
fi

cmp 1 ../hello
cmp 2 ../hello

rm -f 1 2 dwz.err
