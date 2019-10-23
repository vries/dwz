cp $execs/hello 1
cp $execs/hello 2

$execs/dwz-for-test --devel-save-temps -m 3 1 2

files="
  dwz.debug_abbrev
  dwz.debug_info
  dwz.debug_line
  dwz.debug_macro
  dwz.debug_str
  dwz.1
  dwz.2
"

for f in $files; do
    [ -f $f ]
done

rm -f 1 2 3 $files
