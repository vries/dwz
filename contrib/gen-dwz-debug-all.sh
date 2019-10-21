#!/bin/sh

outputfile=dwz.debug_all

echo "
  int
  main (void)
  {
    return 0;
  }
" \
    | gcc -x c - -c -o $outputfile

sections="
  debug_abbrev
  debug_info
  debug_line
  debug_macro
  debug_str
"

for section in $sections; do
    file=dwz.$section

    objcopy \
	--add-section .$section=$file \
       $outputfile
done
