int
main (void)
{
  return 0;
}

int
foo (int i)
{
  int j;
  asm (".global foo_start_lbl\nfoo_start_lbl:");
  j = i *2;
  asm (".global foo_end_lbl\nfoo_end_lbl:");
  return j;
}

int
bar (int i)
{
  int j;
  asm (".global bar_start_lbl\nbar_start_lbl:");
  j = i *2;
  asm (".global bar_end_lbl\nbar_end_lbl:");
  return j;
}
