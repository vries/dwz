struct bbb;
struct ccc {
  int member_three;
};

struct aaa
{
  struct bbb *member_one;
  struct ccc *member_two;
};

struct aaa var1;
struct ccc var3;

int
main (void)
{
  return 0;
}
