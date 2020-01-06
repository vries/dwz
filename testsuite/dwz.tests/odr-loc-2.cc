struct bbb
{
  int member_four;
};
struct ccc;

struct aaa
{
  struct bbb *member_one;
  struct ccc *member_two;
};

struct aaa var2;
