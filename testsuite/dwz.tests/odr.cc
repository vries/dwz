#if NAMESPACE
namespace ns {
#endif
  KIND bbb;
  KIND ccc {
    int member_three;
  };
#if NAMESPACE
}
#endif

#include "odr.h"

#if NAMESPACE
KIND ns::aaa var1;
#else
KIND aaa var1;
#endif

int
main (void)
{
  return 0;
}
