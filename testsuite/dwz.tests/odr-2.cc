#if NAMESPACE
namespace ns {
#endif
  KIND bbb
  {
    int member_four;
  };
  KIND ccc;
#if NAMESPACE
}
#endif
#include "odr.h"

#if NAMESPACE
KIND ns::aaa var2;
KIND ns::bbb var4;
#else
KIND aaa var2;
KIND bbb var4;
#endif
