#include "Nonce.h"
#include "Crypto/Random.h"

namespace P2P
{

  uint64_t generateNetworkNonce()
  {
    uint64_t n = 0;
    Crypto::randomBytes(&n, sizeof(n));
    return n;
  }

} // namespace P2P