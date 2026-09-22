// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SecureZero.h"

namespace Crypto
{

  void secureZero(void *p, size_t n) noexcept
  {
    // volatile prevents the compiler from optimizing away the writes.
    volatile unsigned char *vp = static_cast<volatile unsigned char *>(p);
    while (n--)
      *vp++ = 0;
  }

  bool constantTimeEq(const void *a, const void *b, size_t n) noexcept
  {
    const unsigned char *pa = static_cast<const unsigned char *>(a);
    const unsigned char *pb = static_cast<const unsigned char *>(b);
    unsigned char diff = 0;
    for (size_t i = 0; i < n; ++i)
    {
      diff |= pa[i] ^ pb[i];
    }
    return diff == 0;
  }

} // namespace Crypto