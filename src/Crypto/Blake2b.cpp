// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Blake2b.h"

extern "C"
{
#include "monocypher.h"
}

namespace Crypto
{

  void blake2b(const uint8_t *in, size_t len,
               uint8_t *out, size_t outLen) noexcept
  {
    crypto_blake2b(out, outLen, in, len);
  }

} // namespace Crypto