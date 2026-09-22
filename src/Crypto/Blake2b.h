// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace Crypto
{
  // One-shot Blake2b with configurable output length (1..64).
  void blake2b(const uint8_t *in, size_t len,
               uint8_t *out, size_t outLen) noexcept;

  // Convenience: 32-byte output.
  inline void blake2b(const uint8_t *in, size_t len, uint8_t out[32]) noexcept
  {
    blake2b(in, len, out, 32);
  }

  inline void blake2b(std::string_view s, uint8_t out[32]) noexcept
  {
    blake2b(reinterpret_cast<const uint8_t *>(s.data()), s.size(), out, 32);
  }
}