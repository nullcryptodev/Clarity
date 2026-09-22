// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>

namespace Crypto
{
  // Fill `buf` with `len` cryptographically secure random bytes.
  // Returns true on success, false on failure (RNG unavailable).
  bool randomBytes(void *buf, size_t len) noexcept;

  // Convenience overload for fixed-size C arrays.
  template <size_t N>
  bool randomBytes(unsigned char (&buf)[N]) noexcept
  {
    return randomBytes(buf, N);
  }

  // Uniform random integer in [0, bound).
  // Returns 0 if bound == 0. Uses rejection sampling to avoid modulo bias.
  uint64_t randomUniform(uint64_t bound) noexcept;
}