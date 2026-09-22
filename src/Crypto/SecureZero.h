// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>

namespace Crypto
{
  // Overwrites memory with zeros in a way the compiler cannot elide.
  // Use after any operation involving secret material.
  void secureZero(void *p, size_t n) noexcept;

  // Constant-time memory comparison.
  // Returns true iff the first n bytes are equal.
  // Timing depends only on n, not on the contents.
  bool constantTimeEq(const void *a, const void *b, size_t n) noexcept;

  // Convenience overload for fixed-size C arrays.
  template <size_t N>
  bool constantTimeEq(const unsigned char (&a)[N],
                      const unsigned char (&b)[N]) noexcept
  {
    return constantTimeEq(a, b, N);
  }
}