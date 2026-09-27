// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

namespace Crypto
{
  //  Argon2id (RFC 9106)
  //
  //  Memory-hard password-based key derivation. Used as the default
  //  KDF in the CLRTY keystore format.
  //
  //  The reference implementation (phc-winner-argon2, CC0 / Apache-2.0
  //  dual-licensed) is vendored as `argon2_ref.c` / `argon2_ref.h` and
  //  called from `Argon2id.cpp`. We only expose Argon2id here, not the
  //  i/d variants, since id is the recommended default for password
  //  hashing and key derivation.
  //
  //  Parameter guidance for interactive keystore unlock:
  //    m_cost_kib = 65536   (64 MiB)
  //    t_cost     = 3
  //    p_cost     = 4       (or number of available cores)
  //
  //  These are the defaults below. They target ~100-300 ms on a modern
  //  desktop CPU, which is the standard tradeoff for wallet unlock.

  struct Argon2Params
  {
    // Memory cost in kibibytes (1024 bytes). Minimum 8 KiB, no hard max
    // but practical limits apply. Must satisfy m_cost_kib >= 8 * p_cost.
    uint32_t m_cost_kib{65536};

    // Number of passes over memory. Minimum 1.
    uint32_t t_cost{3};

    // Parallelism (number of lanes). Minimum 1, typically 1-16.
    uint32_t p_cost{4};

    // Validate parameter consistency. Returns false if any parameter is
    // out of range or the memory/lane relationship is violated.
    bool valid() const noexcept
    {
      if (m_cost_kib < 8)
        return false;
      if (t_cost < 1)
        return false;
      if (p_cost < 1)
        return false;
      if (m_cost_kib < 8u * p_cost)
        return false;
      return true;
    }
  };

  // Derive `out_len` bytes from `password` and `salt` using Argon2id.
  //
  // `out_len` must be between 4 and 2^32 - 1. In practice we use 32.
  // `salt` should be at least 8 bytes; we recommend 16.
  //
  // Returns true on success, false if parameters are invalid or the
  // underlying implementation reports an error (e.g. out of memory).
  bool argon2id(const uint8_t *password, size_t password_len,
                const uint8_t *salt, size_t salt_len,
                const Argon2Params &params,
                uint8_t *out, size_t out_len) noexcept;

  // Convenience: string_view inputs, vector output.
  inline bool argon2id(std::string_view password,
                       std::string_view salt,
                       const Argon2Params &params,
                       std::vector<uint8_t> &out,
                       size_t out_len = 32) noexcept
  {
    out.resize(out_len);
    return argon2id(
        reinterpret_cast<const uint8_t *>(password.data()), password.size(),
        reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
        params, out.data(), out.size());
  }

} // namespace Crypto