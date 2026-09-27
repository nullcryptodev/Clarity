// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Argon2id.h"

#include <cstring>

extern "C"
{
#include "argon2.h"
}

namespace Crypto
{
  bool argon2id(const uint8_t *password, size_t password_len,
                const uint8_t *salt, size_t salt_len,
                const Argon2Params &params,
                uint8_t *out, size_t out_len) noexcept
  {
    if (!params.valid())
      return false;
    if (out == nullptr || out_len == 0)
      return false;
    if (salt == nullptr || salt_len == 0)
      return false;
    // Password may be empty (allowed by RFC 9106), but the pointer must
    // be non-null when length > 0.
    if (password == nullptr && password_len > 0)
      return false;

    // RFC 9106 limits:
    //   out_len in [4, 2^32 - 1]
    //   salt_len in [8, 2^32 - 1] for keyed hashing (we enforce >= 8)
    //   password_len in [0, 2^32 - 1]
    if (out_len < 4)
      return false;
    if (salt_len < 8)
      return false;

    // argon2id_hash_raw(t_cost, m_cost, parallelism,
    //                   pwd, pwdlen, salt, saltlen,
    //                   hash, hashlen)
    int rc = argon2id_hash_raw(
        params.t_cost,
        params.m_cost_kib,
        params.p_cost,
        password, password_len,
        salt, salt_len,
        out, out_len);

    return rc == ARGON2_OK;
  }

} // namespace Crypto