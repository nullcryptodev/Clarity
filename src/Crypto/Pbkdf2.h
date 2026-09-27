// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "Hmac.h"

namespace Crypto
{
  //  PBKDF2-HMAC-SHA512 (RFC 2898 / RFC 8018)
  //
  //  Used by:
  //    - BIP-39 mnemonic -> seed  (2048 iterations, salt = "mnemonic" + passphrase)
  //    - Keystore KDF fallback    (higher iteration count, random salt)
  //
  //  Output length may be any positive value up to 2^32 - 1 HMAC outputs.
  //  In practice we use 64 bytes (BIP-39) and 32 bytes (keystore).

  inline constexpr uint32_t PBKDF2_BIP39_ITERATIONS = 2048;

  // BIP-39 specific: derive a 64-byte seed from a mnemonic sentence and
  // an optional passphrase. The passphrase may be empty.
  //
  // Per the spec:
  //   salt     = "mnemonic" || passphrase
  //   password = NFKD(mnemonic sentence)
  //
  // Note: BIP-39 specifies NFKD Unicode normalization on both sides.
  // For ASCII mnemonics (the only kind this codebase produces) NFKD is
  // the identity, so we skip the normalization step. If you ever accept
  // user-supplied mnemonics with non-ASCII characters, add a normalizer
  // here.
  void pbkdf2Bip39(std::string_view mnemonic,
                   std::string_view passphrase,
                   uint8_t out[64]) noexcept;

  // Generic PBKDF2-HMAC-SHA512.
  //
  // `out_len` may be any value from 1 to 2^32 - 1. Writes exactly
  // `out_len` bytes to `out`. `iterations` must be >= 1.
  //
  // The caller owns `out` and must size it correctly.
  void pbkdf2HmacSha512(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t *out, size_t out_len) noexcept;

  inline void pbkdf2HmacSha512(std::string_view password,
                               std::string_view salt,
                               uint32_t iterations,
                               uint8_t *out, size_t out_len) noexcept
  {
    pbkdf2HmacSha512(
        reinterpret_cast<const uint8_t *>(password.data()), password.size(),
        reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
        iterations, out, out_len);
  }

  inline std::vector<uint8_t> pbkdf2HmacSha512(const std::vector<uint8_t> &password,
                                               const std::vector<uint8_t> &salt,
                                               uint32_t iterations,
                                               size_t out_len)
  {
    std::vector<uint8_t> out(out_len);
    pbkdf2HmacSha512(password.data(), password.size(),
                     salt.data(), salt.size(),
                     iterations, out.data(), out.size());
    return out;
  }

} // namespace Crypto