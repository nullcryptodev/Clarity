// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Pbkdf2.h"
#include "SecureZero.h"

#include <cstring>

namespace Crypto
{
  namespace
  {
    // Big-endian 32-bit integer write. PBKDF2's block index is big-endian.
    inline void writeBe32(uint8_t *dst, uint32_t v) noexcept
    {
      dst[0] = uint8_t((v >> 24) & 0xFF);
      dst[1] = uint8_t((v >> 16) & 0xFF);
      dst[2] = uint8_t((v >> 8) & 0xFF);
      dst[3] = uint8_t(v & 0xFF);
    }
  } // namespace

  void pbkdf2HmacSha512(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations,
                        uint8_t *out, size_t out_len) noexcept
  {
    if (out_len == 0 || iterations == 0)
      return;

    // Each output block is HMAC_SHA512_OUTPUT_SIZE bytes.
    // T_i = U_1 xor U_2 xor ... xor U_c
    //   U_1 = PRF(password, salt || BE32(i))
    //   U_j = PRF(password, U_{j-1})
    uint8_t u[HMAC_SHA512_OUTPUT_SIZE];
    uint8_t t[HMAC_SHA512_OUTPUT_SIZE];

    const size_t full_blocks = out_len / HMAC_SHA512_OUTPUT_SIZE;
    const size_t tail_bytes = out_len % HMAC_SHA512_OUTPUT_SIZE;

    const size_t total_blocks = full_blocks + (tail_bytes > 0 ? 1 : 0);

    for (size_t block_idx = 1; block_idx <= total_blocks; ++block_idx)
    {
      // U_1 = HMAC(password, salt || BE32(block_idx))
      {
        HmacSha512 hmac(password, password_len);
        if (salt_len > 0)
          hmac.update(salt, salt_len);
        uint8_t be[4];
        writeBe32(be, uint32_t(block_idx));
        hmac.update(be, sizeof(be));
        hmac.finalize(u);
      }

      std::memcpy(t, u, sizeof(t));

      // U_2 .. U_c
      for (uint32_t iter = 1; iter < iterations; ++iter)
      {
        HmacSha512 hmac(password, password_len);
        hmac.update(u, sizeof(u));
        hmac.finalize(u);

        for (size_t i = 0; i < sizeof(t); ++i)
          t[i] ^= u[i];
      }

      // Copy T_i to the output.
      const size_t out_offset = (block_idx - 1) * HMAC_SHA512_OUTPUT_SIZE;
      const size_t remaining = out_len - out_offset;
      const size_t copy_len = remaining < sizeof(t) ? remaining : sizeof(t);
      std::memcpy(out + out_offset, t, copy_len);
    }

    Crypto::secureZero(u, sizeof(u));
    Crypto::secureZero(t, sizeof(t));
  }

  void pbkdf2Bip39(std::string_view mnemonic,
                   std::string_view passphrase,
                   uint8_t out[64]) noexcept
  {
    // Per BIP-39:
    //   password = NFKD(mnemonic sentence)
    //   salt     = "mnemonic" || NFKD(passphrase)
    //
    // For ASCII inputs (the only kind this codebase produces today),
    // NFKD is the identity. If a user ever supplies a non-ASCII
    // passphrase, a normalizer must be added here.
    static constexpr char kPrefix[] = "mnemonic";
    constexpr size_t kPrefixLen = sizeof(kPrefix) - 1; // exclude NUL

    const size_t salt_len = kPrefixLen + passphrase.size();

    if (salt_len <= 256)
    {
      // Stack path. Covers every realistic mnemonic + passphrase
      // combination (a 24-word English mnemonic is ~200 chars, and
      // passphrases are short by convention).
      uint8_t salt[256];
      std::memcpy(salt, kPrefix, kPrefixLen);
      if (!passphrase.empty())
      {
        std::memcpy(salt + kPrefixLen,
                    passphrase.data(),
                    passphrase.size());
      }

      pbkdf2HmacSha512(
          reinterpret_cast<const uint8_t *>(mnemonic.data()), mnemonic.size(),
          salt, salt_len,
          PBKDF2_BIP39_ITERATIONS,
          out, 64);

      Crypto::secureZero(salt, salt_len);
    }
    else
    {
      // Heap path. Only hit if the passphrase is absurdly long.
      std::vector<uint8_t> salt(salt_len);
      std::memcpy(salt.data(), kPrefix, kPrefixLen);
      if (!passphrase.empty())
      {
        std::memcpy(salt.data() + kPrefixLen,
                    passphrase.data(),
                    passphrase.size());
      }

      pbkdf2HmacSha512(
          reinterpret_cast<const uint8_t *>(mnemonic.data()), mnemonic.size(),
          salt.data(), salt.size(),
          PBKDF2_BIP39_ITERATIONS,
          out, 64);

      Crypto::secureZero(salt.data(), salt.size());
    }
  }

} // namespace Crypto