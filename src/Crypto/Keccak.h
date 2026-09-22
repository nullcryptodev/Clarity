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
  inline constexpr int KECCAK_ROUNDS = 24;
  inline constexpr size_t KECCAK_STATE_BYTES = 200;
  inline constexpr size_t KECCAK256_RATE = 136;

  // Low-level permutation. Exposed for advanced use only.
  void keccakf(uint64_t st[25], int rounds = KECCAK_ROUNDS) noexcept;

  // One-shot hashing.
  void keccak256(const uint8_t *in, size_t inlen, uint8_t out[32]) noexcept;
  void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]) noexcept;
  void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]) noexcept;

  // Generic core.
  int keccak(const uint8_t *in, size_t inlen,
             uint8_t *md, size_t mdlen,
             uint8_t padding = 0x01) noexcept;

  // Convenience overloads.
  inline void keccak256(std::string_view s, uint8_t out[32]) noexcept
  {
    keccak256(reinterpret_cast<const uint8_t *>(s.data()), s.size(), out);
  }

  inline void keccak256(const std::vector<uint8_t> &v, uint8_t out[32]) noexcept
  {
    keccak256(v.data(), v.size(), out);
  }
}