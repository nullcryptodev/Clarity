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
  //  HMAC-SHA512 (RFC 2104)
  //
  //  Built on Crypto::Sha512, which is backed by Monocypher. Monocypher
  //  itself does not ship HMAC, so we implement it here.
  //
  //  Block size for SHA-512 is 128 bytes. Output is 64 bytes.
  //
  //  All functions are noexcept and never throw. They do not allocate
  //  on the heap.

  inline constexpr size_t HMAC_SHA512_BLOCK_SIZE = 128;
  inline constexpr size_t HMAC_SHA512_OUTPUT_SIZE = 64;

  // One-shot HMAC-SHA512. Writes 64 bytes to `out`.
  //
  // `key` may be any length. If longer than the block size it is first
  // hashed with SHA-512.
  void hmacSha512(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t out[HMAC_SHA512_OUTPUT_SIZE]) noexcept;

  inline void hmacSha512(std::string_view key, std::string_view msg,
                         uint8_t out[HMAC_SHA512_OUTPUT_SIZE]) noexcept
  {
    hmacSha512(reinterpret_cast<const uint8_t *>(key.data()), key.size(),
               reinterpret_cast<const uint8_t *>(msg.data()), msg.size(),
               out);
  }

  inline void hmacSha512(const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &msg,
                         uint8_t out[HMAC_SHA512_OUTPUT_SIZE]) noexcept
  {
    hmacSha512(key.data(), key.size(), msg.data(), msg.size(), out);
  }

  //  Streaming HMAC-SHA512
  //
  //  Supports incremental updates. Typical use:
  //
  //    HmacSha512 h(key, key_len);
  //    h.update(a, a_len);
  //    h.update(b, b_len);
  //    h.finalize(out);   // 64 bytes
  //
  //  finalize() may be called exactly once. After finalize() the object
  //  is in an unspecified state and must not be used again.

  class HmacSha512
  {
  public:
    HmacSha512(const uint8_t *key, size_t key_len) noexcept;
    ~HmacSha512() noexcept;

    HmacSha512(const HmacSha512 &) = delete;
    HmacSha512 &operator=(const HmacSha512 &) = delete;

    HmacSha512(HmacSha512 &&) noexcept;
    HmacSha512 &operator=(HmacSha512 &&) noexcept;

    void update(const uint8_t *data, size_t len) noexcept;
    void update(std::string_view s) noexcept;
    void update(const std::vector<uint8_t> &v) noexcept;

    // Writes 64 bytes to `out`. May be called exactly once.
    void finalize(uint8_t out[HMAC_SHA512_OUTPUT_SIZE]) noexcept;

  private:
    struct Impl;
    Impl *impl_;
  };

} // namespace Crypto