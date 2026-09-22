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
  // One-shot SHA-512.
  void sha512(const uint8_t *in, size_t len, uint8_t out[64]) noexcept;

  inline void sha512(std::string_view s, uint8_t out[64]) noexcept
  {
    sha512(reinterpret_cast<const uint8_t *>(s.data()), s.size(), out);
  }

  // Streaming SHA-512.
  class Sha512
  {
  public:
    Sha512() noexcept;
    ~Sha512() noexcept;

    Sha512(const Sha512 &) = delete;
    Sha512 &operator=(const Sha512 &) = delete;

    Sha512(Sha512 &&) noexcept;
    Sha512 &operator=(Sha512 &&) noexcept;

    void update(const uint8_t *data, size_t len) noexcept;
    void update(std::string_view s) noexcept;
    void update(const std::vector<uint8_t> &v) noexcept;

    // Writes 64 bytes to `out` and resets the hasher for reuse.
    void finalize(uint8_t out[64]) noexcept;

  private:
    // Opaque Monocypher context. Defined in the .cpp.
    struct Impl;
    Impl *impl_;
  };
}