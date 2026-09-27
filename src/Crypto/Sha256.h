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
  //  SHA-256 (FIPS 180-4)
  //
  //  Monocypher does not ship SHA-256; it ships SHA-512 (and Blake2b).
  //  We implement SHA-256 here from scratch. It's used by:
  //
  //    - BIP-39 mnemonic checksum    (Wallet/Bip39.cpp)
  //    - Future: various hash-based commitments, if the protocol ever
  //      needs SHA-256 for wire compatibility
  //
  //  It is NOT used by consensus, block hashing, transaction IDs, or
  //  state commitments. Those all use Blake2b (see Crypto/Blake2b.h).
  //
  //  The implementation is a direct transcription of the FIPS 180-4
  //  specification. It is verified against the NIST test vectors in
  //  Tests/Wallet/Sha256.cpp.

  inline constexpr size_t SHA256_BLOCK_SIZE = 64;
  inline constexpr size_t SHA256_OUTPUT_SIZE = 32;

  // One-shot SHA-256. Writes 32 bytes to `out`.
  void sha256(const uint8_t *in, size_t len,
              uint8_t out[SHA256_OUTPUT_SIZE]) noexcept;

  inline void sha256(std::string_view s,
                     uint8_t out[SHA256_OUTPUT_SIZE]) noexcept
  {
    sha256(reinterpret_cast<const uint8_t *>(s.data()), s.size(), out);
  }

  inline void sha256(const std::vector<uint8_t> &v,
                     uint8_t out[SHA256_OUTPUT_SIZE]) noexcept
  {
    sha256(v.data(), v.size(), out);
  }

  // Streaming SHA-256.
  //
  // Supports incremental updates. Typical use:
  //
  //   Sha256 h;
  //   h.update(a, a_len);
  //   h.update(b, b_len);
  //   h.finalize(out);   // 32 bytes, resets the hasher
  //
  // finalize() writes the digest and resets internal state so the
  // object can be reused for another message. This matches the
  // semantics of Crypto::Sha512.

  class Sha256
  {
  public:
    Sha256() noexcept;
    ~Sha256() noexcept;

    Sha256(const Sha256 &) = delete;
    Sha256 &operator=(const Sha256 &) = delete;

    Sha256(Sha256 &&) noexcept;
    Sha256 &operator=(Sha256 &&) noexcept;

    void update(const uint8_t *data, size_t len) noexcept;
    void update(std::string_view s) noexcept;
    void update(const std::vector<uint8_t> &v) noexcept;

    // Writes 32 bytes to `out` and resets the hasher for reuse.
    void finalize(uint8_t out[SHA256_OUTPUT_SIZE]) noexcept;

  private:
    struct Impl;
    Impl *impl_;
  };

} // namespace Crypto