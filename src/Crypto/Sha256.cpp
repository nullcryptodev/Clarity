// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Sha256.h"
#include "SecureZero.h"

#include <cstring>

namespace Crypto
{
  namespace
  {
    // FIPS 180-4 §4.2.2 — SHA-256 round constants.
    // First 32 bits of the fractional parts of the cube roots of the
    // first 64 primes (2 through 311).
    constexpr uint32_t K[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
        0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
        0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
        0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
        0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
        0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
        0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
        0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
        0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
        0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
        0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
        0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
        0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

    // FIPS 180-4 §5.3.3 — initial hash value H(0).
    // First 32 bits of the fractional parts of the square roots of the
    // first 8 primes (2 through 19).
    constexpr uint32_t H0[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};

    // Rotate right.
    inline uint32_t rotr(uint32_t x, unsigned n) noexcept
    {
      return (x >> n) | (x << (32 - n));
    }

    // SHA-256 functions from FIPS 180-4 §4.1.2.
    inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) noexcept
    {
      return (x & y) ^ (~x & z);
    }
    inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) noexcept
    {
      return (x & y) ^ (x & z) ^ (y & z);
    }
    inline uint32_t bsig0(uint32_t x) noexcept
    {
      return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    inline uint32_t bsig1(uint32_t x) noexcept
    {
      return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    inline uint32_t ssig0(uint32_t x) noexcept
    {
      return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    inline uint32_t ssig1(uint32_t x) noexcept
    {
      return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    // Big-endian load/store. SHA-256 operates on big-endian words.
    inline uint32_t loadBe32(const uint8_t *p) noexcept
    {
      return (uint32_t(p[0]) << 24) |
             (uint32_t(p[1]) << 16) |
             (uint32_t(p[2]) << 8) |
             (uint32_t(p[3]));
    }

    inline void storeBe32(uint8_t *p, uint32_t v) noexcept
    {
      p[0] = uint8_t(v >> 24);
      p[1] = uint8_t(v >> 16);
      p[2] = uint8_t(v >> 8);
      p[3] = uint8_t(v);
    }

    // The compression function. Consumes one 64-byte block, updates
    // the 8-word state in place.
    void compress(uint32_t state[8], const uint8_t block[64]) noexcept
    {
      uint32_t w[64];

      // Message schedule.
      for (int i = 0; i < 16; ++i)
        w[i] = loadBe32(block + i * 4);
      for (int i = 16; i < 64; ++i)
        w[i] = ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) + w[i - 16];

      uint32_t a = state[0];
      uint32_t b = state[1];
      uint32_t c = state[2];
      uint32_t d = state[3];
      uint32_t e = state[4];
      uint32_t f = state[5];
      uint32_t g = state[6];
      uint32_t h = state[7];

      for (int i = 0; i < 64; ++i)
      {
        const uint32_t t1 = h + bsig1(e) + ch(e, f, g) + K[i] + w[i];
        const uint32_t t2 = bsig0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
      }

      state[0] += a;
      state[1] += b;
      state[2] += c;
      state[3] += d;
      state[4] += e;
      state[5] += f;
      state[6] += g;
      state[7] += h;

      secureZero(w, sizeof(w));
    }
  } // namespace

  //  One-shot

  void sha256(const uint8_t *in, size_t len,
              uint8_t out[SHA256_OUTPUT_SIZE]) noexcept
  {
    Sha256 h;
    h.update(in, len);
    h.finalize(out);
  }

  //  Streaming

  struct Sha256::Impl
  {
    uint32_t state[8];
    uint8_t buffer[SHA256_BLOCK_SIZE];
    uint64_t total_bits; // message length in bits (per FIPS 180-4)
    size_t buffered;     // bytes currently in `buffer`
  };

  Sha256::Sha256() noexcept
      : impl_(new Impl)
  {
    for (int i = 0; i < 8; ++i)
      impl_->state[i] = H0[i];
    std::memset(impl_->buffer, 0, sizeof(impl_->buffer));
    impl_->total_bits = 0;
    impl_->buffered = 0;
  }

  Sha256::~Sha256() noexcept
  {
    if (impl_)
    {
      Crypto::secureZero(impl_->state, sizeof(impl_->state));
      Crypto::secureZero(impl_->buffer, sizeof(impl_->buffer));
      delete impl_;
      impl_ = nullptr;
    }
  }

  Sha256::Sha256(Sha256 &&o) noexcept
      : impl_(o.impl_)
  {
    o.impl_ = nullptr;
  }

  Sha256 &Sha256::operator=(Sha256 &&o) noexcept
  {
    if (this != &o)
    {
      if (impl_)
      {
        Crypto::secureZero(impl_->state, sizeof(impl_->state));
        Crypto::secureZero(impl_->buffer, sizeof(impl_->buffer));
        delete impl_;
      }
      impl_ = o.impl_;
      o.impl_ = nullptr;
    }
    return *this;
  }

  void Sha256::update(const uint8_t *data, size_t len) noexcept
  {
    if (!impl_ || len == 0)
      return;

    impl_->total_bits += uint64_t(len) * 8;

    // Fill the buffer if we have partial data.
    if (impl_->buffered > 0)
    {
      const size_t need = SHA256_BLOCK_SIZE - impl_->buffered;
      const size_t take = (len < need) ? len : need;
      std::memcpy(impl_->buffer + impl_->buffered, data, take);
      impl_->buffered += take;
      data += take;
      len -= take;

      if (impl_->buffered == SHA256_BLOCK_SIZE)
      {
        compress(impl_->state, impl_->buffer);
        impl_->buffered = 0;
      }
      else
      {
        return; // still not a full block
      }
    }

    // Process full blocks directly from the input.
    while (len >= SHA256_BLOCK_SIZE)
    {
      compress(impl_->state, data);
      data += SHA256_BLOCK_SIZE;
      len -= SHA256_BLOCK_SIZE;
    }

    // Buffer the tail.
    if (len > 0)
    {
      std::memcpy(impl_->buffer, data, len);
      impl_->buffered = len;
    }
  }

  void Sha256::update(std::string_view s) noexcept
  {
    update(reinterpret_cast<const uint8_t *>(s.data()), s.size());
  }

  void Sha256::update(const std::vector<uint8_t> &v) noexcept
  {
    update(v.data(), v.size());
  }

  void Sha256::finalize(uint8_t out[SHA256_OUTPUT_SIZE]) noexcept
  {
    if (!impl_)
    {
      std::memset(out, 0, SHA256_OUTPUT_SIZE);
      return;
    }

    // FIPS 180-4 §5.1.1 padding:
    //   1. Append a single '1' bit.
    //   2. Append '0' bits until the length is 448 mod 512.
    //   3. Append the original length as a 64-bit big-endian integer.
    //
    // In bytes: append 0x80, then zeros, then the 8-byte length.

    const uint64_t total_bits = impl_->total_bits;

    // Append 0x80.
    impl_->buffer[impl_->buffered++] = 0x80;

    // If we don't have room for the 8-byte length in this block,
    // pad with zeros to the end of the block, compress, and start a
    // fresh block for the length.
    if (impl_->buffered > SHA256_BLOCK_SIZE - 8)
    {
      std::memset(impl_->buffer + impl_->buffered, 0,
                  SHA256_BLOCK_SIZE - impl_->buffered);
      compress(impl_->state, impl_->buffer);
      impl_->buffered = 0;
    }

    // Pad with zeros up to the length field.
    std::memset(impl_->buffer + impl_->buffered, 0,
                SHA256_BLOCK_SIZE - 8 - impl_->buffered);

    // Append the message length in bits, big-endian.
    storeBe32(impl_->buffer + SHA256_BLOCK_SIZE - 8,
              uint32_t(total_bits >> 32));
    storeBe32(impl_->buffer + SHA256_BLOCK_SIZE - 4,
              uint32_t(total_bits & 0xFFFFFFFFu));

    compress(impl_->state, impl_->buffer);

    // Write the digest.
    for (int i = 0; i < 8; ++i)
      storeBe32(out + i * 4, impl_->state[i]);

    // Reset for reuse.
    for (int i = 0; i < 8; ++i)
      impl_->state[i] = H0[i];
    impl_->total_bits = 0;
    impl_->buffered = 0;
    std::memset(impl_->buffer, 0, sizeof(impl_->buffer));
  }

} // namespace Crypto