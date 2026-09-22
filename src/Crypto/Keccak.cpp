// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Keccak.h"

#include <cstring>

namespace Crypto
{
  namespace
  {
    constexpr uint64_t RC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
        0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
        0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
        0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
        0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
        0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
        0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};

    constexpr int ROT[24] = {
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};

    constexpr int PIL[24] = {
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

    inline uint64_t load64le(const uint8_t *p) noexcept
    {
      uint64_t v;
      std::memcpy(&v, p, sizeof(v));
      return v;
    }

    inline void store64le(uint8_t *p, uint64_t v) noexcept
    {
      std::memcpy(p, &v, sizeof(v));
    }

    inline uint64_t rotl64(uint64_t x, int n) noexcept
    {
      return n == 0 ? x : (x << n) | (x >> (64 - n));
    }
  } // anonymous namespace

  void keccakf(uint64_t st[25], int rounds) noexcept
  {
    for (int round = 0; round < rounds; ++round)
    {
      // Theta
      uint64_t bc[5];
      for (int i = 0; i < 5; ++i)
      {
        bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
      }
      for (int i = 0; i < 5; ++i)
      {
        uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
        for (int j = 0; j < 25; j += 5)
          st[j + i] ^= t;
      }

      // Rho + Pi
      uint64_t t = st[1];
      for (int i = 0; i < 24; ++i)
      {
        int j = PIL[i];
        uint64_t tmp = st[j];
        st[j] = rotl64(t, ROT[i]);
        t = tmp;
      }

      // Chi
      for (int j = 0; j < 25; j += 5)
      {
        for (int i = 0; i < 5; ++i)
          bc[i] = st[j + i];
        for (int i = 0; i < 5; ++i)
        {
          st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }
      }

      // Iota
      st[0] ^= RC[round];
    }
  }

  namespace
  {
    inline void absorb_block(uint64_t st[25], const uint8_t *block, size_t rate) noexcept
    {
      const size_t words = rate / 8;
      for (size_t i = 0; i < words; ++i)
      {
        st[i] ^= load64le(block + i * 8);
      }
      keccakf(st);
    }

    int keccak_sponge(const uint8_t *in, size_t inlen,
                      uint8_t *out, size_t outlen,
                      uint8_t padding) noexcept
    {
      if (out == nullptr || outlen == 0 || outlen > 64)
        return -1;

      const size_t rate = 200 - 2 * outlen;
      uint64_t st[25] = {0};

      // Absorb full blocks
      size_t offset = 0;
      while (inlen - offset >= rate)
      {
        absorb_block(st, in + offset, rate);
        offset += rate;
      }

      // Absorb final partial block with padding
      uint8_t last[200] = {0};
      size_t remaining = inlen - offset;
      if (remaining > 0)
        std::memcpy(last, in + offset, remaining);
      last[remaining] = padding;
      last[rate - 1] |= 0x80;

      absorb_block(st, last, rate);

      // Squeeze
      size_t produced = 0;
      while (produced < outlen)
      {
        size_t chunk = (rate < outlen - produced) ? rate : (outlen - produced);
        uint8_t tmp[200];
        for (size_t i = 0; i < rate / 8; ++i)
        {
          store64le(tmp + i * 8, st[i]);
        }
        std::memcpy(out + produced, tmp, chunk);
        produced += chunk;
        if (produced < outlen)
          keccakf(st);
      }

      return 0;
    }
  } // anonymous namespace

  int keccak(const uint8_t *in, size_t inlen,
             uint8_t *md, size_t mdlen,
             uint8_t padding) noexcept
  {
    return keccak_sponge(in, inlen, md, mdlen, padding);
  }

  void keccak256(const uint8_t *in, size_t inlen, uint8_t out[32]) noexcept
  {
    keccak_sponge(in, inlen, out, 32, 0x01);
  }

  void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]) noexcept
  {
    keccak_sponge(in, inlen, out, 32, 0x06);
  }

  void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]) noexcept
  {
    keccak_sponge(in, inlen, out, 64, 0x06);
  }

} // namespace Crypto