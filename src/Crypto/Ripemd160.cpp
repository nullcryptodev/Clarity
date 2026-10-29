// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Ripemd160.h"

#include <cstring>

namespace Crypto
{
  namespace
  {
    inline uint32_t rotl(uint32_t x, int n) noexcept
    {
      return (x << n) | (x >> (32 - n));
    }

    inline uint32_t f(int j, uint32_t x, uint32_t y, uint32_t z) noexcept
    {
      if (j < 16)
        return x ^ y ^ z;
      if (j < 32)
        return (x & y) | (~x & z);
      if (j < 48)
        return (x | ~y) ^ z;
      if (j < 64)
        return (x & z) | (y & ~z);
      return x ^ (y | ~z);
    }

    //  Message word order and rotation amounts, left and right
    //  lines, per the RIPEMD-160 spec.
    constexpr uint8_t RL[80] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};

    constexpr uint8_t RR[80] = {
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};

    constexpr uint8_t SL[80] = {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};

    constexpr uint8_t SR[80] = {
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

    constexpr uint32_t KL[5] = {0x00000000, 0x5A827999,
                                0x6ED9EBA1, 0x8F1BBCDC,
                                0xA953FD4E};
    constexpr uint32_t KR[5] = {0x50A28BE6, 0x5C4DD124,
                                0x6D703EF3, 0x7A6D76E9,
                                0x00000000};
  } // anonymous namespace

  Ripemd160::Ripemd160() noexcept { reset(); }

  void Ripemd160::reset() noexcept
  {
    h_[0] = 0x67452301;
    h_[1] = 0xEFCDAB89;
    h_[2] = 0x98BADCFE;
    h_[3] = 0x10325476;
    h_[4] = 0xC3D2E1F0;
    total_bits_ = 0;
    buffer_len_ = 0;
    std::memset(buffer_, 0, sizeof(buffer_));
  }

  void Ripemd160::processBlock(const uint8_t *block) noexcept
  {
    uint32_t X[16];
    for (int i = 0; i < 16; ++i)
    {
      X[i] = (uint32_t(block[i * 4])) |
             (uint32_t(block[i * 4 + 1]) << 8) |
             (uint32_t(block[i * 4 + 2]) << 16) |
             (uint32_t(block[i * 4 + 3]) << 24);
    }

    uint32_t al = h_[0], bl = h_[1], cl = h_[2], dl = h_[3], el = h_[4];
    uint32_t ar = h_[0], br = h_[1], cr = h_[2], dr = h_[3], er = h_[4];

    for (int j = 0; j < 80; ++j)
    {
      const int round = j / 16;

      //  Left line.
      uint32_t t = rotl(al + f(j, bl, cl, dl) + X[RL[j]] + KL[round], SL[j]) + el;
      al = el;
      el = dl;
      dl = rotl(cl, 10);
      cl = bl;
      bl = t;

      //  Right line.
      t = rotl(ar + f(79 - j, br, cr, dr) + X[RR[j]] + KR[round], SR[j]) + er;
      ar = er;
      er = dr;
      dr = rotl(cr, 10);
      cr = br;
      br = t;
    }

    const uint32_t t = h_[1] + cl + dr;
    h_[1] = h_[2] + dl + er;
    h_[2] = h_[3] + el + ar;
    h_[3] = h_[4] + al + br;
    h_[4] = h_[0] + bl + cr;
    h_[0] = t;
  }

  void Ripemd160::update(const uint8_t *data, size_t len) noexcept
  {
    if (data == nullptr || len == 0)
      return;

    total_bits_ += static_cast<uint64_t>(len) * 8;

    while (len > 0)
    {
      const size_t take = std::min<size_t>(len, 64 - buffer_len_);
      std::memcpy(buffer_ + buffer_len_, data, take);
      buffer_len_ += take;
      data += take;
      len -= take;

      if (buffer_len_ == 64)
      {
        processBlock(buffer_);
        buffer_len_ = 0;
      }
    }
  }

  void Ripemd160::finalize(uint8_t *out) noexcept
  {
    //  Padding: 0x80, zeros, then the 64-bit little-endian length.
    const uint64_t bits = total_bits_;
    buffer_[buffer_len_++] = 0x80;

    if (buffer_len_ > 56)
    {
      while (buffer_len_ < 64)
        buffer_[buffer_len_++] = 0x00;
      processBlock(buffer_);
      buffer_len_ = 0;
    }

    while (buffer_len_ < 56)
      buffer_[buffer_len_++] = 0x00;

    for (int i = 0; i < 8; ++i)
      buffer_[56 + i] = uint8_t(bits >> (8 * i));

    processBlock(buffer_);

    for (int i = 0; i < 5; ++i)
    {
      out[i * 4 + 0] = uint8_t(h_[i]);
      out[i * 4 + 1] = uint8_t(h_[i] >> 8);
      out[i * 4 + 2] = uint8_t(h_[i] >> 16);
      out[i * 4 + 3] = uint8_t(h_[i] >> 24);
    }

    reset();
  }

  void Ripemd160::hash(const uint8_t *data, size_t len,
                       uint8_t *out) noexcept
  {
    Ripemd160 h;
    h.update(data, len);
    h.finalize(out);
  }
} // namespace Crypto