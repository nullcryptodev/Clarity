// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Hex.h"

namespace Bridge::BridgeHex
{
  namespace
  {
    int nib(char c)
    {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return -1;
    }
  } // anonymous namespace

  std::optional<std::vector<uint8_t>> Decode(const std::string &s)
  {
    size_t start = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
      start = 2;

    const size_t n = s.size() - start;
    if (n == 0 || (n & 1) != 0)
      return std::nullopt;

    std::vector<uint8_t> out;
    out.reserve(n / 2);
    for (size_t i = start; i < s.size(); i += 2)
    {
      const int hi = nib(s[i]);
      const int lo = nib(s[i + 1]);
      if (hi < 0 || lo < 0)
        return std::nullopt;
      out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
  }

  std::string Encode(const uint8_t *data, size_t len)
  {
    static const char HEX[] = "0123456789abcdef";
    std::string out = "0x";
    out.reserve(2 + len * 2);
    for (size_t i = 0; i < len; ++i)
    {
      out.push_back(HEX[data[i] >> 4]);
      out.push_back(HEX[data[i] & 0xF]);
    }
    return out;
  }

  std::string Encode(const std::vector<uint8_t> &bytes)
  {
    return Encode(bytes.data(), bytes.size());
  }

  std::string EncodeU64Hex(uint64_t v)
  {
    static const char HEX[] = "0123456789abcdef";
    std::string out = "0x";
    if (v == 0)
    {
      out.push_back('0');
      return out;
    }
    bool started = false;
    for (int i = 15; i >= 0; --i)
    {
      uint8_t n = uint8_t((v >> (i * 4)) & 0xF);
      if (!started && n == 0)
        continue;
      started = true;
      out.push_back(HEX[n]);
    }
    return out;
  }

  std::string EncodeU32Hex(uint32_t v)
  {
    return EncodeU64Hex(v);
  }

  std::optional<uint64_t> DecodeU64Hex(const std::string &s)
  {
    size_t start = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
      start = 2;
    if (start >= s.size())
      return std::nullopt;

    uint64_t v = 0;
    for (size_t i = start; i < s.size(); ++i)
    {
      const int n = nib(s[i]);
      if (n < 0)
        return std::nullopt;
      if (v > (UINT64_MAX >> 4))
        return std::nullopt;
      v = (v << 4) | uint64_t(n);
    }
    return v;
  }
} // namespace Bridge::BridgeHex