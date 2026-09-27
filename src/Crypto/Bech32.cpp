// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Bech32.h"

#include <cstring>

namespace Crypto
{
  namespace
  {
    // Bech32 character set. Index in this table is the 5-bit value.
    constexpr char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // Reverse lookup: ASCII -> 5-bit value, or -1 if not in charset.
    // Built at compile time.
    struct CharsetRev
    {
      int8_t map[128];
      constexpr CharsetRev() : map{}
      {
        for (int i = 0; i < 128; ++i)
          map[i] = -1;
        for (int i = 0; i < 32; ++i)
          map[static_cast<uint8_t>(CHARSET[i])] = static_cast<int8_t>(i);
      }
    };
    constexpr CharsetRev CHARSET_REV{};

    // Generator polynomial constants for the two checksum variants.
    constexpr uint32_t BECH32_CONST = 1u;
    constexpr uint32_t BECH32M_CONST = 0x2bc830a3u;

    uint32_t polymod(const std::vector<uint8_t> &values) noexcept
    {
      static constexpr uint32_t GEN[5] = {
          0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};

      uint32_t chk = 1;
      for (uint8_t v : values)
      {
        const uint8_t top = static_cast<uint8_t>(chk >> 25);
        chk = ((chk & 0x1ffffffu) << 5) ^ v;
        for (int i = 0; i < 5; ++i)
        {
          if ((top >> i) & 1u)
            chk ^= GEN[i];
        }
      }
      return chk;
    }

    std::vector<uint8_t> hrpExpand(std::string_view hrp)
    {
      std::vector<uint8_t> out;
      out.reserve(hrp.size() * 2 + 1);
      for (char c : hrp)
        out.push_back(static_cast<uint8_t>(c) >> 5);
      out.push_back(0);
      for (char c : hrp)
        out.push_back(static_cast<uint8_t>(c) & 0x1f);
      return out;
    }

    uint32_t checksumConst(Bech32Encoding encoding) noexcept
    {
      return encoding == Bech32Encoding::Bech32m ? BECH32M_CONST : BECH32_CONST;
    }

    bool validHrpChar(char c) noexcept
    {
      return c >= 33 && c <= 126;
    }

    bool hasLower(std::string_view s) noexcept
    {
      for (char c : s)
        if (c >= 'a' && c <= 'z')
          return true;
      return false;
    }

    bool hasUpper(std::string_view s) noexcept
    {
      for (char c : s)
        if (c >= 'A' && c <= 'Z')
          return true;
      return false;
    }
  } // namespace

  const char *bech32ErrorName(Bech32Error e) noexcept
  {
    switch (e)
    {
    case Bech32Error::Ok:
      return "Ok";
    case Bech32Error::Empty:
      return "Empty";
    case Bech32Error::TooLong:
      return "TooLong";
    case Bech32Error::InvalidHrpLength:
      return "InvalidHrpLength";
    case Bech32Error::InvalidHrpCharacter:
      return "InvalidHrpCharacter";
    case Bech32Error::MixedCase:
      return "MixedCase";
    case Bech32Error::NoSeparator:
      return "NoSeparator";
    case Bech32Error::InvalidDataCharacter:
      return "InvalidDataCharacter";
    case Bech32Error::ChecksumMismatch:
      return "ChecksumMismatch";
    case Bech32Error::InvalidPadding:
      return "InvalidPadding";
    }
    return "Unknown";
  }

  //  5-bit conversion

  bool convertBitsTo5(const uint8_t *in, size_t in_len,
                      std::vector<uint8_t> &out,
                      bool pad) noexcept
  {
    out.clear();
    if (in_len == 0)
      return true;
    out.reserve((in_len * 8 + 4) / 5);

    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; ++i)
    {
      acc = (acc << 8) | in[i];
      bits += 8;
      while (bits >= 5)
      {
        bits -= 5;
        out.push_back(static_cast<uint8_t>((acc >> bits) & 0x1f));
      }
    }
    if (bits > 0)
    {
      if (pad)
      {
        out.push_back(static_cast<uint8_t>((acc << (5 - bits)) & 0x1f));
      }
      else
      {
        if ((acc & ((1u << bits) - 1u)) != 0)
          return false;
      }
    }
    return true;
  }

  bool convertBitsFrom5(const uint8_t *in, size_t in_len,
                        std::vector<uint8_t> &out,
                        bool pad) noexcept
  {
    out.clear();
    if (in_len == 0)
      return true;
    out.reserve((in_len * 5) / 8);

    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < in_len; ++i)
    {
      const uint8_t v = in[i];
      if (v > 31)
        return false;
      acc = (acc << 5) | v;
      bits += 5;
      while (bits >= 8)
      {
        bits -= 8;
        out.push_back(static_cast<uint8_t>((acc >> bits) & 0xff));
      }
    }
    if (bits > 0)
    {
      if (pad)
      {
        out.push_back(static_cast<uint8_t>((acc << (8 - bits)) & 0xff));
      }
      else
      {
        // Strict mode. Two failure cases:
        //   1. Leftover bits are non-zero  -> non-canonical padding.
        //   2. Leftover bits >= 5          -> would decode to more
        //      than one additional byte, which the spec forbids.
        if ((acc & ((1u << bits) - 1u)) != 0)
          return false;
        if (bits >= 5)
          return false;
      }
    }
    return true;
  }

  //  Encode

  std::string bech32Encode(std::string_view hrp,
                           const std::vector<uint8_t> &data,
                           Bech32Encoding encoding)
  {
    if (hrp.empty() || hrp.size() > BECH32_MAX_HRP_LENGTH)
      return {};
    for (char c : hrp)
      if (!validHrpChar(c))
        return {};

    std::vector<uint8_t> data5;
    if (!convertBitsTo5(data.data(), data.size(), data5, /*pad=*/true))
      return {};

    const size_t total_len =
        hrp.size() + 1 + data5.size() + BECH32_CHECKSUM_LENGTH;
    if (total_len > BECH32_MAX_LENGTH)
      return {};

    // Compute checksum over hrpExpand(hrp) || data5 || [0,0,0,0,0,0].
    std::vector<uint8_t> values = hrpExpand(hrp);
    values.insert(values.end(), data5.begin(), data5.end());
    for (size_t i = 0; i < BECH32_CHECKSUM_LENGTH; ++i)
      values.push_back(0);

    const uint32_t polymod_val = polymod(values) ^ checksumConst(encoding);

    std::string out;
    out.reserve(total_len);
    out.append(hrp.data(), hrp.size());
    out.push_back('1');
    for (uint8_t v : data5)
      out.push_back(CHARSET[v]);
    for (int i = 0; i < 6; ++i)
    {
      const uint8_t v =
          static_cast<uint8_t>((polymod_val >> (5 * (5 - i))) & 0x1f);
      out.push_back(CHARSET[v]);
    }
    return out;
  }

  //  Decode

  Bech32Error bech32Decode(std::string_view input,
                           std::vector<uint8_t> &out_data,
                           std::string &out_hrp,
                           Bech32Encoding &out_encoding)
  {
    out_data.clear();
    out_hrp.clear();

    if (input.empty())
      return Bech32Error::Empty;
    if (input.size() > BECH32_MAX_LENGTH)
      return Bech32Error::TooLong;

    // Case rules: reject mixed case. Lowercase is canonical.
    if (hasLower(input) && hasUpper(input))
      return Bech32Error::MixedCase;

    // Normalize to lowercase for processing.
    std::string s;
    s.reserve(input.size());
    for (char c : input)
      s.push_back((c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c);

    // Find the last '1' — the separator. A '1' anywhere before that is
    // part of the HRP (or, if in the data part, is a bug; the data part
    // alphabet excludes '1').
    const size_t sep = s.rfind('1');
    if (sep == std::string::npos)
      return Bech32Error::NoSeparator;

    if (sep == 0 || sep > BECH32_MAX_HRP_LENGTH)
      return Bech32Error::InvalidHrpLength;

    // Need room for the checksum after the separator.
    if (s.size() - sep - 1 < BECH32_CHECKSUM_LENGTH)
      return Bech32Error::InvalidHrpLength;

    std::string_view hrp(s.data(), sep);
    for (char c : hrp)
      if (!validHrpChar(c))
        return Bech32Error::InvalidHrpCharacter;

    // Data part -> 5-bit values.
    std::vector<uint8_t> data5;
    data5.reserve(s.size() - sep - 1);
    for (size_t i = sep + 1; i < s.size(); ++i)
    {
      const char c = s[i];
      const int8_t v = (static_cast<uint8_t>(c) < 128)
                           ? CHARSET_REV.map[static_cast<uint8_t>(c)]
                           : int8_t(-1);
      if (v < 0)
        return Bech32Error::InvalidDataCharacter;
      data5.push_back(static_cast<uint8_t>(v));
    }

    // Verify checksum. Try Bech32m first (the modern default), then
    // Bech32. A string cannot validate against both because the check
    // constants differ.
    auto verifyWith = [&](Bech32Encoding enc) -> bool
    {
      std::vector<uint8_t> values = hrpExpand(hrp);
      values.insert(values.end(), data5.begin(), data5.end());
      return polymod(values) == checksumConst(enc);
    };

    Bech32Encoding matched;
    if (verifyWith(Bech32Encoding::Bech32m))
      matched = Bech32Encoding::Bech32m;
    else if (verifyWith(Bech32Encoding::Bech32))
      matched = Bech32Encoding::Bech32;
    else
      return Bech32Error::ChecksumMismatch;

    // Strip checksum, convert 5-bit groups back to bytes.
    const size_t data5_len = data5.size() - BECH32_CHECKSUM_LENGTH;
    if (!convertBitsFrom5(data5.data(), data5_len, out_data, /*pad=*/false))
      return Bech32Error::InvalidPadding;

    out_hrp.assign(hrp.data(), hrp.size());
    out_encoding = matched;
    return Bech32Error::Ok;
  }

} // namespace Crypto