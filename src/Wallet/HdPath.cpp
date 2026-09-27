// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cctype>
#include <cstdio>
#include <cstring>
#include <vector>

#include "HdPath.h"
#include "WalletTypes.h"

namespace Wallet
{
  namespace
  {
    // Parse a decimal string to uint32_t. Returns false on overflow,
    // empty input, or any non-digit character.
    bool parseDecimal(std::string_view s, uint32_t &out) noexcept
    {
      if (s.empty())
        return false;

      uint64_t acc = 0;
      for (char c : s)
      {
        if (c < '0' || c > '9')
          return false;
        acc = acc * 10 + uint64_t(c - '0');
        if (acc > 0xFFFFFFFFull)
          return false;
      }
      // Component must fit in the 31-bit index range (the top bit is
      // the hardened flag).
      if (acc > MAX_INDEX)
        return false;
      out = static_cast<uint32_t>(acc);
      return true;
    }

    // Split a path string on '/'. Does not skip empty segments.
    // e.g. "m/44'/9000'" -> ["m", "44'", "9000'"]
    //      "m//44'"      -> ["m", "", "44'"]  (the empty is preserved)
    std::vector<std::string_view> splitOnSlash(std::string_view s)
    {
      std::vector<std::string_view> out;
      size_t start = 0;
      for (size_t i = 0; i <= s.size(); ++i)
      {
        if (i == s.size() || s[i] == '/')
        {
          out.emplace_back(s.substr(start, i - start));
          start = i + 1;
        }
      }
      return out;
    }
  } // namespace

  //  HdPath methods

  std::string HdPath::toString() const
  {
    if (length == 0)
      return "";

    std::string out;
    out.reserve(8 + length * 6);
    out += 'm';

    for (size_t i = 0; i < length; ++i)
    {
      const auto &e = elements[i];
      out += '/';
      out += std::to_string(e.index);
      if (e.hardened)
        out += '\'';
    }
    return out;
  }

  bool HdPath::operator==(const HdPath &o) const noexcept
  {
    if (length != o.length)
      return false;
    for (size_t i = 0; i < length; ++i)
    {
      if (elements[i].index != o.elements[i].index)
        return false;
      if (elements[i].hardened != o.elements[i].hardened)
        return false;
    }
    return true;
  }

  bool HdPath::push(uint32_t index, bool hardened) noexcept
  {
    if (length >= MAX_PATH_LENGTH)
      return false;
    if (index > MAX_INDEX)
      return false;
    elements[length].index = index;
    elements[length].hardened = hardened;
    ++length;
    return true;
  }

  //  Parsing

  std::optional<HdPath> parseHdPath(std::string_view s,
                                    WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<HdPath>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    if (s.empty())
      return fail(WalletError::InvalidPath, "empty path");

    // Reject any whitespace anywhere. Paths are machine-generated and
    // machine-parsed; whitespace is a sign of a copy-paste error.
    for (char c : s)
    {
      if (std::isspace(static_cast<unsigned char>(c)))
        return fail(WalletError::InvalidPath,
                    "path contains whitespace");
    }

    const auto parts = splitOnSlash(s);
    if (parts.empty())
      return fail(WalletError::InvalidPath, "empty path");

    // The leading element must be 'm' or 'M'.
    if (parts[0] != "m" && parts[0] != "M")
      return fail(WalletError::InvalidPath,
                  "path must start with 'm'");

    // A bare "m" is the master key, valid in BIP-32 but not useful
    // for CLRTY (we require a full path to a specific key). Reject.
    if (parts.size() == 1)
      return fail(WalletError::InvalidPath,
                  "path must have at least one component after 'm'");

    // BIP-32 caps at 255, we cap at 16. The typical path is 5 levels;
    // anything deeper is almost certainly a typo or a caller bug.
    if (parts.size() - 1 > MAX_PATH_LENGTH)
      return fail(WalletError::InvalidPath,
                  "path exceeds maximum depth of " +
                      std::to_string(MAX_PATH_LENGTH));

    HdPath path;
    for (size_t i = 1; i < parts.size(); ++i)
    {
      std::string_view part = parts[i];
      if (part.empty())
        return fail(WalletError::InvalidPath,
                    "empty path component at position " +
                        std::to_string(i));

      bool hardened = false;
      if (part.back() == '\'' || part.back() == 'h' || part.back() == 'H')
      {
        hardened = true;
        part.remove_suffix(1);
        if (part.empty())
          return fail(WalletError::InvalidPath,
                      "hardened marker without index at position " +
                          std::to_string(i));
      }

      uint32_t index = 0;
      if (!parseDecimal(part, index))
        return fail(WalletError::InvalidPath,
                    "invalid index at position " + std::to_string(i));

      if (!path.push(index, hardened))
        return fail(WalletError::InvalidPath,
                    "failed to append component at position " +
                        std::to_string(i));
    }

    return path;
  }

  //  Construction

  HdPath clrtyPath(uint32_t account, uint32_t change, uint32_t index)
  {
    HdPath p;
    // All components hardened.
    p.push(BIP44_PURPOSE, true);
    p.push(COIN_TYPE_CLRTY, true);
    p.push(account, true);
    p.push(change, true);
    p.push(index, true);
    return p;
  }

} // namespace Wallet