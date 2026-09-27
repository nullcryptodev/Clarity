// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "WalletTypes.h"

#include <optional>
#include <string>

namespace Wallet
{
  const char *networkName(Network n) noexcept
  {
    switch (n)
    {
    case Network::Mainnet:
      return "mainnet";
    case Network::Testnet:
      return "testnet";
    case Network::Regtest:
      return "regtest";
    }
    return "unknown";
  }

  std::string formatAmount(uint64_t atomic)
  {
    // DECIMALS = 5 by default. Format with a decimal point.
    constexpr uint64_t one_coin = ATOMIC_UNITS_PER_COIN; // 100'000

    const uint64_t whole = atomic / one_coin;
    const uint64_t frac = atomic % one_coin;

    std::string out;
    out.reserve(24);
    out += std::to_string(whole);
    out += '.';

    // Pad frac to DECIMALS digits.
    std::string frac_str = std::to_string(frac);
    for (size_t i = frac_str.size(); i < DECIMALS; ++i)
      out += '0';
    out += frac_str;

    return out;
  }

  std::optional<uint64_t> parseAmount(std::string_view s)
  {
    if (s.empty())
      return std::nullopt;

    // Find the optional decimal point. Reject multiple.
    size_t dot = s.find('.');
    if (dot != std::string_view::npos && s.find('.', dot + 1) != std::string_view::npos)
      return std::nullopt;

    std::string_view whole_s = (dot == std::string_view::npos) ? s : s.substr(0, dot);
    std::string_view frac_s = (dot == std::string_view::npos) ? std::string_view{}
                                                              : s.substr(dot + 1);

    // Both parts must be all digits. Whole part may be empty if frac
    // is non-empty (".5" is allowed; "." is not).
    auto all_digits = [](std::string_view v) -> bool
    {
      if (v.empty())
        return false;
      for (char c : v)
        if (c < '0' || c > '9')
          return false;
      return true;
    };

    if (whole_s.empty() && frac_s.empty())
      return std::nullopt;
    if (!whole_s.empty() && !all_digits(whole_s))
      return std::nullopt;
    if (!frac_s.empty() && !all_digits(frac_s))
      return std::nullopt;
    if (frac_s.size() > DECIMALS)
      return std::nullopt;

    // Parse whole part.
    uint64_t whole = 0;
    if (!whole_s.empty())
    {
      for (char c : whole_s)
      {
        const uint64_t digit = uint64_t(c - '0');
        // Overflow check: whole * 10 + digit must not exceed UINT64_MAX / ATOMIC_UNITS_PER_COIN.
        if (whole > (UINT64_MAX - digit) / 10)
          return std::nullopt;
        whole = whole * 10 + digit;
      }
    }

    // Parse fractional part, pad to DECIMALS.
    uint64_t frac = 0;
    if (!frac_s.empty())
    {
      for (char c : frac_s)
        frac = frac * 10 + uint64_t(c - '0');
      for (size_t i = frac_s.size(); i < DECIMALS; ++i)
        frac *= 10;
    }

    // Combine: atomic = whole * ATOMIC_UNITS_PER_COIN + frac.
    // Overflow check on the multiplication.
    if (whole > UINT64_MAX / ATOMIC_UNITS_PER_COIN)
      return std::nullopt;
    const uint64_t atomic = whole * ATOMIC_UNITS_PER_COIN + frac;
    if (atomic < frac) // addition overflowed
      return std::nullopt;

    return atomic;
  }

} // namespace Wallet