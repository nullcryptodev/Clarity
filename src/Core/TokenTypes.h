// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Serialization/ISerializer.h"

namespace Core
{
  //  TokenInfo
  //
  //  Metadata for a custom token (or for CLRTY itself, token_id = 0).
  //
  //  Stored in the SMT under key = H("tok " || token_id).
  //
  //  State encoding is compact:
  //    [4]  id
  //    [1]  decimals
  //    [1]  backing (enum: 0=Unbacked, 1=Backed, 2=Hybrid)
  //    [1]  name_len
  //    [N]  name          (UTF-8, <= 64 bytes)
  //    [1]  symbol_len
  //    [M]  symbol        (ASCII, <= 8 bytes)
  //    [8]  max_supply
  //    [2]  royalty_bps
  //    [32] creator
  //    [1]  has_fingerprint (0 or 1)
  //    [32] fingerprint    (only if has_fingerprint)

  enum class BackingModel : uint8_t
  {
    Unbacked = 0,
    Backed = 1,
    Hybrid = 2,
  };

  inline constexpr size_t TOKEN_NAME_MAX = 64;
  inline constexpr size_t TOKEN_SYMBOL_MIN = 3;
  inline constexpr size_t TOKEN_SYMBOL_MAX = 8;

  struct TokenInfo
  {
    Id id{0};
    std::string name;
    std::string symbol;
    uint8_t decimals{5};
    Crypto::Address creator{};
    BackingModel backing{BackingModel::Unbacked};
    uint64_t maxSupply{0};  // 0 = unlimited
    uint16_t royaltyBps{0}; // 0-10000

    std::optional<Crypto::Hash> fingerprint{};

    bool isNative() const noexcept { return id == NATIVE_TOKEN_ID; }
    bool isBridged() const noexcept { return fingerprint.has_value(); }

    bool isValid() const noexcept
    {
      if (symbol.size() < TOKEN_SYMBOL_MIN)
        return false;
      if (symbol.size() > TOKEN_SYMBOL_MAX)
        return false;
      if (name.empty() || name.size() > TOKEN_NAME_MAX)
        return false;
      if (decimals > 18)
        return false;
      if (royaltyBps > 10'000)
        return false;
      return true;
    }

    // ------------------------------------------------------------------
    //  State serialization (compact, fixed-prefix + variable strings)
    // ------------------------------------------------------------------

    std::vector<uint8_t> serializeState() const;

    static bool deserializeState(const uint8_t *data, size_t len,
                                 TokenInfo &out);

    // ------------------------------------------------------------------
    //  Framework serialization (for JSON/API responses)
    // ------------------------------------------------------------------

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core