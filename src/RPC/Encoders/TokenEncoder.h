// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Common/Json.h"
#include "Core/TokenTypes.h"

namespace Rpc
{
  //  TokenInfo -> JSON
  //
  //  Fields:
  //    id            (hex)
  //    name          (string)
  //    symbol        (string)
  //    decimals      (number)
  //    creator       (Bech32m; zero address for the native token)
  //    backing       (string: "unbacked" | "backed" | "hybrid")
  //    backing_code  (number)
  //    max_supply    (hex; 0 means unlimited)
  //    royalty_bps   (number)
  //    fingerprint   (0x-prefixed or null)
  //    is_native     (bool; derived)
  //    is_bridged    (bool; derived)
  //
  //  The `creator` field is the zero address for the native token
  //  (id == 0). We still emit it as a Bech32m string, but Bech32m
  //  cannot encode the null pubkey — encodeAddress returns an empty
  //  string for null addresses. Emit null in that case so the field
  //  is present-but-absent rather than an empty string a client might
  //  try to parse.

  Common::Json encodeToken(const Core::TokenInfo &token, const std::string &hrp);
}