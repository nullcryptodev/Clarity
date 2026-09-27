// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Common/Json.h"
#include "Core/AmmPool.h"
#include "Core/AmmPosition.h"

namespace Rpc
{
  //  AmmPool -> JSON
  //
  //  Fields:
  //    id                (hex)
  //    creator           (Bech32m)
  //    token_a           (hex)
  //    token_b           (hex)
  //    reserve_a         (hex)
  //    reserve_b         (hex)
  //    total_liquidity   (hex)
  //    fee_bps           (number)
  //    created_at_height (hex)
  //    active            (bool)
  //    k                 (hex string; 128-bit; computed from reserves)
  //    price_a_per_b     (string; decimal approximation for display)
  //    price_b_per_a     (string; decimal approximation for display)
  //
  //  `k` is a 128-bit value (reserve_a * reserve_b). Encoded as a
  //  0x-prefixed hex string without leading zeros. It can exceed 2^53,
  //  so it cannot be a JSON number.
  //
  //  `price_a_per_b` and `price_b_per_a` are provided for human
  //  display. They are floating-point approximations and should NOT
  //  be used for financial calculations. The exact ratio is
  //  reserve_a : reserve_b, which the client can compute from the
  //  reserves.

  Common::Json encodeAmmPool(const Core::AmmPool &pool, const std::string &hrp);

  //  AmmPosition -> JSON
  //
  //  Fields:
  //    id                (hex)
  //    owner             (Bech32m)
  //    pool_id           (hex)
  //    liquidity         (hex)
  //    created_at_height (hex)
  //    share_bps         (number; 0..10000; derived from pool if provided)
  //
  //  `share_bps` is the owner's share of the pool, in basis points.
  //  Computing it requires the pool's total_liquidity, so it is
  //  optional — if `pool` is null, `share_bps` is omitted.

  Common::Json encodeAmmPosition(const Core::AmmPosition &position,
                                 const Core::AmmPool *pool,
                                 const std::string &hrp);
}