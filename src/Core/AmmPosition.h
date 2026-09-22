// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "AmmPool.h"
#include "Serialization/ISerializer.h"
#include "Crypto/Types.h"

namespace Core
{
  //  AmmPosition
  //
  //  A liquidity provider's share in an AMM pool. Stores the LP token
  //  balance and a checkpoint of the pool's `k` value at the time of the
  //  last fee claim.
  //
  //  Fees are not tracked per position. Instead, the pool's reserves grow
  //  as swaps occur, and LPs withdraw their pro-rata share when they
  //  remove liquidity. This is the standard Uniswap V2 model.
  //
  //  Stored in the SMT under key = H("pos " || position_id).

  struct AmmPosition
  {
    Id id{INVALID_ID};
    Crypto::Address owner{};
    Id pool_id{INVALID_ID};

    // LP tokens held. Represents owner's share of pool.total_liquidity.
    uint64_t liquidity{0};

    uint64_t created_at_height{0};

    bool isValid() const noexcept
    {
      if (id == INVALID_ID)
        return false;
      if (pool_id == INVALID_ID)
        return false;
      if (owner.isNull())
        return false;
      return true;
    }

    // ---- State serialization ----
    //
    // Layout:
    //   [8]  id
    //   [32] owner
    //   [8]  pool_id
    //   [8]  liquidity
    //   [8]  created_at_height
    // Total: 64 bytes

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 AmmPosition &out);

    static constexpr size_t STATE_SIZE = 8 + 32 + 8 + 8 + 8;

    void serialize(Serialization::ISerializer &s);
  };

} // namespace Core