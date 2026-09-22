// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Crypto/Types.h"
#include "Serialization/ISerializer.h"
#include "GlobalConfig.h"

namespace Core
{
  //  AmmPool
  //
  //  A constant-product (x * y = k) automated market maker pool.
  //  Stored in the SMT under key = H("pool" || pool_id).
  //
  //  Invariant: reserve_a * reserve_b = k. Swaps preserve k (with fees).
  //
  //  Fees accumulate in the reserves; LPs withdraw their pro-rata share
  //  via AmmPosition.

  // Fee in basis points. 30 bps = 0.3% (typical Uniswap V2).
  inline constexpr uint16_t AMM_DEFAULT_FEE_BPS = 30;
  inline constexpr uint16_t AMM_MAX_FEE_BPS = 1000; // 10% max

  struct AmmPool
  {
    Id id{INVALID_ID};
    Crypto::Address creator{};

    // Token pair. Token A is always the lower ID (canonical).
    Id token_a{0};
    Id token_b{0};

    // Reserves.
    uint64_t reserve_a{0};
    uint64_t reserve_b{0};

    // LP token supply. Each LP position holds a share of this.
    uint64_t total_liquidity{0};

    // Fee in basis points.
    uint16_t fee_bps{AMM_DEFAULT_FEE_BPS};

    uint64_t created_at_height{0};
    bool active{true};

    // ---- Helpers ----

    bool isValid() const noexcept
    {
      if (id == INVALID_ID)
        return false;
      if (token_a == token_b)
        return false;
      if (token_a > token_b)
        return false; // canonical ordering
      if (fee_bps > AMM_MAX_FEE_BPS)
        return false;
      if (reserve_a == 0 && reserve_b == 0)
      {
        // Empty pool — valid only at creation.
        return true;
      }
      // Both reserves must be positive if the pool has any liquidity.
      return reserve_a > 0 && reserve_b > 0;
    }

    // Constant product invariant.
    // Uses 128-bit intermediate to avoid overflow.
    __uint128_t k() const noexcept
    {
      return static_cast<__uint128_t>(reserve_a) * reserve_b;
    }

    // ---- State serialization ----
    //
    // Layout:
    //   [8]  id
    //   [32] creator
    //   [4]  token_a
    //   [4]  token_b
    //   [8]  reserve_a
    //   [8]  reserve_b
    //   [8]  total_liquidity
    //   [2]  fee_bps
    //   [8]  created_at_height
    //   [1]  active
    // Total: 83 bytes

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len, AmmPool &out);

    static constexpr size_t STATE_SIZE =
        8 + 32 + 4 + 4 + 8 + 8 + 8 + 2 + 8 + 1;

    // ---- Framework serialization ----
    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core