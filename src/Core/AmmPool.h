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
#include "RewardTypes.h"

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

  //  Minimum initial reserve on each side of a new pool.
  //
  //  A pool with reserves below this floor is a griefing surface:
  //  the price is trivially manipulable for a few atomic units, and
  //  the pool has no economic function. Enforced at pool creation
  //  only; a pool that later drains below the floor through
  //  withdrawals is handled by the last-LP drain path, not by this
  //  check.
  //
  //  Denominated in atomic units of the native token. The check
  //  applies to both sides of the pool regardless of the tokens'
  //  own decimals, so a token with decimals=0 needs this many whole
  //  tokens on each side to be poolable. That's a deliberate
  //  "you must be serious about this" floor for a chain where the
  //  native unit is the reference.
  //
  //  Consensus constant: changing it is a hard fork.
  inline constexpr Amount MIN_POOL_LIQUIDITY = 100 * GlobalConfig::ATOMIC_UNITS_PER_COIN;

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

    //  ---- Rolling volume (tumbling window) ----
    //
    //  Volume tracking for OrderConditionType::VolumeBelow.
    //
    //  Each swap contributes its CLRTY-equivalent amount to
    //  `volume_current`. When the current height reaches
    //  `volume_window_height + ROTATION_INTERVAL`, the window rolls:
    //  `volume_last` becomes the previous window's total, and
    //  `volume_current` resets to zero for the new window.
    //
    //  `VolumeBelow` conditions read `volume_last` — the total
    //  volume of the previous complete epoch. This means the value
    //  lags by up to one epoch (ROTATION_INTERVAL blocks, ~1 minute).
    //  That is deliberate: a rolling per-block ring buffer would
    //  cost 960 bytes per pool versus 24 for these three fields, and
    //  a one-epoch lag is acceptable for limit-order conditions.
    //
    //  A swap in a pool with no CLRTY side contributes zero (the
    //  volume unit is CLRTY; there is no way to denominate a
    //  token-only trade in CLRTY without an oracle).
    //
    //  Initialization: all three fields are zero on a freshly created
    //  pool. The first swap starts the first window at
    //  `current_height` and adds its amount to `volume_current`.
    uint64_t volume_window_height{0};
    uint64_t volume_current{0};
    uint64_t volume_last{0};

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

    // True when the pool has been fully drained: every LP has
    // withdrawn, both reserves are zero, and no liquidity remains.
    bool isClosed() const noexcept
    {
      return total_liquidity == 0 &&
             reserve_a == 0 &&
             reserve_b == 0;
    }

    // Constant product invariant.
    __uint128_t k() const noexcept
    {
      return static_cast<__uint128_t>(reserve_a) * reserve_b;
    }

    //  Return the current "reported volume" for condition evaluation.
    //
    //  If a full window has elapsed since `volume_window_height`, the
    //  previous window's total is `volume_current` (the roll happens
    //  lazily on the next swap, so between the window boundary and
    //  the next swap we must report the in-progress window as the
    //  most-recent complete one).
    uint64_t reportedVolume(uint64_t current_height) const noexcept
    {
      if (volume_window_height == 0)
        return 0;

      if (current_height >= volume_window_height + ROTATION_INTERVAL)
      {
        //  The window has ended but no swap has rolled it yet.
        //  Report the in-progress total, which is now a complete
        //  window.
        return volume_current;
      }

      //  Mid-window: report the previous complete window.
      return volume_last;
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
    //   [8]  volume_window_height
    //   [8]  volume_current
    //   [8]  volume_last
    // Total: 107 bytes

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len, AmmPool &out);

    static constexpr size_t STATE_SIZE =
        8 + 32 + 4 + 4 + 8 + 8 + 8 + 2 + 8 + 1 + 8 + 8 + 8;

    // ---- Framework serialization ----
    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core