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
  //  =========================================================================
  //  AMM farming
  //
  //  A farm is an escrow + a rate, attached to one pool. The escrow is a
  //  real token balance at Keys::ammFarmAddress(pool_id); it is funded
  //  by the farm creator and topped up by RefillAmmFarm. The rate is
  //  the total emission per epoch, split pro-rata across the pool's LP
  //  shares at each epoch boundary.
  //
  //  Emission uses the reward-per-share (RPS) accumulator, the same
  //  accounting MasterChef and SushiSwap use:
  //
  //    - At each epoch boundary, per farmed pool:
  //        emission = min(rate, escrow)
  //        escrow  -= emission
  //        rps     += emission * SCALE / pool.total_liquidity
  //
  //    - At settle time, per position:
  //        accrued  = (rps - position.last_rps) * pos.liquidity / SCALE
  //        pending += accrued
  //        last_rps = rps
  //
  //  The escrow is the single source of truth. It only decreases at the
  //  epoch boundary (and at farm close) and only increases on a
  //  RefillAmmFarm. The epoch boundary never credits an individual LP;
  //  claims do. This is the same accrue-then-claim model the NFT
  //  collection reward schedule uses, and it has the same property: the
  //  sum of all pending claims is always <= the total the escrow has
  //  decremented for.
  //
  //  The epoch-boundary pass is O(farmed pools), not O(LPs). A chain
  //  with 1,000,000 LPs across 50 farmed pools pays 50 writes at each
  //  boundary, not a million.
  //
  //  Scale. FARM_RPS_SCALE is 10^10, matching BOOK_PRICE_SCALE. It
  //  leaves plenty of headroom above the native token's granularity,
  //  and it is small enough that a realistic emission rate does not
  //  overflow a uint64 accumulator; the epoch pass checks the
  //  overflow explicitly anyway (see BlockProcessor's farm pass).
  //  =========================================================================

  inline constexpr uint64_t FARM_RPS_SCALE = 10'000'000'000ULL;

  //  Per-pool farm schedule.
  //
  //  Stored in the SMT under key = Keys::ammFarm(pool_id), a companion
  //  key. It is NOT a field on AmmPool: AmmPool's serialized layout is
  //  fixed at 107 bytes and every reader of it depends on that layout
  //  not changing. Adding a farm schedule to it would widen the
  //  record and force every reader to change in lockstep for a
  //  feature most pools will never enable.
  //
  //  The escrow custody is a real balance at Keys::ammFarmAddress(pool_id).
  //  `reward_escrow_remaining` is a cache of that balance, kept in
  //  sync by the four write sites (CreateAmmFarm, RefillAmmFarm,
  //  the epoch-boundary decrement, and the CloseAmmFarm / full-drain
  //  refund). The cache exists so the epoch pass can check "can I
  //  emit this much?" without a second SMT read per pool; the balance
  //  is the authoritative value a client reads with getTokenBalance.
  struct AmmFarmSchedule
  {
    Id pool_id{INVALID_ID};
    Crypto::Address creator{};

    //  Reward token. Any on-chain token: native CLRTY, a user token,
    //  or a bridged wrapper. NATIVE_TOKEN_ID (0) is valid — it means
    //  the farm pays CLRTY. Set at creation and immutable: changing
    //  it would require re-funding from a different token, which is a
    //  different farm, not an update.
    Id reward_token_id{NATIVE_TOKEN_ID};

    //  Total emitted per epoch, split pro-rata across the pool's
    //  total_liquidity at the epoch boundary. A rate change applies at
    //  the *next* boundary, not the current one; see
    //  executeUpdateAmmFarm.
    uint64_t reward_rate_per_epoch{0};

    //  Cache of getTokenBalance(Keys::ammFarmAddress(pool_id),
    //  reward_token_id). Decremented at each epoch boundary by the
    //  emission; incremented by RefillAmmFarm; refunded to the
    //  creator and zeroed on a full-drain close.
    uint64_t reward_escrow_remaining{0};

    //  Set when the escrow cannot cover a full epoch's obligation. The
    //  epoch pass drains what's left, emits it, and pauses; a
    //  RefillAmmFarm un-pauses. A paused farm emits nothing.
    bool reward_paused{false};

    //  Monotone cumulative emissions per LP share, scaled by
    //  FARM_RPS_SCALE. Only ever increases. A position's accrual is
    //  (rps_per_share - position.last_rps) * liquidity / SCALE.
    uint64_t rps_per_share{0};

    uint64_t created_at_height{0};

    //  True when this farm has a positive per-epoch obligation. Mirror
    //  of NftCollection::hasReward().
    bool hasEmission() const noexcept
    {
      return reward_rate_per_epoch > 0;
    }

    //  True when the farm is actively emitting right now. Mirror of
    //  NftCollection::isActive(). The epoch pass and
    //  executeClaimAmmFarmRewards both gate on this.
    bool isActive() const noexcept
    {
      return hasEmission() &&
             !reward_paused &&
             reward_escrow_remaining > 0;
    }

    bool isValid() const noexcept
    {
      if (pool_id == INVALID_ID)
        return false;
      if (creator.isNull())
        return false;
      //  reward_token_id may be NATIVE_TOKEN_ID (0) — that is a valid
      //  farm paying CLRTY. Do not reject on it.
      //
      //  A farm with rate == 0 AND escrow == 0 is meaningless: it can
      //  never emit and has nothing to refund. An empty, zero-rate
      //  farm is rejected.
      //
      //  rate == 0 with escrow > 0 is valid ("set up, not yet
      //  activated"). rate > 0 with escrow == 0 is valid ("rate set,
      //  escrow exhausted"; the epoch pass will set reward_paused).
      if (reward_rate_per_epoch == 0 && reward_escrow_remaining == 0)
        return false;
      return true;
    }

    //  State serialization.
    //
    //  Layout (all multi-byte little-endian):
    //    [8]   pool_id
    //    [32]  creator
    //    [4]   reward_token_id       (Id truncated to 32 bits on wire,
    //                                 matching AmmPool::token_a/token_b
    //                                 and NftCollection::reward_token_id)
    //    [8]   reward_rate_per_epoch
    //    [8]   reward_escrow_remaining
    //    [1]   reward_paused (0 or 1)
    //    [8]   rps_per_share
    //    [8]   created_at_height
    //  Total: 77 bytes, fixed.

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 AmmFarmSchedule &out);

    static constexpr size_t STATE_SIZE =
        8 + 32 + 4 + 8 + 8 + 1 + 8 + 8;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  //  Per-position accrual companion.
  //
  //  Stored in the SMT under key = Keys::ammPositionAccrual(position_id).
  //  It is NOT a field on AmmPosition: AmmPosition's serialized layout
  //  is fixed at 64 bytes, and every reader of it depends on that
  //  layout. Adding `last_rps` to it would widen the record and force
  //  every reader to change for a feature most positions on most
  //  pools will never use.
  //
  //  The record is small on purpose. It exists only to remember what
  //  rps_per_share the position last settled against; the accrual
  //  itself is computed from the difference. If the record is absent
  //  (a position created before the farm existed), the caller treats
  //  last_rps as 0 — which is correct, because the farm's
  //  rps_per_share was also 0 when the position was created.
  //
  //  Lifecycle:
  //    - Created on the position's first AddLiquidity (or CreatePool,
  //      for the initial LP), with last_rps = the farm's current
  //      rps_per_share. A position that joins a farm after it has
  //      been running starts earning from the next boundary, not from
  //      the farm's beginning.
  //    - Updated on every settle (RemoveLiquidity, ClaimAmmFarmRewards).
  //    - Deleted with the position on last-removal, so a fully
  //      withdrawn position does not leave an orphan companion key.
  struct AmmPositionAccrual
  {
    Id position_id{INVALID_ID};

    //  The pool's rps_per_share at the last settle. The next settle
    //  computes (current_rps - last_rps) * liquidity / SCALE.
    uint64_t last_rps{0};

    bool isValid() const noexcept
    {
      return position_id != INVALID_ID;
    }

    //  State serialization.
    //
    //  Layout (all multi-byte little-endian):
    //    [8]  position_id
    //    [8]  last_rps
    //  Total: 16 bytes, fixed.

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 AmmPositionAccrual &out);

    static constexpr size_t STATE_SIZE = 8 + 8;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core