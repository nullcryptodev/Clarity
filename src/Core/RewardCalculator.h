// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Crypto/Types.h"
#include "StakingTypes.h"
#include "ValidatorTypes.h"

namespace Core
{
  //  Reward math
  //
  //  Pure functions. No state, no side effects, no I/O. All functions are
  //  deterministic and can be called from anywhere.
  //
  //  The reward calculator operates on a "reward context" — a snapshot of
  //  the state needed to compute rewards for a block or an epoch.

  // Snapshot of state needed to compute rewards.
  struct RewardContext
  {
    uint64_t height{0};
    uint64_t epoch_number{0};
    uint64_t active_set_size{0};
    uint64_t total_staked{0};
    uint64_t pot{0};
    uint64_t fees_this_block{0};
    uint64_t block_reward_atomic{GlobalConfig::BLOCK_REWARD};
    uint16_t apy_base_bps{APY_BASE_BPS};
    uint16_t apy_activity_bps{0};
    uint16_t apy_pot_bonus_bps{0};
  };

  // Per-validator reward for a single block (if they produce it).
  struct ProducerReward
  {
    Id validator_id{INVALID_ID};
    uint64_t amount{0};
  };

  // Per-validator reward for participating in the active set (per block).
  struct SetReward
  {
    Id validator_id{INVALID_ID};
    uint64_t amount{0};
  };

  // Per-staker reward for an epoch.
  struct StakerReward
  {
    Crypto::Address address{};
    uint64_t amount{0};
  };

  // Result of computing rewards for a single block.
  struct BlockRewardResult
  {
    // Total CLRTY issued this block.
    uint64_t total_issued{0};

    // CLRTY allocated to the producer.
    uint64_t producer_amount{0};

    // CLRTY allocated to the active set (divided equally).
    uint64_t set_amount{0};

    // Per-validator amounts (producer + set).
    std::vector<SetReward> validator_rewards;
  };

  // Result of computing rewards for an epoch.
  struct EpochRewardResult
  {
    // Total CLRTY allocated to stakers this epoch (before pot adjustments).
    uint64_t staker_pool{0};

    // CLRTY actually distributed to stakers.
    uint64_t distributed{0};

    // CLRTY added to the pot (if positive).
    uint64_t pot_added{0};

    // CLRTY drained from the pot (if pool < target).
    uint64_t pot_drained{0};

    // CLRTY burned (if pot exceeded max).
    uint64_t burned{0};

    // Effective APY in basis points.
    uint16_t effective_apy_bps{0};

    // Individual staker rewards.
    std::vector<StakerReward> staker_rewards;
  };

  // ---- Pure calculation functions ----

  // Compute the block reward split and per-validator distribution.
  BlockRewardResult computeBlockReward(const RewardContext &ctx,
                                       const ValidatorRegistry &registry);

  // Compute the effective APY for this epoch.
  // Returns basis points.
  uint16_t computeEffectiveApy(const RewardContext &ctx,
                               uint64_t seconds_since_last_epoch);

  // Compute the target staker payout for an epoch.
  // = total_staked * effective_apy * epoch_seconds / seconds_per_year
  uint64_t computeTargetStakerPayout(const RewardContext &ctx,
                                     uint16_t effective_apy_bps,
                                     uint64_t epoch_seconds);

  // Compute the activity APY bonus, in basis points.
  //
  // Derived from the epoch's average transactions per block, linearly
  // interpolated between 0 (no activity) and APY_ACTIVITY_MAX_BPS (at
  // TRAFFIC_SATURATION_TX). This is the "popularity" signal: a chain
  // under load pays stakers more to attract more stake.
  //
  // Returns 0 for zero activity, APY_ACTIVITY_MAX_BPS at or above
  // saturation.
  uint16_t computeActivityBps(uint64_t avg_tx_per_block) noexcept;

  // Compute the pot bonus APY, in basis points.
  //
  // The pot bonus is the release valve for the pot: when the pot grows
  // past POT_HIGH, stakers earn an extra bonus to drain it. The bonus
  // ramps linearly from 0 at POT_HIGH to APY_POT_BONUS_MAX_BPS at
  // POT_MAX. Above POT_MAX the bonus is capped (the excess above
  // POT_MAX is burned by applyPotMechanics).
  //
  // pool_baseline is one epoch's worth of staker pool, used to convert
  // the POT_*_EPOCHS multipliers into absolute amounts. Pass 0 if
  // unknown — the function returns 0 in that case.
  uint16_t computePotBonusBps(uint64_t pot, uint64_t pool_baseline) noexcept;

  // Compute how much of the pool to distribute and how much goes to the pot.
  struct PotAdjustment
  {
    uint64_t distributed{0};
    uint64_t added_to_pot{0};
    uint64_t drained_from_pot{0};
    uint64_t burned{0};
  };
  PotAdjustment applyPotMechanics(uint64_t staker_pool,
                                  uint64_t target_payout,
                                  uint64_t current_pot,
                                  uint64_t epoch_pool_baseline);

  // ---- Utility ----

  // Normalize an APY in bps to a per-second rate in bps.
  // (bps / year_seconds). Returns bps-per-second * 10^12 for precision.
  uint64_t apyToPerSecondScaled(uint16_t apy_bps) noexcept;

  // Seconds per year (365.2425 days, Gregorian).
  inline constexpr uint64_t SECONDS_PER_YEAR = 31'556'952;

} // namespace Core