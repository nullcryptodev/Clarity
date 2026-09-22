// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "RewardCalculator.h"
#include "RewardTypes.h"

#include <algorithm>

namespace Core
{

  //  Block rewards

  BlockRewardResult computeBlockReward(const RewardContext &ctx,
                                       const ValidatorRegistry &registry)
  {
    BlockRewardResult result;

    if (registry.active_set.empty())
    {
      result.total_issued = 0;
      return result;
    }

    const uint64_t block_reward = ctx.block_reward_atomic;
    const uint64_t validator_pool = applyBps(block_reward, GlobalConfig::VALIDATOR_SHARE_BPS);

    const uint64_t producer_amount = applyBps(validator_pool, GlobalConfig::PRODUCER_BONUS_BPS);
    const uint64_t set_amount = validator_pool - producer_amount;

    result.total_issued = validator_pool;
    result.producer_amount = producer_amount;
    result.set_amount = set_amount;

    const uint64_t n = static_cast<uint64_t>(registry.active_set.size());
    const uint64_t per_validator = set_amount / n;
    uint64_t remainder = set_amount % n;

    result.validator_rewards.reserve(registry.active_set.size());

    for (size_t i = 0; i < registry.active_set.size(); ++i)
    {
      Id vid = registry.active_set[i];
      uint64_t amount = per_validator;

      if (remainder > 0)
      {
        amount += 1;
        --remainder;
      }

      result.validator_rewards.push_back({vid, amount});
    }

    return result;
  }

  //  APY calculation

  uint64_t apyToPerSecondScaled(uint16_t apy_bps) noexcept
  {
    constexpr uint64_t SCALE = 1'000'000'000'000ULL; // 10^12

    __uint128_t tmp = static_cast<__uint128_t>(apy_bps) * SCALE;
    return static_cast<uint64_t>(tmp / SECONDS_PER_YEAR);
  }

  uint16_t computeEffectiveApy(const RewardContext &ctx,
                               uint64_t seconds_since_last_epoch)
  {
    // Base + activity + pot bonus, capped at their respective maximums.

    uint32_t apy = ctx.apy_base_bps;

    // Activity component (0..APY_ACTIVITY_MAX_BPS).
    apy += std::min<uint32_t>(ctx.apy_activity_bps, APY_ACTIVITY_MAX_BPS);

    // Pot bonus (0..APY_POT_BONUS_MAX_BPS).
    apy += std::min<uint32_t>(ctx.apy_pot_bonus_bps, APY_POT_BONUS_MAX_BPS);

    // Cap at uint16 range.
    if (apy > 65535)
      apy = 65535;
    return static_cast<uint16_t>(apy);
  }

  //  Staker payout

  uint64_t computeTargetStakerPayout(const RewardContext &ctx,
                                     uint16_t effective_apy_bps,
                                     uint64_t epoch_seconds)
  {
    if (ctx.total_staked == 0)
      return 0;
    if (effective_apy_bps == 0)
      return 0;

    __uint128_t step1 = static_cast<__uint128_t>(ctx.total_staked) * epoch_seconds;
    __uint128_t step2 = step1 * effective_apy_bps;
    __uint128_t step3 = step2 / 10'000;
    __uint128_t step4 = step3 / SECONDS_PER_YEAR;

    return static_cast<uint64_t>(step4);
  }

  //  Activity APY

  uint16_t computeActivityBps(uint64_t avg_tx_per_block) noexcept
  {
    if (avg_tx_per_block == 0)
      return 0;

    if (avg_tx_per_block >= TRAFFIC_SATURATION_TX)
      return APY_ACTIVITY_MAX_BPS;

    // Linear interpolation from 0 at 0 tx to APY_ACTIVITY_MAX_BPS at
    // TRAFFIC_SATURATION_TX.
    __uint128_t scaled = static_cast<__uint128_t>(avg_tx_per_block) *
                         APY_ACTIVITY_MAX_BPS;
    uint32_t result = static_cast<uint32_t>(scaled / TRAFFIC_SATURATION_TX);

    if (result > APY_ACTIVITY_MAX_BPS)
      result = APY_ACTIVITY_MAX_BPS;

    return static_cast<uint16_t>(result);
  }

  //  Pot bonus APY

  uint16_t computePotBonusBps(uint64_t pot, uint64_t pool_baseline) noexcept
  {
    if (pool_baseline == 0)
      return 0;

    const uint64_t pot_high = pool_baseline * POT_HIGH_EPOCHS;
    const uint64_t pot_max = pool_baseline * POT_MAX_EPOCHS;

    if (pot <= pot_high)
      return 0;

    if (pot >= pot_max)
      return APY_POT_BONUS_MAX_BPS;

    const uint64_t span = pot_max - pot_high;
    if (span == 0)
      return 0;

    const uint64_t offset = pot - pot_high;
    __uint128_t scaled = static_cast<__uint128_t>(offset) *
                         APY_POT_BONUS_MAX_BPS;
    uint32_t result = static_cast<uint32_t>(scaled / span);

    if (result > APY_POT_BONUS_MAX_BPS)
      result = APY_POT_BONUS_MAX_BPS;

    return static_cast<uint16_t>(result);
  }

  //  Pot mechanics

  PotAdjustment applyPotMechanics(uint64_t staker_pool,
                                  uint64_t target_payout,
                                  uint64_t current_pot,
                                  uint64_t epoch_pool_baseline)
  {
    PotAdjustment adj;

    const uint64_t pool_baseline = epoch_pool_baseline > 0
                                       ? epoch_pool_baseline
                                       : staker_pool;

    const uint64_t pot_low = pool_baseline * POT_LOW_EPOCHS;
    const uint64_t pot_high = pool_baseline * POT_HIGH_EPOCHS;
    const uint64_t pot_max = pool_baseline * POT_MAX_EPOCHS;

    if (staker_pool >= target_payout)
    {
      adj.distributed = target_payout;
      adj.added_to_pot = staker_pool - target_payout;
    }
    else
    {
      uint64_t shortfall = target_payout - staker_pool;

      if (current_pot >= shortfall)
      {
        adj.distributed = target_payout;
        adj.drained_from_pot = shortfall;
      }
      else
      {
        adj.distributed = staker_pool + current_pot;
        adj.drained_from_pot = current_pot;
      }
    }

    uint64_t new_pot = current_pot + adj.added_to_pot - adj.drained_from_pot;

    if (new_pot > pot_max)
    {
      adj.burned = new_pot - pot_max;
    }

    (void)pot_low;
    (void)pot_high;

    return adj;
  }

} // namespace Core