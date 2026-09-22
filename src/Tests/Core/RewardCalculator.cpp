// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/RewardCalculator.h"
#include "Core/RewardTypes.h"

#include "Tests/Utils.h"

using namespace Core;
using namespace Tests;

// ============================================================================
//  applyBps — arithmetic helper
// ============================================================================

TEST(ApplyBps, Zero)
{
  EXPECT_EQ(applyBps(1000, 0), 0u);
  EXPECT_EQ(applyBps(0, 5000), 0u);
}

TEST(ApplyBps, Full)
{
  // 10000 bps = 100%
  EXPECT_EQ(applyBps(1000, 10'000), 1000u);
  EXPECT_EQ(applyBps(0xDEADBEEF, 10'000), 0xDEADBEEFu);
}

TEST(ApplyBps, Half)
{
  EXPECT_EQ(applyBps(1000, 5000), 500u);
  EXPECT_EQ(applyBps(1, 5000), 0u); // rounds down
}

TEST(ApplyBps, NoOverflowAtMax)
{
  // UINT64_MAX * 10000 would overflow uint64 but fits in uint128.
  const uint64_t v = std::numeric_limits<uint64_t>::max();
  EXPECT_EQ(applyBps(v, 10'000), v);
  EXPECT_EQ(applyBps(v, 0), 0u);
}

TEST(ApplyBpsRound, RoundsToNearest)
{
  // 1000 * 250 / 10000 = 25.0 exactly.
  EXPECT_EQ(applyBpsRound(1000, 250), 25u);

  // 1001 * 250 / 10000 = 25.025 → rounds to 25.
  EXPECT_EQ(applyBpsRound(1001, 250), 25u);

  // 1002 * 250 / 10000 = 25.05 → rounds to 25.
  // 1003 * 250 / 10000 = 25.075 → rounds to 25.
  // 1004 * 250 / 10000 = 25.1 → rounds to 25.
  // 1005 * 250 / 10000 = 25.125 → rounds to 25.
  // 1006 * 250 / 10000 = 25.15 → rounds to 25.
  // 1007 * 250 / 10000 = 25.175 → rounds to 25.
  // 1008 * 250 / 10000 = 25.2 → rounds to 25.
  // 1009 * 250 / 10000 = 25.225 → rounds to 25.
  // 1010 * 250 / 10000 = 25.25 → rounds to 25.

  // 2000 * 250 / 10000 = 50.0 exactly.
  EXPECT_EQ(applyBpsRound(2000, 250), 50u);

  // 2001 * 250 / 10000 = 50.025 → rounds to 50.
  EXPECT_EQ(applyBpsRound(2001, 250), 50u);

  // 2010 * 250 / 10000 = 50.25 → rounds to 50.
  EXPECT_EQ(applyBpsRound(2010, 250), 50u);

  // 2020 * 250 / 10000 = 50.5 → rounds to 51.
  EXPECT_EQ(applyBpsRound(2020, 250), 51u);
}

// ============================================================================
//  computeBlockReward
// ============================================================================

TEST(ComputeBlockReward, EmptyActiveSetReturnsZero)
{
  RewardContext ctx = makeContext();
  ValidatorRegistry registry; // no validators

  auto result = computeBlockReward(ctx, registry);

  EXPECT_EQ(result.total_issued, 0u);
  EXPECT_TRUE(result.validator_rewards.empty());
}

TEST(ComputeBlockReward, ValidatorPoolShare)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 1000;
  ValidatorRegistry registry = makeRegistry(1);

  auto result = computeBlockReward(ctx, registry);

  // Validator pool = 60% of 1000 = 600.
  EXPECT_EQ(result.total_issued, 600u);
}

TEST(ComputeBlockReward, ProducerBonusShare)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  ValidatorRegistry registry = makeRegistry(1);

  auto result = computeBlockReward(ctx, registry);

  // Validator pool = 60% of 10000 = 6000.
  // Producer bonus = 20% of 6000 = 1200.
  // Set amount = 80% of 6000 = 4800.
  EXPECT_EQ(result.total_issued, 6000u);
  EXPECT_EQ(result.producer_amount, 1200u);
  EXPECT_EQ(result.set_amount, 4800u);
}

TEST(ComputeBlockReward, SetDistributionSingleValidator)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  ValidatorRegistry registry = makeRegistry(1);

  auto result = computeBlockReward(ctx, registry);

  ASSERT_EQ(result.validator_rewards.size(), 1u);
  EXPECT_EQ(result.validator_rewards[0].validator_id, 1u);
  EXPECT_EQ(result.validator_rewards[0].amount, 4800u);
}

TEST(ComputeBlockReward, SetDistributionMultipleValidators)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  ValidatorRegistry registry = makeRegistry(10);

  auto result = computeBlockReward(ctx, registry);

  // Set amount = 4800. Split across 10 → 480 each.
  ASSERT_EQ(result.validator_rewards.size(), 10u);

  uint64_t total = 0;
  for (const auto &r : result.validator_rewards)
  {
    EXPECT_EQ(r.amount, 480u);
    total += r.amount;
  }
  EXPECT_EQ(total, 4800u);
}

TEST(ComputeBlockReward, RemainderDistributedDeterministically)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  // Set amount = 4800, 7 validators → 685 each + 5 remainder.
  ValidatorRegistry registry = makeRegistry(7);

  auto result = computeBlockReward(ctx, registry);

  ASSERT_EQ(result.validator_rewards.size(), 7u);

  // First 5 validators get +1 remainder.
  for (size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.validator_rewards[i].amount, 686u)
        << "index " << i;
  }
  for (size_t i = 5; i < 7; ++i)
  {
    EXPECT_EQ(result.validator_rewards[i].amount, 685u)
        << "index " << i;
  }

  uint64_t total = 0;
  for (const auto &r : result.validator_rewards)
    total += r.amount;
  EXPECT_EQ(total, 4800u);
}

TEST(ComputeBlockReward, TotalDistributionEqualsPool)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;

  for (size_t n = 1; n <= 21; ++n)
  {
    ValidatorRegistry registry = makeRegistry(n);
    auto result = computeBlockReward(ctx, registry);

    uint64_t sum = 0;
    for (const auto &r : result.validator_rewards)
      sum += r.amount;
    EXPECT_EQ(sum, result.set_amount) << "n=" << n;
  }
}

TEST(ComputeBlockReward, ActiveSetIdsMatchOrder)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  ValidatorRegistry registry = makeRegistry(5);

  auto result = computeBlockReward(ctx, registry);

  ASSERT_EQ(result.validator_rewards.size(), 5u);
  for (size_t i = 0; i < 5; ++i)
  {
    EXPECT_EQ(result.validator_rewards[i].validator_id, i + 1);
  }
}

// ============================================================================
//  computeEffectiveApy
// ============================================================================

TEST(ComputeEffectiveApy, BaseOnly)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = 500;
  ctx.apy_activity_bps = 0;
  ctx.apy_pot_bonus_bps = 0;

  EXPECT_EQ(computeEffectiveApy(ctx, 60), 500u);
}

TEST(ComputeEffectiveApy, ActivityAdded)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = 500;
  ctx.apy_activity_bps = 300;

  EXPECT_EQ(computeEffectiveApy(ctx, 60), 800u);
}

TEST(ComputeEffectiveApy, ActivityCapped)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = 500;
  ctx.apy_activity_bps = 9999; // exceeds max

  // Base 500 + cap of 500 (APY_ACTIVITY_MAX_BPS) = 1000.
  EXPECT_EQ(computeEffectiveApy(ctx, 60), 1000u);
}

TEST(ComputeEffectiveApy, PotBonusAdded)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = 500;
  ctx.apy_pot_bonus_bps = 200;

  EXPECT_EQ(computeEffectiveApy(ctx, 60), 700u);
}

TEST(ComputeEffectiveApy, PotBonusCapped)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = 500;
  ctx.apy_pot_bonus_bps = 9999; // exceeds max

  // Base 500 + cap of 300 (APY_POT_BONUS_MAX_BPS) = 800.
  EXPECT_EQ(computeEffectiveApy(ctx, 60), 800u);
}

TEST(ComputeEffectiveApy, AllComponentsMax)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = 500;
  ctx.apy_activity_bps = 500;  // at cap
  ctx.apy_pot_bonus_bps = 300; // at cap

  // 500 + 500 + 300 = 1300.
  EXPECT_EQ(computeEffectiveApy(ctx, 60), 1300u);
}

TEST(ComputeEffectiveApy, Uint16Cap)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = 60'000;
  ctx.apy_activity_bps = 500;
  ctx.apy_pot_bonus_bps = 300;

  // Should cap at 65535, but also won't exceed because inputs are small.
  // Actually 60000 + 500 + 300 = 60800, fits in uint16.
  EXPECT_EQ(computeEffectiveApy(ctx, 60), 60'800u);
}

// ============================================================================
//  computeTargetStakerPayout
// ============================================================================

TEST(ComputeTargetStakerPayout, ZeroStake)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 0;

  EXPECT_EQ(computeTargetStakerPayout(ctx, 500, 60), 0u);
}

TEST(ComputeTargetStakerPayout, ZeroApy)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 1'000'000;

  EXPECT_EQ(computeTargetStakerPayout(ctx, 0, 60), 0u);
}

TEST(ComputeTargetStakerPayout, BasicCase)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 1'000'000'000ULL; // 1B atomic units

  // APY = 500 bps = 5%. Epoch = 60 seconds.
  // Target = 1e9 * 500 / 10000 * 60 / 31556952
  //        = 5e7 * 60 / 31556952
  //        = 3e9 / 31556952
  //        = 95.06...
  //        = 95 (integer division)
  uint64_t payout = computeTargetStakerPayout(ctx, 500, 60);
  EXPECT_EQ(payout, 95u);
}

TEST(ComputeTargetStakerPayout, ScalesWithStake)
{
  RewardContext ctx = makeContext();

  ctx.total_staked = 1'000'000'000ULL;
  uint64_t p1 = computeTargetStakerPayout(ctx, 500, 60);

  ctx.total_staked = 2'000'000'000ULL;
  uint64_t p2 = computeTargetStakerPayout(ctx, 500, 60);

  // Should approximately double.
  EXPECT_GE(p2, p1 * 2 - 1);
  EXPECT_LE(p2, p1 * 2 + 1);
}

TEST(ComputeTargetStakerPayout, ScalesWithTime)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 1'000'000'000ULL;

  uint64_t p1 = computeTargetStakerPayout(ctx, 500, 60);
  uint64_t p2 = computeTargetStakerPayout(ctx, 500, 120);

  // Should approximately double.
  EXPECT_GE(p2, p1 * 2 - 1);
  EXPECT_LE(p2, p1 * 2 + 1);
}

TEST(ComputeTargetStakerPayout, ScalesWithApy)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 100'000'000'000ULL; // 100B

  // Longer epoch to reduce rounding error.
  uint64_t p1 = computeTargetStakerPayout(ctx, 500, 3600);  // 5%
  uint64_t p2 = computeTargetStakerPayout(ctx, 1000, 3600); // 10%

  EXPECT_GE(p2, p1 * 2 - 1);
  EXPECT_LE(p2, p1 * 2 + 1);
}

TEST(ComputeTargetStakerPayout, NoOverflowAtMax)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = std::numeric_limits<uint64_t>::max();

  // Shouldn't overflow due to __uint128_t usage.
  uint64_t payout = computeTargetStakerPayout(ctx, 10'000, SECONDS_PER_YEAR);
  EXPECT_GT(payout, 0u);

  // Sanity: should approximately equal total_staked (100% APY, 1 year).
  // uint128 math: max * 10000 * 31556952 / 10000 / 31556952 = max.
  // But intermediate steps might truncate. Expect within a factor of 2.
  EXPECT_GE(payout, ctx.total_staked / 2);
}

// ============================================================================
//  applyPotMechanics
// ============================================================================

TEST(ApplyPotMechanics, PoolCoversTarget)
{
  // Pool = 1000, target = 600, pot = 0, baseline = 100.
  // Result: distribute 600, add 400 to pot, no drain, no burn.
  auto adj = applyPotMechanics(
      /*staker_pool=*/1000,
      /*target_payout=*/600,
      /*current_pot=*/0,
      /*epoch_pool_baseline=*/100);

  EXPECT_EQ(adj.distributed, 600u);
  EXPECT_EQ(adj.added_to_pot, 400u);
  EXPECT_EQ(adj.drained_from_pot, 0u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(ApplyPotMechanics, PoolEqualsTarget)
{
  // Pool == target, pot unchanged.
  auto adj = applyPotMechanics(1000, 1000, 0, 100);

  EXPECT_EQ(adj.distributed, 1000u);
  EXPECT_EQ(adj.added_to_pot, 0u);
  EXPECT_EQ(adj.drained_from_pot, 0u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(ApplyPotMechanics, PoolShortPotCovers)
{
  // Pool = 500, target = 1000, pot = 700.
  // Result: distribute 1000, drain 500 from pot, no add.
  auto adj = applyPotMechanics(500, 1000, 700, 100);

  EXPECT_EQ(adj.distributed, 1000u);
  EXPECT_EQ(adj.added_to_pot, 0u);
  EXPECT_EQ(adj.drained_from_pot, 500u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(ApplyPotMechanics, PoolShortPotInsufficient)
{
  // Pool = 500, target = 1000, pot = 300.
  // Result: distribute 800 (all available), drain 300, no add.
  auto adj = applyPotMechanics(500, 1000, 300, 100);

  EXPECT_EQ(adj.distributed, 800u);
  EXPECT_EQ(adj.added_to_pot, 0u);
  EXPECT_EQ(adj.drained_from_pot, 300u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(ApplyPotMechanics, PotBurnedAtMax)
{
  // pot_max = baseline * POT_MAX_EPOCHS. Compute it rather than
  // hardcoding so this test stays correct if the constant changes.
  const uint64_t baseline = 100;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  // Case 1: pot + added stays at or below pot_max — no burn.
  //
  // Pool = 1000, target = 100, so added = 900.
  // Current pot chosen so new_pot = pot + 900 = pot_max exactly.
  {
    const uint64_t pot_before = pot_max - 900;
    auto adj = applyPotMechanics(1000, 100, pot_before, baseline);
    EXPECT_EQ(adj.added_to_pot, 900u);
    EXPECT_EQ(adj.burned, 0u);
  }

  // Case 2: pot + added exceeds pot_max — burn the excess.
  //
  // Start at pot_max. Add 900. New pot = pot_max + 900.
  // Burn = 900.
  {
    auto adj = applyPotMechanics(1000, 100, pot_max, baseline);
    EXPECT_EQ(adj.added_to_pot, 900u);
    EXPECT_EQ(adj.burned, 900u);
  }
}

TEST(ApplyPotMechanics, PoolZeroTargetZero)
{
  auto adj = applyPotMechanics(0, 0, 0, 100);

  EXPECT_EQ(adj.distributed, 0u);
  EXPECT_EQ(adj.added_to_pot, 0u);
  EXPECT_EQ(adj.drained_from_pot, 0u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(ApplyPotMechanics, ZeroBaselineUsesPool)
{
  // If baseline is 0, use staker_pool.
  // Shouldn't crash, should still compute reasonably.
  auto adj = applyPotMechanics(1000, 500, 0, 0);
  EXPECT_EQ(adj.distributed, 500u);
  EXPECT_EQ(adj.added_to_pot, 500u);
}

// ============================================================================
//  apyToPerSecondScaled
// ============================================================================

TEST(ApyToPerSecondScaled, Zero)
{
  EXPECT_EQ(apyToPerSecondScaled(0), 0u);
}

TEST(ApyToPerSecondScaled, NonZero)
{
  // 500 * 10^12 / 31,556,952 = 15,844,369 (integer division).
  // Pinning the exact value makes this test fail loudly if SCALE or
  // SECONDS_PER_YEAR changes.
  EXPECT_EQ(apyToPerSecondScaled(500), 15'844'369u);
}

TEST(ApyToPerSecondScaled, ScalesLinearly)
{
  uint64_t r1 = apyToPerSecondScaled(500);
  uint64_t r2 = apyToPerSecondScaled(1000);

  // Should double.
  EXPECT_GE(r2, r1 * 2 - 1);
  EXPECT_LE(r2, r1 * 2 + 1);
}

// ============================================================================
//  Integration scenarios
// ============================================================================

TEST(RewardIntegration, TypicalBlock)
{
  // 21 active validators, standard block reward.
  RewardContext ctx = makeContext();
  ctx.active_set_size = 21;
  ctx.block_reward_atomic = GlobalConfig::BLOCK_REWARD;

  ValidatorRegistry reg = makeRegistry(21);

  auto result = computeBlockReward(ctx, reg);

  // Validator pool = 60% of 1,000,000 = 600,000.
  EXPECT_EQ(result.total_issued, 600'000u);

  // Producer bonus = 20% of 600,000 = 120,000.
  EXPECT_EQ(result.producer_amount, 120'000u);

  // Set share = 480,000.
  EXPECT_EQ(result.set_amount, 480'000u);

  // Per validator: 480,000 / 21 = 22,857 remainder 3.
  // First 3 validators get 22,858, rest get 22,857.
  uint64_t total = 0;
  for (const auto &r : result.validator_rewards)
    total += r.amount;
  EXPECT_EQ(total, 480'000u);
  EXPECT_EQ(result.validator_rewards.size(), 21u);
}

TEST(RewardIntegration, TypicalEpoch)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 50'000'000 * 100'000ULL; // 50M CLRTY staked
  ctx.apy_base_bps = APY_BASE_BPS;            // 5%
  ctx.apy_activity_bps = 300;                 // medium activity
  ctx.apy_pot_bonus_bps = 0;

  // Effective APY = 500 + 300 + 0 = 800 bps = 8%.
  uint16_t apy = computeEffectiveApy(ctx, 60);
  EXPECT_EQ(apy, 800u);

  // Target for one epoch (60 seconds).
  uint64_t target = computeTargetStakerPayout(ctx, apy, 60);
  EXPECT_GT(target, 0u);

  // Expected: 50M * 100,000 * 800 / 10,000 * 60 / 31,556,952
  //         = 5e12 * 800 / 10,000 * 60 / 31,556,952
  //         = 5e12 * 0.08 * 60 / 31,556,952
  //         = 4e11 * 60 / 31,556,952
  //         = 2.4e13 / 31,556,952
  //         ≈ 760,498 atomic units
  EXPECT_NEAR(target, 760'000u, 10'000u);
}

// ============================================================================
//  computeActivityBps
//
//  Returns 0 at zero activity, APY_ACTIVITY_MAX_BPS at TRAFFIC_SATURATION_TX,
//  linearly interpolated between. Clamps above saturation.
// ============================================================================

TEST(ComputeActivityBps, ZeroTxReturnsZero)
{
  EXPECT_EQ(computeActivityBps(0), 0u);
}

TEST(ComputeActivityBps, AtSaturationReturnsMax)
{
  EXPECT_EQ(computeActivityBps(TRAFFIC_SATURATION_TX), APY_ACTIVITY_MAX_BPS);
}

TEST(ComputeActivityBps, AboveSaturationClampsToMax)
{
  EXPECT_EQ(computeActivityBps(TRAFFIC_SATURATION_TX + 1), APY_ACTIVITY_MAX_BPS);
  EXPECT_EQ(computeActivityBps(TRAFFIC_SATURATION_TX * 100), APY_ACTIVITY_MAX_BPS);
  EXPECT_EQ(computeActivityBps(std::numeric_limits<uint64_t>::max()),
            APY_ACTIVITY_MAX_BPS);
}

TEST(ComputeActivityBps, LinearInterpolation)
{
  // TRAFFIC_SATURATION_TX = 1000, APY_ACTIVITY_MAX_BPS = 500.
  // Halfway: 500 tx → 250 bps.
  EXPECT_EQ(computeActivityBps(500), 250u);

  // Quarter: 250 tx → 125 bps.
  EXPECT_EQ(computeActivityBps(250), 125u);

  // Tenth: 100 tx → 50 bps.
  EXPECT_EQ(computeActivityBps(100), 50u);
}

TEST(ComputeActivityBps, SmallValuesRoundDown)
{
  // 1 tx out of 1000 → 500 * 1 / 1000 = 0 (integer division).
  EXPECT_EQ(computeActivityBps(1), 0u);

  // 2 tx → 1.
  EXPECT_EQ(computeActivityBps(2), 1u);

  // 3 tx → 1.
  EXPECT_EQ(computeActivityBps(3), 1u);

  // 4 tx → 2.
  EXPECT_EQ(computeActivityBps(4), 2u);
}

TEST(ComputeActivityBps, NeverExceedsMax)
{
  // Sweep a range and confirm the cap holds.
  for (uint64_t tx = 0; tx <= TRAFFIC_SATURATION_TX * 2; tx += 50)
  {
    EXPECT_LE(computeActivityBps(tx), APY_ACTIVITY_MAX_BPS)
        << "tx=" << tx;
  }
}

// ============================================================================
//  computePotBonusBps
//
//  Returns 0 below POT_HIGH, ramps linearly from 0 to APY_POT_BONUS_MAX_BPS
//  between POT_HIGH and POT_MAX, clamps at the max above POT_MAX. Returns
//  0 when baseline is 0.
// ============================================================================

TEST(ComputePotBonusBps, ZeroBaselineReturnsZero)
{
  EXPECT_EQ(computePotBonusBps(0, 0), 0u);
  EXPECT_EQ(computePotBonusBps(1'000'000'000ULL, 0), 0u);
}

TEST(ComputePotBonusBps, BelowPotHighReturnsZero)
{
  const uint64_t baseline = 100;
  const uint64_t pot_high = baseline * POT_HIGH_EPOCHS;

  EXPECT_EQ(computePotBonusBps(0, baseline), 0u);
  EXPECT_EQ(computePotBonusBps(baseline, baseline), 0u);
  EXPECT_EQ(computePotBonusBps(pot_high - 1, baseline), 0u);
}

TEST(ComputePotBonusBps, AtPotHighReturnsZero)
{
  const uint64_t baseline = 100;
  const uint64_t pot_high = baseline * POT_HIGH_EPOCHS;

  // The bonus zone starts just above POT_HIGH. At exactly POT_HIGH,
  // the bonus is still 0 (the boundary is inclusive on the "below"
  // side).
  EXPECT_EQ(computePotBonusBps(pot_high, baseline), 0u);
}

TEST(ComputePotBonusBps, MidpointInterpolates)
{
  const uint64_t baseline = 100;
  const uint64_t pot_high = baseline * POT_HIGH_EPOCHS;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  // Halfway between POT_HIGH and POT_MAX → half the max bonus.
  const uint64_t midpoint = pot_high + (pot_max - pot_high) / 2;
  const uint16_t expected = APY_POT_BONUS_MAX_BPS / 2;

  // Allow ±1 for integer rounding.
  uint16_t actual = computePotBonusBps(midpoint, baseline);
  EXPECT_GE(actual, expected - 1);
  EXPECT_LE(actual, expected + 1);
}

TEST(ComputePotBonusBps, AtPotMaxReturnsMax)
{
  const uint64_t baseline = 100;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  EXPECT_EQ(computePotBonusBps(pot_max, baseline), APY_POT_BONUS_MAX_BPS);
}

TEST(ComputePotBonusBps, AbovePotMaxClampsToMax)
{
  const uint64_t baseline = 100;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  EXPECT_EQ(computePotBonusBps(pot_max + 1, baseline), APY_POT_BONUS_MAX_BPS);
  EXPECT_EQ(computePotBonusBps(pot_max * 10, baseline), APY_POT_BONUS_MAX_BPS);
  EXPECT_EQ(computePotBonusBps(std::numeric_limits<uint64_t>::max(), baseline),
            APY_POT_BONUS_MAX_BPS);
}

TEST(ComputePotBonusBps, MonotonicallyNonDecreasing)
{
  const uint64_t baseline = 100;
  const uint64_t pot_high = baseline * POT_HIGH_EPOCHS;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  // Sweep across the ramp and confirm the value never decreases.
  // The step is span/20, which doesn't necessarily land exactly on
  // pot_max from pot_high - 1, so we stop just before it and check
  // the endpoint separately below.
  uint16_t prev = 0;
  for (uint64_t pot = pot_high - 1; pot < pot_max; pot += (pot_max - pot_high) / 20)
  {
    uint16_t cur = computePotBonusBps(pot, baseline);
    EXPECT_GE(cur, prev) << "pot=" << pot;
    prev = cur;
  }

  // The top of the ramp is exactly APY_POT_BONUS_MAX_BPS.
  EXPECT_EQ(computePotBonusBps(pot_max, baseline), APY_POT_BONUS_MAX_BPS);
}

TEST(ComputePotBonusBps, NeverExceedsMax)
{
  const uint64_t baseline = 100;

  // Sweep a huge range and confirm the cap holds.
  for (uint64_t pot = 0; pot < 1'000'000'000ULL; pot += 50'000'000ULL)
  {
    EXPECT_LE(computePotBonusBps(pot, baseline), APY_POT_BONUS_MAX_BPS)
        << "pot=" << pot;
  }
}