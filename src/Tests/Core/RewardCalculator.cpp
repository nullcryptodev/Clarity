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

// arithmetic helper

TEST(Core_ApplyBps, Zero)
{
  EXPECT_EQ(applyBps(1000, 0), 0u);
  EXPECT_EQ(applyBps(0, 5000), 0u);
}

TEST(Core_ApplyBps, Full)
{
  // 10000 bps = 100%
  EXPECT_EQ(applyBps(1000, 10'000), 1000u);
  EXPECT_EQ(applyBps(0xDEADBEEF, 10'000), 0xDEADBEEFu);
}

TEST(Core_ApplyBps, Half)
{
  EXPECT_EQ(applyBps(1000, 5000), 500u);
  EXPECT_EQ(applyBps(1, 5000), 0u); // rounds down
}

TEST(Core_ApplyBps, NoOverflowAtMax)
{
  // UINT64_MAX * 10000 would overflow uint64 but fits in uint128.
  const uint64_t v = std::numeric_limits<uint64_t>::max();
  EXPECT_EQ(applyBps(v, 10'000), v);
  EXPECT_EQ(applyBps(v, 0), 0u);
}

TEST(Core_ApplyBpsRound, RoundsToNearest)
{
  // 1000 * 250 / 10000 = 25.0 exactly.
  EXPECT_EQ(applyBpsRound(1000, 250), 25u);

  // 1001 * 250 / 10000 = 25.025 → rounds to 25.
  EXPECT_EQ(applyBpsRound(1001, 250), 25u);

  // 2000 * 250 / 10000 = 50.0 exactly.
  EXPECT_EQ(applyBpsRound(2000, 250), 50u);

  // 2001 * 250 / 10000 = 50.025 → rounds to 50.
  EXPECT_EQ(applyBpsRound(2001, 250), 50u);

  // 2010 * 250 / 10000 = 50.25 → rounds to 50.
  EXPECT_EQ(applyBpsRound(2010, 250), 50u);

  // 2020 * 250 / 10000 = 50.5 → rounds to 51.
  EXPECT_EQ(applyBpsRound(2020, 250), 51u);
}

TEST(Core_ComputeBlockReward, EmptyActiveSetReturnsZero)
{
  RewardContext ctx = makeContext();
  ValidatorRegistry registry; // no validators

  auto result = computeBlockReward(ctx, registry);

  EXPECT_EQ(result.total_issued, 0u);
  EXPECT_TRUE(result.validator_rewards.empty());
}

TEST(Core_ComputeBlockReward, ValidatorPoolShare)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 1000;
  ValidatorRegistry registry = makeRegistry(1);

  auto result = computeBlockReward(ctx, registry);

  // Validator pool = VALIDATOR_SHARE_BPS (60%) of 1000.
  EXPECT_EQ(result.total_issued,
            applyBps(1000, GlobalConfig::VALIDATOR_SHARE_BPS));
}

TEST(Core_ComputeBlockReward, ProducerBonusShare)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  ValidatorRegistry registry = makeRegistry(1);

  auto result = computeBlockReward(ctx, registry);

  const uint64_t validator_pool =
      applyBps(10'000, GlobalConfig::VALIDATOR_SHARE_BPS);

  EXPECT_EQ(result.total_issued, validator_pool);
  EXPECT_EQ(result.producer_amount,
            applyBps(validator_pool, GlobalConfig::PRODUCER_BONUS_BPS));
  EXPECT_EQ(result.set_amount,
            applyBps(validator_pool, GlobalConfig::SET_SHARE_BPS));
}

TEST(Core_ComputeBlockReward, SetDistributionSingleValidator)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  ValidatorRegistry registry = makeRegistry(1);

  auto result = computeBlockReward(ctx, registry);

  const uint64_t validator_pool =
      applyBps(10'000, GlobalConfig::VALIDATOR_SHARE_BPS);

  ASSERT_EQ(result.validator_rewards.size(), 1u);
  EXPECT_EQ(result.validator_rewards[0].validator_id, 1u);
  EXPECT_EQ(result.validator_rewards[0].amount,
            applyBps(validator_pool, GlobalConfig::SET_SHARE_BPS));
}

TEST(Core_ComputeBlockReward, SetDistributionMultipleValidators)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  ValidatorRegistry registry = makeRegistry(10);

  auto result = computeBlockReward(ctx, registry);

  const uint64_t set_amount =
      applyBps(applyBps(10'000, GlobalConfig::VALIDATOR_SHARE_BPS),
               GlobalConfig::SET_SHARE_BPS);

  ASSERT_EQ(result.validator_rewards.size(), 10u);

  uint64_t total = 0;
  for (const auto &r : result.validator_rewards)
  {
    EXPECT_EQ(r.amount, set_amount / 10);
    total += r.amount;
  }
  EXPECT_EQ(total, set_amount);
}

TEST(Core_ComputeBlockReward, RemainderDistributedDeterministically)
{
  RewardContext ctx = makeContext();
  ctx.block_reward_atomic = 10'000;
  // Set amount = 4800, 7 validators → 685 each + 5 remainder.
  ValidatorRegistry registry = makeRegistry(7);

  auto result = computeBlockReward(ctx, registry);

  const uint64_t set_amount =
      applyBps(applyBps(10'000, GlobalConfig::VALIDATOR_SHARE_BPS),
               GlobalConfig::SET_SHARE_BPS);
  const uint64_t base = set_amount / 7;
  const uint64_t rem = set_amount % 7;

  ASSERT_EQ(result.validator_rewards.size(), 7u);

  // First `rem` validators get +1 remainder.
  for (size_t i = 0; i < rem; ++i)
  {
    EXPECT_EQ(result.validator_rewards[i].amount, base + 1)
        << "index " << i;
  }
  for (size_t i = rem; i < 7; ++i)
  {
    EXPECT_EQ(result.validator_rewards[i].amount, base)
        << "index " << i;
  }

  uint64_t total = 0;
  for (const auto &r : result.validator_rewards)
    total += r.amount;
  EXPECT_EQ(total, set_amount);
}

TEST(Core_ComputeBlockReward, TotalDistributionEqualsPool)
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

TEST(Core_ComputeBlockReward, ActiveSetIdsMatchOrder)
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

TEST(Core_ComputeEffectiveApy, BaseOnly)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = GlobalConfig::APY_BASE_BPS;
  ctx.apy_activity_bps = 0;
  ctx.apy_pot_bonus_bps = 0;

  EXPECT_EQ(computeEffectiveApy(ctx, 60), GlobalConfig::APY_BASE_BPS);
}

TEST(Core_ComputeEffectiveApy, ActivityAdded)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = GlobalConfig::APY_BASE_BPS;
  ctx.apy_activity_bps = 100; // below cap

  EXPECT_EQ(computeEffectiveApy(ctx, 60),
            GlobalConfig::APY_BASE_BPS + 100);
}

TEST(Core_ComputeEffectiveApy, ActivityCapped)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = GlobalConfig::APY_BASE_BPS;
  ctx.apy_activity_bps = 9999; // exceeds max

  EXPECT_EQ(computeEffectiveApy(ctx, 60),
            GlobalConfig::APY_BASE_BPS + GlobalConfig::APY_ACTIVITY_MAX_BPS);
}

TEST(Core_ComputeEffectiveApy, PotBonusAdded)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = GlobalConfig::APY_BASE_BPS;
  ctx.apy_pot_bonus_bps = 100;

  EXPECT_EQ(computeEffectiveApy(ctx, 60),
            GlobalConfig::APY_BASE_BPS + 100);
}

TEST(Core_ComputeEffectiveApy, PotBonusCapped)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = GlobalConfig::APY_BASE_BPS;
  ctx.apy_pot_bonus_bps = 9999; // exceeds max

  EXPECT_EQ(computeEffectiveApy(ctx, 60),
            GlobalConfig::APY_BASE_BPS + GlobalConfig::APY_POT_BONUS_MAX_BPS);
}

TEST(Core_ComputeEffectiveApy, AllComponentsMax)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = GlobalConfig::APY_BASE_BPS;
  ctx.apy_activity_bps = GlobalConfig::APY_ACTIVITY_MAX_BPS;
  ctx.apy_pot_bonus_bps = GlobalConfig::APY_POT_BONUS_MAX_BPS;

  EXPECT_EQ(computeEffectiveApy(ctx, 60),
            GlobalConfig::APY_BASE_BPS +
                GlobalConfig::APY_ACTIVITY_MAX_BPS +
                GlobalConfig::APY_POT_BONUS_MAX_BPS);
}

TEST(Core_ComputeEffectiveApy, Uint16Cap)
{
  RewardContext ctx = makeContext();
  ctx.apy_base_bps = 60'000;
  ctx.apy_activity_bps = GlobalConfig::APY_ACTIVITY_MAX_BPS;
  ctx.apy_pot_bonus_bps = GlobalConfig::APY_POT_BONUS_MAX_BPS;

  // 60000 + APY_ACTIVITY_MAX_BPS + APY_POT_BONUS_MAX_BPS.
  EXPECT_EQ(computeEffectiveApy(ctx, 60),
            60'000u +
                GlobalConfig::APY_ACTIVITY_MAX_BPS +
                GlobalConfig::APY_POT_BONUS_MAX_BPS);
}

TEST(Core_ComputeTargetStakerPayout, ZeroStake)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 0;

  EXPECT_EQ(computeTargetStakerPayout(ctx, 500, 60), 0u);
}

TEST(Core_ComputeTargetStakerPayout, ZeroApy)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 1'000'000;

  EXPECT_EQ(computeTargetStakerPayout(ctx, 0, 60), 0u);
}

TEST(Core_ComputeTargetStakerPayout, BasicCase)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 1'000'000'000ULL; // 1B atomic units

  // APY = 500 bps = 5%. Epoch = 60 seconds.
  // Target = 1e9 * 500 / 10000 * 60 / 31556952
  //        = 3e9 / 31556952
  //        = 95 (integer division)
  uint64_t payout = computeTargetStakerPayout(ctx, 500, 60);
  EXPECT_EQ(payout, 95u);
}

TEST(Core_ComputeTargetStakerPayout, ScalesWithStake)
{
  RewardContext ctx = makeContext();

  ctx.total_staked = 1'000'000'000ULL;
  uint64_t p1 = computeTargetStakerPayout(ctx, 500, 60);

  ctx.total_staked = 2'000'000'000ULL;
  uint64_t p2 = computeTargetStakerPayout(ctx, 500, 60);

  EXPECT_GE(p2, p1 * 2 - 1);
  EXPECT_LE(p2, p1 * 2 + 1);
}

TEST(Core_ComputeTargetStakerPayout, ScalesWithTime)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 1'000'000'000ULL;

  uint64_t p1 = computeTargetStakerPayout(ctx, 500, 60);
  uint64_t p2 = computeTargetStakerPayout(ctx, 500, 120);

  EXPECT_GE(p2, p1 * 2 - 1);
  EXPECT_LE(p2, p1 * 2 + 1);
}

TEST(Core_ComputeTargetStakerPayout, ScalesWithApy)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 100'000'000'000ULL;

  uint64_t p1 = computeTargetStakerPayout(ctx, 500, 3600);
  uint64_t p2 = computeTargetStakerPayout(ctx, 1000, 3600);

  EXPECT_GE(p2, p1 * 2 - 1);
  EXPECT_LE(p2, p1 * 2 + 1);
}

TEST(Core_ComputeTargetStakerPayout, NoOverflowAtMax)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = std::numeric_limits<uint64_t>::max();

  uint64_t payout = computeTargetStakerPayout(ctx, 10'000, SECONDS_PER_YEAR);
  EXPECT_GT(payout, 0u);

  EXPECT_GE(payout, ctx.total_staked / 2);
}

TEST(Core_ApplyPotMechanics, PoolCoversTarget)
{
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

TEST(Core_ApplyPotMechanics, PoolEqualsTarget)
{
  auto adj = applyPotMechanics(1000, 1000, 0, 100);

  EXPECT_EQ(adj.distributed, 1000u);
  EXPECT_EQ(adj.added_to_pot, 0u);
  EXPECT_EQ(adj.drained_from_pot, 0u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(Core_ApplyPotMechanics, PoolShortPotCovers)
{
  auto adj = applyPotMechanics(500, 1000, 700, 100);

  EXPECT_EQ(adj.distributed, 1000u);
  EXPECT_EQ(adj.added_to_pot, 0u);
  EXPECT_EQ(adj.drained_from_pot, 500u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(Core_ApplyPotMechanics, PoolShortPotInsufficient)
{
  auto adj = applyPotMechanics(500, 1000, 300, 100);

  EXPECT_EQ(adj.distributed, 800u);
  EXPECT_EQ(adj.added_to_pot, 0u);
  EXPECT_EQ(adj.drained_from_pot, 300u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(Core_ApplyPotMechanics, PotBurnedAtMax)
{
  const uint64_t baseline = 100;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  {
    const uint64_t pot_before = pot_max - 900;
    auto adj = applyPotMechanics(1000, 100, pot_before, baseline);
    EXPECT_EQ(adj.added_to_pot, 900u);
    EXPECT_EQ(adj.burned, 0u);
  }

  {
    auto adj = applyPotMechanics(1000, 100, pot_max, baseline);
    EXPECT_EQ(adj.added_to_pot, 900u);
    EXPECT_EQ(adj.burned, 900u);
  }
}

TEST(Core_ApplyPotMechanics, PoolZeroTargetZero)
{
  auto adj = applyPotMechanics(0, 0, 0, 100);

  EXPECT_EQ(adj.distributed, 0u);
  EXPECT_EQ(adj.added_to_pot, 0u);
  EXPECT_EQ(adj.drained_from_pot, 0u);
  EXPECT_EQ(adj.burned, 0u);
}

TEST(Core_ApplyPotMechanics, ZeroBaselineUsesPool)
{
  auto adj = applyPotMechanics(1000, 500, 0, 0);
  EXPECT_EQ(adj.distributed, 500u);
  EXPECT_EQ(adj.added_to_pot, 500u);
}

TEST(Core_ApyToPerSecondScaled, Zero)
{
  EXPECT_EQ(apyToPerSecondScaled(0), 0u);
}

TEST(Core_ApyToPerSecondScaled, NonZero)
{
  // 500 * 10^12 / 31,556,952 = 15,844,369 (integer division).
  // This pins the exact value; if SCALE or SECONDS_PER_YEAR changes
  // this test will fail and must be recomputed.
  EXPECT_EQ(apyToPerSecondScaled(500), 15'844'369u);
}

TEST(Core_ApyToPerSecondScaled, ScalesLinearly)
{
  uint64_t r1 = apyToPerSecondScaled(500);
  uint64_t r2 = apyToPerSecondScaled(1000);

  EXPECT_GE(r2, r1 * 2 - 1);
  EXPECT_LE(r2, r1 * 2 + 1);
}

// Integration scenarios

TEST(Core_RewardIntegration, TypicalBlock)
{
  // 21 active validators, standard block reward.
  RewardContext ctx = makeContext();
  ctx.active_set_size = 21;
  ctx.block_reward_atomic = GlobalConfig::BLOCK_REWARD;

  ValidatorRegistry reg = makeRegistry(21);

  auto result = computeBlockReward(ctx, reg);

  // Every expectation is derived from GlobalConfig::BLOCK_REWARD so
  // this test does not go stale if DECIMALS or the block-reward
  // constant changes again.
  const uint64_t validator_pool =
      applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::VALIDATOR_SHARE_BPS);
  const uint64_t producer = applyBps(validator_pool,
                                     GlobalConfig::PRODUCER_BONUS_BPS);
  const uint64_t set_amount = applyBps(validator_pool,
                                       GlobalConfig::SET_SHARE_BPS);

  EXPECT_EQ(result.total_issued, validator_pool);
  EXPECT_EQ(result.producer_amount, producer);
  EXPECT_EQ(result.set_amount, set_amount);

  uint64_t total = 0;
  for (const auto &r : result.validator_rewards)
    total += r.amount;
  EXPECT_EQ(total, set_amount);
  EXPECT_EQ(result.validator_rewards.size(), 21u);
}

TEST(Core_RewardIntegration, TypicalEpoch)
{
  RewardContext ctx = makeContext();
  ctx.total_staked = 50'000'000 * GlobalConfig::ATOMIC_UNITS_PER_COIN;
  ctx.apy_base_bps = GlobalConfig::APY_BASE_BPS;
  ctx.apy_activity_bps = 100;
  ctx.apy_pot_bonus_bps = 0;

  // Effective APY = APY_BASE_BPS + 100.
  const uint16_t expected_apy =
      GlobalConfig::APY_BASE_BPS + 100;
  uint16_t apy = computeEffectiveApy(ctx, 60);
  EXPECT_EQ(apy, expected_apy);

  uint64_t target = computeTargetStakerPayout(ctx, apy, 60);
  EXPECT_GT(target, 0u);

  // Recompute the expected target in the same integer arithmetic the
  // calculator uses, so the test tracks the constants.
  const __uint128_t numerator =
      static_cast<__uint128_t>(ctx.total_staked) * apy * 60;
  const __uint128_t denominator =
      static_cast<__uint128_t>(10'000) * SECONDS_PER_YEAR;
  const uint64_t expected = static_cast<uint64_t>(numerator / denominator);

  EXPECT_EQ(target, expected);
}

TEST(Core_ComputeActivityBps, ZeroTxReturnsZero)
{
  EXPECT_EQ(computeActivityBps(0), 0u);
}

TEST(Core_ComputeActivityBps, AtSaturationReturnsMax)
{
  EXPECT_EQ(computeActivityBps(TRAFFIC_SATURATION_TX),
            GlobalConfig::APY_ACTIVITY_MAX_BPS);
}

TEST(Core_ComputeActivityBps, AboveSaturationClampsToMax)
{
  EXPECT_EQ(computeActivityBps(TRAFFIC_SATURATION_TX + 1),
            GlobalConfig::APY_ACTIVITY_MAX_BPS);
  EXPECT_EQ(computeActivityBps(TRAFFIC_SATURATION_TX * 100),
            GlobalConfig::APY_ACTIVITY_MAX_BPS);
  EXPECT_EQ(computeActivityBps(std::numeric_limits<uint64_t>::max()),
            GlobalConfig::APY_ACTIVITY_MAX_BPS);
}

TEST(Core_ComputeActivityBps, LinearInterpolation)
{
  // Halfway through the saturation window the bonus is half the max.
  // Expressed against the constants so a future change to
  // APY_ACTIVITY_MAX_BPS doesn't break the test.
  const uint64_t half = TRAFFIC_SATURATION_TX / 2;
  const uint64_t quarter = TRAFFIC_SATURATION_TX / 4;
  const uint64_t tenth = TRAFFIC_SATURATION_TX / 10;

  EXPECT_EQ(computeActivityBps(half),
            applyBps(GlobalConfig::APY_ACTIVITY_MAX_BPS, half * 10'000 / TRAFFIC_SATURATION_TX));
  EXPECT_EQ(computeActivityBps(quarter),
            applyBps(GlobalConfig::APY_ACTIVITY_MAX_BPS, quarter * 10'000 / TRAFFIC_SATURATION_TX));
  EXPECT_EQ(computeActivityBps(tenth),
            applyBps(GlobalConfig::APY_ACTIVITY_MAX_BPS, tenth * 10'000 / TRAFFIC_SATURATION_TX));

  // Anchor the exact expected values under the current config.
  EXPECT_EQ(computeActivityBps(half),
            GlobalConfig::APY_ACTIVITY_MAX_BPS / 2);
  EXPECT_EQ(computeActivityBps(quarter),
            GlobalConfig::APY_ACTIVITY_MAX_BPS / 4);
  EXPECT_EQ(computeActivityBps(tenth),
            GlobalConfig::APY_ACTIVITY_MAX_BPS / 10);
}

TEST(Core_ComputeActivityBps, SmallValuesRoundDown)
{
  // 1 tx out of TRAFFIC_SATURATION_TX → APY_ACTIVITY_MAX_BPS / TRAFFIC_SATURATION_TX,
  // which rounds down to 0 for the small inputs.
  EXPECT_EQ(computeActivityBps(1), 0u);

  // 2 tx → 300 * 2 / 1000 = 0.
  EXPECT_EQ(computeActivityBps(2), 0u);

  // 3 tx → 300 * 3 / 1000 = 0.
  EXPECT_EQ(computeActivityBps(3), 0u);

  // 4 tx → 300 * 4 / 1000 = 1.
  EXPECT_EQ(computeActivityBps(4), 1u);
}

TEST(Core_ComputeActivityBps, NeverExceedsMax)
{
  for (uint64_t tx = 0; tx <= TRAFFIC_SATURATION_TX * 2; tx += 50)
  {
    EXPECT_LE(computeActivityBps(tx), GlobalConfig::APY_ACTIVITY_MAX_BPS)
        << "tx=" << tx;
  }
}

TEST(Core_ComputePotBonusBps, ZeroBaselineReturnsZero)
{
  EXPECT_EQ(computePotBonusBps(0, 0), 0u);
  EXPECT_EQ(computePotBonusBps(1'000'000'000ULL, 0), 0u);
}

TEST(Core_ComputePotBonusBps, BelowPotHighReturnsZero)
{
  const uint64_t baseline = 100;
  const uint64_t pot_high = baseline * POT_HIGH_EPOCHS;

  EXPECT_EQ(computePotBonusBps(0, baseline), 0u);
  EXPECT_EQ(computePotBonusBps(baseline, baseline), 0u);
  EXPECT_EQ(computePotBonusBps(pot_high - 1, baseline), 0u);
}

TEST(Core_ComputePotBonusBps, AtPotHighReturnsZero)
{
  const uint64_t baseline = 100;
  const uint64_t pot_high = baseline * POT_HIGH_EPOCHS;

  EXPECT_EQ(computePotBonusBps(pot_high, baseline), 0u);
}

TEST(Core_ComputePotBonusBps, MidpointInterpolates)
{
  const uint64_t baseline = 100;
  const uint64_t pot_high = baseline * POT_HIGH_EPOCHS;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  const uint64_t midpoint = pot_high + (pot_max - pot_high) / 2;
  const uint16_t expected = GlobalConfig::APY_POT_BONUS_MAX_BPS / 2;

  uint16_t actual = computePotBonusBps(midpoint, baseline);
  EXPECT_GE(actual, expected - 1);
  EXPECT_LE(actual, expected + 1);
}

TEST(Core_ComputePotBonusBps, AtPotMaxReturnsMax)
{
  const uint64_t baseline = 100;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  EXPECT_EQ(computePotBonusBps(pot_max, baseline),
            GlobalConfig::APY_POT_BONUS_MAX_BPS);
}

TEST(Core_ComputePotBonusBps, AbovePotMaxClampsToMax)
{
  const uint64_t baseline = 100;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  EXPECT_EQ(computePotBonusBps(pot_max + 1, baseline),
            GlobalConfig::APY_POT_BONUS_MAX_BPS);
  EXPECT_EQ(computePotBonusBps(pot_max * 10, baseline),
            GlobalConfig::APY_POT_BONUS_MAX_BPS);
  EXPECT_EQ(computePotBonusBps(std::numeric_limits<uint64_t>::max(), baseline),
            GlobalConfig::APY_POT_BONUS_MAX_BPS);
}

TEST(Core_ComputePotBonusBps, MonotonicallyNonDecreasing)
{
  const uint64_t baseline = 100;
  const uint64_t pot_high = baseline * POT_HIGH_EPOCHS;
  const uint64_t pot_max = baseline * POT_MAX_EPOCHS;

  uint16_t prev = 0;
  for (uint64_t pot = pot_high - 1; pot < pot_max;
       pot += (pot_max - pot_high) / 20)
  {
    uint16_t cur = computePotBonusBps(pot, baseline);
    EXPECT_GE(cur, prev) << "pot=" << pot;
    prev = cur;
  }

  EXPECT_EQ(computePotBonusBps(pot_max, baseline),
            GlobalConfig::APY_POT_BONUS_MAX_BPS);
}

TEST(Core_ComputePotBonusBps, NeverExceedsMax)
{
  const uint64_t baseline = 100;

  for (uint64_t pot = 0; pot < 1'000'000'000ULL; pot += 50'000'000ULL)
  {
    EXPECT_LE(computePotBonusBps(pot, baseline),
              GlobalConfig::APY_POT_BONUS_MAX_BPS)
        << "pot=" << pot;
  }
}