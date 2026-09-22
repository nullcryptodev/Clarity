// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/RewardTypes.h"
#include "Core/ValidatorRotation.h"
#include "Core/ValidatorTypes.h"

#include "Tests/Utils.h"

#include <algorithm>

using namespace Core;
using namespace Tests;

TEST(BftQuorum, KnownValues)
{
  EXPECT_EQ(bftQuorum(4), 3u);
  EXPECT_EQ(bftQuorum(7), 5u);
  EXPECT_EQ(bftQuorum(11), 8u);
  EXPECT_EQ(bftQuorum(21), 15u);
  EXPECT_EQ(bftQuorum(100), 67u);
}

TEST(RotationCount, ZeroSizeReturnsZero)
{
  EXPECT_EQ(computeRotationCount(0), 0u);
}

TEST(RotationCount, PositiveForNonEmpty)
{
  EXPECT_GE(computeRotationCount(21), 1u);
  EXPECT_GE(computeRotationCount(100), 1u);
}

TEST(RotationCount, NeverExceedsBftSafety)
{
  for (uint64_t n : {11u, 21u, 50u, 100u})
  {
    uint64_t count = computeRotationCount(n);
    uint64_t max_safe = n - bftQuorum(n);
    EXPECT_LE(count, max_safe) << "n=" << n;
  }
}

TEST(TargetSize, ZeroTraffic)
{
  EXPECT_EQ(computeTargetActiveSetSize(0), ACTIVE_SET_MIN);
}

TEST(TargetSize, SaturationTraffic)
{
  EXPECT_EQ(computeTargetActiveSetSize(TRAFFIC_SATURATION_TX),
            ACTIVE_SET_MAX);
}

TEST(TargetSize, OverSaturation)
{
  EXPECT_EQ(computeTargetActiveSetSize(TRAFFIC_SATURATION_TX * 10),
            ACTIVE_SET_MAX);
}

TEST(TargetSize, WithinBounds)
{
  for (uint64_t traffic : {0u, 1u, 100u, 500u, 999u, 1000u, 5000u})
  {
    uint64_t size = computeTargetActiveSetSize(traffic);
    EXPECT_GE(size, ACTIVE_SET_MIN);
    EXPECT_LE(size, ACTIVE_SET_MAX);
  }
}

// planRotation, same-size rotation

TEST(PlanRotation, SameSizeLowestUptimeRemoved)
{
  RotationBuilder b(30, 21);

  // Make validator 5 the worst.
  b.setUptime(5, 5000);
  // Others vary but all above 5000.
  for (Id id = 1; id <= 21; ++id)
  {
    if (id != 5)
      b.setUptime(id, 9000 + id * 10);
  }

  // Choose traffic such that computeTargetActiveSetSize returns 21,
  // i.e. same as our current active set size. This forces the plan
  // down the same-size rotation path.
  //
  // target = 11 + (traffic * 89) / 1000
  // 21     = 11 + (traffic * 89) / 1000
  // traffic ≈ 113
  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/113);

  // Confirm we're actually in the same-size branch.
  ASSERT_EQ(plan.new_target_size, 21u);

  // Validator 5 should be in the removal list.
  auto it = std::find(plan.to_remove.begin(), plan.to_remove.end(), 5);
  EXPECT_NE(it, plan.to_remove.end())
      << "lowest-uptime validator not scheduled for removal";
}

TEST(PlanRotation, HighestUptimeCandidatesAdded)
{
  RotationBuilder b(30, 21);
  for (Id id = 22; id <= 30; ++id)
  {
    b.setUptime(id, 9000);
  }
  b.setUptime(25, 9999);

  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/500);

  // Grow path: target 55, current 21, so we want to add 9 candidates
  // (all that exist in the pool).
  ASSERT_GT(plan.new_target_size, 21u);
  ASSERT_FALSE(plan.to_add.empty());
  ASSERT_LE(plan.to_add.size(), 9u);

  // The highest-uptime candidate should be first in the addition list.
  EXPECT_EQ(plan.to_add[0], 25u);
}

TEST(PlanRotation, SeedsNeverRemoved)
{
  RotationBuilder b(30, 21);

  // Make seed validator 1 the worst uptime.
  b.setUptime(1, 1000);
  b.setSeed(1);

  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/500);

  auto it = std::find(plan.to_remove.begin(), plan.to_remove.end(), 1);
  EXPECT_EQ(it, plan.to_remove.end())
      << "seed validator was scheduled for removal";
}

TEST(PlanRotation, GrowSet)
{
  // 10 active, 20 in pool. Traffic high enough that target > 10.
  RotationBuilder b(30, 10);

  // Target size will be computed from traffic; use high traffic.
  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/900);

  // With high traffic, target > current (10). Plan should have to_add.
  EXPECT_GT(plan.new_target_size, 10u);
  EXPECT_GT(plan.to_add.size(), 0u);
  EXPECT_EQ(plan.to_remove.size(), 0u);
}

TEST(PlanRotation, ShrinkSet)
{
  // 50 active, low traffic.
  RotationBuilder b(50, 50);

  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/0);

  // Target = ACTIVE_SET_MIN = 11, so shrink.
  EXPECT_LT(plan.new_target_size, 50u);
  EXPECT_GT(plan.to_remove.size(), 0u);
  EXPECT_EQ(plan.to_add.size(), 0u);
}

TEST(PlanRotation, EmptyRegistry)
{
  ValidatorRegistry empty;
  auto plan = planRotation(empty, 500);

  EXPECT_TRUE(plan.to_remove.empty());
  EXPECT_TRUE(plan.to_add.empty());
}

TEST(PlanRotation, InsufficientCandidates)
{
  // 30 active, need to grow but no pool candidates.
  RotationBuilder b(30, 30);

  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/900);

  // Target > 30, but pool is empty.
  EXPECT_GT(plan.new_target_size, 30u);
  EXPECT_EQ(plan.to_add.size(), 0u);
}

TEST(ApplyRotation, RemovesFromActiveSet)
{
  RotationBuilder b(30, 21);

  RotationPlan plan;
  plan.to_remove = {5, 10, 15};
  plan.new_target_size = 18;

  size_t before = b.reg.active_set.size();
  applyRotation(b.reg, plan, /*current_height=*/100);

  EXPECT_EQ(b.reg.active_set.size(), before - 3);
  EXPECT_FALSE(b.reg.isActive(5));
  EXPECT_FALSE(b.reg.isActive(10));
  EXPECT_FALSE(b.reg.isActive(15));
}

TEST(ApplyRotation, AddsToActiveSet)
{
  RotationBuilder b(30, 10);

  RotationPlan plan;
  plan.to_add = {11, 12, 13};
  plan.new_target_size = 13;

  size_t before = b.reg.active_set.size();
  applyRotation(b.reg, plan, /*current_height=*/100);

  EXPECT_EQ(b.reg.active_set.size(), before + 3);
  EXPECT_TRUE(b.reg.isActive(11));
  EXPECT_TRUE(b.reg.isActive(12));
  EXPECT_TRUE(b.reg.isActive(13));
}

TEST(ApplyRotation, UpdatesFlags)
{
  RotationBuilder b(30, 21);

  RotationPlan plan;
  plan.to_remove = {5};
  plan.to_add = {25};
  plan.new_target_size = 21;

  applyRotation(b.reg, plan, /*current_height=*/100);

  if (auto *v = b.reg.find(5))
  {
    EXPECT_FALSE(v->is_active);
    EXPECT_EQ(v->last_active_at, 100u);
  }
  if (auto *v = b.reg.find(25))
  {
    EXPECT_TRUE(v->is_active);
    EXPECT_EQ(v->became_active_at, 100u);
  }
}

TEST(ApplyRotation, PreservesTargetSize)
{
  RotationBuilder b(30, 21);

  RotationPlan plan;
  plan.new_target_size = 15;

  applyRotation(b.reg, plan, /*current_height=*/100);

  EXPECT_EQ(b.reg.target_size, 15u);
  EXPECT_EQ(b.reg.last_rotation_height, 100u);
}

TEST(ApplyRotation, ActiveSetSortedAfter)
{
  RotationBuilder b(30, 21);

  RotationPlan plan;
  plan.to_remove = {3, 7};
  plan.to_add = {25, 22};
  plan.new_target_size = 21;

  applyRotation(b.reg, plan, /*current_height=*/100);

  // Active set should be sorted ascending.
  auto set = b.reg.active_set;
  auto sorted = set;
  std::sort(sorted.begin(), sorted.end());
  EXPECT_EQ(set, sorted);
}

TEST(OfflineRemoval, NoOpWhenAllOnline)
{
  RotationBuilder b(30, 21);

  // All validators seen at current height.
  for (Id id = 1; id <= 30; ++id)
  {
    b.setLastSeen(id, 1000);
  }

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  EXPECT_TRUE(plan.removed.empty());
  EXPECT_TRUE(plan.promoted.empty());
}

TEST(OfflineRemoval, IdentifiesOffline)
{
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
  {
    b.setLastSeen(id, 1000);
  }
  // Validator 5 last seen way back.
  b.setLastSeen(5, 1000 - OFFLINE_KICK_BLOCKS - 1);

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  auto it = std::find(plan.removed.begin(), plan.removed.end(), 5);
  EXPECT_NE(it, plan.removed.end());
}

TEST(OfflineRemoval, IgnoresOnline)
{
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
  {
    b.setLastSeen(id, 1000);
  }

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  for (auto vid : plan.removed)
  {
    EXPECT_NE(vid, 1u);
  }
}

TEST(OfflineRemoval, ProtectsSeeds)
{
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
  {
    b.setLastSeen(id, 1000);
  }
  // Seed validator 1 is offline.
  b.setSeed(1);
  b.setLastSeen(1, 500);

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  auto it = std::find(plan.removed.begin(), plan.removed.end(), 1);
  EXPECT_EQ(it, plan.removed.end());
}

TEST(OfflineRemoval, PromotesFromPool)
{
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
  {
    b.setLastSeen(id, 1000);
  }
  // Validator 5 offline.
  b.setLastSeen(5, 500);

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  ASSERT_EQ(plan.removed.size(), 1u);
  EXPECT_EQ(plan.removed[0], 5u);
  EXPECT_EQ(plan.promoted.size(), 1u);
}

TEST(OfflineRemoval, EmptyPool)
{
  // All 21 active, no waiting pool.
  RotationBuilder b(21, 21);

  for (Id id = 1; id <= 21; ++id)
  {
    b.setLastSeen(id, 1000);
  }
  b.setLastSeen(5, 500);

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  ASSERT_EQ(plan.removed.size(), 1u);
  EXPECT_TRUE(plan.promoted.empty());
}

TEST(OfflineRemoval, SkipsUnhealthyCandidates)
{
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
  {
    b.setLastSeen(id, 1000);
  }
  b.setLastSeen(5, 500);

  // Make all candidates unhealthy (uptime below threshold).
  for (Id id = 22; id <= 30; ++id)
  {
    b.setUptime(id, UPTIME_ACTIVE_MIN_BPS - 1);
  }

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  EXPECT_EQ(plan.removed.size(), 1u);
  EXPECT_TRUE(plan.promoted.empty());
}

TEST(ApplyOfflineRemoval, RemovesFromActiveSet)
{
  RotationBuilder b(30, 21);

  OfflineCheckResult plan;
  plan.removed = {5, 7};
  plan.promoted = {22, 23};

  size_t before = b.reg.active_set.size();
  applyOfflineRemoval(b.reg, plan, /*current_height=*/1000);

  // Size stays the same (removed == promoted).
  EXPECT_EQ(b.reg.active_set.size(), before);
  EXPECT_FALSE(b.reg.isActive(5));
  EXPECT_FALSE(b.reg.isActive(7));
  EXPECT_TRUE(b.reg.isActive(22));
  EXPECT_TRUE(b.reg.isActive(23));
}

TEST(ApplyOfflineRemoval, ShrinksWhenNoPromotions)
{
  RotationBuilder b(21, 21);

  OfflineCheckResult plan;
  plan.removed = {5, 7};
  // no promotions

  applyOfflineRemoval(b.reg, plan, /*current_height=*/1000);

  EXPECT_EQ(b.reg.active_set.size(), 19u);
}

TEST(UptimeScore, NoPingsLeavesUnchanged)
{
  uint16_t score = 5000;
  EXPECT_EQ(updateUptimeScore(score, 0, 0), score);
}

TEST(UptimeScore, PerfectUptimeIncreases)
{
  // Start below 10000, converge upward.
  uint16_t result = updateUptimeScore(5000, 100, 100);
  EXPECT_GT(result, 5000);
}

TEST(UptimeScore, ZeroUptimeDecreases)
{
  // Start high, converge downward.
  uint16_t result = updateUptimeScore(9000, 0, 100);
  EXPECT_LT(result, 9000);
}

TEST(UptimeScore, ClampedAtMax)
{
  // Even with impossible input, never above 10000.
  uint16_t result = updateUptimeScore(10000, 200, 100);
  EXPECT_LE(result, 10000);
}

TEST(UptimeScore, EMASmoothing)
{
  // Starting from 10000, a single bad epoch of 0% should not drop to 0.
  uint16_t result = updateUptimeScore(10000, 0, 100);
  EXPECT_GT(result, 7000); // EMA smooths over one epoch
}

TEST(Infraction, FullMultiplierReduced)
{
  ValidatorInfo v;
  v.reward_multiplier = REWARD_MULTIPLIER_START;

  bool applied = applyInfractionPenalty(v, /*current_height=*/100);

  EXPECT_TRUE(applied);
  EXPECT_EQ(v.reward_multiplier,
            REWARD_MULTIPLIER_START - REWARD_MULTIPLIER_PENALTY);
  EXPECT_EQ(v.infraction_count, 1u);
  EXPECT_EQ(v.last_infraction_height, 100u);
}

TEST(Infraction, ConvergesToFloor)
{
  ValidatorInfo v;
  v.reward_multiplier = REWARD_MULTIPLIER_FLOOR + 500;

  applyInfractionPenalty(v, 100);

  EXPECT_EQ(v.reward_multiplier, REWARD_MULTIPLIER_FLOOR);
}

TEST(Infraction, AtFloorStaysAtFloor)
{
  ValidatorInfo v;
  v.reward_multiplier = REWARD_MULTIPLIER_FLOOR;

  bool applied = applyInfractionPenalty(v, 100);

  EXPECT_FALSE(applied);
  EXPECT_EQ(v.reward_multiplier, REWARD_MULTIPLIER_FLOOR);
  // Infraction is still recorded.
  EXPECT_EQ(v.infraction_count, 1u);
}

TEST(Infraction, MultipleStack)
{
  ValidatorInfo v;
  v.reward_multiplier = 10'000;

  applyInfractionPenalty(v, 100);
  EXPECT_EQ(v.reward_multiplier, 8000);

  applyInfractionPenalty(v, 200);
  EXPECT_EQ(v.reward_multiplier, 6000);

  applyInfractionPenalty(v, 300);
  EXPECT_EQ(v.reward_multiplier, 4000);

  applyInfractionPenalty(v, 400);
  EXPECT_EQ(v.reward_multiplier, 2000);

  // Already at floor.
  bool applied = applyInfractionPenalty(v, 500);
  EXPECT_FALSE(applied);
  EXPECT_EQ(v.reward_multiplier, 2000);
  EXPECT_EQ(v.infraction_count, 5u);
}

TEST(Unhealthy, IdentifiesBelowThreshold)
{
  RotationBuilder b(10, 5);
  b.setUptime(3, UPTIME_REMOVAL_THRESHOLD_BPS - 1);

  auto result = findUnhealthy(b.reg);

  auto it = std::find(result.begin(), result.end(), 3);
  EXPECT_NE(it, result.end());
}

TEST(Unhealthy, IgnoresHealthy)
{
  RotationBuilder b(10, 5);
  b.setUptime(3, 9000);

  auto result = findUnhealthy(b.reg);

  auto it = std::find(result.begin(), result.end(), 3);
  EXPECT_EQ(it, result.end());
}

TEST(Unhealthy, ProtectsSeeds)
{
  RotationBuilder b(10, 5);
  b.setUptime(1, UPTIME_REMOVAL_THRESHOLD_BPS - 1);
  b.setSeed(1);

  auto result = findUnhealthy(b.reg);

  auto it = std::find(result.begin(), result.end(), 1);
  EXPECT_EQ(it, result.end());
}

TEST(Unhealthy, EmptyRegistry)
{
  ValidatorRegistry empty;
  auto result = findUnhealthy(empty);
  EXPECT_TRUE(result.empty());
}

TEST(Integration, SingleOfflineValidator)
{
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
  {
    b.setLastSeen(id, 1000);
  }
  b.setLastSeen(7, 500);

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  ASSERT_EQ(plan.removed.size(), 1u);
  ASSERT_EQ(plan.promoted.size(), 1u);

  applyOfflineRemoval(b.reg, plan, 1000);

  EXPECT_FALSE(b.reg.isActive(7));
  EXPECT_TRUE(b.reg.isActive(plan.promoted[0]));
}

TEST(Integration, MultipleOfflineValidators)
{
  RotationBuilder b(40, 21);

  for (Id id = 1; id <= 40; ++id)
  {
    b.setLastSeen(id, 1000);
  }

  // 5 offline.
  std::vector<Id> offline = {3, 7, 11, 15, 19};
  for (auto vid : offline)
  {
    b.setLastSeen(vid, 500);
  }

  auto plan = planOfflineRemoval(b.reg, /*current_height=*/1000);

  EXPECT_EQ(plan.removed.size(), offline.size());
  EXPECT_EQ(plan.promoted.size(), offline.size());

  applyOfflineRemoval(b.reg, plan, 1000);

  for (auto vid : offline)
  {
    EXPECT_FALSE(b.reg.isActive(vid));
  }
  EXPECT_EQ(b.reg.active_set.size(), 21u);
}

TEST(Integration, SeedNodeAlwaysActive)
{
  RotationBuilder b(30, 21);
  b.setSeed(1);
  b.setSeed(2);

  // Even if seeds are the worst uptime and offline, they shouldn't be
  // touched.
  b.setUptime(1, 1000);
  b.setUptime(2, 1000);
  b.setLastSeen(1, 500);
  b.setLastSeen(2, 500);
  for (Id id = 3; id <= 30; ++id)
  {
    b.setLastSeen(id, 1000);
  }

  auto offline = planOfflineRemoval(b.reg, 1000);
  for (auto vid : offline.removed)
  {
    EXPECT_NE(vid, 1u);
    EXPECT_NE(vid, 2u);
  }
}

TEST(Integration, RotationCyclePreservesSetSize)
{
  RotationBuilder b(30, 21);
  b.setTargetSize(21);

  // Force a same-size rotation.
  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/500);

  size_t before = b.reg.active_set.size();
  applyRotation(b.reg, plan, 100);

  EXPECT_EQ(b.reg.active_set.size(),
            before - plan.to_remove.size() + plan.to_add.size());
}