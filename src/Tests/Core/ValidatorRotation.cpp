// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/RewardTypes.h"
#include "Core/ValidatorRotation.h"
#include "Core/ValidatorTypes.h"

#include "Utils.h"

#include <algorithm>

using namespace Core;
using namespace Tests;

namespace
{
  //  Compute the avg_tx_per_block that makes
  //  computeTargetActiveSetSize() return exactly `target`.
  //
  //  The formula is:
  //      target = MIN + (traffic * (MAX - MIN)) / SATURATION
  //  So:
  //      traffic = (target - MIN) * SATURATION / (MAX - MIN)
  //
  //  Integer division means the result is a lower bound: passing it
  //  to computeTargetActiveSetSize() yields a value <= `target`, and
  //  may be one less due to truncation. The tests below verify the
  //  round-trip and adjust if needed.
  //
  //  Hardcoding this value in a test is what broke
  //  SameSizeLowestUptimeRemoved when ACTIVE_SET_MIN changed from 11
  //  to 2: the comment claimed traffic ≈ 113 with the old constants,
  //  but the actual formula with the new constants produced 13, and
  //  the assertion on new_target_size == 21 failed. Deriving from the
  //  constants makes the test immune to that class of change.
  uint64_t trafficForTarget(uint64_t target)
  {
    if (target <= GlobalConfig::ACTIVE_SET_MIN)
      return 0;
    if (target >= GlobalConfig::ACTIVE_SET_MAX)
      return TRAFFIC_SATURATION_TX;

    const uint64_t range = GlobalConfig::ACTIVE_SET_MAX - GlobalConfig::ACTIVE_SET_MIN;
    return ((target - GlobalConfig::ACTIVE_SET_MIN) * TRAFFIC_SATURATION_TX + range - 1) / range;
  }
}

TEST(Core_BftQuorum, KnownValues)
{
  EXPECT_EQ(bftQuorum(4), 3u);
  EXPECT_EQ(bftQuorum(7), 5u);
  EXPECT_EQ(bftQuorum(11), 8u);
  EXPECT_EQ(bftQuorum(21), 15u);
  EXPECT_EQ(bftQuorum(100), 67u);
}

TEST(Core_RotationCount, ZeroSizeReturnsZero)
{
  EXPECT_EQ(computeRotationCount(0), 0u);
}

TEST(Core_RotationCount, PositiveForNonEmpty)
{
  EXPECT_GE(computeRotationCount(21), 1u);
  EXPECT_GE(computeRotationCount(100), 1u);
}

TEST(Core_RotationCount, NeverExceedsBftSafety)
{
  for (uint64_t n : {11u, 21u, 50u, 100u})
  {
    uint64_t count = computeRotationCount(n);
    uint64_t max_safe = n - bftQuorum(n);
    EXPECT_LE(count, max_safe) << "n=" << n;
  }
}

TEST(Core_TargetSize, ZeroTraffic)
{
  EXPECT_EQ(computeTargetActiveSetSize(0), GlobalConfig::ACTIVE_SET_MIN);
}

TEST(Core_TargetSize, SaturationTraffic)
{
  EXPECT_EQ(computeTargetActiveSetSize(TRAFFIC_SATURATION_TX),
            GlobalConfig::ACTIVE_SET_MAX);
}

TEST(Core_TargetSize, OverSaturation)
{
  EXPECT_EQ(computeTargetActiveSetSize(TRAFFIC_SATURATION_TX * 10),
            GlobalConfig::ACTIVE_SET_MAX);
}

TEST(Core_TargetSize, WithinBounds)
{
  for (uint64_t traffic : {0u, 1u, 100u, 500u, 999u, 1000u, 5000u})
  {
    uint64_t size = computeTargetActiveSetSize(traffic);
    EXPECT_GE(size, GlobalConfig::ACTIVE_SET_MIN);
    EXPECT_LE(size, GlobalConfig::ACTIVE_SET_MAX);
  }
}

// planRotation, same-size rotation

TEST(Core_PlanRotation, SameSizeLowestUptimeRemoved)
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
  // The traffic value is computed from the current constants rather
  // than hardcoded. If a constant changes such that no traffic value
  // produces exactly 21, the assertion below catches it and the test
  // needs to pick a target size that IS reachable.
  const uint64_t traffic = trafficForTarget(21);

  // Sanity-check the round trip before trusting the plan output.
  // Without this, an unreachable target would show up as a confusing
  // "shrink branch ran instead of same-size" failure.
  ASSERT_EQ(computeTargetActiveSetSize(traffic), 21u)
      << "traffic value " << traffic
      << " does not produce target size 21 with the current constants; "
      << "ACTIVE_SET_MIN=" << GlobalConfig::ACTIVE_SET_MIN
      << " ACTIVE_SET_MAX=" << GlobalConfig::ACTIVE_SET_MAX
      << " TRAFFIC_SATURATION_TX=" << TRAFFIC_SATURATION_TX;

  auto plan = planRotation(b.reg, traffic);

  // Confirm we're actually in the same-size branch.
  ASSERT_EQ(plan.new_target_size, 21u);

  // Validator 5 should be in the removal list.
  auto it = std::find(plan.to_remove.begin(), plan.to_remove.end(), 5);
  EXPECT_NE(it, plan.to_remove.end())
      << "lowest-uptime validator not scheduled for removal";
}

TEST(Core_PlanRotation, HighestUptimeCandidatesAdded)
{
  RotationBuilder b(30, 21);
  for (Id id = 22; id <= 30; ++id)
  {
    b.setUptime(id, 9000);
  }
  b.setUptime(25, 9999);

  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/500);

  // Grow path: target > 21, so we want to add candidates.
  ASSERT_GT(plan.new_target_size, 21u);
  ASSERT_FALSE(plan.to_add.empty());
  ASSERT_LE(plan.to_add.size(), 9u);

  // The highest-uptime candidate should be first in the addition list.
  EXPECT_EQ(plan.to_add[0], 25u);
}

TEST(Core_PlanRotation, SeedsNeverRemoved)
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

TEST(Core_PlanRotation, GrowSet)
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

TEST(Core_PlanRotation, ShrinkSet)
{
  // 50 active, low traffic.
  RotationBuilder b(50, 50);

  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/0);

  // Target = ACTIVE_SET_MIN, so shrink.
  EXPECT_LT(plan.new_target_size, 50u);
  EXPECT_GT(plan.to_remove.size(), 0u);
  EXPECT_EQ(plan.to_add.size(), 0u);
}

TEST(Core_PlanRotation, EmptyRegistry)
{
  ValidatorRegistry empty;
  auto plan = planRotation(empty, 500);

  EXPECT_TRUE(plan.to_remove.empty());
  EXPECT_TRUE(plan.to_add.empty());
}

TEST(Core_PlanRotation, InsufficientCandidates)
{
  // 30 active, need to grow but no pool candidates.
  RotationBuilder b(30, 30);

  auto plan = planRotation(b.reg, /*avg_tx_per_block=*/900);

  // Target > 30, but pool is empty.
  EXPECT_GT(plan.new_target_size, 30u);
  EXPECT_EQ(plan.to_add.size(), 0u);
}

TEST(Core_ApplyRotation, RemovesFromActiveSet)
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

TEST(Core_ApplyRotation, AddsToActiveSet)
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

TEST(Core_ApplyRotation, UpdatesFlags)
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

TEST(Core_ApplyRotation, PreservesTargetSize)
{
  RotationBuilder b(30, 21);

  RotationPlan plan;
  plan.new_target_size = 15;

  applyRotation(b.reg, plan, /*current_height=*/100);

  EXPECT_EQ(b.reg.target_size, 15u);
  EXPECT_EQ(b.reg.last_rotation_height, 100u);
}

TEST(Core_ApplyRotation, ActiveSetSortedAfter)
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

TEST(Core_OfflineRemoval, NoOpWhenAllOnline)
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

TEST(Core_OfflineRemoval, IdentifiesOffline)
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

TEST(Core_OfflineRemoval, IgnoresOnline)
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

TEST(Core_OfflineRemoval, ProtectsSeeds)
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

TEST(Core_OfflineRemoval, PromotesFromPool)
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

TEST(Core_OfflineRemoval, EmptyPool)
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

TEST(Core_OfflineRemoval, SkipsUnhealthyCandidates)
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

TEST(Core_ApplyOfflineRemoval, RemovesFromActiveSet)
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

TEST(Core_ApplyOfflineRemoval, ShrinksWhenNoPromotions)
{
  RotationBuilder b(21, 21);

  OfflineCheckResult plan;
  plan.removed = {5, 7};
  // no promotions

  applyOfflineRemoval(b.reg, plan, /*current_height=*/1000);

  EXPECT_EQ(b.reg.active_set.size(), 19u);
}

TEST(Core_UptimeScore, NoPingsLeavesUnchanged)
{
  uint16_t score = 5000;
  EXPECT_EQ(updateUptimeScore(score, 0, 0), score);
}

TEST(Core_UptimeScore, PerfectUptimeIncreases)
{
  // Start below 10000, converge upward.
  uint16_t result = updateUptimeScore(5000, 100, 100);
  EXPECT_GT(result, 5000);
}

TEST(Core_UptimeScore, ZeroUptimeDecreases)
{
  // Start high, converge downward.
  uint16_t result = updateUptimeScore(9000, 0, 100);
  EXPECT_LT(result, 9000);
}

TEST(Core_UptimeScore, ClampedAtMax)
{
  // Even with impossible input, never above 10000.
  uint16_t result = updateUptimeScore(10000, 200, 100);
  EXPECT_LE(result, 10000);
}

TEST(Core_UptimeScore, EMASmoothing)
{
  // Starting from 10000, a single bad epoch of 0% should not drop to 0.
  uint16_t result = updateUptimeScore(10000, 0, 100);
  EXPECT_GT(result, 7000); // EMA smooths over one epoch
}

TEST(Core_Infraction, FullMultiplierReduced)
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

TEST(Core_Infraction, ConvergesToFloor)
{
  ValidatorInfo v;
  v.reward_multiplier = REWARD_MULTIPLIER_FLOOR + 500;

  applyInfractionPenalty(v, 100);

  EXPECT_EQ(v.reward_multiplier, REWARD_MULTIPLIER_FLOOR);
}

TEST(Core_Infraction, AtFloorStaysAtFloor)
{
  ValidatorInfo v;
  v.reward_multiplier = REWARD_MULTIPLIER_FLOOR;

  bool applied = applyInfractionPenalty(v, 100);

  EXPECT_FALSE(applied);
  EXPECT_EQ(v.reward_multiplier, REWARD_MULTIPLIER_FLOOR);
  // Infraction is still recorded.
  EXPECT_EQ(v.infraction_count, 1u);
}

TEST(Core_Infraction, MultipleStack)
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

TEST(Core_Unhealthy, IdentifiesBelowThreshold)
{
  RotationBuilder b(10, 5);
  b.setUptime(3, UPTIME_REMOVAL_THRESHOLD_BPS - 1);

  auto result = findUnhealthy(b.reg);

  auto it = std::find(result.begin(), result.end(), 3);
  EXPECT_NE(it, result.end());
}

TEST(Core_Unhealthy, IgnoresHealthy)
{
  RotationBuilder b(10, 5);
  b.setUptime(3, 9000);

  auto result = findUnhealthy(b.reg);

  auto it = std::find(result.begin(), result.end(), 3);
  EXPECT_EQ(it, result.end());
}

TEST(Core_Unhealthy, ProtectsSeeds)
{
  RotationBuilder b(10, 5);
  b.setUptime(1, UPTIME_REMOVAL_THRESHOLD_BPS - 1);
  b.setSeed(1);

  auto result = findUnhealthy(b.reg);

  auto it = std::find(result.begin(), result.end(), 1);
  EXPECT_EQ(it, result.end());
}

TEST(Core_Unhealthy, EmptyRegistry)
{
  ValidatorRegistry empty;
  auto result = findUnhealthy(empty);
  EXPECT_TRUE(result.empty());
}

TEST(Core_Integration, SingleOfflineValidator)
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

TEST(Core_Integration, MultipleOfflineValidators)
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

TEST(Core_Integration, SeedNodeAlwaysActive)
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

TEST(Core_Integration, RotationCyclePreservesSetSize)
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

// computeEmergencyActiveSet

TEST(Core_EmergencyRotation, NormalSet_ReturnsCommitted)
{
  //  No rotation requested. Committed set is returned unchanged.
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
    b.setLastSeen(id, 1000);

  auto result = computeEmergencyActiveSet(
      b.reg, b.reg.active_set, /*current_height=*/1000,
      /*force_rotation=*/false);

  EXPECT_EQ(result, b.reg.active_set);
}

TEST(Core_EmergencyRotation, ForceWithAllLive_ReturnsCommitted)
{
  //  Rotation forced, but every validator is live. Nothing to rotate —
  //  the emergency path returns the committed set, since a stall with
  //  no offline validators has a different cause.
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
    b.setLastSeen(id, 1000);

  auto result = computeEmergencyActiveSet(
      b.reg, b.reg.active_set, /*current_height=*/1000,
      /*force_rotation=*/true);

  EXPECT_EQ(result, b.reg.active_set);
}

TEST(Core_EmergencyRotation, LostQuorum_DerivesEmergencySet)
{
  //  21 active, 10 offline, 10 pool candidates.
  RotationBuilder b(40, 21);

  for (Id id = 1; id <= 40; ++id)
    b.setLastSeen(id, 1000);

  std::vector<Id> offline;
  for (Id id = 1; id <= 10; ++id)
  {
    b.setLastSeen(id, 1000 - OFFLINE_KICK_BLOCKS - 1);
    offline.push_back(id);
  }

  auto result = computeEmergencyActiveSet(
      b.reg, b.reg.active_set, /*current_height=*/1000,
      /*force_rotation=*/true);

  for (Id vid : offline)
  {
    EXPECT_EQ(std::find(result.begin(), result.end(), vid), result.end())
        << "offline validator " << vid << " still in emergency set";
  }

  EXPECT_EQ(result.size(), 21u);

  auto sorted = result;
  std::sort(sorted.begin(), sorted.end());
  EXPECT_EQ(result, sorted);
}

TEST(Core_EmergencyRotation, PoolEmpty_ShrinksSet)
{
  RotationBuilder b(21, 21);

  for (Id id = 1; id <= 21; ++id)
    b.setLastSeen(id, 1000);

  for (Id id = 1; id <= 10; ++id)
    b.setLastSeen(id, 1000 - OFFLINE_KICK_BLOCKS - 1);

  auto result = computeEmergencyActiveSet(
      b.reg, b.reg.active_set, /*current_height=*/1000,
      /*force_rotation=*/true);

  EXPECT_EQ(result.size(), 11u);
}

TEST(Core_EmergencyRotation, SingleValidator_Unchanged)
{
  RotationBuilder b(3, 1);
  b.setLastSeen(1, 1000 - OFFLINE_KICK_BLOCKS - 1);

  auto result = computeEmergencyActiveSet(
      b.reg, b.reg.active_set, /*current_height=*/1000,
      /*force_rotation=*/true);

  EXPECT_EQ(result, b.reg.active_set);
  EXPECT_EQ(result.size(), 1u);
}

TEST(Core_EmergencyRotation, DeterministicAcrossCalls)
{
  RotationBuilder b(40, 21);

  for (Id id = 1; id <= 40; ++id)
    b.setLastSeen(id, 1000);

  for (Id id = 1; id <= 10; ++id)
    b.setLastSeen(id, 1000 - OFFLINE_KICK_BLOCKS - 1);

  auto first = computeEmergencyActiveSet(
      b.reg, b.reg.active_set, 1000, true);
  auto second = computeEmergencyActiveSet(
      b.reg, b.reg.active_set, 1000, true);

  EXPECT_EQ(first, second);
}

TEST(Core_EmergencyRotation, EmergencyMayDropOfflineSeeds)
{
  RotationBuilder b(30, 21);

  for (Id id = 1; id <= 30; ++id)
    b.setLastSeen(id, 1000);

  // Seed 1 is offline and must be droppable — this is the whole
  // point of the emergency path: a stalled chain whose seed has
  // failed cannot recover if the seed is protected.
  //
  // Seed 2 is also a seed, but is live, so it survives.
  b.setSeed(1);
  b.setSeed(2);
  b.setLastSeen(1, 500);
  b.setLastSeen(2, 1000);

  // A non-seed is also offline.
  b.setLastSeen(7, 500);

  auto result = computeEmergencyActiveSet(
      b.reg, b.reg.active_set, 1000, true);

  // Offline seed 1 is dropped.
  EXPECT_EQ(std::find(result.begin(), result.end(), 1), result.end())
      << "offline seed should be droppable in emergency rotation";

  // Live seed 2 survives.
  EXPECT_NE(std::find(result.begin(), result.end(), 2), result.end())
      << "live seed should survive emergency rotation";

  // Offline non-seed 7 is dropped.
  EXPECT_EQ(std::find(result.begin(), result.end(), 7), result.end());

  // Two offline validators dropped, two pool candidates promoted,
  // so the set size is unchanged.
  EXPECT_EQ(result.size(), 21u);
}