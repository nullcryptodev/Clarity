// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Fixtures.h"
#include "Core/BlockProcessor.h"
#include "Core/ValidatorTypes.h"
#include "State/StateAccess.h"

#include <cstring>

using namespace State;
using namespace Core;
using namespace Tests;

// ============================================================================
//  About these tests
//
//  BlockProcessor::resolveActiveSet has two paths:
//
//    - Non-emergency (force_rotation=false): returns the committed set
//      unchanged.
//    - Emergency (force_rotation=true): delegates to
//      computeEmergencyActiveSet, which
//        * returns the committed set unchanged if no committed validator
//          is offline,
//        * otherwise partitions the committed set into live/offline by
//          ValidatorInfo::isOffline(current_height),
//        * gathers pool candidates from the registry (not in committed,
//          not is_active, canBeActive),
//        * sorts candidates by uptime descending, then last_active
//          ascending,
//        * promotes exactly min(offline.size(), pool.size()) candidates,
//        * returns live++promoted sorted ascending by id.
//
//  There is no ACTIVE_SET_MIN floor. There is no seed exclusion for the
//  emergency path. Promotion count is driven by the number of offline
//  validators, not by a floor.
//
//  Every test below pins one of these behaviours.
// ============================================================================

namespace
{
  //  Write the length-prefixed `active_set` global. Not read by
  //  resolveActiveSet, but kept for tests that want it present.
  void putActiveSet(StateAccess &s, const std::vector<Id> &ids)
  {
    std::vector<uint8_t> bytes;
    bytes.reserve(ids.size() * 8);
    for (auto id : ids)
      for (int i = 0; i < 8; ++i)
        bytes.push_back(uint8_t(id >> (i * 8)));
    s.putGlobal("active_set", bytes);
  }

  //  Seed a validator. is_active defaults to false, which is what
  //  the pool filter wants for pool candidates. Committed-set
  //  validators are excluded from the pool by the committed_set
  //  check, not by is_active.
  void seedValidator(StateAccess &s, Id id,
                     uint64_t last_seen_height,
                     bool is_seed = false,
                     uint64_t stake = GlobalConfig::VALIDATOR_MIN_STAKE,
                     uint16_t uptime = 10'000)
  {
    Core::ValidatorInfo v;
    v.id = id;
    v.stake = stake;
    v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
    v.uptime_score = uptime;
    v.last_seen_height = last_seen_height;
    v.is_seed = is_seed;
    v.is_active = false;
    s.putValidator(v);
  }

  //  Convenience: are all elements of `set` present in `vec`?
  bool containsAll(const std::vector<Id> &vec, const std::vector<Id> &set)
  {
    for (Id id : set)
      if (std::find(vec.begin(), vec.end(), id) == vec.end())
        return false;
    return true;
  }
} // anonymous namespace

// ============================================================================
//  Non-emergency path
// ============================================================================

TEST(Consensus_ActiveSetResolution, NonEmergencyReturnsCommittedUnchanged)
{
  TempDB db;
  StateAccess s(db.db(), 0);
  std::vector<Id> committed = {5, 6, 7, 8};

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/100, /*force_rotation=*/false);

  EXPECT_EQ(result, committed);
}

TEST(Consensus_ActiveSetResolution, NonEmergencyIgnoresOfflineState)
{
  //  Even if every committed validator is marked offline, the
  //  non-emergency path returns the committed set verbatim.
  TempDB db;
  StateAccess s(db.db(), 0);
  for (Id id : {5, 6, 7, 8})
    seedValidator(s, id, /*last_seen_height=*/0);

  std::vector<Id> committed = {5, 6, 7, 8};

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/10'000, /*force_rotation=*/false);

  EXPECT_EQ(result, committed);
}

// ============================================================================
//  Emergency path: early-outs
// ============================================================================

TEST(Consensus_ActiveSetResolution, EmergencyEmptyOfflineReturnsCommitted)
{
  //  Nobody is offline: the emergency path returns the committed set
  //  unchanged rather than promoting anyone.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {10, 11, 12, 13};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/1000);

  //  A pool candidate exists but must not be touched.
  seedValidator(s, 1, 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result, committed);
  EXPECT_EQ(std::find(result.begin(), result.end(), Id{1}), result.end());
}

TEST(Consensus_ActiveSetResolution, EmergencySingleValidatorReturnsCommitted)
{
  //  A committed set of size 1 is returned unchanged. No quorum can
  //  be lost at n=1, and the emergency path can't help.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {42};
  seedValidator(s, 42, /*last_seen_height=*/0); // offline
  seedValidator(s, 1, 1000);                    // pool

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result, committed);
}

TEST(Consensus_ActiveSetResolution, EmergencyEmptyCommittedReturnsEmpty)
{
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed;

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_TRUE(result.empty());
}

// ============================================================================
//  Emergency path: filtering without promotion
// ============================================================================

TEST(Consensus_ActiveSetResolution, EmergencyDropsOfflineNoPoolReturnsLive)
{
  //  11 committed, 1 offline, empty pool. Result is the 10
  //  survivors, sorted ascending. There is no floor: the result is
  //  exactly the live set.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed;
  for (Id id = 100; id <= 110; ++id)
    committed.push_back(id);

  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 105 ? 0 : 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  std::vector<Id> expected;
  for (Id id : committed)
    if (id != 105)
      expected.push_back(id);

  EXPECT_EQ(result, expected);
}

TEST(Consensus_ActiveSetResolution, EmergencyResultIsSortedAscending)
{
  //  The final result is sorted ascending by id, regardless of
  //  committed order. Signer indices resolve through this vector by
  //  position, so the sort has to be deterministic.
  TempDB db;
  StateAccess s(db.db(), 0);

  //  Committed in deliberately non-ascending order.
  std::vector<Id> committed = {110, 105, 108, 102, 104, 101};

  //  Offline: 108.
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 108 ? 0 : 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_TRUE(std::is_sorted(result.begin(), result.end()))
      << "result is not sorted ascending by id";
}

// ============================================================================
//  Emergency path: promotion
// ============================================================================

TEST(Consensus_ActiveSetResolution, EmergencyPromotesOnePerOfflineValidator)
{
  //  12 committed, 3 offline. Pool has 5 eligible candidates. Exactly
  //  3 are promoted — one per offline, not "up to some floor."
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed;
  for (Id id = 100; id <= 111; ++id)
    committed.push_back(id);

  for (Id id : committed)
  {
    bool offline = (id == 103 || id == 107 || id == 110);
    seedValidator(s, id, /*last_seen_height=*/offline ? 0 : 1000);
  }

  for (Id id = 1; id <= 5; ++id)
    seedValidator(s, id, /*last_seen_height=*/1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  //  12 committed - 3 offline + 3 promoted = 12.
  EXPECT_EQ(result.size(), 12u);

  //  9 survivors are all present.
  for (Id id : committed)
    if (id != 103 && id != 107 && id != 110)
      EXPECT_NE(std::find(result.begin(), result.end(), id), result.end())
          << "survivor " << id << " missing";

  //  3 of the pool were promoted. Which three depends on tie-break
  //  order; all have equal uptime and last_active, so std::sort
  //  gives some permutation of the first three. Assert that exactly
  //  three of {1..5} appear.
  size_t promoted = 0;
  for (Id id = 1; id <= 5; ++id)
    if (std::find(result.begin(), result.end(), id) != result.end())
      ++promoted;

  EXPECT_EQ(promoted, 3u);
}

TEST(Consensus_ActiveSetResolution, EmergencyPromotesMinOfflineAndPoolSize)
{
  //  12 committed, 5 offline, pool has only 2 candidates. Promotes 2,
  //  not 5. Result shrinks: 7 live + 2 promoted = 9.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed;
  for (Id id = 100; id <= 111; ++id)
    committed.push_back(id);

  for (Id id : committed)
  {
    bool offline = (id >= 103 && id <= 107);
    seedValidator(s, id, /*last_seen_height=*/offline ? 0 : 1000);
  }

  seedValidator(s, 1, 1000);
  seedValidator(s, 2, 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  //  12 committed - 5 offline + 2 promoted = 9.
  EXPECT_EQ(result.size(), 9u);
  EXPECT_NE(std::find(result.begin(), result.end(), Id{1}), result.end());
  EXPECT_NE(std::find(result.begin(), result.end(), Id{2}), result.end());
}

TEST(Consensus_ActiveSetResolution, EmergencyIncludesPromotedIdsInResult)
{
  //  12 committed, 1 offline, pool = {1, 2, 3}. Exactly one promoted.
  //  Which one depends on tie-break. Assert that exactly one of
  //  {1, 2, 3} appears.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed;
  for (Id id = 100; id <= 111; ++id)
    committed.push_back(id);

  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 105 ? 0 : 1000);

  seedValidator(s, 1, 1000);
  seedValidator(s, 2, 1000);
  seedValidator(s, 3, 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result.size(), 12u);

  size_t promoted = 0;
  for (Id id : {1, 2, 3})
    if (std::find(result.begin(), result.end(), id) != result.end())
      ++promoted;

  EXPECT_EQ(promoted, 1u)
      << "exactly one pool candidate should have been promoted";
}

// ============================================================================
//  Emergency path: pool filter
// ============================================================================

TEST(Consensus_ActiveSetResolution, EmergencySkipsActivePoolCandidates)
{
  //  A pool candidate with is_active=true is not promoted.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {100, 101, 102, 103};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 100 ? 0 : 1000);

  //  Pool candidate 1 is is_active=true; skipped.
  Core::ValidatorInfo active;
  active.id = 1;
  active.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
  active.uptime_score = 10'000;
  active.reward_multiplier = Core::REWARD_MULTIPLIER_START;
  active.last_seen_height = 1000;
  active.is_active = true;
  s.putValidator(active);

  //  Pool candidate 2 is available.
  seedValidator(s, 2, 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result.size(), 4u);
  EXPECT_EQ(std::find(result.begin(), result.end(), Id{1}), result.end())
      << "active candidate 1 should not have been promoted";
  EXPECT_NE(std::find(result.begin(), result.end(), Id{2}), result.end())
      << "candidate 2 should have been promoted";
}

TEST(Consensus_ActiveSetResolution, EmergencySkipsUnhealthyPoolCandidates)
{
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {100, 101, 102, 103};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 100 ? 0 : 1000);

  //  Candidate 1 is below UPTIME_ACTIVE_MIN_BPS.
  seedValidator(s, 1, 1000, false, GlobalConfig::VALIDATOR_MIN_STAKE, /*uptime=*/100);
  //  Candidate 2 is healthy.
  seedValidator(s, 2, 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result.size(), 4u);
  EXPECT_EQ(std::find(result.begin(), result.end(), Id{1}), result.end());
  EXPECT_NE(std::find(result.begin(), result.end(), Id{2}), result.end());
}

TEST(Consensus_ActiveSetResolution, EmergencySkipsUnderstakedPoolCandidates)
{
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {100, 101, 102, 103};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 100 ? 0 : 1000);

  seedValidator(s, 1, 1000, false, /*stake=*/GlobalConfig::VALIDATOR_MIN_STAKE - 1);
  seedValidator(s, 2, 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result.size(), 4u);
  EXPECT_EQ(std::find(result.begin(), result.end(), Id{1}), result.end());
  EXPECT_NE(std::find(result.begin(), result.end(), Id{2}), result.end());
}

TEST(Consensus_ActiveSetResolution, EmergencySkipsCommittedValidatorsAsCandidates)
{
  //  A committed validator can't be promoted into the same set it's
  //  already in. Verified by asserting no duplicates in the result.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {100, 101, 102, 103};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 100 ? 0 : 1000);

  seedValidator(s, 1, 1000);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  //  No duplicates.
  std::set<Id> unique(result.begin(), result.end());
  EXPECT_EQ(unique.size(), result.size())
      << "result contains duplicate ids";

  //  Size: 3 live + 1 promoted = 4.
  EXPECT_EQ(result.size(), 4u);
}

// ============================================================================
//  Emergency path: seed handling
// ============================================================================

TEST(Consensus_ActiveSetResolution, EmergencyCanPromoteSeeds)
{
  //  Unlike normal rotation and offline removal, the emergency path
  //  has no seed special-case. A seed in the pool is a legitimate
  //  candidate.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {100, 101, 102, 103};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 100 ? 0 : 1000);

  //  Pool candidate 1 is a seed.
  seedValidator(s, /*id=*/1, 1000, /*is_seed=*/true);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result.size(), 4u);
  EXPECT_NE(std::find(result.begin(), result.end(), Id{1}), result.end())
      << "seed pool candidate should have been promoted";
}

// ============================================================================
//  Emergency path: promotion ordering
// ============================================================================

TEST(Consensus_ActiveSetResolution, EmergencyPromotesHighestUptimeFirst)
{
  //  Pool candidates are sorted by uptime descending. With one offline,
  //  the highest-uptime candidate is the one promoted.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {100, 101, 102, 103};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 100 ? 0 : 1000);

  seedValidator(s, 1, 1000, false, GlobalConfig::VALIDATOR_MIN_STAKE, /*uptime=*/9'100);
  seedValidator(s, 2, 1000, false, GlobalConfig::VALIDATOR_MIN_STAKE, /*uptime=*/9'900);
  seedValidator(s, 3, 1000, false, GlobalConfig::VALIDATOR_MIN_STAKE, /*uptime=*/9'500);

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result.size(), 4u);
  EXPECT_NE(std::find(result.begin(), result.end(), Id{2}), result.end())
      << "highest-uptime candidate (id 2) should have been promoted";
  EXPECT_EQ(std::find(result.begin(), result.end(), Id{1}), result.end());
  EXPECT_EQ(std::find(result.begin(), result.end(), Id{3}), result.end());
}

TEST(Consensus_ActiveSetResolution, EmergencyTiesBreakByLastActiveAscending)
{
  //  Equal uptime: the candidate with the smaller last_active_at wins.
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {100, 101, 102, 103};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 100 ? 0 : 1000);

  //  Same uptime, different last_active.
  {
    Core::ValidatorInfo v;
    v.id = 1;
    v.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
    v.uptime_score = 10'000;
    v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
    v.last_seen_height = 1000;
    v.last_active_at = 500;
    s.putValidator(v);
  }
  {
    Core::ValidatorInfo v;
    v.id = 2;
    v.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
    v.uptime_score = 10'000;
    v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
    v.last_seen_height = 1000;
    v.last_active_at = 100;
    s.putValidator(v);
  }

  auto result = BlockProcessor::resolveActiveSet(
      s, committed, /*current_height=*/1000, /*force_rotation=*/true);

  EXPECT_EQ(result.size(), 4u);
  EXPECT_NE(std::find(result.begin(), result.end(), Id{2}), result.end())
      << "candidate with smaller last_active_at (id 2) should have won";
  EXPECT_EQ(std::find(result.begin(), result.end(), Id{1}), result.end());
}

// ============================================================================
//  Emergency path: purity
// ============================================================================

TEST(Consensus_ActiveSetResolution, PureAcrossTwoViews)
{
  TempDB db;
  {
    StateAccess s(db.db(), 0);
    std::vector<Id> committed = {10, 20, 30, 40, 50, 60};
    for (Id id : committed)
      seedValidator(s, id, /*last_seen_height=*/id == 30 ? 0 : 1000);
    for (Id id = 1; id <= 3; ++id)
      seedValidator(s, id, 1000);
  }

  StateAccess s1(db.db(), 0);
  StateAccess s2(db.db(), 0);

  std::vector<Id> committed = {10, 20, 30, 40, 50, 60};

  auto r1 = BlockProcessor::resolveActiveSet(
      s1, committed, 1000, /*force_rotation=*/true);
  auto r2 = BlockProcessor::resolveActiveSet(
      s2, committed, 1000, /*force_rotation=*/true);

  EXPECT_EQ(r1, r2);
}

TEST(Consensus_ActiveSetResolution, RepeatCallsProduceIdenticalResults)
{
  TempDB db;
  StateAccess s(db.db(), 0);

  std::vector<Id> committed = {100, 101, 102, 103};
  for (Id id : committed)
    seedValidator(s, id, /*last_seen_height=*/id == 100 ? 0 : 1000);
  seedValidator(s, 1, 1000);

  auto r1 = BlockProcessor::resolveActiveSet(
      s, committed, 1000, /*force_rotation=*/true);
  auto r2 = BlockProcessor::resolveActiveSet(
      s, committed, 1000, /*force_rotation=*/true);

  EXPECT_EQ(r1, r2);

  //  State root unchanged.
  Crypto::Hash before = s.stateRoot();
  BlockProcessor::resolveActiveSet(s, committed, 1000, true);
  Crypto::Hash after = s.stateRoot();
  EXPECT_EQ(before, after);
}