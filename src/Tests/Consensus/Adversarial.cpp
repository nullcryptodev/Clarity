// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <set>

#include "Fixtures.h"

using namespace Consensus;
using namespace Tests;

// ============================================================================
//  Safety property helpers
// ============================================================================

namespace
{
  //  Count how many commits a validator has at a given height.
  //  Returns 0 if the height is beyond its chain tip.
  bool hasCommitAtHeight(const ConsensusNetwork &net, size_t i, Height h)
  {
    const auto &chain = net.committed(i);
    for (const auto &block : chain)
      if (block.header.height == h)
        return true;
    return false;
  }

  //  Largest committed height across all validators, or 0 if nobody
  //  has committed. Used to describe divergence in failures.
  Height maxCommittedHeight(const ConsensusNetwork &net)
  {
    Height best = 0;
    bool any = false;
    for (size_t i = 0; i < net.size(); ++i)
    {
      const auto &chain = net.committed(i);
      if (chain.empty())
        continue;
      any = true;
      best = std::max(best, chain.back().header.height);
    }
    return any ? best : 0;
  }

  //  Smallest committed height across the *online* validators. Used
  //  to describe divergence in failures — a wide gap between max and
  //  min indicates a liveness problem where one validator is racing
  //  ahead while others are stuck.
  Height minCommittedHeight(const ConsensusNetwork &net)
  {
    Height best = std::numeric_limits<Height>::max();
    bool any = false;
    for (size_t i = 0; i < net.size(); ++i)
    {
      const auto &chain = net.committed(i);
      if (chain.empty())
        continue;
      any = true;
      best = std::min(best, chain.back().header.height);
    }
    return any ? best : 0;
  }

  //  Walk every node's committed list, group by height, and verify
  //  that all commits at a given height have the same hash. Fails with
  //  a diagnostic if a fork is detected.
  void assertNoFork(const ConsensusNetwork &net, const std::string &context)
  {
    std::map<Height, Crypto::Hash> seen;
    for (size_t i = 0; i < net.size(); ++i)
    {
      for (const auto &block : net.committed(i))
      {
        const Height h = block.header.height;
        const Crypto::Hash hash = block.hash();
        auto it = seen.find(h);
        if (it != seen.end() && it->second != hash)
        {
          FAIL() << "safety violation at height " << h
                 << " (" << context << "): "
                 << it->second.toString().substr(0, 16) << " vs "
                 << hash.toString().substr(0, 16);
        }
        seen[h] = hash;
      }
    }
  }

  //  Every height that has been committed by at least one node should
  //  eventually be committed by every node that's online and not
  //  partitioned. This is a weaker liveness check: it doesn't fail if
  //  some node is behind, but it fails if a node commits a height that
  //  no other node ever commits (which would indicate a fork).
  void assertAllCommittedHeightsMatch(const ConsensusNetwork &net,
                                      size_t n,
                                      const std::string &context)
  {
    std::map<Height, Crypto::Hash> canonical;
    for (size_t i = 0; i < n; ++i)
    {
      for (const auto &block : net.committed(i))
      {
        const Height h = block.header.height;
        auto it = canonical.find(h);
        if (it == canonical.end())
          canonical[h] = block.hash();
        else
          EXPECT_EQ(it->second, block.hash())
              << "height " << h << " diverges (" << context << ")";
      }
    }
  }

  //  Number of validators that currently hold at least `n` commits.
  size_t countWithAtLeast(const ConsensusNetwork &net, size_t n)
  {
    size_t c = 0;
    for (size_t i = 0; i < net.size(); ++i)
      if (net.committed(i).size() >= n)
        ++c;
    return c;
  }

  //  True when every validator holds at least `n` commits.
  bool allHaveAtLeast(const ConsensusNetwork &net, size_t n)
  {
    return countWithAtLeast(net, n) == net.size();
  }

  //  Compare the first `n` commits of every validator against
  //  validator 0's first `n` commits. Requires every validator to
  //  have at least `n` commits. Emits a non-fatal failure on mismatch.
  void expectPrefixMatches(const ConsensusNetwork &net,
                           size_t n,
                           const std::string &context)
  {
    for (size_t i = 0; i < net.size(); ++i)
    {
      ASSERT_GE(net.committed(i).size(), n)
          << context << ": validator " << i
          << " has " << net.committed(i).size() << " commits";
    }
    for (size_t h = 0; h < n; ++h)
    {
      for (size_t i = 1; i < net.size(); ++i)
      {
        EXPECT_EQ(net.committed(i)[h].hash(), net.committed(0)[h].hash())
            << context << ": height " << h
            << " diverges on validator " << i;
      }
    }
  }
} // anonymous namespace

// ============================================================================
//  Randomized message ordering
// ============================================================================

TEST_F(Consensus_NetworkFixture, RandomOrderingProducesSameCommit)
{
  constexpr size_t N = 4;
  constexpr uint64_t SEEDS = 100;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(N, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    net.advanceUntil([&]
                     { return allHaveAtLeast(net, 1); }, 64);

    ASSERT_TRUE(allHaveAtLeast(net, 1))
        << "seed " << seed << ": not all validators committed";
    for (size_t i = 0; i < N; ++i)
    {
      ASSERT_GE(net.committed(i).size(), 1u)
          << "seed " << seed << ": validator " << i << " didn't commit";
      EXPECT_EQ(net.committed(i)[0].hash(), net.committed(0)[0].hash())
          << "seed " << seed << ": validator " << i << " disagrees";
    }

    assertNoFork(net, "seed " + std::to_string(seed));
  }
}

TEST_F(Consensus_NetworkFixture, RandomOrderingSurvivesOneOffline)
{
  constexpr size_t N = 4;
  constexpr uint64_t SEEDS = 50;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(N, logger_);
    net.setRandomSeed(seed);
    net.setOffline(3, true);
    net.startAll(0);

    net.advanceUntil([&]
                     { return net.committed(0).size() >= 1u &&
                              net.committed(1).size() >= 1u &&
                              net.committed(2).size() >= 1u; }, 64);

    ASSERT_GE(net.committed(0).size(), 1u) << "seed " << seed;
    ASSERT_GE(net.committed(1).size(), 1u) << "seed " << seed;
    ASSERT_GE(net.committed(2).size(), 1u) << "seed " << seed;

    EXPECT_EQ(net.committed(0)[0].hash(), net.committed(1)[0].hash())
        << "seed " << seed;
    EXPECT_EQ(net.committed(0)[0].hash(), net.committed(2)[0].hash())
        << "seed " << seed;

    assertNoFork(net, "seed " + std::to_string(seed));
  }
}

// ============================================================================
//  Network partition
// ============================================================================

TEST_F(Consensus_NetworkFixture, PartitionOfTwoTwoStallsBothSides)
{
  ConsensusNetwork net(4, logger_);
  net.setPartition({0, 1}, {2, 3}); // before startAll
  net.startAll(0);

  for (int i = 0; i < 5; ++i)
    net.advanceAllTimers();

  for (size_t i = 0; i < 4; ++i)
    EXPECT_TRUE(net.committed(i).empty())
        << "validator " << i << " committed under 2-2 partition";

  net.clearPartition();
  net.advanceUntil([&]
                   { return !net.committed(0).empty(); }, 40);

  EXPECT_FALSE(net.committed(0).empty())
      << "no commit after partition healed";
  assertNoFork(net, "post-heal");
}

TEST_F(Consensus_NetworkFixture, PartitionOfThreeOneCommits)
{
  ConsensusNetwork net(4, logger_);
  net.setPartition({0, 1, 2}, {3}); // before startAll
  net.startAll(0);

  net.advanceUntil([&]
                   { return !net.committed(0).empty(); }, 40);

  ASSERT_FALSE(net.committed(0).empty());
  EXPECT_EQ(net.committed(0)[0].hash(), net.committed(1)[0].hash());
  EXPECT_EQ(net.committed(0)[0].hash(), net.committed(2)[0].hash());
  EXPECT_TRUE(net.committed(3).empty())
      << "partitioned validator should not have committed";

  net.clearPartition();
  net.advanceUntil([&]
                   { return net.committed(0).size() >= 2u; }, 40);

  assertNoFork(net, "post-heal");
}

TEST_F(Consensus_NetworkFixture, PartitionHealsWithoutFork)
{
  constexpr uint64_t SEEDS = 30;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(4, logger_);
    net.setRandomSeed(seed);
    net.setPartition({0, 1}, {2, 3}); // before startAll
    net.startAll(0);

    for (int i = 0; i < 3; ++i)
      net.advanceAllTimers();

    net.clearPartition();
    net.advanceUntil([&]
                     { return !net.committed(0).empty(); }, 60);

    assertNoFork(net, "seed " + std::to_string(seed) + " partition");
  }
}

// ============================================================================
//  Crash / restart
// ============================================================================
TEST_F(Consensus_NetworkFixture, ValidatorRestartsAfterMissedRound)
{
  ConsensusNetwork net(4, logger_);
  net.startAll(0);

  //  One height commits.
  net.advanceUntil([&]
                   { return net.committed(0).size() >= 1u; }, 32);
  ASSERT_GE(net.committed(0).size(), 1u);

  //  Stop validator 3 and snapshot its committed chain length.
  //  From this point on, its chain must not grow — the running_
  //  guards in BftConsensus and the offline_ check in the fixture
  //  both block the message-driven paths, and pollTimers is not
  //  called on offline instances.
  net.stopValidator(3);
  const size_t frozen_size = net.committed(3).size();

  //  Run more heights on the remaining three validators.
  net.advanceUntil([&]
                   { return net.committed(0).size() >= 2u; }, 32);

  ASSERT_GE(net.committed(0).size(), 2u);
  EXPECT_GE(net.committed(1).size(), 2u);
  EXPECT_GE(net.committed(2).size(), 2u);
  EXPECT_EQ(net.committed(3).size(), frozen_size)
      << "stopped validator's chain grew while offline";

  //  Bring it back.
  const Height restart_height =
      net.committed(0).back().header.height + 1;
  net.restartValidator(3, restart_height);

  const size_t baseline = net.committed(3).size();
  net.advanceUntil([&]
                   { return net.committed(3).size() > baseline &&
                            net.committed(0).size() == net.committed(3).size(); }, 128);

  EXPECT_GT(net.committed(3).size(), baseline)
      << "restarted validator did not rejoin";

  EXPECT_EQ(net.committed(3).back().hash(),
            net.committed(0).back().hash());

  assertNoFork(net, "crash-restart");
}

TEST_F(Consensus_NetworkFixture, RandomizedCrashRestart)
{
  constexpr uint64_t SEEDS = 30;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(4, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    net.advanceUntil([&]
                     { return allHaveAtLeast(net, 1); }, 64);

    net.stopValidator(2);
    net.advanceUntil([&]
                     { return net.committed(0).size() >= 2u; }, 64);

    const Height next = net.committed(0).back().header.height + 1;
    net.restartValidator(2, next);

    const size_t baseline = net.committed(2).size();
    net.advanceUntil([&]
                     { return net.committed(2).size() > baseline &&
                              net.committed(0).size() == net.committed(2).size(); }, 128);

    assertNoFork(net, "seed " + std::to_string(seed) + " crash");
  }
}

// ============================================================================
//  Combined: partition + crash + random
// ============================================================================

TEST_F(Consensus_NetworkFixture, RandomizedChaos)
{
  constexpr size_t N = 7; // 7 validators, quorum 5
  constexpr uint64_t SEEDS = 50;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(N, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    for (int step = 0; step < 8; ++step)
    {
      switch (step)
      {
      case 0:
      case 1:
        // Clean run.
        break;
      case 2:
        net.setPartition({0, 1, 2, 3, 4}, {5, 6});
        break;
      case 3:
        net.clearPartition();
        break;
      case 4:
        net.stopValidator(6);
        break;
      case 5:
        net.restartValidator(6, net.committed(0).empty()
                                    ? 0
                                    : net.committed(0).back().header.height + 1);
        break;
      case 6:
      case 7:
        // Clean run again.
        break;
      }

      net.advanceAllTimers();
      assertNoFork(net, "seed " + std::to_string(seed) +
                            " step " + std::to_string(step));
    }
  }
}

TEST_F(Consensus_NetworkFixture, FutureHeightVotesAreBufferedNotDropped)
{
  constexpr size_t N = 4;
  constexpr uint64_t SEEDS = 50;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(N, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    const bool reached = net.advanceUntil([&]
                                          { return allHaveAtLeast(net, 2); }, 64);

    ASSERT_TRUE(reached)
        << "seed " << seed << ": not all validators reached height 1 "
        << "within 64 passes"
        << " (max committed height " << maxCommittedHeight(net)
        << ", min committed height " << minCommittedHeight(net) << ")";

    for (size_t i = 0; i < N; ++i)
    {
      ASSERT_GE(net.committed(i).size(), 2u)
          << "seed " << seed << ": validator " << i << " has "
          << net.committed(i).size() << " commits";
    }

    expectPrefixMatches(net, 2, "seed " + std::to_string(seed));
    assertNoFork(net, "seed " + std::to_string(seed));
  }
}

TEST_F(Consensus_NetworkFixture, FutureHeightBufferIsBounded)
{
  constexpr size_t N = 4;

  ConsensusNetwork net(N, logger_);
  net.setRandomSeed(7);
  net.startAll(0);

  net.advanceUntil([&]
                   { return allHaveAtLeast(net, 1); }, 64);
  ASSERT_TRUE(allHaveAtLeast(net, 1));

  net.stopValidator(3);
  const size_t frozen_size = net.committed(3).size();

  net.advanceUntil([&]
                   { return net.committed(0).size() >= 4u; }, 128);

  ASSERT_GE(net.committed(0).size(), 4u)
      << "online peers stalled while one validator was stopped";

  EXPECT_EQ(net.committed(3).size(), frozen_size)
      << "stopped validator's chain grew while offline";

  const Height next = net.committed(0).back().header.height + 1;
  net.restartValidator(3, next);

  const size_t baseline = net.committed(3).size();
  net.advanceUntil([&]
                   { return net.committed(3).size() > baseline; }, 128);

  EXPECT_GT(net.committed(3).size(), baseline)
      << "restarted validator did not rejoin";

  assertNoFork(net, "bounded-buffer");
}

TEST_F(Consensus_NetworkFixture, RandomOrderingAcrossTwoHeights)
{
  constexpr size_t N = 4;
  constexpr uint64_t SEEDS = 50;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(N, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    net.advanceUntil([&]
                     { return allHaveAtLeast(net, 2); }, 128);

    ASSERT_TRUE(allHaveAtLeast(net, 2))
        << "seed " << seed << ": not all validators reached height 1 "
        << "(max committed height " << maxCommittedHeight(net)
        << ", min committed height " << minCommittedHeight(net) << ")";

    for (size_t i = 0; i < N; ++i)
    {
      EXPECT_GE(net.committed(i).size(), 2u)
          << "seed " << seed << ": validator " << i << " has "
          << net.committed(i).size() << " commits";
    }

    expectPrefixMatches(net, 2, "seed " + std::to_string(seed));

    assertNoFork(net, "seed " + std::to_string(seed));
  }
}

TEST_F(Consensus_NetworkFixture, EmergencyRotationRecoversFromSustainedProposalStall)
{
  constexpr size_t N = 4;

  ConsensusNetwork net(N, logger_);
  net.setRandomSeed(11);
  net.setProposalSuppressed(true);
  net.startAll(0);

  constexpr int MAX_PASSES = 512;

  const bool committed = net.advanceUntil(
      [&]
      { return !net.committed(0).empty(); },
      MAX_PASSES);

  ASSERT_TRUE(committed)
      << "network never recovered from sustained proposal stall "
      << "(no validator committed within " << MAX_PASSES << " passes)";

  assertNoFork(net, "emergency-recovery");

  //  Find the emergency block on validator 0's chain.
  const auto &chain = net.committed(0);
  size_t emergency_index = SIZE_MAX;
  for (size_t i = 0; i < chain.size(); ++i)
  {
    if (chain[i].header.emergency_rotation > 0)
    {
      emergency_index = i;
      break;
    }
  }
  ASSERT_NE(emergency_index, SIZE_MAX)
      << "no emergency block in validator 0's chain";

  const Core::Block &emergency = chain[emergency_index];
  EXPECT_FALSE(emergency.header.timeout_certificate.votes.empty())
      << "emergency block carries no timeout certificate";

  //  Every online validator must agree on that block.
  for (size_t i = 0; i < N; ++i)
  {
    ASSERT_GE(net.committed(i).size(), emergency_index + 1)
        << "validator " << i << " did not commit the emergency block";
    EXPECT_EQ(net.committed(i)[emergency_index].hash(), emergency.hash())
        << "validator " << i << " disagrees on the recovered block";
  }

  //  No duplicate signers in the certificate.
  std::set<Index> seen;
  for (const auto &tv : emergency.header.timeout_certificate.votes)
  {
    EXPECT_TRUE(seen.insert(tv.signer_index).second)
        << "duplicate signer " << tv.signer_index
        << " in recovered certificate";
  }
}

TEST_F(Consensus_NetworkFixture, EmergencyRotationIsOneShotThenResumesNormalOperation)
{
  constexpr size_t N = 4;

  ConsensusNetwork net(N, logger_);
  net.setRandomSeed(13);
  net.setProposalSuppressed(true);
  net.startAll(0);

  ASSERT_TRUE(net.advanceUntil(
      [&]
      { return !net.committed(0).empty(); },
      512))
      << "network never recovered from sustained proposal stall";

  //  Find the emergency block.
  size_t emergency_index = SIZE_MAX;
  {
    const auto &chain = net.committed(0);
    for (size_t i = 0; i < chain.size(); ++i)
    {
      if (chain[i].header.emergency_rotation > 0)
      {
        emergency_index = i;
        break;
      }
    }
  }
  ASSERT_NE(emergency_index, SIZE_MAX)
      << "no emergency block found in chain";

  net.setProposalSuppressed(false);

  //  Wait for a block after the emergency one to appear.
  const size_t needed = emergency_index + 2;
  const bool progressed = net.advanceUntil(
      [&]
      { return net.committed(0).size() >= needed; },
      128);

  ASSERT_TRUE(progressed)
      << "network did not resume normal operation after fault cleared";

  const auto &chain = net.committed(0);
  const Core::Block &next = chain[emergency_index + 1];
  EXPECT_EQ(next.header.height, chain[emergency_index].header.height + 1);
  EXPECT_EQ(next.header.emergency_rotation, 0u)
      << "post-recovery block should not be an emergency block";

  assertNoFork(net, "emergency-one-shot");

  for (size_t i = 0; i < N; ++i)
    EXPECT_GE(net.committed(i).size(), needed)
        << "validator " << i << " did not resume committing";
}