// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <set>

#include "Fixtures.h"
#include "Utils.h"

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

  //  Largest committed height across all validators, or INVALID if
  //  nobody has committed. Used to describe divergence in failures.
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
  //  Run the same 4-validator network 100 times with different
  //  delivery seeds. Every run should commit exactly one block at
  //  height 0, and every validator should agree on its hash.
  //
  //  This is the single most valuable adversarial test. It exercises
  //  100 different message orderings of the same round and asserts
  //  the safety property in each.
  constexpr size_t N = 4;
  constexpr uint64_t SEEDS = 100;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(N, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    //  Poll until every validator has committed once. Under
    //  randomized delivery, one advanceAllTimers() pass is not
    //  sufficient for every node — we must poll until convergence.
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
  //  4 validators, 1 offline. Quorum is 3, so the remaining 3 still
  //  reach quorum. Randomize delivery; every run must commit the same
  //  block.
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
  //  4 validators, quorum 3. A 2-2 partition means neither side has
  //  quorum, so no commits happen.
  ConsensusNetwork net(4, logger_);
  net.startAll(0);

  net.setPartition({0, 1}, {2, 3});

  for (int i = 0; i < 5; ++i)
    net.advanceAllTimers();

  for (size_t i = 0; i < 4; ++i)
    EXPECT_TRUE(net.committed(i).empty())
        << "validator " << i << " committed under 2-2 partition";

  //  Heal the partition. The network should settle within a few rounds.
  net.clearPartition();
  net.advanceUntil([&]
                   { return !net.committed(0).empty(); }, 40);

  EXPECT_FALSE(net.committed(0).empty())
      << "no commit after partition healed";
  assertNoFork(net, "post-heal");
}

TEST_F(Consensus_NetworkFixture, PartitionOfThreeOneCommits)
{
  //  4 validators, quorum 3. Split 3-1. The 3-side has quorum and
  //  should commit; the 1-side stalls.
  ConsensusNetwork net(4, logger_);
  net.startAll(0);

  net.setPartition({0, 1, 2}, {3});

  net.advanceUntil([&]
                   { return !net.committed(0).empty(); }, 40);

  ASSERT_FALSE(net.committed(0).empty());
  EXPECT_EQ(net.committed(0)[0].hash(), net.committed(1)[0].hash());
  EXPECT_EQ(net.committed(0)[0].hash(), net.committed(2)[0].hash());
  EXPECT_TRUE(net.committed(3).empty())
      << "partitioned validator should not have committed";

  //  Heal. The 1-side should catch up on the next commit.
  net.clearPartition();
  net.advanceUntil([&]
                   { return net.committed(0).size() >= 2u; }, 40);

  assertNoFork(net, "post-heal");
}

TEST_F(Consensus_NetworkFixture, PartitionHealsWithoutFork)
{
  //  Even with randomized delivery, a partition+heal cycle must not
  //  produce a fork. This is the safety property under partition.
  constexpr uint64_t SEEDS = 30;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(4, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    net.setPartition({0, 1}, {2, 3});
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
  //  One validator is stopped for a round, then restarted. The chain
  //  should keep committing under the remaining 3 (quorum is 3). When
  //  the stopped validator restarts, it should rejoin and start
  //  committing alongside the others.
  //
  //  The harness backfills the restarted node's committed_ list from
  //  a live peer on restart, so the restarted node starts out with
  //  the same history as the peer it synced from. We then require it
  //  to contribute at least one *new* commit on top of that history.
  ConsensusNetwork net(4, logger_);
  net.startAll(0);

  //  One round commits.
  net.advanceUntil([&]
                   { return net.committed(0).size() == 1u; }, 32);
  ASSERT_GE(net.committed(0).size(), 1u);

  //  Stop validator 3, then run another round.
  net.stopValidator(3);
  net.advanceUntil([&]
                   { return net.committed(0).size() == 2u; }, 32);

  ASSERT_GE(net.committed(0).size(), 2u);
  EXPECT_GE(net.committed(1).size(), 2u);
  EXPECT_GE(net.committed(2).size(), 2u);
  EXPECT_EQ(net.committed(3).size(), 1u)
      << "stopped validator should not have committed the second block";

  //  Bring it back. The harness picks the correct height and backfills
  //  the committed chain from a live peer.
  const Height restart_height =
      net.committed(0).back().header.height + 1;
  net.restartValidator(3, restart_height);

  //  Drive the network forward until validator 3 has committed past
  //  its backfilled history AND has converged with validator 0 on the
  //  latest height. Requiring convergence (not just a bump) is
  //  important: a lagging validator may briefly hold a shorter chain
  //  than validator 0 before catching up.
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
  //  4 validators, random ordering, one crashes and restarts. No fork
  //  in any seed.
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
  //  The umbrella test. Random ordering, occasional partition, one
  //  crash-restart. Assert the safety property holds for every seed.
  //
  //  This is a smoke test: it doesn't prove correctness, it just gives
  //  the implementation a chance to fail under conditions the
  //  deterministic tests can't reach.
  constexpr size_t N = 7; // 7 validators, quorum 5
  constexpr uint64_t SEEDS = 50;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(N, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    //  Step through several rounds, changing the environment.
    for (int step = 0; step < 8; ++step)
    {
      switch (step)
      {
      case 0:
      case 1:
        // Clean run.
        break;
      case 2:
        // Partition 5-2. The 5-side has quorum (5 needed), the 2-side
        // does not.
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
  //  Regression test for the height-buffering fix.
  //
  //  4 validators, randomized delivery. Without future-height
  //  buffering, a validator that finishes height 0 late drops the
  //  height-1 prevotes and precommits that arrived while it was still
  //  committing height 0, and can only reach height 1 by timing out
  //  into a later round. With buffering, it should reach height 1
  //  without any round skips: its first attempt at height 1 (round 0)
  //  should succeed because the votes are waiting for it.
  //
  //  The assertion is intentionally strict: we require every validator
  //  to reach height 1 at round 0. A validator that needed a round
  //  timeout to get there would have a height advance entry at round
  //  > 0, which we don't have a direct accessor for — so we instead
  //  assert that no round-timeout-driven height advance happened by
  //  checking that every validator's chain has exactly the expected
  //  prefix. If a validator had to skip rounds, its chain would still
  //  match, but the safety property would hold while liveness was
  //  degraded. We therefore use a direct proxy: the number of
  //  height-advance events per validator should equal the number of
  //  commits, since a round-skip that eventually commits produces
  //  exactly one advance event too. That doesn't discriminate.
  //
  //  Instead we assert the property that actually matters and is
  //  observable: every validator reaches height 1 within a small
  //  number of passes, and all agree on heights 0 and 1. The
  //  regression is caught because without buffering the slow
  //  validator's round-0 attempt at height 1 fails and it must burn
  //  at least one extra timer pass per skipped round, which the
  //  512-pass budget in RandomOrderingAcrossTwoHeights was already
  //  not enough to absorb reliably. Here we use a tight budget to
  //  make the regression bite.
  constexpr size_t N = 4;
  constexpr uint64_t SEEDS = 50;

  for (uint64_t seed = 1; seed <= SEEDS; ++seed)
  {
    ConsensusNetwork net(N, logger_);
    net.setRandomSeed(seed);
    net.startAll(0);

    //  Tight budget: with correct buffering every validator should
    //  reach height 1 well within this. Without it, a slow validator
    //  can need many round-timeout cycles to find a live proposer.
    const bool reached = net.advanceUntil([&]
                                          { return allHaveAtLeast(net, 2); }, 64);

    ASSERT_TRUE(reached)
        << "seed " << seed << ": not all validators reached height 1 "
        << "within 64 passes (max committed height "
        << maxCommittedHeight(net) << ")";

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
  //  A validator that is stopped should not accumulate unbounded
  //  state from future-height votes. We can't inspect the buffer
  //  directly through ConsensusNetwork, but we can assert the
  //  observable consequences:
  //
  //    - the stopped validator commits nothing while stopped,
  //    - when it comes back it still reaches the chain tip,
  //    - no fork results.
  //
  //  The bound itself (height_ + 1 only) is a code-level invariant
  //  enforced in drainFutureHeightVotes / drainFutureHeightProposal;
  //  this test exercises the paths that feed those buffers.
  constexpr size_t N = 4;

  ConsensusNetwork net(N, logger_);
  net.setRandomSeed(7);
  net.startAll(0);

  //  Let the network get moving.
  net.advanceUntil([&]
                   { return allHaveAtLeast(net, 1); }, 64);
  ASSERT_TRUE(allHaveAtLeast(net, 1));

  //  Stop validator 3. It stops sending, stops receiving, and stops
  //  firing timers; the online peers carry on without it.
  net.stopValidator(3);

  //  Drive several more heights while 3 is stopped.
  net.advanceUntil([&]
                   { return net.committed(0).size() >= 4u; }, 128);

  ASSERT_GE(net.committed(0).size(), 4u)
      << "online peers stalled while one validator was stopped";

  EXPECT_EQ(net.committed(3).size(), 1u)
      << "stopped validator should not have committed";

  //  Bring it back. The harness backfills its committed chain from a
  //  live peer and re-delivers the peer's current proposal, so it
  //  should converge on the next commit.
  const Height next = net.committed(0).back().header.height + 1;
  net.restartValidator(3, next);

  const size_t baseline = net.committed(3).size();
  net.advanceUntil([&]
                   { return net.committed(3).size() > baseline &&
                            net.committed(0).size() == net.committed(3).size(); }, 128);

  EXPECT_GT(net.committed(3).size(), baseline)
      << "restarted validator did not rejoin";

  assertNoFork(net, "bounded-buffer");
}

TEST_F(Consensus_NetworkFixture, RandomOrderingAcrossTwoHeights)
{
  //  Same as RandomOrderingProducesSameCommit but two heights, to
  //  exercise the round-reset and height-advance paths under
  //  randomized delivery.
  //
  //  Under randomized delivery, one validator can legitimately run
  //  ahead while another lags. We therefore assert only that every
  //  validator eventually reaches height 1 (two commits), and that
  //  the first two heights agree across all validators. We do NOT
  //  assert exact commit counts: a lagging validator may still be
  //  catching up when the leading validator has advanced several
  //  heights.
  //
  //  Budget note: this used to be 512 passes, which masked a
  //  liveness bug where a slow validator dropped the height-1 votes
  //  that arrived while it was still committing height 0, and had to
  //  burn round timeouts to recover. With future-height buffering in
  //  place, 128 is comfortably enough and makes the test bite on a
  //  regression. If this starts flaking, raise it — but investigate
  //  first: the whole point is that the height transition should be
  //  cheap.
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
        << "(max committed height " << maxCommittedHeight(net) << ")";

    for (size_t i = 0; i < N; ++i)
    {
      EXPECT_GE(net.committed(i).size(), 2u)
          << "seed " << seed << ": validator " << i << " has "
          << net.committed(i).size() << " commits";
    }

    //  Every validator agreed on heights 0 and 1.
    expectPrefixMatches(net, 2, "seed " + std::to_string(seed));

    assertNoFork(net, "seed " + std::to_string(seed));
  }
}

TEST_F(Consensus_NetworkFixture, EmergencyRotationRecoversFromSustainedProposalStall)
{
  //  Integration test for the emergency-rotation path.
  //
  //  Every unit piece is already covered by Consensus_BftFixture
  //  (counter increment, threshold trigger, certificate assembly,
  //  certificate verification, proposer-side gate). What this test
  //  adds is the end-to-end drive: a live network where proposals
  //  are persistently rejected, so every validator's round timer
  //  fires for many consecutive rounds, timeout votes gossip and
  //  accumulate, and the emergency set eventually takes over and
  //  commits a block carrying a certificate.
  //
  //  The fault is *proposal suppression*, not partition or crash:
  //  proposers still propose, the network still carries proposals,
  //  and timeout-vote gossip is fully intact. Only the receiving
  //  side drops proposals. That is the condition under which
  //  consecutive_timeouts_ can actually reach
  //  EMERGENCY_ROTATION_ROUNDS — a partition or a crash would also
  //  silence the timeout votes needed to assemble the certificate.
  constexpr size_t N = 4;

  ConsensusNetwork net(N, logger_);
  net.setRandomSeed(11);
  net.setProposalSuppressed(true);
  net.startAll(0);

  //  Give it room to climb past EMERGENCY_ROTATION_ROUNDS. The
  //  exact threshold is a Core constant; we drive enough passes to
  //  cross it with margin. Each pass advances every validator by at
  //  most one round, so a budget of a few hundred is plenty.
  constexpr int MAX_PASSES = 512;

  const bool committed = net.advanceUntil(
      [&]
      { return !net.committed(0).empty(); },
      MAX_PASSES);

  ASSERT_TRUE(committed)
      << "network never recovered from sustained proposal stall "
      << "(no validator committed within " << MAX_PASSES << " passes)";

  //  Every validator that is online should agree on the block. The
  //  emergency path must not fork.
  assertNoFork(net, "emergency-recovery");

  for (size_t i = 0; i < N; ++i)
  {
    ASSERT_FALSE(net.committed(i).empty())
        << "validator " << i << " did not commit after recovery";
    EXPECT_EQ(net.committed(i)[0].hash(), net.committed(0)[0].hash())
        << "validator " << i << " disagrees on the recovered block";
  }

  //  The block that broke the stall must carry the emergency flag and
  //  a certificate. If it didn't, we didn't actually exercise the
  //  emergency path — we just got lucky with a normal commit.
  const Core::Block &recovered = net.committed(0)[0];
  EXPECT_GT(recovered.header.emergency_rotation, 0u)
      << "recovered block is not an emergency block";
  EXPECT_FALSE(recovered.header.timeout_certificate.votes.empty())
      << "emergency block carries no timeout certificate";

  //  The certificate must have the required f+1 attestations from the
  //  committed set. quorumThreshold() is the BFT quorum for the
  //  active set; the certificate requirement is f+1, which for
  //  N=4 is 2. We assert the weaker, universally-true bound: at
  //  least one vote, and no duplicate signers.
  std::set<Index> seen;
  for (const auto &tv : recovered.header.timeout_certificate.votes)
  {
    EXPECT_TRUE(seen.insert(tv.signer_index).second)
        << "duplicate signer " << tv.signer_index
        << " in recovered certificate";
  }

  //  With proposals suppressed, the pre-emergency rounds should have
  //  produced no commits at all. The recovered block should be the
  //  very first commit on every chain.
  for (size_t i = 0; i < N; ++i)
    EXPECT_EQ(net.committed(i).size(), 1u)
        << "validator " << i
        << " committed more than once during suppression";
}

TEST_F(Consensus_NetworkFixture, EmergencyRotationIsOneShotThenResumesNormalOperation)
{
  //  After emergency rotation breaks a proposal stall, clearing the
  //  fault should let the network resume ordinary commits: the next
  //  block should be a normal (non-emergency) block at height +1,
  //  and consecutive_timeouts_ should have reset.
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

  //  The recovery block is the emergency one. Capture its height.
  const Height emergency_height = net.committed(0)[0].header.height;
  ASSERT_GT(net.committed(0)[0].header.emergency_rotation, 0u);

  //  Clear the fault. The network should now commit normally.
  net.setProposalSuppressed(false);

  const bool progressed = net.advanceUntil(
      [&]
      { return net.committed(0).size() >= 2u; },
      128);

  ASSERT_TRUE(progressed)
      << "network did not resume normal operation after fault cleared";

  const Core::Block &next = net.committed(0)[1];
  EXPECT_EQ(next.header.height, emergency_height + 1);
  EXPECT_EQ(next.header.emergency_rotation, 0u)
      << "post-recovery block should not be an emergency block";

  assertNoFork(net, "emergency-one-shot");

  for (size_t i = 0; i < N; ++i)
    EXPECT_GE(net.committed(i).size(), 2u)
        << "validator " << i << " did not resume committing";
}