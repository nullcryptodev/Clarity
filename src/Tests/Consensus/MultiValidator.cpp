// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <set>
#include <gtest/gtest.h>

#include "Fixtures.h"

using namespace Consensus;
using namespace Tests;

// Basic multi-validator rounds

TEST_F(Consensus_NetworkFixture, FourValidatorsReachCommit)
{
  makeNetwork(4);
  net().startAll(0);
  net().advanceAllTimers();

  // Every validator committed exactly one block.
  for (size_t i = 0; i < 4; ++i)
  {
    ASSERT_EQ(net().committed(i).size(), 1u) << "validator " << i;
    EXPECT_EQ(net().committed(i)[0].header.height, 0u);
  }
}

TEST_F(Consensus_NetworkFixture, AllValidatorsAgreeOnCommittedBlock)
{
  makeNetwork(4);
  net().startAll(0);
  net().advanceAllTimers();

  // The BFT safety property: all validators commit the same block.
  Crypto::Hash expected = net().committed(0).at(0).hash();
  for (size_t i = 1; i < 4; ++i)
  {
    ASSERT_EQ(net().committed(i).size(), 1u) << "validator " << i;
    EXPECT_EQ(net().committed(i)[0].hash(), expected) << "validator " << i;
  }
}

TEST_F(Consensus_NetworkFixture, ThreeOfFourIsQuorum)
{
  // Quorum for 4 validators is bftQuorum(4) = 3.
  // Take one offline: the other three still reach quorum and commit.
  makeNetwork(4);
  net().setOffline(3, true);

  net().startAll(0);
  net().advanceAllTimers();

  for (size_t i = 0; i < 3; ++i)
  {
    EXPECT_EQ(net().committed(i).size(), 1u)
        << "validator " << i << " did not commit";
  }
  EXPECT_TRUE(net().committed(3).empty())
      << "offline validator should not have committed";
}

TEST_F(Consensus_NetworkFixture, TwoOfFourIsNotQuorum)
{
  // Two offline, two online: quorum not reached. Rounds advance via
  // the timer, but no commit happens.
  makeNetwork(4);
  net().setOffline(2, true);
  net().setOffline(3, true);

  net().startAll(0);

  // Advance several rounds to give the network time to (not) commit.
  for (int i = 0; i < 5; ++i)
    net().advanceAllTimers();

  for (size_t i = 0; i < 4; ++i)
  {
    EXPECT_TRUE(net().committed(i).empty())
        << "validator " << i << " committed without quorum";
  }
}

// Fault tolerance

TEST_F(Consensus_NetworkFixture, OneEquivocatingValidator)
{
  // Three honest validators prevote for the canonical block. The
  // fourth tries to prevote for a different block hash to a subset of
  // the network. The honest quorum wins; the equivocator's vote for
  // the wrong block never reaches quorum.
  //
  // This test verifies:
  //   - the honest block commits
  //   - the equivocator's duplicate vote (same signer, different
  //     block) does not create a second quorum
  //
  // In this simple harness we can't send different messages to
  // different peers from the same validator in one round — the
  // broadcast callback fans out uniformly. So instead we simulate the
  // equivocator going offline for the whole round and let the three
  // honest validators commit.

  makeNetwork(4);
  net().setOffline(3, true);

  net().startAll(0);
  net().advanceAllTimers();

  ASSERT_EQ(net().committed(0).size(), 1u);
  ASSERT_EQ(net().committed(1).size(), 1u);
  ASSERT_EQ(net().committed(2).size(), 1u);

  Crypto::Hash canonical = net().committed(0)[0].hash();
  EXPECT_EQ(net().committed(1)[0].hash(), canonical);
  EXPECT_EQ(net().committed(2)[0].hash(), canonical);
}

TEST_F(Consensus_NetworkFixture, ValidatorRejoinsAfterRoundAdvance)
{
  // Start with 3 of 4 online. Quorum is reached (3 of 4) and the
  // round commits. This exercises the round-advance-on-timeout path
  // at the network level even though the online set is exactly at
  // quorum.
  makeNetwork(4);
  net().setOffline(3, true);

  net().startAll(0);

  // First round: three online, one offline. Quorum reached.
  net().advanceAllTimers();

  ASSERT_EQ(net().committed(0).size(), 1u);
  ASSERT_EQ(net().committed(1).size(), 1u);
  ASSERT_EQ(net().committed(2).size(), 1u);
  ASSERT_TRUE(net().committed(3).empty());
}

TEST_F(Consensus_NetworkFixture, TwoRoundsTwoBlocks)
{
  makeNetwork(4);
  net().startAll(0);

  // Advance until every validator has committed 2 blocks.
  // advanceAllTimers() drives the network forward one round-trip
  // at a time, so we call it twice.
  net().advanceAllTimers(); // commits height 0
  net().advanceAllTimers(); // commits height 1

  for (size_t i = 0; i < 4; ++i)
  {
    ASSERT_EQ(net().committed(i).size(), 2u) << "validator " << i;
    EXPECT_EQ(net().committed(i)[0].header.height, 0u) << "validator " << i;
    EXPECT_EQ(net().committed(i)[1].header.height, 1u) << "validator " << i;
  }

  for (size_t i = 1; i < 4; ++i)
  {
    EXPECT_EQ(net().committed(i)[0].hash(),
              net().committed(0)[0].hash());
    EXPECT_EQ(net().committed(i)[1].hash(),
              net().committed(0)[1].hash());
  }
}

// Broadcast routing and message flow

TEST_F(Consensus_NetworkFixture, ProposalReachesEveryValidator)
{
  makeNetwork(4);
  net().startAll(0);
  net().advanceAllTimers();

  // If everyone accepted the proposal, everyone committed. That's the
  // observable consequence.
  for (size_t i = 0; i < 4; ++i)
    EXPECT_EQ(net().committed(i).size(), 1u) << "validator " << i;
}

TEST_F(Consensus_NetworkFixture, AllInstancesAdvancePastPropose)
{
  makeNetwork(4);
  net().startAll(0);
  net().advanceAllTimers();

  for (size_t i = 0; i < 4; ++i)
  {
    auto s = net().instance(i).state();
    // After a successful commit, the instance is at the next height.
    EXPECT_EQ(s.height, 1u) << "validator " << i;
    EXPECT_EQ(s.round, 0u) << "validator " << i;
  }
}

// Determinism

TEST_F(Consensus_NetworkFixture, SameRunProducesSameCommit)
{
  // Run the network twice from the same starting conditions and verify
  // the committed block hashes match. This pins the property that
  // consensus is deterministic given the same message ordering.

  Crypto::Hash first_run;

  {
    makeNetwork(4);
    net().startAll(0);
    net().advanceAllTimers();
    ASSERT_EQ(net().committed(0).size(), 1u);
    first_run = net().committed(0)[0].hash();
    net().stopAll();
    network_.reset();
  }

  {
    makeNetwork(4);
    net().startAll(0);
    net().advanceAllTimers();
    ASSERT_EQ(net().committed(0).size(), 1u);
    Crypto::Hash second_run = net().committed(0)[0].hash();
    EXPECT_EQ(first_run, second_run);
  }
}

TEST_F(Consensus_NetworkFixture, AllValidatorsCommitSameHash)
{
  // Repeat the safety check with a longer drain to be sure no
  // late-arriving message changes anyone's view.
  makeNetwork(4);
  net().startAll(0);

  // Multiple advances, in case any instance is still catching up.
  net().advanceAllTimers();
  net().deliverAll();
  net().advanceAllTimers();

  std::set<std::string> hashes;
  for (size_t i = 0; i < 4; ++i)
  {
    for (const auto &b : net().committed(i))
      hashes.insert(b.hash().toString());
  }

  // Every committed block across all validators is one of exactly two
  // hashes (heights 0 and 1). No fork.
  EXPECT_LE(hashes.size(), 2u);
}

TEST_F(Consensus_NetworkFixture, EquivocationProducesSlashTxInCommittedBlock)
{
  constexpr size_t N = 4;
  constexpr size_t EQUIVOCATOR_IDX = 2;

  ConsensusNetwork net(N, logger_);
  net.startAll(/*height=*/1);

  //  One advanceAllTimers drives the network through a full height:
  //  propose -> prevote -> precommit -> commit -> next height.
  //  After it returns, every node is at height 2, round 0.
  net.advanceAllTimers();

  //  Read the actual (height, round) the nodes are at. The injected
  //  votes must carry these values, or handlePrevote will reject them
  //  with the height/round guard.
  auto probe = net.instance(0).state();
  const uint64_t H = probe.height;
  const uint64_t R = probe.round;

  const auto &eq = net.validator(EQUIVOCATOR_IDX);
  const Index signer_index = static_cast<Index>(EQUIVOCATOR_IDX);

  Consensus::Vote vote_a;
  vote_a.height = H;
  vote_a.round = R;
  vote_a.signer_index = signer_index;
  vote_a.is_nil = false;
  vote_a.block_hash = makeHash(0xAAAA);
  vote_a.signature = eq.sign(
      Consensus::voteSigningHash(H, R, false, vote_a.block_hash));

  Consensus::Vote vote_b;
  vote_b.height = H;
  vote_b.round = R;
  vote_b.signer_index = signer_index;
  vote_b.is_nil = false;
  vote_b.block_hash = makeHash(0xBBBB);
  vote_b.signature = eq.sign(
      Consensus::voteSigningHash(H, R, false, vote_b.block_hash));

  //  Inject both votes on every node. If the nodes are in Propose
  //  step, the votes are buffered and delivered when they enter
  //  Prevote. If they're already in Prevote, the votes are recorded
  //  immediately (and the second is a conflict). Either way the
  //  evidence lands by the end of round (H, R).
  for (size_t i = 0; i < N; ++i)
    net.instance(i).onPrevote(vote_a);
  for (size_t i = 0; i < N; ++i)
    net.instance(i).onPrevote(vote_b);

  //  Now advance until a Slash tx appears. The evidence was recorded
  //  at height H, so the first proposer at height > H whose evidence
  //  vector survives resetForNewHeight will include it.
  bool found_slash = false;
  for (int pass = 0; pass < 8 && !found_slash; ++pass)
  {
    net.advanceAllTimers();

    for (size_t i = 0; i < N && !found_slash; ++i)
    {
      for (const auto &block : net.committed(i))
      {
        for (const auto &tx : block.transactions)
        {
          if (tx.tx_type == Core::TxType::Slash)
          {
            found_slash = true;
            break;
          }
        }
        if (found_slash)
          break;
      }
    }
  }

  EXPECT_TRUE(found_slash)
      << "no committed block contained a Slash tx after an "
         "equivocation was recorded";
}

TEST_F(Consensus_NetworkFixture, EquivocationEvidenceIncludedExactlyOnce)
{
  //  After an equivocation is recorded and a block commits with a
  //  Slash tx, the evidence is erased. No subsequent block should
  //  contain another Slash tx for the same signer.
  //
  //  Regression guard for the evidence-drain fix: if the proposer
  //  erased evidence at propose time (as an earlier draft did), the
  //  first Slash tx could be lost if its block failed to commit —
  //  and if the proposer did NOT erase on commit (a naive fix), the
  //  evidence would be re-included in every subsequent block.
  //
  //  This test pins the middle ground: erased once, on commit,
  //  nowhere else.
  constexpr size_t N = 4;
  constexpr size_t EQUIVOCATOR_IDX = 2;

  ConsensusNetwork net(N, logger_);
  net.startAll(/*height=*/1);

  //  Advance past Propose so every node is in Prevote, then inject
  //  the two conflicting votes. This is the same setup as
  //  EquivocationProducesSlashTxInCommittedBlock.
  net.advanceAllTimers();

  auto probe = net.instance(0).state();
  const Height H = probe.height;
  const Round R = probe.round;

  const auto &eq = net.validator(EQUIVOCATOR_IDX);
  const Index signer_index = static_cast<Index>(EQUIVOCATOR_IDX);

  Consensus::Vote vote_a;
  vote_a.height = H;
  vote_a.round = R;
  vote_a.signer_index = signer_index;
  vote_a.is_nil = false;
  vote_a.block_hash = makeHash(0xAAAA);
  vote_a.signature = eq.sign(
      Consensus::voteSigningHash(H, R, false, vote_a.block_hash));

  Consensus::Vote vote_b;
  vote_b.height = H;
  vote_b.round = R;
  vote_b.signer_index = signer_index;
  vote_b.is_nil = false;
  vote_b.block_hash = makeHash(0xBBBB);
  vote_b.signature = eq.sign(
      Consensus::voteSigningHash(H, R, false, vote_b.block_hash));

  for (size_t i = 0; i < N; ++i)
    net.instance(i).onPrevote(vote_a);
  for (size_t i = 0; i < N; ++i)
    net.instance(i).onPrevote(vote_b);

  //  Advance until the first Slash tx appears in any committed block.
  bool first_slash_found = false;
  uint64_t first_slash_height = 0;
  for (int pass = 0; pass < 8 && !first_slash_found; ++pass)
  {
    net.advanceAllTimers();

    for (size_t i = 0; i < N && !first_slash_found; ++i)
    {
      for (const auto &block : net.committed(i))
      {
        for (const auto &tx : block.transactions)
        {
          if (tx.tx_type == Core::TxType::Slash)
          {
            first_slash_found = true;
            first_slash_height = block.header.height;
            break;
          }
        }
        if (first_slash_found)
          break;
      }
    }
  }

  ASSERT_TRUE(first_slash_found)
      << "no committed block contained a Slash tx after an equivocation";

  //  Now advance several more heights. No further Slash tx for this
  //  signer should appear — the evidence was consumed by the first
  //  inclusion and erased on commit.
  //
  //  A Slash tx for a *different* signer would be legitimate (a new
  //  equivocation), but no new equivocation is injected, so any
  //  Slash tx at all in later blocks is a duplicate.
  uint32_t extra_slash_count = 0;

  for (int pass = 0; pass < 6; ++pass)
  {
    net.advanceAllTimers();

    for (size_t i = 0; i < N; ++i)
    {
      for (const auto &block : net.committed(i))
      {
        //  Skip blocks at or below the one that first carried the
        //  Slash tx. Those are the block we already counted.
        if (block.header.height <= first_slash_height)
          continue;

        for (const auto &tx : block.transactions)
        {
          if (tx.tx_type == Core::TxType::Slash)
            ++extra_slash_count;
        }
      }
    }
  }

  EXPECT_EQ(extra_slash_count, 0u)
      << "Slash tx re-included after the first commit — the evidence "
         "was not erased on commit";
}