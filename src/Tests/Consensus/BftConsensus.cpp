// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fixtures.h"

using namespace Consensus;
using namespace Tests;

// Single validator, full lifecycle

TEST_F(Consensus_BftFixture, StartEntersPropose)
{
  makeValidators(1);
  makeConsensus(0);

  EXPECT_FALSE(consensus_->isRunning());
  consensus_->start(0);
  EXPECT_TRUE(consensus_->isRunning());

  auto s = consensus_->state();
  EXPECT_EQ(s.height, 0u);
  EXPECT_EQ(s.round, 0u);
  EXPECT_EQ(s.step, Step::Propose);
}

TEST_F(Consensus_BftFixture, SingleValidatorProposes)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_EQ(broadcast_proposals.size(), 1u);
  EXPECT_EQ(broadcast_proposals[0].height, 0u);
  EXPECT_EQ(broadcast_proposals[0].round, 0u);
}

TEST_F(Consensus_BftFixture, NonValidatorDoesNotPropose)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  EXPECT_TRUE(broadcast_proposals.empty());
  EXPECT_TRUE(broadcast_prevotes.empty());
  EXPECT_TRUE(broadcast_precommits.empty());

  auto s = consensus_->state();
  EXPECT_EQ(s.step, Step::Propose);
}

TEST_F(Consensus_BftFixture, ProposeTimeoutEntersPrevote)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  auto before = consensus_->state();
  ASSERT_EQ(before.step, Step::Propose);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  auto after = consensus_->state();
  EXPECT_EQ(after.step, Step::Prevote);
}

TEST_F(Consensus_BftFixture, PrevoteTimeoutEntersPrecommit)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(consensus_->state().step, Step::Precommit);
}

TEST_F(Consensus_BftFixture, SingleValidatorCommitsEmptyBlock)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(committed_blocks[0].header.height, 0u);
}

TEST_F(Consensus_BftFixture, CommitAdvancesHeight)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_EQ(height_advances.size(), 1u);
  EXPECT_EQ(height_advances[0], 1u);

  auto s = consensus_->state();
  EXPECT_EQ(s.height, 1u);
  EXPECT_EQ(s.round, 0u);
}

TEST_F(Consensus_BftFixture, StopHaltsConsensus)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);
  ASSERT_TRUE(consensus_->isRunning());

  consensus_->stop();
  EXPECT_FALSE(consensus_->isRunning());

  auto before = consensus_->state();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  auto after = consensus_->state();
  EXPECT_EQ(before.step, after.step);
}

// Proposal handling

TEST_F(Consensus_BftFixture, AcceptsValidProposal)
{
  makeValidators(4);
  makeConsensus(2);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);

  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  auto s = consensus_->state();
  EXPECT_EQ(s.step, Step::Prevote);
  EXPECT_EQ(s.prevote_count, 1u);
}

TEST_F(Consensus_BftFixture, RejectsProposalFromWrongHeight)
{
  makeValidators(4);
  makeConsensus(2);
  consensus_->start(0);

  Core::Block block = makeBlock(5);
  Proposal p = proposeFromProposer(0, 5, 0, block);

  consensus_->onProposal(p);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  auto s = consensus_->state();
  EXPECT_EQ(s.step, Step::Prevote);
}

TEST_F(Consensus_BftFixture, RejectsProposalFromWrongRound)
{
  makeValidators(4);
  makeConsensus(2);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 3, block);

  consensus_->onProposal(p);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  auto s = consensus_->state();
  EXPECT_EQ(s.step, Step::Prevote);
}

TEST_F(Consensus_BftFixture, RejectsProposalFromWrongSigner)
{
  makeValidators(4);
  makeConsensus(2);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(1, 0, 0, block);

  consensus_->onProposal(p);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(consensus_->state().step, Step::Prevote);
}

TEST_F(Consensus_BftFixture, RejectsProposalWithBadSignature)
{
  makeValidators(4);
  makeConsensus(2);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);

  p.signature.data[0] ^= 0xFF;

  consensus_->onProposal(p);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(consensus_->state().step, Step::Prevote);
}

// Vote handling
TEST_F(Consensus_BftFixture, RecordsValidPrevote)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  //  Deliver a proposal so the round has a known block. The vote
  //  must reference a real block — a vote for an unknown block is
  //  buffered, not counted.
  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);

  EXPECT_EQ(consensus_->state().prevote_count, 2u);
}

TEST_F(Consensus_BftFixture, IgnoresDuplicatePrevote)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();

  deliverPrevote(0, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().prevote_count, 2u);

  deliverPrevote(0, 0, 0, false, block_hash);
  EXPECT_EQ(consensus_->state().prevote_count, 2u);
}

TEST_F(Consensus_BftFixture, IgnoresVoteWithWrongHeight)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  deliverPrevote(0, /*height=*/99, 0, true);

  EXPECT_EQ(consensus_->state().prevote_count, 1u);
}

TEST_F(Consensus_BftFixture, IgnoresVoteWithWrongRound)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  deliverPrevote(0, 0, /*round=*/9, true);

  EXPECT_EQ(consensus_->state().prevote_count, 1u);
}

TEST_F(Consensus_BftFixture, IgnoresVoteWithBadSignature)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Vote v = makeSignedVote(0, 0, 0, true);
  v.signature.data[0] ^= 0xFF;

  consensus_->onPrevote(v);
  EXPECT_EQ(consensus_->state().prevote_count, 1u);
}

// Quorum

TEST_F(Consensus_BftFixture, QuorumThresholdIsBftQuorum)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();

  deliverPrevote(0, 0, 0, false, block_hash);
  EXPECT_EQ(consensus_->state().step, Step::Prevote);
  EXPECT_EQ(consensus_->state().prevote_count, 2u);
}

TEST_F(Consensus_BftFixture, ReachesQuorumWithThresholdPrevotes)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();

  deliverPrevote(2, 0, 0, false, block_hash);
  EXPECT_EQ(consensus_->state().step, Step::Prevote);

  deliverPrevote(3, 0, 0, false, block_hash);
  EXPECT_EQ(consensus_->state().step, Step::Precommit);
}

TEST_F(Consensus_BftFixture, PrecommitQuorumEntersCommit)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  deliverPrecommit(2, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  deliverPrecommit(3, 0, 0, false, block_hash);

  EXPECT_EQ(committed_blocks.size(), 1u);
}

TEST_F(Consensus_BftFixture, CommitAppliesQuorumBlockNotLatestProposal)
{
  // Reproduce the round-crossing scenario: proposer at round 0 proposes
  // block X, validators reach precommit on X, but the precommit quorum
  // doesn't fully form before the precommit timer expires. Round 1
  // begins, proposer 1 proposes block Y, we accept it. Then a precommit
  // quorum for X arrives in round 1. We must commit X, not Y.
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block x = makeBlock(0, /*state_root=*/Crypto::Hash{});
  x.header.timestamp_ms = 1'000;
  Crypto::Hash x_hash = x.hash();

  Core::Block y = makeBlock(0);
  y.header.timestamp_ms = 2'000;
  Crypto::Hash y_hash = y.hash();
  ASSERT_NE(x_hash, y_hash);

  // --- Round 0: accept X ---
  Proposal p0 = proposeFromProposer(0, 0, 0, x);
  consensus_->onProposal(p0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  deliverPrevote(2, 0, 0, false, x_hash);
  deliverPrevote(3, 0, 0, false, x_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  ASSERT_EQ(consensus_->state().precommit_count, 1u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().round, 1u);
  ASSERT_EQ(consensus_->state().step, Step::Propose);

  // --- Round 1: accept Y ---
  Proposal p1 = proposeFromProposer(1, 0, 1, y);
  consensus_->onProposal(p1);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  // --- Precommit quorum arrives for X, not Y ---
  deliverPrecommit(0, 0, 1, false, x_hash);
  deliverPrecommit(2, 0, 1, false, x_hash);
  deliverPrecommit(3, 0, 1, false, x_hash);

  ASSERT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(committed_blocks[0].hash(), x_hash)
      << "committed block is not the one the precommit quorum voted for";
  EXPECT_NE(committed_blocks[0].hash(), y_hash);
}

// Locking

TEST_F(Consensus_BftFixture, LocksOnFirstPrevote)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_FALSE(consensus_->state().locked);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_TRUE(consensus_->state().locked);
  EXPECT_EQ(consensus_->state().locked_hash, block.hash());
}

TEST_F(Consensus_BftFixture, LockReleasedOnNewHeight)
{
  makeValidators(1);
  makeConsensus(0);

  consensus_->start(0);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  auto s = consensus_->state();
  ASSERT_EQ(s.height, 1u);
  EXPECT_FALSE(s.locked);
}

TEST_F(Consensus_BftFixture, WrongSignerIndexOutOfRangeIsIgnored)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Vote v = makeSignedVote(0, 0, 0, true);
  v.signer_index = 99;
  consensus_->onPrevote(v);

  EXPECT_EQ(consensus_->state().prevote_count, 1u);
}

// Vote type routing
// Prevotes and precommits are distinct message types on the wire. The
// consensus engine must be told which is which by the caller; it must
// not infer the type from the receiver's current step.

TEST_F(Consensus_BftFixture, PrecommitRejectedDuringPrevoteStep)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  const size_t initial_prevotes = consensus_->state().prevote_count;
  const size_t initial_precommits = consensus_->state().precommit_count;

  Crypto::Hash block_hash;
  block_hash.data[0] = 0xAA;
  deliverPrecommit(0, 0, 0, false, block_hash);

  EXPECT_EQ(consensus_->state().prevote_count, initial_prevotes)
      << "precommit was incorrectly recorded as a prevote";
  EXPECT_EQ(consensus_->state().precommit_count, initial_precommits)
      << "precommit was recorded during the wrong step";
  EXPECT_EQ(consensus_->state().step, Step::Prevote);
}

TEST_F(Consensus_BftFixture, PrevoteRejectedDuringPrecommitStep)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  const size_t initial_prevotes = consensus_->state().prevote_count;
  const size_t initial_precommits = consensus_->state().precommit_count;

  Crypto::Hash block_hash;
  block_hash.data[0] = 0xAA;
  deliverPrevote(0, 0, 0, false, block_hash);

  EXPECT_EQ(consensus_->state().prevote_count, initial_prevotes)
      << "prevote was recorded during the wrong step";
  EXPECT_EQ(consensus_->state().precommit_count, initial_precommits)
      << "prevote was incorrectly recorded as a precommit";
  EXPECT_EQ(consensus_->state().step, Step::Precommit);
}

TEST_F(Consensus_BftFixture, MixedVotesDoNotFormFalseQuorum)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();

  deliverPrevote(0, 0, 0, false, block_hash);
  deliverPrecommit(1, 0, 0, false, block_hash);

  EXPECT_EQ(consensus_->state().step, Step::Prevote)
      << "engine advanced on mixed vote types";

  EXPECT_EQ(consensus_->state().prevote_count, 2u);
  EXPECT_EQ(consensus_->state().precommit_count, 0u);
}

TEST_F(Consensus_BftFixture, CorrectlyRoutedVotesFormQuorum)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);

  EXPECT_EQ(consensus_->state().step, Step::Precommit);
}

// Precommit validity
// A precommit references a block by hash. It is only acceptable if
// the current round has a prevote quorum for that block, or if the
// receiver is already locked on it. Otherwise the precommit is a
// protocol violation and must be dropped — accepting it would let a
// minority of validators drive the receiver toward a commit on a
// block that was never legitimately proposed.

TEST_F(Consensus_BftFixture, PrecommitForUnknownBlockIsRejected)
{
  // After entering Precommit with no prevote quorum (valid_set_ is
  // false) and no lock, a precommit for an arbitrary block must be
  // dropped.
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers(); // Propose -> Prevote
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers(); // Prevote -> Precommit (timeout, no quorum)
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  const size_t initial_precommits = consensus_->state().precommit_count;

  Crypto::Hash unknown;
  unknown.data[0] = 0xDE;
  unknown.data[1] = 0xAD;
  deliverPrecommit(0, 0, 0, false, unknown);

  EXPECT_EQ(consensus_->state().precommit_count, initial_precommits)
      << "precommit for an unknown block was accepted";
}

TEST_F(Consensus_BftFixture, PrecommitForLockedBlockIsAccepted)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);
  ASSERT_TRUE(consensus_->state().locked);
  ASSERT_EQ(consensus_->state().locked_hash, block_hash);

  const size_t before = consensus_->state().precommit_count;
  deliverPrecommit(2, 0, 0, false, block_hash);
  EXPECT_GT(consensus_->state().precommit_count, before);
}

TEST_F(Consensus_BftFixture, PrecommitForOtherBlockIsRejected)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  const size_t before = consensus_->state().precommit_count;

  Crypto::Hash other;
  other.data[0] = 0xBE;
  other.data[1] = 0xEF;
  deliverPrecommit(2, 0, 0, false, other);

  EXPECT_EQ(consensus_->state().precommit_count, before)
      << "precommit for a non-locked, non-valid block was accepted";
}

// Broadcast type routing
// The consensus engine emits two kinds of vote through distinct
// callbacks. The wire format does not carry the vote type — the
// enclosing P2P message type does. An earlier version funnelled both
// through a single broadcast_vote callback and the node hardcoded
// the P2P message type as Prevote, so precommits went out labeled as
// prevotes. These tests verify that each kind of vote reaches its
// own callback.

TEST_F(Consensus_BftFixture, ProposalBroadcastsProposal)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_EQ(broadcast_proposals.size(), 1u);
  EXPECT_TRUE(broadcast_prevotes.empty());
  EXPECT_TRUE(broadcast_precommits.empty());
}

TEST_F(Consensus_BftFixture, EnterPrevoteBroadcastsPrevote)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  ASSERT_TRUE(broadcast_prevotes.empty());
  ASSERT_TRUE(broadcast_precommits.empty());

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(broadcast_prevotes.size(), 1u);
  EXPECT_TRUE(broadcast_precommits.empty())
      << "entering prevote broadcast a precommit";
}

TEST_F(Consensus_BftFixture, EnterPrecommitBroadcastsPrecommit)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  // Propose -> Prevote (broadcasts a prevote).
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(broadcast_prevotes.size(), 1u);

  // Prevote -> Precommit (timeout, no prevote quorum, so we broadcast
  // a nil precommit).
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(broadcast_precommits.size(), 1u)
      << "entering precommit did not broadcast a precommit";
  EXPECT_EQ(broadcast_prevotes.size(), 1u)
      << "entering precommit broadcast an extra prevote";
}

TEST_F(Consensus_BftFixture, PrecommitQuorumDoesNotBroadcastPrevote)
{
  // Once we're past the prevote step, no further prevotes should be
  // broadcast. This pins the invariant that broadcast routing follows
  // the step, not the vote's contents.
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  const size_t prevotes_at_prevote = broadcast_prevotes.size();

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  // Entering Precommit broadcasts a precommit, not a prevote.
  EXPECT_EQ(broadcast_prevotes.size(), prevotes_at_prevote)
      << "a prevote was broadcast after entering Precommit";
  EXPECT_GE(broadcast_precommits.size(), 1u);
}

// ============================================================================
//  Emergency rotation trigger
// ============================================================================

TEST_F(Consensus_BftFixture, ConsecutiveTimeoutsIncrementOnFailedRound)
{
  //  Non-proposer. Every round it enters ends in a timeout — no
  //  proposal arrives, no votes form a quorum. Each round advance
  //  increments consecutive_timeouts_ by one. This is what drives
  //  the emergency rotation trigger.
  //
  //  Regression guard: the counter is only reset on a successful
  //  commit. A failed round — timeout at any step, no quorum — must
  //  leave the counter climbing, or the emergency path can never
  //  fire on a genuinely stalled chain.
  makeValidators(4);
  makeConsensus(SIZE_MAX); // not a validator: never proposes
  consensus_->start(0);

  ASSERT_EQ(consensus_->consecutiveTimeouts(), 0u);

  //  Round 0: Propose -> Prevote -> Precommit -> next round.
  //  Each timer expiry advances one step; the last one rolls the
  //  round forward.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers(); // Propose -> Prevote
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers(); // Prevote -> Precommit
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers(); // Precommit -> next round

  EXPECT_EQ(consensus_->state().round, 1u);
  EXPECT_EQ(consensus_->consecutiveTimeouts(), 1u)
      << "counter did not increment on the first failed round";

  //  Round 1: same again.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(consensus_->state().round, 2u);
  EXPECT_EQ(consensus_->consecutiveTimeouts(), 2u)
      << "counter did not increment on the second failed round";
}

TEST_F(Consensus_BftFixture, ConsecutiveTimeoutsResetOnSuccessfulCommit)
{
  //  Single validator. One force-poll drives propose -> prevote ->
  //  precommit -> commit, because the lone validator's own votes
  //  form quorum at each step. The counter must be 0 afterwards.
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_EQ(consensus_->consecutiveTimeouts(), 0u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(consensus_->consecutiveTimeouts(), 0u)
      << "counter not reset after a successful commit";
}

TEST_F(Consensus_BftFixture, EmergencyRotationActiveOnlyAfterThreshold)
{
  //  Non-proposer. Drive through EMERGENCY_ROTATION_ROUNDS - 1
  //  failed rounds and assert the flag is still off, then one more
  //  and assert it turns on.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  const uint64_t threshold = Core::EMERGENCY_ROTATION_ROUNDS;

  for (uint64_t r = 0; r < threshold - 1; ++r)
  {
    //  Advance one round by timing out all three steps.
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }

  EXPECT_EQ(consensus_->consecutiveTimeouts(), threshold - 1);
  EXPECT_FALSE(consensus_->emergencyRotationActive())
      << "emergency flag turned on before the threshold";

  //  One more failed round crosses the threshold.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(consensus_->consecutiveTimeouts(), threshold);
  EXPECT_TRUE(consensus_->emergencyRotationActive())
      << "emergency flag did not turn on at the threshold";
}

// ============================================================================
//  Vote verification against the block's emergency flag
// ============================================================================

TEST_F(Consensus_BftFixture, VoteBufferedUntilBlockKnown)
{
  //  Non-proposer. Enter prevote step, then deliver a prevote for a
  //  block we haven't seen. The vote is unverifiable — without the
  //  block we don't know which active set the round ran on, so we
  //  can't look up the signer's public key. It must be buffered, not
  //  counted.
  //
  //  When the proposal arrives, the block becomes known, the buffer
  //  drains, and the vote is verified against the block's flag.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  //  Advance to Prevote.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  const size_t initial = consensus_->state().prevote_count;

  //  Build the block first so we know its hash, but don't deliver
  //  the proposal yet.
  Core::Block block = makeBlock(0);
  Crypto::Hash block_hash = block.hash();

  //  Validator 0 (the actual proposer of round 0 with 4 validators)
  //  prevotes the block. We don't have the block, so the vote is
  //  buffered.
  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);

  EXPECT_EQ(consensus_->state().prevote_count, initial)
      << "vote for an unknown block was counted before its block arrived";

  //  Deliver the proposal from validator 0. The block becomes known,
  //  the buffer drains, and the vote is verified.
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_GT(consensus_->state().prevote_count, initial)
      << "buffered vote was not delivered after its block arrived";
}

TEST_F(Consensus_BftFixture, VoteVerifiedAgainstBlockEmergencyFlag)
{
  //  Four validators. The committed set is {1, 2, 3, 4}. The
  //  emergency set is {1, 3} — a subset, chosen so that a vote from
  //  validator 2 is valid against the committed set but out of range
  //  (or pointing at a different validator) against the emergency set.
  //
  //  A proposal whose block header carries emergency_rotation > 0 is
  //  the signal that the round ran on the emergency set. Votes must
  //  be verified against the emergency set, not the committed set,
  //  even though the local counter may be below the threshold.
  makeValidators(4);

  //  Committed set is all four. Emergency set is {1, 3}.
  std::vector<Id> emergency = {1, 3};
  setEmergencyIds(emergency);

  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  //  Advance to Prevote.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  const size_t initial = consensus_->state().prevote_count;

  //  Build a block whose header carries the emergency flag. The
  //  block must be signed-into a proposal by the round's real
  //  proposer — index 0 in the committed set (proposerFor returns
  //  active[0] for round 0 with 4 validators).
  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = 1; // round at which the decision was made
  //  The block's validator_set_root was computed by makeBlock against
  //  the full set. That's fine for the consensus-layer test — the
  //  fixture's simulate_block returns the header's own state root, so
  //  validateProposal never checks the set root. BlockProcessor does,
  //  and that path is already covered by Core_BlockProcessorFixture.
  Crypto::Hash block_hash = block.hash();

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  //  A vote from validator 1 (index 0 in emergency set = {1, 3}, so
  //  index 0 → id 1, matches validators_[0]) should verify.
  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);
  EXPECT_GT(consensus_->state().prevote_count, initial)
      << "vote from a member of the emergency set was not counted";

  //  A vote from validator 2 (index 1 in committed set, but index 1
  //  in emergency set {1, 3} resolves to id 3, whose key is
  //  validators_[2]'s — not validators_[1]'s). The vote is signed by
  //  validator 2's key, but the emergency set's index 1 expects
  //  validator 3's key. Verification fails.
  const size_t after_first = consensus_->state().prevote_count;
  deliverPrevote(1, 0, 0, /*is_nil=*/false, block_hash);
  EXPECT_EQ(consensus_->state().prevote_count, after_first)
      << "vote signed by a non-member of the emergency set was counted";
}

TEST_F(Consensus_BftFixture, EvidenceSurvivesFailedRound)
{
  //  A conflict is observed. The round then fails to commit — no
  //  quorum forms on any block. The evidence must still be present
  //  for the next proposer.
  //
  //  Regression guard: an earlier draft erased evidence at propose
  //  time, which meant a failed round silently discarded the
  //  evidence and no slash could ever be applied.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  //  Deliver a proposal so the round has a known block. The first
  //  injected vote must reference it — an unverifiable vote is
  //  buffered, not recorded, and the conflict check needs a
  //  previously recorded vote to fire.
  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  ASSERT_EQ(consensus_->equivocationCount(), 0u);

  //  First vote: for the real block. Verifies, is recorded.
  const Crypto::Hash block_hash = block.hash();
  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);

  //  Second vote: same signer, same (height, round), different block
  //  hash. The block doesn't need to be known — once we hold a vote
  //  from this signer, a second one reaches recordVote, and the
  //  conflict fires.
  Crypto::Hash conflicting_hash;
  conflicting_hash.data[0] = 0xCC;
  conflicting_hash.data[1] = 0xDD;
  ASSERT_NE(conflicting_hash, block_hash);

  deliverPrevote(0, 0, 0, /*is_nil=*/false, conflicting_hash);

  ASSERT_EQ(consensus_->equivocationCount(), 1u)
      << "conflict was not recorded";

  //  Advance the round without committing. No value quorum forms
  //  because only one honest validator prevoted for the proposal;
  //  the local node is not a validator and doesn't vote.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers(); // prevote -> precommit
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers(); // precommit -> next round

  ASSERT_GT(consensus_->state().round, 0u);

  EXPECT_EQ(consensus_->equivocationCount(), 1u)
      << "evidence was lost when the round failed to commit";
}