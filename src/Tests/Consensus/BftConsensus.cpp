// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Tests/Fixtures.h"

using namespace Consensus;
using namespace Tests;

// ============================================================================
//  A. Single validator, full lifecycle
// ============================================================================

TEST_F(ConsensusTestFixture, StartEntersPropose)
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

TEST_F(ConsensusTestFixture, SingleValidatorProposes)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_EQ(broadcast_proposals.size(), 1u);
  EXPECT_EQ(broadcast_proposals[0].height, 0u);
  EXPECT_EQ(broadcast_proposals[0].round, 0u);
}

TEST_F(ConsensusTestFixture, NonValidatorDoesNotPropose)
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

TEST_F(ConsensusTestFixture, ProposeTimeoutEntersPrevote)
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

TEST_F(ConsensusTestFixture, PrevoteTimeoutEntersPrecommit)
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

TEST_F(ConsensusTestFixture, SingleValidatorCommitsEmptyBlock)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(committed_blocks[0].header.height, 0u);
}

TEST_F(ConsensusTestFixture, CommitAdvancesHeight)
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

TEST_F(ConsensusTestFixture, StopHaltsConsensus)
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

// ============================================================================
//  B. Proposal handling
// ============================================================================

TEST_F(ConsensusTestFixture, AcceptsValidProposal)
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

TEST_F(ConsensusTestFixture, RejectsProposalFromWrongHeight)
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

TEST_F(ConsensusTestFixture, RejectsProposalFromWrongRound)
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

TEST_F(ConsensusTestFixture, RejectsProposalFromWrongSigner)
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

TEST_F(ConsensusTestFixture, RejectsProposalWithBadSignature)
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

// ============================================================================
//  C. Vote handling
// ============================================================================

TEST_F(ConsensusTestFixture, RecordsValidPrevote)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash;
  block_hash.data[0] = 0xAA;
  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);

  EXPECT_EQ(consensus_->state().prevote_count, 2u);
}

TEST_F(ConsensusTestFixture, IgnoresDuplicatePrevote)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash;
  block_hash.data[0] = 0xAA;

  deliverPrevote(0, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().prevote_count, 2u);

  deliverPrevote(0, 0, 0, false, block_hash);
  EXPECT_EQ(consensus_->state().prevote_count, 2u);
}

TEST_F(ConsensusTestFixture, IgnoresVoteWithWrongHeight)
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

TEST_F(ConsensusTestFixture, IgnoresVoteWithWrongRound)
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

TEST_F(ConsensusTestFixture, IgnoresVoteWithBadSignature)
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

// ============================================================================
//  D. Quorum
// ============================================================================

TEST_F(ConsensusTestFixture, QuorumThresholdIsBftQuorum)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash;
  block_hash.data[0] = 0xAA;

  deliverPrevote(0, 0, 0, false, block_hash);
  EXPECT_EQ(consensus_->state().step, Step::Prevote);
  EXPECT_EQ(consensus_->state().prevote_count, 2u);
}

TEST_F(ConsensusTestFixture, ReachesQuorumWithThresholdPrevotes)
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

TEST_F(ConsensusTestFixture, PrecommitQuorumEntersCommit)
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

TEST_F(ConsensusTestFixture, CommitAppliesQuorumBlockNotLatestProposal)
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

// ============================================================================
//  E. Locking
// ============================================================================

TEST_F(ConsensusTestFixture, LocksOnFirstPrevote)
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

TEST_F(ConsensusTestFixture, LockReleasedOnNewHeight)
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

TEST_F(ConsensusTestFixture, WrongSignerIndexOutOfRangeIsIgnored)
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

// ============================================================================
//  F. Vote type routing
//
//  Prevotes and precommits are distinct message types on the wire. The
//  consensus engine must be told which is which by the caller; it must
//  not infer the type from the receiver's current step.
// ============================================================================

TEST_F(ConsensusTestFixture, PrecommitRejectedDuringPrevoteStep)
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

TEST_F(ConsensusTestFixture, PrevoteRejectedDuringPrecommitStep)
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

TEST_F(ConsensusTestFixture, MixedVotesDoNotFormFalseQuorum)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash;
  block_hash.data[0] = 0xAA;

  deliverPrevote(0, 0, 0, false, block_hash);
  deliverPrecommit(1, 0, 0, false, block_hash);

  EXPECT_EQ(consensus_->state().step, Step::Prevote)
      << "engine advanced on mixed vote types";

  EXPECT_EQ(consensus_->state().prevote_count, 2u);
  EXPECT_EQ(consensus_->state().precommit_count, 0u);
}

TEST_F(ConsensusTestFixture, CorrectlyRoutedVotesFormQuorum)
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

// ============================================================================
//  G. Precommit validity
//
//  A precommit references a block by hash. It is only acceptable if
//  the current round has a prevote quorum for that block, or if the
//  receiver is already locked on it. Otherwise the precommit is a
//  protocol violation and must be dropped — accepting it would let a
//  minority of validators drive the receiver toward a commit on a
//  block that was never legitimately proposed.
// ============================================================================

TEST_F(ConsensusTestFixture, PrecommitForUnknownBlockIsRejected)
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

TEST_F(ConsensusTestFixture, PrecommitForLockedBlockIsAccepted)
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

TEST_F(ConsensusTestFixture, PrecommitForOtherBlockIsRejected)
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

// ============================================================================
//  H. Broadcast type routing
//
//  The consensus engine emits two kinds of vote through distinct
//  callbacks. The wire format does not carry the vote type — the
//  enclosing P2P message type does. An earlier version funnelled both
//  through a single broadcast_vote callback and the node hardcoded
//  the P2P message type as Prevote, so precommits went out labeled as
//  prevotes. These tests verify that each kind of vote reaches its
//  own callback.
// ============================================================================

TEST_F(ConsensusTestFixture, ProposalBroadcastsProposal)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_EQ(broadcast_proposals.size(), 1u);
  EXPECT_TRUE(broadcast_prevotes.empty());
  EXPECT_TRUE(broadcast_precommits.empty());
}

TEST_F(ConsensusTestFixture, EnterPrevoteBroadcastsPrevote)
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

TEST_F(ConsensusTestFixture, EnterPrecommitBroadcastsPrecommit)
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

TEST_F(ConsensusTestFixture, PrecommitQuorumDoesNotBroadcastPrevote)
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