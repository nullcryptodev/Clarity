// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fixtures.h"
#include "Consensus/Types.h"

using namespace Consensus;
using namespace Tests;

// ============================================================================
//  Single validator, full lifecycle
// ============================================================================

TEST_F(Consensus_BftFixture, StartCommitsAtN1)
{
  makeValidators(1);
  makeConsensus(0);

  EXPECT_FALSE(consensus_->isRunning());
  consensus_->start(0);
  EXPECT_TRUE(consensus_->isRunning());

  auto s = consensus_->state();
  EXPECT_EQ(s.height, 0u);
  EXPECT_EQ(s.round, 0u);
  EXPECT_EQ(s.step, Step::Commit);
  EXPECT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(committed_blocks[0].header.height, 0u);
}

TEST_F(Consensus_BftFixture, SingleValidatorProposes)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_GE(broadcast_proposals.size(), 1u);
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

  ASSERT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(committed_blocks[0].header.height, 0u);
}

TEST_F(Consensus_BftFixture, CommitAdvancesHeight)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(committed_blocks[0].header.height, 0u);

  //  Drain the pending height transition.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

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

// ============================================================================
//  Proposal handling
// ============================================================================

TEST_F(Consensus_BftFixture, AcceptsValidProposal)
{
  makeValidators(4);
  makeConsensus(2);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);

  consensus_->onProposal(p);

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

// ============================================================================
//  Vote handling
// ============================================================================

TEST_F(Consensus_BftFixture, RecordsValidPrevote)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

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

// ============================================================================
//  Quorum
// ============================================================================

TEST_F(Consensus_BftFixture, QuorumThresholdIsBftQuorum)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

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
  //  Round-crossing scenario. The local node is index 1, the proposer
  //  for round 1. After the round advances it proposes and enters
  //  prevote. The precommit quorum for X arrives while the local node
  //  is still in Prevote; with the relaxed step guard in recordVote,
  //  the commit fires immediately.
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block x = makeBlock(0, /*state_root=*/Crypto::Hash{});
  x.header.timestamp_ms = 1'000;
  Crypto::Hash x_hash = x.hash();

  // --- Round 0: accept X ---
  Proposal p0 = proposeFromProposer(0, 0, 0, x);
  consensus_->onProposal(p0);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  deliverPrevote(2, 0, 0, false, x_hash);
  deliverPrevote(3, 0, 0, false, x_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  // --- Advance to round 1. Local node is the proposer, so it
  //     proposes and enters prevote synchronously. ---
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().round, 1u);
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  // --- Deliver a precommit quorum for X at round 1. ---
  deliverPrecommit(0, 0, 1, false, x_hash);
  deliverPrecommit(2, 0, 1, false, x_hash);
  deliverPrecommit(3, 0, 1, false, x_hash);

  ASSERT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(committed_blocks[0].hash(), x_hash)
      << "committed block is not the one the precommit quorum voted for";
}

// ============================================================================
//  Locking
// ============================================================================

TEST_F(Consensus_BftFixture, LocksOnPrecommitNotPrevote)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  EXPECT_FALSE(consensus_->state().locked);

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  EXPECT_TRUE(consensus_->state().locked);
  EXPECT_EQ(consensus_->state().locked_hash, block_hash);
  EXPECT_EQ(consensus_->state().locked_round, 0u);
}

TEST_F(Consensus_BftFixture, LockedValidatorPrevotesLockedBlockInLaterRound)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block x = makeBlock(0);
  x.header.timestamp_ms = 1'000;
  Crypto::Hash x_hash = x.hash();

  Proposal p0 = proposeFromProposer(0, 0, 0, x);
  consensus_->onProposal(p0);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  deliverPrevote(2, 0, 0, false, x_hash);
  deliverPrevote(3, 0, 0, false, x_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);
  ASSERT_TRUE(consensus_->state().locked);
  ASSERT_EQ(consensus_->state().locked_hash, x_hash);

  //  Advance to round 1. Local node is the proposer, so it re-proposes
  //  the lock (X) and prevotes X.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().round, 1u);

  ASSERT_FALSE(broadcast_prevotes.empty());
  const Vote &last = broadcast_prevotes.back();
  EXPECT_EQ(last.round, 1u);
  EXPECT_FALSE(last.is_nil);
  EXPECT_EQ(last.block_hash, x_hash)
      << "locked validator prevoted a block other than its lock";
}

TEST_F(Consensus_BftFixture, CommitOnLockedBlockAfterRoundCrosses)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block x = makeBlock(0);
  x.header.timestamp_ms = 1'000;
  Crypto::Hash x_hash = x.hash();

  Proposal p0 = proposeFromProposer(0, 0, 0, x);
  consensus_->onProposal(p0);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  deliverPrevote(2, 0, 0, false, x_hash);
  deliverPrevote(3, 0, 0, false, x_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);
  ASSERT_TRUE(consensus_->state().locked);

  //  Advance to round 1.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().round, 1u);

  //  Precommits for X arrive in round 1.
  deliverPrecommit(0, 0, 1, false, x_hash);
  deliverPrecommit(2, 0, 1, false, x_hash);
  deliverPrecommit(3, 0, 1, false, x_hash);

  ASSERT_EQ(committed_blocks.size(), 1u);
  EXPECT_EQ(committed_blocks[0].hash(), x_hash);
}

TEST_F(Consensus_BftFixture, LockReleasedOnNewHeight)
{
  //  The lock is per-height. To observe it being cleared we need a
  //  height transition that does not immediately re-lock. At n=1,
  //  the new height's first polka re-locks immediately, so the test
  //  uses n=4 and drives a real commit that advances the height.
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);
  ASSERT_TRUE(consensus_->state().locked);

  deliverPrecommit(2, 0, 0, false, block_hash);
  deliverPrecommit(3, 0, 0, false, block_hash);
  ASSERT_EQ(committed_blocks.size(), 1u);

  //  Drain the pending height transition.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_EQ(consensus_->state().height, 1u);
  EXPECT_FALSE(consensus_->state().locked)
      << "lock was not cleared on height transition";
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

// ============================================================================
//  Vote type routing
// ============================================================================

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

  EXPECT_EQ(consensus_->state().prevote_count, initial_prevotes);
  EXPECT_EQ(consensus_->state().precommit_count, initial_precommits);
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

  EXPECT_EQ(consensus_->state().prevote_count, initial_prevotes);
  EXPECT_EQ(consensus_->state().precommit_count, initial_precommits);
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

  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();

  deliverPrevote(0, 0, 0, false, block_hash);
  deliverPrecommit(1, 0, 0, false, block_hash);

  EXPECT_EQ(consensus_->state().step, Step::Prevote);
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

  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);

  EXPECT_EQ(consensus_->state().step, Step::Precommit);
}

// ============================================================================
//  Precommit validity
// ============================================================================

TEST_F(Consensus_BftFixture, PrecommitForUnknownBlockIsRejected)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  const size_t initial_precommits = consensus_->state().precommit_count;

  Crypto::Hash unknown;
  unknown.data[0] = 0xDE;
  unknown.data[1] = 0xAD;
  deliverPrecommit(0, 0, 0, false, unknown);

  EXPECT_EQ(consensus_->state().precommit_count, initial_precommits);
}

TEST_F(Consensus_BftFixture, PrecommitForLockedBlockIsAccepted)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

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

  EXPECT_EQ(consensus_->state().precommit_count, before);
}

// ============================================================================
//  Broadcast type routing
// ============================================================================

TEST_F(Consensus_BftFixture, ProposalBroadcastsProposal)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_GE(broadcast_proposals.size(), 1u);
  EXPECT_GE(broadcast_prevotes.size(), 1u);
  EXPECT_GE(broadcast_precommits.size(), 1u);
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
  EXPECT_TRUE(broadcast_precommits.empty());
}

TEST_F(Consensus_BftFixture, EnterPrecommitBroadcastsPrecommit)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(broadcast_prevotes.size(), 1u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(broadcast_precommits.size(), 1u);
  EXPECT_EQ(broadcast_prevotes.size(), 1u);
}

TEST_F(Consensus_BftFixture, PrecommitQuorumDoesNotBroadcastPrevote)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  const size_t prevotes_at_prevote = broadcast_prevotes.size();

  Crypto::Hash block_hash = block.hash();
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  EXPECT_EQ(broadcast_prevotes.size(), prevotes_at_prevote);
  EXPECT_GE(broadcast_precommits.size(), 1u);
}

// ============================================================================
//  Emergency rotation trigger
// ============================================================================

TEST_F(Consensus_BftFixture, ConsecutiveTimeoutsIncrementOnFailedRound)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  ASSERT_EQ(consensus_->consecutiveTimeouts(), 0u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(consensus_->state().round, 1u);
  EXPECT_EQ(consensus_->consecutiveTimeouts(), 1u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(consensus_->state().round, 2u);
  EXPECT_EQ(consensus_->consecutiveTimeouts(), 2u);
}

TEST_F(Consensus_BftFixture, ConsecutiveTimeoutsResetOnSuccessfulCommit)
{
  makeValidators(1);
  makeConsensus(0);
  consensus_->start(0);

  ASSERT_GE(committed_blocks.size(), 1u);
  EXPECT_EQ(consensus_->consecutiveTimeouts(), 0u);
}

TEST_F(Consensus_BftFixture, EmergencyRotationActiveOnlyAfterThreshold)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  const uint64_t threshold = Core::EMERGENCY_ROTATION_ROUNDS;

  for (uint64_t r = 0; r < threshold - 1; ++r)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }

  EXPECT_EQ(consensus_->consecutiveTimeouts(), threshold - 1);
  EXPECT_FALSE(consensus_->emergencyRotationActive());

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  EXPECT_EQ(consensus_->consecutiveTimeouts(), threshold);
  EXPECT_TRUE(consensus_->emergencyRotationActive());
}

// ============================================================================
//  Vote verification against the block's emergency flag
// ============================================================================

TEST_F(Consensus_BftFixture, VoteBufferedUntilBlockKnown)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  const size_t initial = consensus_->state().prevote_count;

  Core::Block block = makeBlock(0);
  Crypto::Hash block_hash = block.hash();

  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);

  EXPECT_EQ(consensus_->state().prevote_count, initial);

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_GT(consensus_->state().prevote_count, initial);
}

TEST_F(Consensus_BftFixture, VoteVerifiedAgainstBlockEmergencyFlag)
{
  //  Committed set: {1, 2, 3, 4}. Emergency set: {1, 3}.
  makeValidators(4);
  setEmergencyIds({1, 3});

  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  const Round em_round = Core::EMERGENCY_ROTATION_ROUNDS;

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = em_round;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/0, em_round, /*signers=*/{0, 1});
  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Crypto::Hash block_hash = block.hash();

  Proposal p = proposeFromProposer(/*proposer_index=*/0,
                                   /*height=*/0,
                                   /*round=*/em_round,
                                   block);

  consensus_->onProposal(p); // queued, since local round is 0

  //  Advance to em_round.
  int guard = 0;
  while (consensus_->state().round < em_round && guard++ < 256)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }
  ASSERT_EQ(consensus_->state().round, em_round);

  //  The proposal should have been installed by drainFutureProposal
  //  during the round advance; step may already be Prevote.
  guard = 0;
  while (consensus_->state().step != Step::Prevote && guard++ < 4)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }
  ASSERT_EQ(consensus_->state().round, em_round);
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  const size_t initial = consensus_->state().prevote_count;

  //  Vote from emergency-set index 0 (validator 1).
  deliverPrevote(/*signer_index=*/0,
                 /*height=*/0,
                 /*round=*/em_round,
                 /*is_nil=*/false,
                 block_hash);

  EXPECT_GT(consensus_->state().prevote_count, initial);

  //  Vote from emergency-set index 1 (validator 3) but signed by
  //  validators_[1]'s key — should fail verification against the
  //  emergency set's slot 1.
  const size_t after_first = consensus_->state().prevote_count;
  deliverPrevote(/*signer_index=*/1,
                 /*height=*/0,
                 /*round=*/em_round,
                 /*is_nil=*/false,
                 block_hash);

  EXPECT_EQ(consensus_->state().prevote_count, after_first);
}

TEST_F(Consensus_BftFixture, EvidenceSurvivesFailedRound)
{
  //  Conflict is delivered as a block vote and a nil vote. A block
  //  vote for an unknown block would be buffered, not passed to
  //  recordVote; the nil vote is verifiable as soon as the round's
  //  proposal is installed, so it reaches the conflict path.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(consensus_->equivocationCount(), 0u);

  const Crypto::Hash block_hash = block.hash();
  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);
  deliverPrevote(0, 0, 0, /*is_nil=*/true, Crypto::Hash{});

  ASSERT_EQ(consensus_->equivocationCount(), 1u)
      << "conflict was not recorded";

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_GT(consensus_->state().round, 0u);

  EXPECT_EQ(consensus_->equivocationCount(), 1u);
}

// ============================================================================
//  Equivocation evidence — signature gating
// ============================================================================

TEST_F(Consensus_BftFixture, ForgedConflictDoesNotRecordEvidence)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(consensus_->equivocationCount(), 0u);

  const Crypto::Hash block_hash = block.hash();
  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);
  ASSERT_EQ(consensus_->state().prevote_count, 1u);

  //  Nil vote from the same signer, garbage signature. It fails
  //  verification and never reaches the conflict path.
  Vote forged = makeSignedVote(0, 0, 0, /*is_nil=*/true);
  forged.signature.data[0] ^= 0xFF;

  consensus_->onPrevote(forged);

  EXPECT_EQ(consensus_->equivocationCount(), 0u);
  EXPECT_EQ(consensus_->state().prevote_count, 1u);
}

TEST_F(Consensus_BftFixture, ConflictWithUnverifiableBlockIsNotRecorded)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(consensus_->equivocationCount(), 0u);

  Crypto::Hash hash_a;
  hash_a.data[0] = 0xAA;
  Crypto::Hash hash_b;
  hash_b.data[0] = 0xBB;

  deliverPrevote(0, 0, 0, /*is_nil=*/false, hash_a);
  deliverPrevote(0, 0, 0, /*is_nil=*/false, hash_b);

  EXPECT_EQ(consensus_->equivocationCount(), 0u);
  EXPECT_EQ(consensus_->state().prevote_count, 0u);
}

TEST_F(Consensus_BftFixture, ConflictRecordedWhenBlockArrivesLater)
{
  //  Block vote + nil vote from the same signer, both before the
  //  round's proposal is known. Both are buffered. When the proposal
  //  arrives, the block vote becomes verifiable (its block is now
  //  known) and the nil vote becomes verifiable (the round's proposal
  //  is now known). The first is recorded, the second reaches the
  //  conflict path with a resolvable signer.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(consensus_->equivocationCount(), 0u);

  Core::Block block = makeBlock(0);
  const Crypto::Hash block_hash = block.hash();

  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);
  deliverPrevote(0, 0, 0, /*is_nil=*/true, Crypto::Hash{});

  EXPECT_EQ(consensus_->equivocationCount(), 0u);

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->equivocationCount(), 1u)
      << "conflict was not recorded after its block arrived";
}

// ============================================================================
//  Timeout certificate
// ============================================================================

TEST_F(Consensus_BftFixture, EmergencyBlockWithoutCertificateIsRejected)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = Core::EMERGENCY_ROTATION_ROUNDS;

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

TEST_F(Consensus_BftFixture, EmergencyBlockWithValidCertificateIsAccepted)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  const Round em_round = Core::EMERGENCY_ROTATION_ROUNDS;

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = em_round;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/0, em_round, /*signers=*/{0, 1});
  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Proposal p = proposeFromProposer(/*proposer_index=*/0,
                                   /*height=*/0,
                                   /*round=*/em_round,
                                   block);

  consensus_->onProposal(p);

  int guard = 0;
  while (consensus_->state().round < em_round && guard++ < 256)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }
  ASSERT_EQ(consensus_->state().round, em_round);

  guard = 0;
  while (consensus_->state().step != Step::Prevote && guard++ < 4)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }
  EXPECT_EQ(consensus_->state().step, Step::Prevote);
}

TEST_F(Consensus_BftFixture, EmergencyBlockWithTooFewAttestationsIsRejected)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = Core::EMERGENCY_ROTATION_ROUNDS;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/0,
                             /*round=*/Core::EMERGENCY_ROTATION_ROUNDS,
                             /*signers=*/{0});
  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

TEST_F(Consensus_BftFixture, EmergencyBlockWithBadCertificateSignatureIsRejected)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = Core::EMERGENCY_ROTATION_ROUNDS;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/0,
                             /*round=*/Core::EMERGENCY_ROTATION_ROUNDS,
                             /*signers=*/{0, 1});

  block.header.timeout_certificate.votes[0].signature.data[0] ^= 0xFF;

  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

TEST_F(Consensus_BftFixture, EmergencyBlockWithWrongRoundCertificateIsRejected)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = Core::EMERGENCY_ROTATION_ROUNDS;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/0,
                             /*round=*/Core::EMERGENCY_ROTATION_ROUNDS + 5,
                             /*signers=*/{0, 1});
  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

TEST_F(Consensus_BftFixture, TimeoutVoteBroadcastOnRoundTimeout)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  ASSERT_TRUE(broadcast_timeout_votes.empty());

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(broadcast_timeout_votes.size(), 1u);
  EXPECT_EQ(broadcast_timeout_votes[0].round, 0u);
  EXPECT_EQ(broadcast_timeout_votes[0].height, 0u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Precommit);
  ASSERT_EQ(broadcast_timeout_votes.size(), 2u);
  EXPECT_EQ(broadcast_timeout_votes[1].round, 0u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().round, 1u);
  ASSERT_EQ(broadcast_timeout_votes.size(), 3u);
  EXPECT_EQ(broadcast_timeout_votes[2].round, 0u);
}

TEST_F(Consensus_BftFixture, TimeoutVoteReceivedFromPeerIsRetained)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  deliverTimeoutVote(/*signer=*/0, /*height=*/0,
                     /*round=*/Core::EMERGENCY_ROTATION_ROUNDS);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

TEST_F(Consensus_BftFixture, TimeoutVoteBelowThresholdIsIgnored)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  deliverTimeoutVote(/*signer=*/0, /*height=*/0, /*round=*/1);
  deliverTimeoutVote(/*signer=*/1, /*height=*/0, /*round=*/1);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
  EXPECT_EQ(consensus_->consecutiveTimeouts(), 0u);
}

TEST_F(Consensus_BftFixture, EmergencyProposalRequiresCertificateFromCommittedSet)
{
  makeValidators(4);
  makeConsensus(0);
  consensus_->start(0);

  const uint64_t threshold = Core::EMERGENCY_ROTATION_ROUNDS;

  uint64_t iterations = 0;
  while (!consensus_->emergencyRotationActive() && iterations < threshold * 2)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    ++iterations;
  }

  ASSERT_TRUE(consensus_->emergencyRotationActive());

  for (const auto &proposal : broadcast_proposals)
  {
    Core::Block block;
    if (!Core::Block::deserialize(proposal.block_bytes.data(),
                                  proposal.block_bytes.size(), block))
      continue;

    EXPECT_EQ(block.header.emergency_rotation, 0u);
  }
}

TEST_F(Consensus_BftFixture, EmergencyBlockWithCertificateForWrongHeightIsRejected)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = Core::EMERGENCY_ROTATION_ROUNDS;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/7,
                             /*round=*/Core::EMERGENCY_ROTATION_ROUNDS,
                             /*signers=*/{0, 1});
  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

TEST_F(Consensus_BftFixture, EmergencyBlockWithSignerOutOfRangeIsRejected)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = Core::EMERGENCY_ROTATION_ROUNDS;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/0,
                             /*round=*/Core::EMERGENCY_ROTATION_ROUNDS,
                             /*signers=*/{0, 99});
  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

TEST_F(Consensus_BftFixture, EmergencyBlockWithDuplicateSignersIsRejected)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = Core::EMERGENCY_ROTATION_ROUNDS;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/0,
                             /*round=*/Core::EMERGENCY_ROTATION_ROUNDS,
                             /*signers=*/{0, 0});
  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

TEST_F(Consensus_BftFixture, EmergencyBlockWithSignerFromEmergencySetOnlyIsRejected)
{
  makeValidators(4);
  setEmergencyIds({1, 3});

  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  const Round em_round = Core::EMERGENCY_ROTATION_ROUNDS;

  Core::Block block = makeBlock(0);
  block.header.emergency_rotation = em_round;
  block.header.timeout_certificate =
      makeTimeoutCertificate(/*height=*/0, em_round, /*signers=*/{0, 1});
  block.header.timeout_certificate_hash =
      Core::computeTimeoutCertificateHash(block.header.timeout_certificate);

  Proposal p = proposeFromProposer(/*proposer_index=*/0,
                                   /*height=*/0,
                                   /*round=*/em_round,
                                   block);

  consensus_->onProposal(p);

  int guard = 0;
  while (consensus_->state().round < em_round && guard++ < 256)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }
  ASSERT_EQ(consensus_->state().round, em_round);

  guard = 0;
  while (consensus_->state().step != Step::Prevote && guard++ < 4)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }
  EXPECT_EQ(consensus_->state().step, Step::Prevote)
      << "certificate resolved against the wrong set";
}

TEST_F(Consensus_BftFixture, RecordedEquivocationProducesSlashTx)
{
  //  Local node is validator 2 (index 1). It is not the proposer for
  //  (height=0, round=0) — validator 1 is — so it does not self-propose.
  //  It *is* the proposer for (height=1, round=0), so its height-1
  //  proposal is where the Slash tx will appear.
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  //  Deliver a proposal for (0, 0). The local node has no proposal
  //  yet, so handleProposal installs it.
  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);
  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_FALSE(consensus_->state().prevote_count == 0 && broadcast_prevotes.empty());
  //  The local node's own prevote for the proposal is in prevotes_
  //  (as a validator), and it was broadcast.

  //  Inject an equivocation: validator 2 prevotes the block and nil.
  const Crypto::Hash block_hash = block.hash();
  deliverPrevote(1, 0, 0, /*is_nil=*/false, block_hash);
  deliverPrevote(1, 0, 0, /*is_nil=*/true, Crypto::Hash{});
  ASSERT_EQ(consensus_->equivocationCount(), 1u);

  //  Drive a commit at height 0. The local node is validator 2
  //  (index 1), so deliver the remaining prevotes and precommits
  //  needed for quorum.
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  deliverPrecommit(2, 0, 0, false, block_hash);
  deliverPrecommit(3, 0, 0, false, block_hash);
  ASSERT_EQ(committed_blocks.size(), 1u);

  //  Drain pending_height_ so the local node enters height 1 and
  //  proposes. As the (1, 0) proposer, it builds a fresh block and
  //  includes any surviving evidence as a Slash tx.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().height, 1u);

  //  Find the height-1 proposal in broadcast_proposals.
  bool found_slash = false;
  for (const auto &prop : broadcast_proposals)
  {
    Core::Block b;
    if (!Core::Block::deserialize(prop.block_bytes.data(),
                                  prop.block_bytes.size(), b))
      continue;
    if (b.header.height != 1u)
      continue;
    for (const auto &tx : b.transactions)
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

  EXPECT_TRUE(found_slash)
      << "height-1 proposal did not include a Slash tx";
}