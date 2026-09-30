// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fixtures.h"
#include "Consensus/Types.h"

using namespace Consensus;
using namespace Tests;

// ============================================================================
//  Height transitions
// ============================================================================

TEST_F(Consensus_BftFixture, EvidenceSurvivesHeightTransition)
{
  //  Evidence recorded at height H must be visible to a proposer at
  //  height H+1. The existing EvidenceSurvivesFailedRound test
  //  covers round transitions within a height; this one covers the
  //  height boundary, where resetForNewHeight runs.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  ASSERT_EQ(consensus_->equivocationCount(), 0u);

  const Crypto::Hash block_hash = block.hash();
  deliverPrevote(0, 0, 0, /*is_nil=*/false, block_hash);

  Crypto::Hash conflicting_hash;
  conflicting_hash.data[0] = 0xCC;
  deliverPrevote(0, 0, 0, /*is_nil=*/false, conflicting_hash);

  ASSERT_EQ(consensus_->equivocationCount(), 1u);

  //  Advance through commit. The local node is a non-validator, so
  //  it won't commit on its own; drive a commit by supplying enough
  //  votes for the round's block.
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  deliverPrecommit(0, 0, 0, false, block_hash);
  deliverPrecommit(2, 0, 0, false, block_hash);
  deliverPrecommit(3, 0, 0, false, block_hash);

  ASSERT_EQ(committed_blocks.size(), 1u);
  ASSERT_EQ(consensus_->state().height, 1u);

  //  The evidence must still be present at the new height.
  EXPECT_EQ(consensus_->equivocationCount(), 1u)
      << "evidence was lost at height transition";
}

TEST_F(Consensus_BftFixture, HeightTransitionClearsLock)
{
  //  Lock is per-height. After a commit advances the height, the
  //  lock must be cleared.
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

  deliverPrecommit(2, 0, 0, false, block_hash);
  deliverPrecommit(3, 0, 0, false, block_hash);

  ASSERT_EQ(committed_blocks.size(), 1u);
  ASSERT_EQ(consensus_->state().height, 1u);
  EXPECT_FALSE(consensus_->state().locked)
      << "lock was not cleared on height transition";
}

TEST_F(Consensus_BftFixture, HeightTransitionClearsValidSet)
{
  //  valid_set_/valid_hash_/valid_round_ are per-height. They must
  //  be cleared when the height advances, because a polka at height
  //  H says nothing about height H+1.
  //
  //  We can't read valid_set_ directly. Indirect check: at height
  //  H+1, a precommit for the block that was valid at H must be
  //  rejected, because valid_hash_ no longer matches anything at
  //  H+1 and the lock is gone.
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  deliverPrevote(2, 0, 0, false, block.hash());
  deliverPrevote(3, 0, 0, false, block.hash());
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  deliverPrecommit(2, 0, 0, false, block.hash());
  deliverPrecommit(3, 0, 0, false, block.hash());
  ASSERT_EQ(committed_blocks.size(), 1u);

  //  At height 1, round 0, a precommit for the old height's block
  //  is for a block we've never seen at this height. It must be
  //  dropped.
  ASSERT_EQ(consensus_->state().height, 1u);
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  const size_t before = consensus_->state().precommit_count;
  deliverPrecommit(2, 0, 0, false, block.hash());
  EXPECT_EQ(consensus_->state().precommit_count, before)
      << "precommit for old height's block was accepted at new height";
}

// ============================================================================
//  Cross-height proposals
// ============================================================================

TEST_F(Consensus_BftFixture, ProposalForFutureHeightIsRejected)
{
  //  A proposal for height H+1 arriving while the local node is at
  //  height H is dropped. handleProposal's height check rejects it
  //  unconditionally. This pins that behaviour.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block future_block = makeBlock(1);
  Proposal p = proposeFromProposer(0, /*height=*/1, /*round=*/0, future_block);

  consensus_->onProposal(p);

  //  Local node should not have accepted the proposal.
  EXPECT_EQ(consensus_->state().height, 0u);
  EXPECT_EQ(consensus_->state().step, Step::Propose);

  //  Advance the local timer; if the proposal had been accepted,
  //  entering prevote would broadcast a non-nil prevote. Since it
  //  was rejected, prevote is nil.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  //  The local node is a non-validator, so it doesn't broadcast.
  //  But the step transitioned cleanly and no block was recorded.
  EXPECT_TRUE(committed_blocks.empty());
}

TEST_F(Consensus_BftFixture, ProposalForPastHeightIsRejected)
{
  //  A proposal for height H-1 is dropped by the same height check.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(5);

  Core::Block past_block = makeBlock(4);
  Proposal p = proposeFromProposer(0, /*height=*/4, /*round=*/0, past_block);

  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().height, 5u);
  EXPECT_EQ(consensus_->state().step, Step::Propose);
}

// ============================================================================
//  Cross-round votes
// ============================================================================

TEST_F(Consensus_BftFixture, VoteForPreviousRoundIsRejected)
{
  //  A vote for round N-1 arriving at round N is dropped.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  //  Advance one round so the local node is at round 1.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().round, 1u);

  //  A prevote for round 0 arrives. Dropped by the round check in
  //  handlePrevote.
  deliverPrevote(0, 0, /*round=*/0, true);

  //  The prevote tally at round 1 is unchanged (0 for a non-validator
  //  before voting).
  EXPECT_EQ(consensus_->state().prevote_count, 0u);
}

TEST_F(Consensus_BftFixture, VoteForFutureRoundIsBuffered)
{
  //  A prevote for round N+1 arriving at round N is buffered, not
  //  dropped and not counted. When the local node reaches round N+1,
  //  the buffer drains.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  //  A prevote for round 1 arrives while we're at round 0, step Propose.
  Crypto::Hash h;
  h.data[0] = 0xAA;
  deliverPrevote(0, 0, /*round=*/1, false, h);

  //  Not counted.
  EXPECT_EQ(consensus_->state().prevote_count, 0u);

  //  Advance to round 1.
  for (int i = 0; i < 3; ++i)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }
  ASSERT_EQ(consensus_->state().round, 1u);

  //  Advance to Prevote at round 1.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  //  The buffered vote for round 1 was for an unknown block. It
  //  stays buffered until the block arrives. The count is still 0.
  EXPECT_EQ(consensus_->state().prevote_count, 0u);
}

// ============================================================================
//  Self-vote semantics
// ============================================================================

TEST_F(Consensus_BftFixture, ValidatorSelfVoteCounts)
{
  //  A validator that is a member of the active set broadcasts its
  //  own prevote on entering the step, and that vote counts toward
  //  the prevote tally. Deliver one external prevote and expect the
  //  tally to be 2.
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(consensus_->state().prevote_count, 1u); // self-vote

  deliverPrevote(0, 0, 0, false, block.hash());
  EXPECT_EQ(consensus_->state().prevote_count, 2u);
}

TEST_F(Consensus_BftFixture, NonValidatorDoesNotSelfVote)
{
  //  A non-validator does not broadcast a vote. After entering
  //  prevote, the tally is 0, and one delivered vote brings it to 1.
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(consensus_->state().prevote_count, 0u);

  deliverPrevote(0, 0, 0, false, block.hash());
  EXPECT_EQ(consensus_->state().prevote_count, 1u);
}