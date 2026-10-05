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
  //  height H+1. The conflict is delivered as a block vote and a nil
  //  vote: the block vote is verifiable once the proposal is
  //  installed, and the nil vote is verifiable as soon as the round's
  //  proposal is known.
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

  ASSERT_EQ(consensus_->equivocationCount(), 1u);

  //  Drive a commit by supplying enough votes for the round's block.
  deliverPrevote(2, 0, 0, false, block_hash);
  deliverPrevote(3, 0, 0, false, block_hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  deliverPrecommit(0, 0, 0, false, block_hash);
  deliverPrecommit(2, 0, 0, false, block_hash);
  deliverPrecommit(3, 0, 0, false, block_hash);

  ASSERT_EQ(committed_blocks.size(), 1u);

  //  Drain the pending height transition.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_EQ(consensus_->state().height, 1u);
  EXPECT_EQ(consensus_->equivocationCount(), 1u)
      << "evidence was lost at height transition";
}

TEST_F(Consensus_BftFixture, HeightTransitionClearsLock)
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

  deliverPrecommit(2, 0, 0, false, block_hash);
  deliverPrecommit(3, 0, 0, false, block_hash);
  ASSERT_EQ(committed_blocks.size(), 1u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_EQ(consensus_->state().height, 1u);
  EXPECT_FALSE(consensus_->state().locked)
      << "lock was not cleared on height transition";
}

TEST_F(Consensus_BftFixture, HeightTransitionClearsValidSet)
{
  //  At height H+1, a precommit for the block that was valid at H
  //  must be rejected: valid_hash_ no longer matches anything at H+1
  //  and the lock is gone.
  //
  //  The local node (index 1) is the proposer for height 1, so after
  //  draining pending_height_ it enters prevote synchronously. There
  //  is no second timer pair — one pollTimers drains the transition
  //  and (because the proposer acts immediately) leaves the engine
  //  in Prevote.
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  deliverPrevote(2, 0, 0, false, block.hash());
  deliverPrevote(3, 0, 0, false, block.hash());
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  deliverPrecommit(2, 0, 0, false, block.hash());
  deliverPrecommit(3, 0, 0, false, block.hash());
  ASSERT_EQ(committed_blocks.size(), 1u);

  //  Drain pending_height_. The proposer for height 1 proposes and
  //  enters prevote within the same call.
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();

  ASSERT_EQ(consensus_->state().height, 1u);
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
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block future_block = makeBlock(1);
  Proposal p = proposeFromProposer(0, /*height=*/1, /*round=*/0, future_block);

  consensus_->onProposal(p);

  EXPECT_EQ(consensus_->state().height, 0u);
  EXPECT_EQ(consensus_->state().step, Step::Propose);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  EXPECT_TRUE(committed_blocks.empty());
}

TEST_F(Consensus_BftFixture, ProposalForPastHeightIsRejected)
{
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
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().round, 1u);

  deliverPrevote(0, 0, /*round=*/0, true);

  EXPECT_EQ(consensus_->state().prevote_count, 0u);
}

TEST_F(Consensus_BftFixture, VoteForFutureRoundIsBuffered)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Crypto::Hash h;
  h.data[0] = 0xAA;
  deliverPrevote(0, 0, /*round=*/1, false, h);

  EXPECT_EQ(consensus_->state().prevote_count, 0u);

  for (int i = 0; i < 3; ++i)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }
  ASSERT_EQ(consensus_->state().round, 1u);

  consensus_->forceTimerExpiryForTest();
  consensus_->pollTimers();
  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  EXPECT_EQ(consensus_->state().prevote_count, 0u);
}

// ============================================================================
//  Self-vote semantics
// ============================================================================

TEST_F(Consensus_BftFixture, ValidatorSelfVoteCounts)
{
  makeValidators(4);
  makeConsensus(3);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(consensus_->state().prevote_count, 1u); // self-vote

  deliverPrevote(0, 0, 0, false, block.hash());
  EXPECT_EQ(consensus_->state().prevote_count, 2u);
}

TEST_F(Consensus_BftFixture, NonValidatorDoesNotSelfVote)
{
  makeValidators(4);
  makeConsensus(SIZE_MAX);
  consensus_->start(0);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_EQ(consensus_->state().prevote_count, 0u);

  deliverPrevote(0, 0, 0, false, block.hash());
  EXPECT_EQ(consensus_->state().prevote_count, 1u);
}