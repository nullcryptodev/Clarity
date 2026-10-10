// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <algorithm>
#include <set>

#include "Fixtures.h"

using namespace Consensus;
using namespace Tests;

// ============================================================================
//  Commit apply failure — retry, halt, and chain-head override
// ============================================================================

TEST_F(Consensus_BftFixture, CommitApplyFailureRetriesThenSucceeds)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  setBlockCommitFailsFor(1);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  ASSERT_EQ(consensus_->state().step, Step::Prevote);

  const Crypto::Hash hash = block.hash();
  deliverPrevote(2, 0, 0, false, hash);
  deliverPrevote(3, 0, 0, false, hash);
  ASSERT_EQ(consensus_->state().step, Step::Precommit);

  deliverPrecommit(2, 0, 0, false, hash);
  deliverPrecommit(3, 0, 0, false, hash);

  ASSERT_EQ(consensus_->state().step, Step::Commit);
  EXPECT_FALSE(consensusHalted());
  EXPECT_TRUE(height_advances.empty())
      << "height advanced despite a failed apply";

  //  Advance the clock past the backoff and retry.
  pollWithTimeAdvance([&]
                      { return !height_advances.empty(); });

  EXPECT_FALSE(consensusHalted());
  ASSERT_EQ(height_advances.size(), 1u)
      << "height never advanced after the retry succeeded";
  EXPECT_EQ(height_advances[0], 1u);
}

TEST_F(Consensus_BftFixture, CommitApplyFailureHalts)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  setBlockCommitFailsFor(100);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  const Crypto::Hash hash = block.hash();
  deliverPrevote(2, 0, 0, false, hash);
  deliverPrevote(3, 0, 0, false, hash);
  deliverPrecommit(2, 0, 0, false, hash);
  deliverPrecommit(3, 0, 0, false, hash);

  pollWithTimeAdvance([&]
                      { return consensusHalted(); });

  EXPECT_TRUE(consensusHalted())
      << "engine never halted after repeated apply failures";
  EXPECT_FALSE(lastHaltReason().empty());
  EXPECT_TRUE(height_advances.empty())
      << "height advanced despite every apply failing";
}

TEST_F(Consensus_BftFixture, NoteChainHeadAbortsRetry)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  //  Apply keeps failing — the engine is stuck in retry.
  setBlockCommitFailsFor(100);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  const Crypto::Hash hash = block.hash();
  deliverPrevote(2, 0, 0, false, hash);
  deliverPrevote(3, 0, 0, false, hash);
  deliverPrecommit(2, 0, 0, false, hash);
  deliverPrecommit(3, 0, 0, false, hash);

  ASSERT_EQ(consensus_->state().step, Step::Commit);

  //  An external path (relay, sync) applied the block. Telling the
  //  engine should abandon the retry and jump ahead.
  consensus_->noteChainHead(0);

  consensus_->pollTimers();

  EXPECT_EQ(consensus_->state().height, 1u)
      << "engine did not advance to the chain head's next height";
  EXPECT_FALSE(consensusHalted());
}

TEST_F(Consensus_BftFixture, HaltedStateIsObservable)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  EXPECT_FALSE(consensusHalted());
  EXPECT_EQ(halt_count_, 0u);

  setBlockCommitFailsFor(100);

  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  const Crypto::Hash hash = block.hash();
  deliverPrevote(2, 0, 0, false, hash);
  deliverPrevote(3, 0, 0, false, hash);
  deliverPrecommit(2, 0, 0, false, hash);
  deliverPrecommit(3, 0, 0, false, hash);

  pollWithTimeAdvance([&]
                      { return consensusHalted(); });

  EXPECT_TRUE(consensusHalted());
  EXPECT_EQ(halt_count_, 1u)
      << "on_consensus_halt fired more than once";
}

// ============================================================================
//  WAL: never double-sign after a crash
// ============================================================================

TEST_F(Consensus_BftFixture, WalReplayPreventsDoubleSigning)
{
  makeValidators(4);
  makeConsensus(0);
  consensus_->start(0);

  //  We are the proposer at (0, 0); start() drives us into Prevote
  //  synchronously.
  ASSERT_EQ(consensus_->state().step, Step::Prevote);
  ASSERT_FALSE(broadcast_prevotes.empty());

  const Vote original = broadcast_prevotes.back();
  ASSERT_EQ(original.signer_id, validators_[0].id);

  auto snap = snapshotForRestart();
  restartFromSnapshot(snap);

  //  The engine restarts and replays the WAL. Its recorded signed
  //  vote for (0, 0, prevote) is restored. Hand it the same proposal
  //  and let it try to prevote.
  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  //  At most one more prevote may have been broadcast, and if it was,
  //  it must byte-match the original (same signature, same hash).
  ASSERT_LE(broadcast_prevotes.size(), 2u)
      << "engine produced multiple prevotes on restart";

  if (broadcast_prevotes.size() == 2)
  {
    const Vote &second = broadcast_prevotes[1];
    EXPECT_EQ(second.height, original.height);
    EXPECT_EQ(second.round, original.round);
    EXPECT_EQ(second.is_nil, original.is_nil);
    EXPECT_EQ(second.block_hash, original.block_hash);
    EXPECT_EQ(second.signature.data, original.signature.data)
        << "restarted engine produced a different signature for the "
        << "same (height, round, type)";
  }
}

TEST_F(Consensus_BftFixture, WalReplayResumesAtHighestSignedRound)
{
  makeValidators(4);
  makeConsensus(0);
  consensus_->start(0);

  //  Drive several rounds by timing each out. Each round the engine
  //  signs a prevote and a precommit, both written to the WAL.
  for (int r = 0; r < 3; ++r)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }

  const Round before_restart = consensus_->state().round;
  ASSERT_GE(before_restart, 3u)
      << "did not reach round 3 before restart";

  auto snap = snapshotForRestart();
  restartFromSnapshot(snap);

  EXPECT_EQ(consensus_->state().round, before_restart)
      << "engine did not resume at the highest signed round";
}

TEST_F(Consensus_BftFixture, WalReplayKeepsHighestLock)
{
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  //  Round 0: get a polka for block X and adopt a lock.
  Core::Block block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, block);
  consensus_->onProposal(p);

  const Crypto::Hash hash = block.hash();
  deliverPrevote(2, 0, 0, false, hash);
  deliverPrevote(3, 0, 0, false, hash);

  ASSERT_EQ(consensus_->state().step, Step::Precommit);
  ASSERT_TRUE(consensus_->state().locked);
  const Round locked_at = consensus_->state().locked_round;
  const Crypto::Hash locked_hash = consensus_->state().locked_hash;

  auto snap = snapshotForRestart();
  restartFromSnapshot(snap);

  EXPECT_TRUE(consensus_->state().locked)
      << "lock was not restored from the WAL";
  EXPECT_EQ(consensus_->state().locked_round, locked_at);
  EXPECT_EQ(consensus_->state().locked_hash, locked_hash);
}

TEST_F(Consensus_BftFixture, LockedValidatorVotesLockAcrossEmergencyBoundary)
{
  //  Locked at a normal round, then forced into an emergency round.
  //  The validator must still prevote its lock, signing as the set
  //  the locked block's emergency flag selects.
  makeValidators(4);
  makeConsensus(1);
  consensus_->start(0);

  Core::Block locked_block = makeBlock(0);
  Proposal p = proposeFromProposer(0, 0, 0, locked_block);
  consensus_->onProposal(p);

  const Crypto::Hash lock_hash = locked_block.hash();
  deliverPrevote(2, 0, 0, false, lock_hash);
  deliverPrevote(3, 0, 0, false, lock_hash);

  ASSERT_EQ(consensus_->state().step, Step::Precommit);
  ASSERT_TRUE(consensus_->state().locked);
  ASSERT_EQ(consensus_->state().locked_hash, lock_hash);

  //  Time out enough rounds to enter emergency mode.
  const Round em = Core::EMERGENCY_ROTATION_ROUNDS;
  for (Round r = 0; r < em; ++r)
  {
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
    consensus_->forceTimerExpiryForTest();
    consensus_->pollTimers();
  }

  ASSERT_GE(consensus_->state().round, em);

  //  The engine's latest prevote must be for the locked hash, not
  //  nil and not some fresh block.
  ASSERT_FALSE(broadcast_prevotes.empty());
  const Vote &last = broadcast_prevotes.back();

  EXPECT_EQ(last.block_hash, lock_hash)
      << "locked validator abandoned its lock across the emergency "
      << "boundary";
  EXPECT_FALSE(last.is_nil);
}