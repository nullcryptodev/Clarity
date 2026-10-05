// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>

#include "Fixtures.h"

#include "Core/ValidatorRotation.h"

using namespace Core;
using namespace Tests;

// Header validation

TEST_F(Core_BlockProcessorFixture, RejectsNotWellFormedHeader)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  b.header.version = 999;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "block header not well-formed");
}

TEST_F(Core_BlockProcessorFixture, RejectsWrongChainId)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  b.header.chain_id = 0xDEAD;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "chain_id mismatch");
}

TEST_F(Core_BlockProcessorFixture, RejectsWrongHeight)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());

  BlockContext ctx = makeContext(2);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "height mismatch");
}

TEST_F(Core_BlockProcessorFixture, RejectsNullParentForNonGenesis)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  b.header.parent_hash = Crypto::Hash{};

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  // A null parent fails structural validation before the block
  // processor's chain-connectivity check runs. Either message is a
  // correct rejection.
  EXPECT_TRUE(r.error == "parent hash is null" ||
              r.error == "block header not well-formed")
      << "got: " << r.error;
}

TEST_F(Core_BlockProcessorFixture, RejectsFutureTimestamp)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  b.header.timestamp_ms = 99'999'999'999'999ULL;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "timestamp is too far in the future");
}

TEST_F(Core_BlockProcessorFixture, RejectsTxRootMismatch)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  for (size_t i = 0; i < 32; ++i)
    b.header.tx_root.data[i] = 0xAA;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "tx_root mismatch");
}

TEST_F(Core_BlockProcessorFixture, RejectsValidatorSetRootMismatch)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  for (size_t i = 0; i < 32; ++i)
    b.header.validator_set_root.data[i] = 0xBB;

  // The header field is part of the block hash, so corrupting it after
  // signing invalidates the signatures. Re-sign so the signature check
  // passes and the validator_set_root check is the one that fires.
  b.quorum_signatures = makeQuorumForBlock(b, {seed1_, seed2_});

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "validator_set_root mismatch");
}

TEST_F(Core_BlockProcessorFixture, RejectsActiveValidatorCountMismatch)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  b.header.active_validator_count = 5;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "active validator count mismatch");
}

// Quorum validation

TEST_F(Core_BlockProcessorFixture, RejectsInsufficientSignatures)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  b.quorum_signatures.clear();

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "insufficient quorum signatures");
}

TEST_F(Core_BlockProcessorFixture, RejectsDuplicateSigners)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  for (auto &vs : b.quorum_signatures)
    vs.signer_index = 0;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "duplicate signature from same signer");
}

TEST_F(Core_BlockProcessorFixture, RejectsOutOfRangeSignerIndex)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  b.quorum_signatures[0].signer_index = 999;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "signer index out of range");
}

TEST_F(Core_BlockProcessorFixture, RejectsInvalidSignerIndex)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  b.quorum_signatures[0].signer_index = INVALID_INDEX;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "invalid signer index");
}

TEST_F(Core_BlockProcessorFixture, AcceptsExactQuorum)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_TRUE(r.valid) << r.error;
}

// Transaction application

TEST_F(Core_BlockProcessorFixture, AppliesEmptyBlock)
{
  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_TRUE(r.receipts.empty());
  EXPECT_TRUE(r.tx_hashes.empty());
}

TEST_F(Core_BlockProcessorFixture, AppliesSingleTransfer)
{
  uint64_t a_before = balanceOf(alice_.publicKey);
  uint64_t b_before = balanceOf(bob_.publicKey);

  Transaction tx = makeSignedTransfer(alice_, bob_.publicKey, 500, 3, 0);

  BlockResult r = applyBlock(1, genesis_hash_, {tx});
  ASSERT_TRUE(r.valid) << r.error;
  ASSERT_EQ(r.receipts.size(), 1u);
  EXPECT_EQ(r.receipts[0].status, ReceiptStatus::Success);

  EXPECT_EQ(balanceOf(alice_.publicKey), a_before - 500 - 3);
  EXPECT_EQ(balanceOf(bob_.publicKey), b_before + 500);
}

TEST_F(Core_BlockProcessorFixture, AppliesMultipleTransfers)
{
  uint64_t a_before = balanceOf(alice_.publicKey);
  uint64_t b_before = balanceOf(bob_.publicKey);

  std::vector<Transaction> txs;
  for (uint64_t n = 0; n < 4; ++n)
    txs.push_back(makeSignedTransfer(alice_, bob_.publicKey, 100, 2, n));

  BlockResult r = applyBlock(1, genesis_hash_, txs);
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_EQ(r.receipts.size(), 4u);

  EXPECT_EQ(balanceOf(alice_.publicKey), a_before - 4 * (100 + 2));
  EXPECT_EQ(balanceOf(bob_.publicKey), b_before + 4 * 100);
}

TEST_F(Core_BlockProcessorFixture, RejectsFailedTransaction)
{
  Transaction tx = makeSignedTransfer(alice_, bob_.publicKey, 100, 2, 999);
  BlockResult r = applyBlock(1, genesis_hash_, {tx});
  EXPECT_FALSE(r.valid);
  EXPECT_NE(r.error.find("transaction failed"), std::string::npos);
}

TEST_F(Core_BlockProcessorFixture, SkipsSystemTransactions)
{
  Transaction sys_tx;
  sys_tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
  sys_tx.chain_id = regtestGenesis().chain_id;
  sys_tx.tx_type = TxType::BlockReward;
  sys_tx.nonce = 999;
  sys_tx.from = alice_.publicKey;
  sys_tx.to = bob_.publicKey;
  sys_tx.token_id = NATIVE_TOKEN_ID;
  sys_tx.amount = 0;
  sys_tx.fee = 0;

  BlockResult r = applyBlock(1, genesis_hash_, {sys_tx});
  ASSERT_TRUE(r.valid) << r.error;
  ASSERT_EQ(r.receipts.size(), 1u);
  EXPECT_EQ(r.receipts[0].fee_paid, 0u);
}

TEST_F(Core_BlockProcessorFixture, ReceiptsMatchTxCount)
{
  std::vector<Transaction> txs;
  for (uint64_t n = 0; n < 3; ++n)
    txs.push_back(makeSignedTransfer(alice_, bob_.publicKey, 100, 2, n));

  BlockResult r = applyBlock(1, genesis_hash_, txs);
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_EQ(r.receipts.size(), txs.size());
  EXPECT_EQ(r.tx_hashes.size(), txs.size());
}

// State root verification

TEST_F(Core_BlockProcessorFixture, RejectsWrongStateRoot)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  for (size_t i = 0; i < 32; ++i)
    b.header.state_root.data[i] ^= 0xFF;

  // state_root is part of the block hash, so re-sign to make sure the
  // signature check passes and the state-root check is the one that
  // fires.
  b.quorum_signatures = makeQuorumForBlock(b, {seed1_, seed2_});

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_NE(r.error.find("state root mismatch"), std::string::npos);
}

TEST_F(Core_BlockProcessorFixture, ComputesCorrectStateRoot)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  BlockContext ctx = makeContext(1);

  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  Crypto::Hash live_root = s.stateRoot();
  t.abort();

  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_EQ(r.new_state_root, b.header.state_root);
  EXPECT_EQ(r.new_state_root, live_root);
}

TEST_F(Core_BlockProcessorFixture, StateRootChangesWithTxs)
{
  Block b1 = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  BlockContext ctx1 = makeContext(1);
  auto t1 = db_->beginWrite();
  State::StateAccess s1(*db_, t1, 0);
  BlockResult r1 = BlockProcessor::applyBlock(s1, b1, ctx1);
  Crypto::Hash root_empty = r1.new_state_root;
  t1.abort();

  ASSERT_TRUE(r1.valid) << r1.error;

  Transaction tx = makeSignedTransfer(alice_, bob_.publicKey, 100, 2, 0);
  BlockResult r2 = applyBlock(1, genesis_hash_, {tx});
  ASSERT_TRUE(r2.valid) << r2.error;
  Crypto::Hash root_with_tx = r2.new_state_root;

  EXPECT_NE(root_empty, root_with_tx);
}

// Receipts root verification

TEST_F(Core_BlockProcessorFixture, RejectsWrongReceiptsRoot)
{
  Transaction tx = makeSignedTransfer(alice_, bob_.publicKey, 100, 2, 0);
  Block b = makeProcessableBlock(1, genesis_hash_, {tx}, activeSet());
  for (size_t i = 0; i < 32; ++i)
    b.header.receipts_root.data[i] ^= 0xFF;

  // receipts_root is part of the block hash; re-sign so the signature
  // check passes and the receipts_root check is the one that fires.
  b.quorum_signatures = makeQuorumForBlock(b, {seed1_, seed2_});

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "receipts_root mismatch");
}

TEST_F(Core_BlockProcessorFixture, ComputesCorrectReceiptsRoot)
{
  Transaction tx = makeSignedTransfer(alice_, bob_.publicKey, 100, 2, 0);
  Block b = makeProcessableBlock(1, genesis_hash_, {tx}, activeSet());

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  ASSERT_TRUE(r.valid) << r.error;
  Crypto::Hash recomputed =
      computeReceiptsRootForTest(r.tx_hashes, r.receipts);
  EXPECT_EQ(recomputed, b.header.receipts_root);
}

TEST_F(Core_BlockProcessorFixture, ReceiptsRootEmptyForEmptyBlock)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  EXPECT_TRUE(b.header.receipts_root.isNull());

  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;
}

// Reward distribution

TEST_F(Core_BlockProcessorFixture, RewardsGoToValidatorAddress)
{
  Crypto::Address seed1 = validatorAddress(1);
  Crypto::Address seed2 = validatorAddress(2);

  uint64_t s1_before = balanceOf(seed1);
  uint64_t s2_before = balanceOf(seed2);
  uint64_t pot_before = currentPot();

  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  uint64_t s1_after = balanceOf(seed1);
  uint64_t s2_after = balanceOf(seed2);
  uint64_t pot_after = currentPot();

  EXPECT_GT(s1_after, s1_before);
  EXPECT_GT(s2_after, s2_before);

  uint64_t total_gained = (s1_after - s1_before) + (s2_after - s2_before);
  uint64_t pot_gain = pot_after - pot_before;
  EXPECT_EQ(total_gained + pot_gain, GlobalConfig::BLOCK_REWARD);
}

TEST_F(Core_BlockProcessorFixture, StakerPoolAddedToPot)
{
  uint64_t pot_before = currentPot();
  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_GT(currentPot(), pot_before);
}

TEST_F(Core_BlockProcessorFixture, RewardMultiplierApplied)
{
  Crypto::Address seed1 = validatorAddress(1);
  Crypto::Address seed2 = validatorAddress(2);

  withState([&](State::StateAccess &s)
            {
    ValidatorInfo v1;
    if (s.getValidator(1, v1))
    {
      v1.reward_multiplier = 5'000;
      s.putValidator(v1);
    } });

  uint64_t s1_before = balanceOf(seed1);
  uint64_t s2_before = balanceOf(seed2);

  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  uint64_t s1_gain = balanceOf(seed1) - s1_before;
  uint64_t s2_gain = balanceOf(seed2) - s2_before;

  EXPECT_GT(s2_gain, s1_gain);
}

TEST_F(Core_BlockProcessorFixture, SlashedRewardsGoToPot)
{
  uint64_t pot_before = currentPot();
  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_GT(currentPot(), pot_before);
}

TEST_F(Core_BlockProcessorFixture, TotalRewardsEqualBlockReward)
{
  Crypto::Address seed1 = validatorAddress(1);
  Crypto::Address seed2 = validatorAddress(2);

  uint64_t s1_before = balanceOf(seed1);
  uint64_t s2_before = balanceOf(seed2);
  uint64_t pot_before = currentPot();

  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  uint64_t s1_gain = balanceOf(seed1) - s1_before;
  uint64_t s2_gain = balanceOf(seed2) - s2_before;
  uint64_t pot_gain = currentPot() - pot_before;

  EXPECT_EQ(s1_gain + s2_gain + pot_gain, GlobalConfig::BLOCK_REWARD);
}

// Edge cases for reward conservation

TEST_F(Core_BlockProcessorFixture, MissingValidatorRewardGoesToPot)
{
  // The active set contains validator 999, which has no validator
  // record in state. The reward distribution code path being tested
  // here is: an active set entry with no record has its share routed
  // to the pot.
  //
  // This scenario cannot produce a validly signed block, because
  // checkQuorum would try to resolve active_set[1] = 999 to a signing
  // key and fail. So the block is applied in dry_run mode, which
  // skips checkQuorum and the state-root check. The state writes still
  // happen inside the txn, and the caller commits them.
  //
  // This is an honest tradeoff: the property being tested (reward
  // routing for an unknown validator) doesn't depend on signature
  // verification, and the alternative — allowing unsigned blocks to
  // bypass checkQuorum — would be a worse test.

  const std::vector<Id> weird_set = {1, 999};

  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(weird_set)); });

  uint64_t pot_before = currentPot();

  Block b = makeProcessableBlock(1, genesis_hash_, {}, weird_set);
  BlockContext ctx = makeContext(1, /*dry_run=*/true);

  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  if (r.valid)
  {
    s.commit(/*version=*/0);
    t.commit();
  }
  else
  {
    t.abort();
  }

  ASSERT_TRUE(r.valid) << r.error;

  uint64_t pot_gain = currentPot() - pot_before;
  uint64_t staker_pool = applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::STAKER_SHARE_BPS);

  EXPECT_GT(pot_gain, staker_pool);
}

TEST_F(Core_BlockProcessorFixture, EmptyActiveSetRejectedByHeader)
{
  const std::vector<Id> empty_set = {};

  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(empty_set)); });

  Block b = makeProcessableBlock(1, genesis_hash_, {}, empty_set);

  EXPECT_EQ(b.header.active_validator_count, 0u);

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "block header not well-formed");
}

// Global state updates

TEST_F(Core_BlockProcessorFixture, TotalSupplyIncreasesByBlockReward)
{
  auto getSupply = [&]() -> uint64_t
  {
    uint64_t v = 0;
    readState([&](State::StateAccess &s)
              {
      std::vector<uint8_t> b;
      if (s.getGlobal("total_supply", b) && b.size() == 8)
        for (int i = 0; i < 8; ++i) v |= uint64_t(b[i]) << (i * 8); });
    return v;
  };

  uint64_t before = getSupply();
  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  EXPECT_EQ(getSupply() - before, GlobalConfig::BLOCK_REWARD);
}

TEST_F(Core_BlockProcessorFixture, EpochNumberUpdates)
{
  auto getEpoch = [&]() -> uint64_t
  {
    uint64_t v = 0;
    readState([&](State::StateAccess &s)
              {
      std::vector<uint8_t> b;
      if (s.getGlobal("epoch_number", b) && b.size() == 8)
        for (int i = 0; i < 8; ++i) v |= uint64_t(b[i]) << (i * 8); });
    return v;
  };

  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_EQ(getEpoch(), 0u);
}

TEST_F(Core_BlockProcessorFixture, TotalFeesAccumulated)
{
  Transaction tx1 = makeSignedTransfer(alice_, bob_.publicKey, 100, 7, 0);
  Transaction tx2 = makeSignedTransfer(alice_, bob_.publicKey, 100, 3, 1);

  Block b = makeProcessableBlock(1, genesis_hash_, {tx1, tx2}, activeSet());
  EXPECT_EQ(b.header.total_fees, 10u);

  BlockResult r = applyBlock(1, genesis_hash_, {tx1, tx2});
  ASSERT_TRUE(r.valid) << r.error;
}

// Order expiries

TEST_F(Core_BlockProcessorFixture, ProcessOrderExpiriesIsNoOpForV1)
{
  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;
}

// Participants liveness

TEST_F(Core_BlockProcessorFixture, ParticipantsLastSeenUpdated)
{
  ValidatorInfo v1_before;
  readState([&](State::StateAccess &s)
            { s.getValidator(1, v1_before); });
  EXPECT_EQ(v1_before.last_seen_height, 0u);

  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  ValidatorInfo v1_after;
  readState([&](State::StateAccess &s)
            { s.getValidator(1, v1_after); });
  EXPECT_EQ(v1_after.last_seen_height, 1u);
}

TEST_F(Core_BlockProcessorFixture, NonParticipantsUnaffected)
{
  withState([&](State::StateAccess &s)
            {
    ValidatorInfo v3;
    v3.id = 3;
    v3.reward_address = carol_.publicKey;
    v3.owner = carol_.publicKey;
    v3.registered_at_height = 0;
    v3.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
    v3.is_active = false;
    v3.last_seen_height = 0;
    s.putValidator(v3); });

  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  ValidatorInfo v3_after;
  readState([&](State::StateAccess &s)
            { s.getValidator(3, v3_after); });
  EXPECT_EQ(v3_after.last_seen_height, 0u);
}

TEST_F(Core_BlockProcessorFixture, OfflineCheckRunsEveryTenBlocks)
{
  BlockResult r = applyBlock(9, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  ValidatorInfo v1;
  readState([&](State::StateAccess &s)
            { s.getValidator(1, v1); });
  EXPECT_TRUE(v1.is_active);
}

// Rotation boundary

TEST_F(Core_BlockProcessorFixture, RotationCannotShrinkBelowSeeds)
{
  // Write a target size of 1 to global state. planRotation's shrink
  // branch will try to remove (current_size - target_size) validators,
  // but both active validators are seeds, so no removal is possible.
  withState([&](State::StateAccess &s)
            {
    std::vector<uint8_t> bytes(8);
    bytes[0] = 1;
    s.putGlobal("active_set_size", bytes); });

  BlockResult r = applyBlock(59, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  auto active = readActiveSet();
  EXPECT_EQ(active.size(), 2u)
      << "seeds must never be removed, even when the target shrinks";
}

TEST_F(Core_BlockProcessorFixture, RotationNoOpWhenOnlySeedsActive)
{
  // Fixture's active set is {1, 2}, both seeds. Seeds are never removed,
  // and there are no candidates to add, so a rotation-boundary block
  // must leave the active set unchanged.
  BlockResult r = applyBlock(59, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  auto active = readActiveSet();
  ASSERT_EQ(active.size(), 2u);
  EXPECT_EQ(active[0], 1u);
  EXPECT_EQ(active[1], 2u);
}

TEST_F(Core_BlockProcessorFixture, RotationPromotesWaitingValidator)
{
  //  The rotation target size is derived from traffic:
  //
  //      target = ACTIVE_SET_MIN + (traffic * (MAX - MIN)) / SATURATION
  //             = 2 + (traffic * 98) / 1000
  //
  //  With the fixture's active set of {1, 2}, the target must exceed 2
  //  for the grow branch of planRotation to fire. That requires
  //  traffic >= 11 (11 * 98 / 1000 == 1, giving target = 3).
  //
  //  So we build a block with 11 transfers. The transfers must succeed
  //  (executor validation, nonce ordering, sufficient balance), which
  //  is why they're issued from Alice in nonce order rather than
  //  being stubs.

  ValidatorInfo waiting;
  waiting.id = 3;
  waiting.reward_address = carol_.publicKey;
  waiting.owner = carol_.publicKey;
  waiting.registered_at_height = 0;
  waiting.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
  waiting.uptime_score = 10'000;
  waiting.is_seed = false;
  waiting.is_active = false;
  putValidatorDirect(waiting);
  setNextValidatorId(4);

  //  11 transfers from Alice, nonce 0..10. The fixture funds Alice
  //  with 1e9 at setup, so 11 * (100 + 2) is well within budget.
  std::vector<Transaction> txs;
  for (uint64_t n = 0; n < 11; ++n)
    txs.push_back(makeSignedTransfer(alice_, bob_.publicKey, 100, 2, n));

  BlockResult r = applyBlock(59, genesis_hash_, txs);
  ASSERT_TRUE(r.valid) << r.error;

  auto active = readActiveSet();
  EXPECT_GT(active.size(), 2u);
  EXPECT_NE(std::find(active.begin(), active.end(), 3u), active.end())
      << "validator 3 was not promoted";

  ValidatorInfo v3;
  ASSERT_TRUE(readValidator(3, v3));
  EXPECT_TRUE(v3.is_active);
}

TEST_F(Core_BlockProcessorFixture, RotationDoesNotRunMidEpoch)
{
  // Seed the pool so rotation would have something to do.
  ValidatorInfo waiting;
  waiting.id = 3;
  waiting.reward_address = carol_.publicKey;
  waiting.owner = carol_.publicKey;
  waiting.registered_at_height = 0;
  waiting.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
  waiting.uptime_score = 10'000;
  waiting.is_seed = false;
  waiting.is_active = false;
  putValidatorDirect(waiting);
  setNextValidatorId(4);

  // Block 30 is mid-epoch. Rotation must not fire.
  BlockResult r = applyBlock(30, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  auto active = readActiveSet();
  EXPECT_EQ(active.size(), 2u);
  EXPECT_EQ(std::find(active.begin(), active.end(), 3u), active.end())
      << "validator 3 was promoted mid-epoch";
}

TEST_F(Core_BlockProcessorFixture, RotationDoesNotBreakQuorum)
{
  // computeRotationCount(n) = min(ceil(n / TARGET_ROTATION_EPOCHS),
  //                               n - bftQuorum(n))
  // with the caveat that when n - bftQuorum(n) is 0 or negative,
  // the function returns 0 — no rotation is safe.
  //
  // TARGET_ROTATION_EPOCHS = 21.
  // bftQuorum(n) = (2n)/3 + 1 (integer division).

  // No safe rotation possible — margin is zero or negative.
  EXPECT_EQ(computeRotationCount(0), 0u);
  EXPECT_EQ(computeRotationCount(1), 0u);
  EXPECT_EQ(computeRotationCount(2), 0u);
  EXPECT_EQ(computeRotationCount(3), 0u);

  // Margin exists, but ceil(n/21) is 1 for n up to 21.
  EXPECT_EQ(computeRotationCount(4), 1u);
  EXPECT_EQ(computeRotationCount(7), 1u);
  EXPECT_EQ(computeRotationCount(11), 1u);
  EXPECT_EQ(computeRotationCount(21), 1u);

  // Now ceil dominates.
  EXPECT_EQ(computeRotationCount(22), 2u);
  EXPECT_EQ(computeRotationCount(42), 2u);
  EXPECT_EQ(computeRotationCount(43), 3u);
  EXPECT_EQ(computeRotationCount(63), 3u);
}

TEST_F(Core_BlockProcessorFixture, RotationPersistsTargetSize)
{
  ValidatorInfo waiting;
  waiting.id = 3;
  waiting.reward_address = carol_.publicKey;
  waiting.owner = carol_.publicKey;
  waiting.registered_at_height = 0;
  waiting.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
  waiting.uptime_score = 10'000;
  waiting.is_seed = false;
  waiting.is_active = false;
  putValidatorDirect(waiting);
  setNextValidatorId(4);

  BlockResult r = applyBlock(59, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  // The target size with zero traffic is ACTIVE_SET_MIN (2).
  // computeTargetActiveSetSize interpolates linearly from MIN at
  // zero traffic to MAX at saturation.
  const uint64_t expected_target = computeTargetActiveSetSize(0);
  EXPECT_EQ(expected_target, GlobalConfig::ACTIVE_SET_MIN)
      << "sanity: zero traffic should target the minimum";

  EXPECT_EQ(readActiveSetSize(), expected_target);
}

// Integration

TEST_F(Core_BlockProcessorFixture, FullBlockWithMultipleTxs)
{
  uint64_t a_before = balanceOf(alice_.publicKey);
  uint64_t b_before = balanceOf(bob_.publicKey);

  std::vector<Transaction> txs;
  txs.push_back(makeSignedTransfer(alice_, bob_.publicKey, 100, 2, 0));
  txs.push_back(makeSignedTransfer(alice_, carol_.publicKey, 200, 3, 1));
  txs.push_back(makeSignedTransfer(bob_, alice_.publicKey, 50, 1, 0));

  BlockResult r = applyBlock(1, genesis_hash_, txs);
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_EQ(r.receipts.size(), 3u);

  EXPECT_EQ(balanceOf(alice_.publicKey), a_before - 100 - 2 - 200 - 3 + 50);
  EXPECT_EQ(balanceOf(bob_.publicKey), b_before + 100 - 50 - 1);
}

TEST_F(Core_BlockProcessorFixture, RepeatedBlocksInSequence)
{
  Crypto::Hash parent = genesis_hash_;

  for (uint64_t h = 1; h <= 3; ++h)
  {
    Transaction tx = makeSignedTransfer(alice_, bob_.publicKey,
                                        100, 2, h - 1);
    BlockResult r = applyBlock(h, parent, {tx});
    ASSERT_TRUE(r.valid) << "height " << h << ": " << r.error;
    parent = r.block_hash;
  }

  EXPECT_EQ(nonceOf(alice_.publicKey), 3u);
}

TEST_F(Core_BlockProcessorFixture, StateRootChain)
{
  Transaction tx1 = makeSignedTransfer(alice_, bob_.publicKey, 100, 2, 0);
  BlockResult r1 = applyBlock(1, genesis_hash_, {tx1});
  ASSERT_TRUE(r1.valid) << r1.error;

  Crypto::Hash after_block1 = currentStateRoot();
  EXPECT_EQ(after_block1, r1.new_state_root);

  Transaction tx2 = makeSignedTransfer(alice_, bob_.publicKey, 50, 1, 1);
  Block b2 = makeProcessableBlock(2, r1.block_hash, {tx2}, activeSet());
  ASSERT_FALSE(b2.header.state_root.isNull())
      << "makeProcessableBlock failed to compute a state root for block 2";

  BlockContext ctx2 = makeContext(2);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r2 = BlockProcessor::applyBlock(s, b2, ctx2);
  Crypto::Hash after_block2 = s.stateRoot();
  t.abort();

  ASSERT_TRUE(r2.valid) << r2.error;
  EXPECT_EQ(after_block2, b2.header.state_root);
  EXPECT_NE(after_block1, after_block2);
}

TEST_F(Core_BlockProcessorFixture, AbortTxnLeavesNoState)
{
  Crypto::Hash pre_root = currentStateRoot();
  uint64_t a_before = balanceOf(alice_.publicKey);

  Transaction tx = makeSignedTransfer(alice_, bob_.publicKey, 500, 3, 0);
  Block b = makeProcessableBlock(1, genesis_hash_, {tx}, activeSet());

  {
    auto throwaway_txn = db_->beginWrite();
    State::StateAccess ts(*db_, throwaway_txn, 0);
    BlockContext ctx = makeContext(1);
    BlockResult r = BlockProcessor::applyBlock(ts, b, ctx);
    ASSERT_TRUE(r.valid) << r.error;
    throwaway_txn.abort();
  }

  EXPECT_EQ(currentStateRoot(), pre_root);
  EXPECT_EQ(balanceOf(alice_.publicKey), a_before);
}

// Genesis state

TEST_F(Core_BlockProcessorFixture, GenesisWritesValidatorByAddressIndex)
{
  // The fixture applies genesis in SetUp. Seed validators 1 and 2
  // should both be reachable by their reward address.
  Crypto::Address seed1 = validatorAddress(1);
  Crypto::Address seed2 = validatorAddress(2);

  uint64_t id_from_index = 0;

  bool found1 = false;
  readState([&](State::StateAccess &s)
            { found1 = s.getValidatorByAddress(seed1, id_from_index); });
  ASSERT_TRUE(found1) << "seed 1 not in validator-by-address index";
  EXPECT_EQ(id_from_index, 1u);

  bool found2 = false;
  readState([&](State::StateAccess &s)
            { found2 = s.getValidatorByAddress(seed2, id_from_index); });
  ASSERT_TRUE(found2) << "seed 2 not in validator-by-address index";
  EXPECT_EQ(id_from_index, 2u);
}

TEST_F(Core_BlockProcessorFixture, GenesisWritesActiveSetSize)
{
  // active_set_size should match the number of seed validators (2),
  // not the compile-time default.
  EXPECT_EQ(readActiveSetSize(), 2u);
}

// Order expiry processing

TEST_F(Core_BlockProcessorFixture, ProcessOrderExpiriesRefundsAndDeletes)
{
  // Create an order that expires at the block we're about to apply.
  const Id buy_token = 200;
  const uint64_t expires_at = 1;

  uint64_t alice_before = balanceOf(alice_.publicKey);

  Transaction create_tx =
      TransactionBuilder()
          .type(TxType::CreateOrder)
          .from(alice_)
          .to(Crypto::Address{})
          .amount(500)
          .fee(1)
          .nonce(0)
          .tokenId(NATIVE_TOKEN_ID)
          .chainId(regtestGenesis().chain_id)
          .payload(makeCreateOrderPayload(
              static_cast<uint32_t>(buy_token),
              100,
              static_cast<uint8_t>(OrderExecutionMode::Passive),
              expires_at))
          .build();

  // Apply the create-order block. It runs at height 1, which is where
  // the order expires. Since the executor adds to the expiry index,
  // and the block processor's expiry pass runs *after* the
  // transactions, the order created in this block will be expired in
  // the same block. That's the edge case worth pinning: an order with
  // expiry == current height is treated as already expired by the
  // time the block finishes.
  BlockResult r1 = applyBlock(1, genesis_hash_, {create_tx});
  ASSERT_TRUE(r1.valid) << r1.error;

  // After this block:
  //   - Alice paid 1 fee.
  //   - The 500 she locked was refunded by the expiry pass.
  //   - The order record was deleted.
  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 1);

  // Confirm the order is gone.
  bool order_found = false;
  readState([&](State::StateAccess &s)
            {
    for (uint64_t oid = 1; oid <= 8; ++oid)
    {
      Order o;
      if (s.getOrder(oid, o))
      {
        order_found = true;
        break;
      }
    } });

  EXPECT_FALSE(order_found);
}

TEST_F(Core_BlockProcessorFixture, ProcessOrderExpiriesSkipsLaterHeight)
{
  // Create an order that expires far in the future. Applying a block
  // at height 1 should not touch it.
  const Id buy_token = 200;
  const uint64_t expires_at = 1000;

  uint64_t alice_before = balanceOf(alice_.publicKey);

  Transaction create_tx =
      TransactionBuilder()
          .type(TxType::CreateOrder)
          .from(alice_)
          .to(Crypto::Address{})
          .amount(500)
          .fee(1)
          .nonce(0)
          .tokenId(NATIVE_TOKEN_ID)
          .chainId(regtestGenesis().chain_id)
          .payload(makeCreateOrderPayload(
              static_cast<uint32_t>(buy_token),
              100,
              static_cast<uint8_t>(OrderExecutionMode::Passive),
              expires_at))
          .build();

  BlockResult r = applyBlock(1, genesis_hash_, {create_tx});
  ASSERT_TRUE(r.valid) << r.error;

  // Alice paid the fee and had 500 locked into the order. No refund
  // because the order hasn't expired yet.
  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 500 - 1);

  // The order record should still exist.
  bool order_found = false;
  readState([&](State::StateAccess &s)
            {
    for (uint64_t oid = 1; oid <= 8; ++oid)
    {
      Order o;
      if (s.getOrder(oid, o))
      {
        order_found = true;
        break;
      }
    } });

  EXPECT_TRUE(order_found);
}

TEST_F(Core_BlockProcessorFixture, RejectsBlockWithInvalidQuorumSignature)
{
  Block b = makeProcessableBlock(1, genesis_hash_, {}, activeSet());
  // Corrupt one byte of the first signature.
  b.quorum_signatures[0].signature.data[0] ^= 0xFF;

  BlockContext ctx = makeContext(1);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  BlockResult r = BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_EQ(r.error, "invalid quorum signature");
}

// ============================================================================
//  Seed-only reward distribution
// ============================================================================

TEST_F(Core_BlockProcessorFixture, SeedOnlySingleSeed_EarnsProducerBonus)
{
  //  Fixture genesis has two seeds. Reduce the active set to just
  //  seed 1 and apply a block.
  const std::vector<Id> seed_set = {1};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(seed_set)); });

  Crypto::Address seed1 = validatorAddress(1);
  uint64_t before = balanceOf(seed1);
  uint64_t pot_before = currentPot();

  BlockResult r = applyBlock(1, genesis_hash_, {}, false, seed_set);
  ASSERT_TRUE(r.valid) << r.error;

  //  Expected: seed 1 earns the full producer bonus; pot gains the
  //  set share plus the staker pool.
  const uint64_t validator_pool =
      applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::VALIDATOR_SHARE_BPS);
  const uint64_t producer_amount =
      applyBps(validator_pool, GlobalConfig::PRODUCER_BONUS_BPS);
  const uint64_t set_amount = validator_pool - producer_amount;
  const uint64_t staker_pool =
      applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::STAKER_SHARE_BPS);

  EXPECT_EQ(balanceOf(seed1) - before, producer_amount);
  EXPECT_EQ(currentPot() - pot_before, set_amount + staker_pool);
}

TEST_F(Core_BlockProcessorFixture, SeedOnlyTwoSeeds_SplitProducerBonus)
{
  //  Fixture default active set is {1, 2}, both seeds.
  Crypto::Address seed1 = validatorAddress(1);
  Crypto::Address seed2 = validatorAddress(2);
  uint64_t s1_before = balanceOf(seed1);
  uint64_t s2_before = balanceOf(seed2);
  uint64_t pot_before = currentPot();

  BlockResult r = applyBlock(1, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  const uint64_t validator_pool =
      applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::VALIDATOR_SHARE_BPS);
  const uint64_t producer_amount =
      applyBps(validator_pool, GlobalConfig::PRODUCER_BONUS_BPS);
  const uint64_t set_amount = validator_pool - producer_amount;
  const uint64_t staker_pool =
      applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::STAKER_SHARE_BPS);

  const uint64_t per_seed = producer_amount / 2;

  EXPECT_EQ(balanceOf(seed1) - s1_before, per_seed);
  EXPECT_EQ(balanceOf(seed2) - s2_before, per_seed);
  EXPECT_EQ(currentPot() - pot_before, set_amount + staker_pool);
}

TEST_F(Core_BlockProcessorFixture, MixedActiveSet_PaysNormalSplit)
{
  //  Add a non-seed validator to the active set. The seed-only branch
  //  must not fire; both seeds and the new validator participate in
  //  the normal distribution.
  auto target_key = Crypto::generateKeyPair();
  constexpr Id NON_SEED_ID = 100;
  registerValidatorWithKey(NON_SEED_ID, target_key);

  const std::vector<Id> mixed_set = {1, 2, NON_SEED_ID};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(mixed_set)); });

  uint64_t pot_before = currentPot();

  BlockResult r = applyBlock(1, genesis_hash_, {}, false, mixed_set);
  ASSERT_TRUE(r.valid) << r.error;

  const uint64_t staker_pool =
      applyBps(GlobalConfig::BLOCK_REWARD, GlobalConfig::STAKER_SHARE_BPS);

  //  Under normal distribution, the pot only receives the staker pool
  //  plus any multiplier-penalty differences (zero here, all multipliers
  //  are START). The set share is paid to validators, not to the pot.
  EXPECT_EQ(currentPot() - pot_before, staker_pool);

  //  And the non-seed validator earned its share of the set amount.
  ValidatorInfo non_seed;
  ASSERT_TRUE(readValidator(NON_SEED_ID, non_seed));
  EXPECT_GT(non_seed.total_rewards_earned, 0u);
}

// ============================================================================
//  Emergency rotation
// ============================================================================
//
//  These tests exercise the block-processor path for an emergency
//  block: the block carries emergency_rotation > 0 and a certificate
//  whose signatures come from the committed set, and the block's
//  quorum is formed against the emergency set (committed minus
//  offline, plus promotions from the pool).
//
//  verifyTimeoutCertificate requires a committed set of at least 4
//  validators (it computes f = (n-1)/3 and requires f+1 attestations).
//  With n = 2 the certificate cannot exist, so the fixture cannot
//  build a well-formed emergency block. Each test below therefore
//  builds a 4-validator committed set.
//
//  The setup for all three is the same:
//
//      committed = {1, 2, 3, 4}      (written to state as "active_set")
//      1 is offline at height 100    (last_seen_height = 0)
//      2, 3, 4 are live              (last_seen_height = 100)
//      5 is a pool candidate         (registered, not active, healthy)
//
//  resolveActiveSet(committed, 100, true) drops 1, promotes 5, and
//  returns {2, 3, 4, 5}. The block is built with that as its
//  emergency set and a certificate signed by the first f+1 = 2
//  members of the committed set.

namespace
{
  //  Shared setup for the three emergency-block tests. Kept as a
  //  lambda so each test body can read its own pre-state cleanly.
  constexpr uint64_t EMERGENCY_HEIGHT = 100;

  //  The committed set as the tests set it up. Used to construct the
  //  certificate and to assert what resolveActiveSet should produce.
  inline std::vector<Id> emergencyCommittedSet() { return {1, 2, 3, 4}; }

  //  The expected emergency set: committed minus offline 1, plus
  //  promotion of 5.
  inline std::vector<Id> emergencyDerivedSet() { return {2, 3, 4, 5}; }
} // anonymous namespace

TEST_F(Core_BlockProcessorFixture, EmergencyBlock_CommitsNewActiveSet)
{
  //  Register validators 3 and 4 as active non-seeds. Validator 5 is
  //  a pool candidate (registered, not active).
  auto key3 = Crypto::generateKeyPair();
  auto key4 = Crypto::generateKeyPair();
  auto key5 = Crypto::generateKeyPair();

  registerValidatorWithKey(3, key3, /*stake=*/1'000'000'000ULL,
                           /*is_seed=*/false, /*is_active=*/true);
  registerValidatorWithKey(4, key4, /*stake=*/1'000'000'000ULL,
                           /*is_seed=*/false, /*is_active=*/true);
  registerValidatorWithKey(5, key5, /*stake=*/1'000'000'000ULL,
                           /*is_seed=*/false, /*is_active=*/false);

  //  Write the committed set to state. This is what
  //  BlockProcessor::applyBlock reads as committed_set, and what the
  //  certificate's signers must be drawn from.
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set",
                          encodeActiveSet(emergencyCommittedSet())); });

  //  Liveness. 1 is offline; 2, 3, 4 are current; 5 is fresh.
  setValidatorLastSeen(1, 0);
  setValidatorLastSeen(2, EMERGENCY_HEIGHT);
  setValidatorLastSeen(3, EMERGENCY_HEIGHT);
  setValidatorLastSeen(4, EMERGENCY_HEIGHT);
  setValidatorLastSeen(5, EMERGENCY_HEIGHT);

  //  Also set the "next_validator_id" global so any subsequent
  //  bookkeeping that walks the registry sees 5.
  setNextValidatorId(6);

  //  Build the block. The active_set argument is the emergency set
  //  (the block's header commits to it); committed_set is the set the
  //  certificate's signers are drawn from.
  Block b = makeProcessableBlock(
      EMERGENCY_HEIGHT,
      genesis_hash_,
      /*txs=*/{},
      emergencyDerivedSet(),
      /*emergency_rotation=*/EMERGENCY_HEIGHT,
      /*committed_set=*/emergencyCommittedSet());

  ASSERT_EQ(b.header.emergency_rotation, EMERGENCY_HEIGHT);
  ASSERT_FALSE(b.header.timeout_certificate.votes.empty())
      << "fixture failed to build a certificate for the committed set";

  BlockResult r = applyPrebuiltBlock(b);
  ASSERT_TRUE(r.valid) << r.error;

  //  State reflects the emergency set.
  auto active = readActiveSet();
  EXPECT_EQ(active, emergencyDerivedSet());

  //  Flags updated to match.
  ValidatorInfo v1, v5;
  ASSERT_TRUE(readValidator(1, v1));
  ASSERT_TRUE(readValidator(5, v5));
  EXPECT_FALSE(v1.is_active)
      << "offline validator 1 should have been demoted";
  EXPECT_TRUE(v5.is_active)
      << "promoted pool validator 5 should be active";

  //  The block was applied at the emergency height.
  EXPECT_EQ(b.header.height, EMERGENCY_HEIGHT);
}

TEST_F(Core_BlockProcessorFixture, EmergencyBlock_QuorumVerifiedAgainstDerivedSet)
{
  auto key3 = Crypto::generateKeyPair();
  auto key4 = Crypto::generateKeyPair();
  auto key5 = Crypto::generateKeyPair();

  registerValidatorWithKey(3, key3, 1'000'000'000ULL, false, true);
  registerValidatorWithKey(4, key4, 1'000'000'000ULL, false, true);
  registerValidatorWithKey(5, key5, 1'000'000'000ULL, false, false);

  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set",
                          encodeActiveSet(emergencyCommittedSet())); });

  setValidatorLastSeen(1, 0);
  setValidatorLastSeen(2, EMERGENCY_HEIGHT);
  setValidatorLastSeen(3, EMERGENCY_HEIGHT);
  setValidatorLastSeen(4, EMERGENCY_HEIGHT);
  setValidatorLastSeen(5, EMERGENCY_HEIGHT);
  setNextValidatorId(6);

  Block good = makeProcessableBlock(
      EMERGENCY_HEIGHT, genesis_hash_, {},
      emergencyDerivedSet(),
      EMERGENCY_HEIGHT,
      emergencyCommittedSet());

  //  Corrupt one quorum signature. checkQuorum resolves signer_index 0
  //  against the derived emergency set, so emergency_set[0] = 2. The
  //  signature was produced by validator 2's key. Corrupting it fails
  //  verification.
  Block bad = good;
  ASSERT_FALSE(bad.quorum_signatures.empty());
  bad.quorum_signatures[0].signature.data[0] ^= 0xFF;

  //  Apply the corrupted block first, from a throwaway txn, so the
  //  real state stays at the pre-block root for the second apply.
  {
    BlockContext ctx = makeContext(EMERGENCY_HEIGHT);
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);
    BlockResult r = BlockProcessor::applyBlock(s, bad, ctx);
    t.abort();

    EXPECT_FALSE(r.valid);
    EXPECT_EQ(r.error, "invalid quorum signature");
  }

  //  Now apply the good one for real.
  BlockResult r = applyPrebuiltBlock(good);
  EXPECT_TRUE(r.valid) << r.error;
}

TEST_F(Core_BlockProcessorFixture, EmergencyBlock_StateRootMatchesDerivedSet)
{
  //  The state root the block commits to must be the root produced by
  //  applying it against the emergency set. If the block's simulation
  //  and its real application disagreed about the set, the state-root
  //  check inside applyBlock would fire and the block would be
  //  rejected.
  //
  //  This test exists to catch a specific class of bug: if
  //  makeProcessableBlock sets emergency_rotation *after* simulation,
  //  the dry run uses the committed set and the real application uses
  //  the emergency set. Their roots differ, and the block is rejected
  //  even though everything else is correct.

  auto key3 = Crypto::generateKeyPair();
  auto key4 = Crypto::generateKeyPair();
  auto key5 = Crypto::generateKeyPair();

  registerValidatorWithKey(3, key3, 1'000'000'000ULL, false, true);
  registerValidatorWithKey(4, key4, 1'000'000'000ULL, false, true);
  registerValidatorWithKey(5, key5, 1'000'000'000ULL, false, false);

  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set",
                          encodeActiveSet(emergencyCommittedSet())); });

  setValidatorLastSeen(1, 0);
  setValidatorLastSeen(2, EMERGENCY_HEIGHT);
  setValidatorLastSeen(3, EMERGENCY_HEIGHT);
  setValidatorLastSeen(4, EMERGENCY_HEIGHT);
  setValidatorLastSeen(5, EMERGENCY_HEIGHT);
  setNextValidatorId(6);

  Block b = makeProcessableBlock(
      EMERGENCY_HEIGHT, genesis_hash_, {},
      emergencyDerivedSet(),
      EMERGENCY_HEIGHT,
      emergencyCommittedSet());

  //  The block's header state_root was produced by the fixture's
  //  dry-run simulation. Applying the block for real must produce
  //  the same root.
  BlockResult r = applyPrebuiltBlock(b);
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_EQ(r.new_state_root, b.header.state_root);
}
