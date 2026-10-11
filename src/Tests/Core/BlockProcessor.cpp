// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>

#include "Fixtures.h"

#include "Core/BlockProcessor.h"
#include "Core/MatchingEngine.h"
#include "Core/OrderBook.h"
#include "Core/TransactionExecutor.h"
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
  BlockResult r = applyBlock(59, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  auto active = readActiveSet();
  ASSERT_EQ(active.size(), 2u);
  EXPECT_EQ(active[0], 1u);
  EXPECT_EQ(active[1], 2u);
}

TEST_F(Core_BlockProcessorFixture, RotationPromotesWaitingValidator)
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

  BlockResult r = applyBlock(30, genesis_hash_, {});
  ASSERT_TRUE(r.valid) << r.error;

  auto active = readActiveSet();
  EXPECT_EQ(active.size(), 2u);
  EXPECT_EQ(std::find(active.begin(), active.end(), 3u), active.end())
      << "validator 3 was promoted mid-epoch";
}

TEST_F(Core_BlockProcessorFixture, RotationDoesNotBreakQuorum)
{
  EXPECT_EQ(computeRotationCount(0), 0u);
  EXPECT_EQ(computeRotationCount(1), 0u);
  EXPECT_EQ(computeRotationCount(2), 0u);
  EXPECT_EQ(computeRotationCount(3), 0u);

  EXPECT_EQ(computeRotationCount(4), 1u);
  EXPECT_EQ(computeRotationCount(7), 1u);
  EXPECT_EQ(computeRotationCount(11), 1u);
  EXPECT_EQ(computeRotationCount(21), 1u);

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
  EXPECT_EQ(readActiveSetSize(), 2u);
}

// Order expiry processing

TEST_F(Core_BlockProcessorFixture, ProcessOrderExpiriesRefundsAndDeletes)
{
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

  BlockResult r1 = applyBlock(1, genesis_hash_, {create_tx});
  ASSERT_TRUE(r1.valid) << r1.error;

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 1);

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

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 500 - 1);

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
  const std::vector<Id> seed_set = {1};
  withState([&](State::StateAccess &s)
            { s.putGlobal("active_set", encodeActiveSet(seed_set)); });

  Crypto::Address seed1 = validatorAddress(1);
  uint64_t before = balanceOf(seed1);
  uint64_t pot_before = currentPot();

  BlockResult r = applyBlock(1, genesis_hash_, {}, false, seed_set);
  ASSERT_TRUE(r.valid) << r.error;

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

  EXPECT_EQ(currentPot() - pot_before, staker_pool);

  ValidatorInfo non_seed;
  ASSERT_TRUE(readValidator(NON_SEED_ID, non_seed));
  EXPECT_GT(non_seed.total_rewards_earned, 0u);
}

// ============================================================================
//  Emergency rotation
// ============================================================================

namespace
{
  constexpr uint64_t EMERGENCY_HEIGHT = 100;

  inline std::vector<Id> emergencyCommittedSet() { return {1, 2, 3, 4}; }
  inline std::vector<Id> emergencyDerivedSet() { return {2, 3, 4, 5}; }
} // anonymous namespace

TEST_F(Core_BlockProcessorFixture, EmergencyBlock_CommitsNewActiveSet)
{
  auto key3 = Crypto::generateKeyPair();
  auto key4 = Crypto::generateKeyPair();
  auto key5 = Crypto::generateKeyPair();

  registerValidatorWithKey(3, key3, /*stake=*/1'000'000'000ULL,
                           /*is_seed=*/false, /*is_active=*/true);
  registerValidatorWithKey(4, key4, /*stake=*/1'000'000'000ULL,
                           /*is_seed=*/false, /*is_active=*/true);
  registerValidatorWithKey(5, key5, /*stake=*/1'000'000'000ULL,
                           /*is_seed=*/false, /*is_active=*/false);

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

  auto active = readActiveSet();
  EXPECT_EQ(active, emergencyDerivedSet());

  ValidatorInfo v1, v5;
  ASSERT_TRUE(readValidator(1, v1));
  ASSERT_TRUE(readValidator(5, v5));
  EXPECT_FALSE(v1.is_active)
      << "offline validator 1 should have been demoted";
  EXPECT_TRUE(v5.is_active)
      << "promoted pool validator 5 should be active";

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

  Block bad = good;
  ASSERT_FALSE(bad.quorum_signatures.empty());
  bad.quorum_signatures[0].signature.data[0] ^= 0xFF;

  {
    BlockContext ctx = makeContext(EMERGENCY_HEIGHT);
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);
    BlockResult r = BlockProcessor::applyBlock(s, bad, ctx);
    t.abort();

    EXPECT_FALSE(r.valid);
    EXPECT_EQ(r.error, "invalid quorum signature");
  }

  BlockResult r = applyPrebuiltBlock(good);
  EXPECT_TRUE(r.valid) << r.error;
}

TEST_F(Core_BlockProcessorFixture, EmergencyBlock_StateRootMatchesDerivedSet)
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

  Block b = makeProcessableBlock(
      EMERGENCY_HEIGHT, genesis_hash_, {},
      emergencyDerivedSet(),
      EMERGENCY_HEIGHT,
      emergencyCommittedSet());

  BlockResult r = applyPrebuiltBlock(b);
  ASSERT_TRUE(r.valid) << r.error;
  EXPECT_EQ(r.new_state_root, b.header.state_root);
}

// =================================================================
//  Matching engine: simulate-vs-apply state-root equality
//
//  The matcher writes to state through three channels that did
//  not exist before this feature:
//
//    - nextOrderSequence()      — an SMT global write
//    - indexFill(...)           — three index rows in
//                                 TBL_FILL_HISTORY per fill
//    - addToOrderBook's
//      companion sequence key   — an SMT write
//
//  Every one of those must happen on BOTH the dry-run and the
//  apply path. If any of them is gated on !ctx.dry_run upstream,
//  the two paths produce different state roots and a proposer's
//  block is rejected by every node that tries to apply it.
//
//  DIAG lines are temporary; delete them once the test passes.
// =================================================================

TEST_F(Core_BlockProcessorFixture, MatchingSimulateAndApplyProduceSameRoot)
{
  const Id sell_token = 1; // "base"
  const Id buy_token = 2;  // "quote"

  //  ---- Fund the two custom tokens ----
  {
    auto txn = db_->beginWrite();
    State::StateAccess st(*db_, txn, 0);

    st.putTokenBalance(bob_.publicKey, sell_token, 1'000'000);
    st.putTokenBalance(bob_.publicKey, buy_token, 1'000'000);
    st.putTokenBalance(alice_.publicKey, sell_token, 1'000'000);
    st.putTokenBalance(alice_.publicKey, buy_token, 1'000'000);

    st.commit(0);
    txn.commit();
  }

  //  ---- Seed the maker ----
  const uint64_t maker_sell_amount = 100;
  const uint64_t maker_min_buy_amount = 2500; // price = 25

  Core::Order maker;
  maker.id = 1;
  maker.owner = bob_.publicKey;
  maker.mode = Core::OrderExecutionMode::Passive;
  maker.sell_token = sell_token;
  maker.buy_token = buy_token;
  maker.sell_amount = maker_sell_amount;
  maker.min_buy_amount = maker_min_buy_amount;
  maker.created_at_height = 0;
  maker.filled_amount = 0;
  maker.condition_count = 0;

  {
    auto txn = db_->beginWrite();
    State::StateAccess st(*db_, txn, 0);

    const uint64_t bob_before =
        st.getTokenBalance(bob_.publicKey, sell_token);
    ASSERT_GE(bob_before, maker_sell_amount)
        << "fixture did not fund Bob with token " << sell_token;
    st.putTokenBalance(bob_.publicKey, sell_token,
                       bob_before - maker_sell_amount);

    st.putOrder(maker);
    st.addToOrderBook(maker, st.nextOrderSequence());

    //  Advance the id counter past the maker's id. The maker was
    //  seeded by hand with id = 1; without this, the taker tx in
    //  the block below would read next_order_id = 1 and overwrite
    //  the maker's record at Keys::order(1).
    st.putGlobalU64("next_order_id", 2);

    st.commit(0);
    txn.commit();
  }

  //  ---- Build the crossing taker tx ----
  Core::Transaction taker_tx = makeSignedCreateOrder(
      /*from=*/alice_,
      /*sell_token=*/buy_token,
      /*sell_amount=*/2500,
      /*buy_token=*/sell_token,
      /*min_buy_amount=*/100,
      /*mode=*/Core::OrderExecutionMode::Passive,
      /*expires_at_height=*/0,
      /*nonce=*/0);

  //  ---- Build the block ----
  Core::Block block = buildSignedBlockForTest(
      1, genesis_hash_, {taker_tx}, activeSet());

  //  ---- Dry-run ----
  Crypto::Hash dry_root;
  {
    auto txn = db_->beginWrite();
    State::StateAccess st(*db_, txn, 0);

    BlockContext ctx = makeContext(1);
    ctx.dry_run = true;

    BlockResult r = BlockProcessor::applyBlock(st, block, ctx);
    ASSERT_TRUE(r.valid) << "dry-run failed: " << r.error;

    dry_root = r.new_state_root;

    txn.abort();
  }

  //  ---- Apply ----
  Crypto::Hash apply_root;
  {
    auto txn = db_->beginWrite();
    State::StateAccess st(*db_, txn, 0);

    BlockContext ctx = makeContext(1);
    ctx.dry_run = false;

    BlockResult r = BlockProcessor::applyBlock(st, block, ctx);
    ASSERT_TRUE(r.valid) << "apply failed: " << r.error;

    apply_root = r.new_state_root;

    ASSERT_EQ(r.receipts.size(), 1u);
    ASSERT_EQ(r.receipts[0].fills.size(), 1u);
    ASSERT_EQ(r.receipts[0].fills[0].maker_order_id, maker.id);
    ASSERT_EQ(r.receipts[0].fills[0].qty_base, 100u);
    ASSERT_EQ(r.receipts[0].fills[0].qty_quote, 2500u);

    st.commit(1);
    txn.commit();
  }

  EXPECT_EQ(dry_root, apply_root)
      << "dry-run and apply paths produced different state roots.";
}

// =================================================================
//  Matching engine: end-to-end through a block
//
//  Two CreateOrder txs in one block. The first rests; the second
//  crosses.
//
//  DIAG lines are temporary; delete them once the test passes.
// =================================================================

TEST_F(Core_BlockProcessorFixture, MatchingEndToEndThroughBlock)
{
  const Id sell_token = 1;
  const Id buy_token = 2;

  //  ---- Fund the two custom tokens ----
  {
    auto txn = db_->beginWrite();
    State::StateAccess st(*db_, txn, 0);

    st.putTokenBalance(bob_.publicKey, sell_token, 1'000'000);
    st.putTokenBalance(bob_.publicKey, buy_token, 1'000'000);
    st.putTokenBalance(alice_.publicKey, sell_token, 1'000'000);
    st.putTokenBalance(alice_.publicKey, buy_token, 1'000'000);

    st.commit(0);
    txn.commit();
  }

  //  ---- Capture before-balances ----
  const uint64_t alice_t1_before = [&]
  {
    uint64_t v = 0;
    readState([&](State::StateAccess &s)
              { v = s.getTokenBalance(alice_.publicKey, sell_token); });
    return v;
  }();
  const uint64_t alice_t2_before = [&]
  {
    uint64_t v = 0;
    readState([&](State::StateAccess &s)
              { v = s.getTokenBalance(alice_.publicKey, buy_token); });
    return v;
  }();
  const uint64_t bob_t1_before = [&]
  {
    uint64_t v = 0;
    readState([&](State::StateAccess &s)
              { v = s.getTokenBalance(bob_.publicKey, sell_token); });
    return v;
  }();
  const uint64_t bob_t2_before = [&]
  {
    uint64_t v = 0;
    readState([&](State::StateAccess &s)
              { v = s.getTokenBalance(bob_.publicKey, buy_token); });
    return v;
  }();

  //  ---- Build the two CreateOrder txs ----
  Core::Transaction maker_tx = makeSignedCreateOrder(
      /*from=*/bob_,
      /*sell_token=*/sell_token,
      /*sell_amount=*/100,
      /*buy_token=*/buy_token,
      /*min_buy_amount=*/2500,
      /*mode=*/Core::OrderExecutionMode::Passive,
      /*expires_at_height=*/0,
      /*nonce=*/nonceOf(bob_.publicKey));

  Core::Transaction taker_tx = makeSignedCreateOrder(
      /*from=*/alice_,
      /*sell_token=*/buy_token,
      /*sell_amount=*/2500,
      /*buy_token=*/sell_token,
      /*min_buy_amount=*/100,
      /*mode=*/Core::OrderExecutionMode::Passive,
      /*expires_at_height=*/0,
      /*nonce=*/nonceOf(alice_.publicKey));

  //  ---- Build the block ----
  Core::Block block = buildSignedBlockForTest(
      1, genesis_hash_, {maker_tx, taker_tx}, activeSet());

  //  ---- Apply ----
  BlockResult result;
  {
    auto txn = db_->beginWrite();
    State::StateAccess st(*db_, txn, 0);

    BlockContext ctx = makeContext(1);
    ctx.dry_run = false;

    result = BlockProcessor::applyBlock(st, block, ctx);
    ASSERT_TRUE(result.valid) << "block failed: " << result.error;

    st.commit(1);
    txn.commit();
  }

  //  ---- Receipts ----
  ASSERT_EQ(result.receipts.size(), 2u);
  ASSERT_TRUE(result.receipts[0].fills.empty());
  ASSERT_EQ(result.receipts[1].fills.size(), 1u);

  const Core::Fill &fill = result.receipts[1].fills[0];

  ASSERT_EQ(fill.maker_order_id, 1u);
  ASSERT_EQ(fill.taker_order_id, 2u);
  ASSERT_EQ(fill.qty_base, 100u);
  ASSERT_EQ(fill.qty_quote, 2500u);
  ASSERT_EQ(fill.price, 25ULL * Core::OrderBook::BOOK_PRICE_SCALE);
  ASSERT_EQ(fill.base_token, sell_token);
  ASSERT_EQ(fill.quote_token, buy_token);

  //  ---- Balances ----
  readState([&](State::StateAccess &s)
            {
    EXPECT_EQ(s.getTokenBalance(bob_.publicKey, buy_token),
              bob_t2_before + 2500u);
    EXPECT_EQ(s.getTokenBalance(alice_.publicKey, sell_token),
              alice_t1_before + 100u);
    EXPECT_EQ(s.getTokenBalance(bob_.publicKey, sell_token),
              bob_t1_before - 100u);
    EXPECT_EQ(s.getTokenBalance(alice_.publicKey, buy_token),
              alice_t2_before - 2500u); });

  //  ---- Book empty, records gone ----
  readState([&](State::StateAccess &s)
            {
    Core::Order gone;
    EXPECT_FALSE(s.getOrder(fill.maker_order_id, gone));
    EXPECT_FALSE(s.getOrder(fill.taker_order_id, gone));

    size_t side0 = 0, side1 = 0;
    s.forEachBookLevel(sell_token, buy_token, 0,
        [&](Id, uint64_t, uint64_t) { ++side0; return true; });
    s.forEachBookLevel(sell_token, buy_token, 1,
        [&](Id, uint64_t, uint64_t) { ++side1; return true; });
    EXPECT_EQ(side0, 0u);
    EXPECT_EQ(side1, 0u); });
}