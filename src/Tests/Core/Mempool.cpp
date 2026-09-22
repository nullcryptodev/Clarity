// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Mempool.h"
#include "Core/TransactionTypes.h"
#include "Crypto/Ed25519.h"

#include "Tests/Fixtures.h"

using namespace Core;
using namespace Tests;

// ============================================================================
//  Basic acceptance
// ============================================================================

TEST_F(MempoolTestFixture, AcceptsWellFormedTransfer)
{
  EXPECT_EQ(addTransfer(0, 500), MempoolAddResult::Accepted);
  EXPECT_EQ(pool_.size(), 1u);
}

TEST_F(MempoolTestFixture, IdempotentAdd)
{
  Transaction tx = builder_.buildTransfer(0, 1000, 500);

  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard), MempoolAddResult::Accepted);
  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard), MempoolAddResult::Accepted);

  EXPECT_EQ(pool_.size(), 1u);
}

TEST_F(MempoolTestFixture, SameTxRebroadcastAccepted)
{
  // Explicit test: rebroadcasting the exact same tx is idempotent.
  Transaction tx = builder_.buildTransfer(0, 1000, 500);

  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard), MempoolAddResult::Accepted);
  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard), MempoolAddResult::Accepted);
  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard), MempoolAddResult::Accepted);

  EXPECT_EQ(pool_.size(), 1u);
}

// ============================================================================
//  Rejection cases
// ============================================================================

TEST_F(MempoolTestFixture, RejectsMalformedTransaction)
{
  Transaction tx;
  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard),
            MempoolAddResult::Rejected_Malformed);
}

TEST_F(MempoolTestFixture, RejectsWrongChainId)
{
  Transaction tx = builder_.buildTransfer(0, 1000, 500);
  tx.chain_id = 0xDEADBEEF;

  Crypto::Hash sighash = tx.signingHash();
  tx.signature = Crypto::sign(sighash, builder_.keyPair().secretKey);

  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard),
            MempoolAddResult::Rejected_WrongChain);
}

TEST_F(MempoolTestFixture, RejectsBadSignature)
{
  Transaction tx = builder_.buildTransfer(0, 1000, 500);
  tx.signature.data[0] ^= 0xFF;

  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard),
            MempoolAddResult::Rejected_BadSignature);
}

TEST_F(MempoolTestFixture, RejectsLowFee)
{
  EXPECT_EQ(addTransfer(0, /*fee=*/0), MempoolAddResult::Rejected_LowFee);
}

TEST_F(MempoolTestFixture, RejectsHighFee)
{
  EXPECT_EQ(addTransfer(0, /*fee=*/10'000'000ULL),
            MempoolAddResult::Rejected_HighFee);
}

TEST_F(MempoolTestFixture, RejectsNonceTooLow)
{
  state_.setNonce(builder_.senderAddress(), 5);

  Transaction tx = builder_.buildTransfer(3, 1000, 500);
  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard),
            MempoolAddResult::Rejected_NonceTooLow);
}

TEST_F(MempoolTestFixture, RejectsInsufficientBalance)
{
  state_.setBalance(builder_.senderAddress(), 100);

  Transaction tx = builder_.buildTransfer(0, /*amount=*/1000, /*fee=*/500);
  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard),
            MempoolAddResult::Rejected_InsufficientFunds);
}

TEST_F(MempoolTestFixture, RejectsExpiredTx)
{
  state_.setHeight(200);

  Transaction tx = builder_.buildTransfer(0, 1000, 500);
  tx.valid_until_height = 150;

  Crypto::Hash sighash = tx.signingHash();
  tx.signature = Crypto::sign(sighash, builder_.keyPair().secretKey);

  EXPECT_EQ(pool_.add(tx, state_, FeeTier::Standard),
            MempoolAddResult::Rejected_Expired);
}

// ============================================================================
//  Nonce conflict handling
// ============================================================================

TEST_F(MempoolTestFixture, NonceConflictRejected)
{
  // Add nonce 0.
  EXPECT_EQ(addTransfer(0, 500), MempoolAddResult::Accepted);

  // Add a DIFFERENT tx (different amount) with the same nonce and same
  // fee. Should be rejected because neither priority nor fee rate
  // improves on the existing entry.
  Transaction tx2 = builder_.buildTransfer(0, /*amount=*/2000, /*fee=*/500);
  EXPECT_EQ(pool_.add(tx2, state_, FeeTier::Standard),
            MempoolAddResult::Rejected_NonceConflict);

  EXPECT_EQ(pool_.size(), 1u);
}

TEST_F(MempoolTestFixture, HigherFeeReplacesLowFeeNonce)
{
  EXPECT_EQ(addTransfer(0, /*fee=*/500), MempoolAddResult::Accepted);

  Transaction tx2 = builder_.buildTransfer(0, 1000, /*fee=*/2000);
  EXPECT_EQ(pool_.add(tx2, state_, FeeTier::Standard),
            MempoolAddResult::Accepted);

  EXPECT_EQ(pool_.size(), 1u);
}

TEST_F(MempoolTestFixture, PriorityReplacesStandardNonce)
{
  EXPECT_EQ(addTransfer(0, /*fee=*/5000, FeeTier::Standard),
            MempoolAddResult::Accepted);

  Transaction tx2 = builder_.buildTransfer(0, 1000, /*fee=*/500);
  EXPECT_EQ(pool_.add(tx2, state_, FeeTier::Priority),
            MempoolAddResult::Accepted);

  EXPECT_EQ(pool_.size(), 1u);
  EXPECT_EQ(pool_.priorityCount(), 1u);
}

TEST_F(MempoolTestFixture, NonPriorityCannotReplacePriority)
{
  EXPECT_EQ(addTransfer(0, /*fee=*/500, FeeTier::Priority),
            MempoolAddResult::Accepted);

  Transaction tx2 = builder_.buildTransfer(0, 1000, /*fee=*/5000);
  EXPECT_EQ(pool_.add(tx2, state_, FeeTier::Standard),
            MempoolAddResult::Rejected_NonceConflict);

  EXPECT_EQ(pool_.size(), 1u);
  EXPECT_EQ(pool_.priorityCount(), 1u);
}

// ============================================================================
//  Stats
// ============================================================================

TEST_F(MempoolTestFixture, StatsReflectPool)
{
  addTransfer(0, 500);
  addTransfer(1, 1000);
  addTransfer(2, 2000, FeeTier::Priority);

  auto s = pool_.stats();
  EXPECT_EQ(s.total_txs, 3u);
  EXPECT_EQ(s.priority_txs, 1u);
  EXPECT_EQ(s.standard_txs, 2u);
  EXPECT_GT(s.total_bytes, 0u);
}

// ============================================================================
//  Block selection
// ============================================================================

TEST_F(MempoolTestFixture, SelectionPicksAllWhenSmall)
{
  addTransfer(0, 500);
  addTransfer(1, 500);
  addTransfer(2, 500);

  auto selected = pool_.selectForBlock(
      state_, /*max_bytes=*/256 * 1024, /*max_txs=*/1000);

  EXPECT_EQ(selected.size(), 3u);
}

TEST_F(MempoolTestFixture, SelectionRespectsByteLimit)
{
  for (uint64_t i = 0; i < 10; ++i)
  {
    addTransfer(i, 500);
  }

  auto selected = pool_.selectForBlock(
      state_, /*max_bytes=*/600, /*max_txs=*/1000);

  EXPECT_LE(selected.size(), 3u);
  EXPECT_GT(selected.size(), 0u);
}

TEST_F(MempoolTestFixture, SelectionRespectsCountLimit)
{
  for (uint64_t i = 0; i < 10; ++i)
  {
    addTransfer(i, 500);
  }

  auto selected = pool_.selectForBlock(
      state_, /*max_bytes=*/256 * 1024, /*max_txs=*/3);

  EXPECT_EQ(selected.size(), 3u);
}

TEST_F(MempoolTestFixture, SelectionRespectsNonceOrder)
{
  // Add nonces 2, 0, 1 (out of order).
  addTransfer(2, 500);
  addTransfer(0, 500);
  addTransfer(1, 500);

  auto selected = pool_.selectForBlock(
      state_, /*max_bytes=*/256 * 1024, /*max_txs=*/1000);

  ASSERT_EQ(selected.size(), 3u);
  EXPECT_EQ(selected[0].nonce, 0u);
  EXPECT_EQ(selected[1].nonce, 1u);
  EXPECT_EQ(selected[2].nonce, 2u);
}

TEST_F(MempoolTestFixture, SelectionSkipsNonceGap)
{
  // Add nonces 0 and 2, but not 1.
  addTransfer(0, 500);
  addTransfer(2, 500);

  auto selected = pool_.selectForBlock(
      state_, /*max_bytes=*/256 * 1024, /*max_txs=*/1000);

  ASSERT_EQ(selected.size(), 1u);
  EXPECT_EQ(selected[0].nonce, 0u);
}

TEST_F(MempoolTestFixture, SelectionPrioritizesPriorityTier)
{
  for (uint64_t i = 0; i < 5; ++i)
  {
    addTransfer(i, 500, FeeTier::Standard);
  }

  TransactionBuilder other_builder;
  state_.setBalance(other_builder.senderAddress(), 10'000'000'000ULL);
  Transaction priority_tx = other_builder.buildTransfer(0, 1000, 500);
  pool_.add(priority_tx, state_, FeeTier::Priority);

  auto selected = pool_.selectForBlock(
      state_, /*max_bytes=*/256 * 1024, /*max_txs=*/2);

  ASSERT_EQ(selected.size(), 2u);

  bool found_priority = false;
  for (const auto &tx : selected)
  {
    if (tx.from.toString() == other_builder.senderAddress().toString())
    {
      found_priority = true;
    }
  }
  EXPECT_TRUE(found_priority);
}

// ============================================================================
//  Removal
// ============================================================================

TEST_F(MempoolTestFixture, RemoveByTxid)
{
  Transaction tx = builder_.buildTransfer(0, 1000, 500);
  pool_.add(tx, state_, FeeTier::Standard);

  ASSERT_EQ(pool_.size(), 1u);
  Crypto::Hash txid = tx.txid();

  EXPECT_TRUE(pool_.remove(txid));
  EXPECT_EQ(pool_.size(), 0u);
}

TEST_F(MempoolTestFixture, RemoveUnknownTxid)
{
  Crypto::Hash bogus;
  for (size_t i = 0; i < 32; ++i)
    bogus.data[i] = 0xFF;

  EXPECT_FALSE(pool_.remove(bogus));
}

TEST_F(MempoolTestFixture, RemoveIncluded)
{
  Transaction tx1 = builder_.buildTransfer(0, 1000, 500);
  Transaction tx2 = builder_.buildTransfer(1, 1000, 500);
  pool_.add(tx1, state_, FeeTier::Standard);
  pool_.add(tx2, state_, FeeTier::Standard);

  ASSERT_EQ(pool_.size(), 2u);

  std::vector<Crypto::Hash> included = {tx1.txid()};
  pool_.removeIncluded(included);

  EXPECT_EQ(pool_.size(), 1u);
  EXPECT_TRUE(pool_.contains(tx2.txid()));
  EXPECT_FALSE(pool_.contains(tx1.txid()));
}

TEST_F(MempoolTestFixture, RemoveIncludedIgnoresUnknown)
{
  Transaction tx = builder_.buildTransfer(0, 1000, 500);
  pool_.add(tx, state_, FeeTier::Standard);

  Crypto::Hash bogus;
  for (size_t i = 0; i < 32; ++i)
    bogus.data[i] = 0xAA;

  pool_.removeIncluded({bogus});
  EXPECT_EQ(pool_.size(), 1u);
}

TEST_F(MempoolTestFixture, Clear)
{
  for (uint64_t i = 0; i < 5; ++i)
  {
    addTransfer(i, 500);
  }

  ASSERT_EQ(pool_.size(), 5u);
  pool_.clear();
  EXPECT_EQ(pool_.size(), 0u);
  EXPECT_EQ(pool_.bytes(), 0u);
}

// ============================================================================
//  Expiry
// ============================================================================

TEST_F(MempoolTestFixture, PurgeExpired)
{
  addTransfer(0, 500);

  Transaction tx2 = builder_.buildTransfer(1, 1000, 500);
  tx2.valid_until_height = 150;
  Crypto::Hash sighash = tx2.signingHash();
  tx2.signature = Crypto::sign(sighash, builder_.keyPair().secretKey);
  pool_.add(tx2, state_, FeeTier::Standard);

  ASSERT_EQ(pool_.size(), 2u);

  pool_.purgeExpired(200);

  EXPECT_EQ(pool_.size(), 1u);
}

TEST_F(MempoolTestFixture, PurgeExpiredKeepsUnexpired)
{
  addTransfer(0, 500);

  pool_.purgeExpired(1000);
  EXPECT_EQ(pool_.size(), 1u);
}

// ============================================================================
//  Query
// ============================================================================

TEST_F(MempoolTestFixture, Contains)
{
  Transaction tx = builder_.buildTransfer(0, 1000, 500);
  pool_.add(tx, state_, FeeTier::Standard);

  EXPECT_TRUE(pool_.contains(tx.txid()));

  Crypto::Hash bogus;
  for (size_t i = 0; i < 32; ++i)
    bogus.data[i] = 0xAB;
  EXPECT_FALSE(pool_.contains(bogus));
}

TEST_F(MempoolTestFixture, Get)
{
  Transaction tx = builder_.buildTransfer(0, 1000, 500);
  pool_.add(tx, state_, FeeTier::Standard);

  auto got = pool_.get(tx.txid());
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got->nonce, tx.nonce);
  EXPECT_EQ(got->amount, tx.amount);
  EXPECT_EQ(got->fee, tx.fee);
}

TEST_F(MempoolTestFixture, GetMissing)
{
  Crypto::Hash bogus;
  for (size_t i = 0; i < 32; ++i)
    bogus.data[i] = 0xCD;
  EXPECT_FALSE(pool_.get(bogus).has_value());
}

// ============================================================================
//  Priority count
// ============================================================================

TEST_F(MempoolTestFixture, PriorityCount)
{
  EXPECT_EQ(pool_.priorityCount(), 0u);

  addTransfer(0, 500, FeeTier::Standard);
  EXPECT_EQ(pool_.priorityCount(), 0u);

  addTransfer(1, 500, FeeTier::Priority);
  EXPECT_EQ(pool_.priorityCount(), 1u);

  addTransfer(2, 500, FeeTier::Priority);
  EXPECT_EQ(pool_.priorityCount(), 2u);
}

// ============================================================================
//  Byte accounting
// ============================================================================

TEST_F(MempoolTestFixture, BytesAccountedCorrectly)
{
  Transaction tx = builder_.buildTransfer(0, 1000, 500);
  size_t tx_size = tx.serializedSize();

  pool_.add(tx, state_, FeeTier::Standard);
  EXPECT_EQ(pool_.bytes(), tx_size);

  pool_.clear();
  EXPECT_EQ(pool_.bytes(), 0u);
}

// ============================================================================
//  Fee rate ordering
// ============================================================================

TEST_F(MempoolTestFixture, HigherFeeRateSelectedFirst)
{
  TransactionBuilder low_fee_builder;
  TransactionBuilder high_fee_builder;
  state_.setBalance(low_fee_builder.senderAddress(), 10'000'000'000ULL);
  state_.setBalance(high_fee_builder.senderAddress(), 10'000'000'000ULL);

  Transaction low = low_fee_builder.buildTransfer(0, 1000, 500);
  pool_.add(low, state_, FeeTier::Standard);

  Transaction high = high_fee_builder.buildTransfer(0, 1000, 5000);
  pool_.add(high, state_, FeeTier::Standard);

  auto selected = pool_.selectForBlock(
      state_, /*max_bytes=*/256 * 1024, /*max_txs=*/1);

  ASSERT_EQ(selected.size(), 1u);
  EXPECT_EQ(selected[0].from.toString(),
            high_fee_builder.senderAddress().toString());
}

// ============================================================================
//  Multiple senders
// ============================================================================

TEST_F(MempoolTestFixture, MultipleSendersIndependentNonces)
{
  TransactionBuilder other;
  state_.setBalance(other.senderAddress(), 10'000'000'000ULL);

  Transaction tx1 = builder_.buildTransfer(0, 1000, 500);
  Transaction tx2 = other.buildTransfer(0, 1000, 500);

  EXPECT_EQ(pool_.add(tx1, state_, FeeTier::Standard), MempoolAddResult::Accepted);
  EXPECT_EQ(pool_.add(tx2, state_, FeeTier::Standard), MempoolAddResult::Accepted);
  EXPECT_EQ(pool_.size(), 2u);
}