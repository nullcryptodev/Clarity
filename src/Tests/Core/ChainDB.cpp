// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/ChainDB.h"
#include "Core/Block.h"

#include "Tests/Fixtures.h"

using namespace Core;
using namespace Tests;

// ============================================================================
//  Block storage and retrieval
// ============================================================================

TEST_F(ChainTestFixture, StoreAndRetrieveByHash)
{
  Block b = makeTestBlock(makeTestHeader(/*height=*/1));

  Crypto::Hash hash = b.hash();
  chain_db_->storeBlock(b);

  ASSERT_TRUE(chain_db_->hasBlock(hash));
  EXPECT_TRUE(chain_db_->hasBlockAtHeight(1));

  auto retrieved = chain_db_->getBlock(hash);
  ASSERT_TRUE(retrieved.has_value());
  EXPECT_EQ(retrieved->header.height, 1u);
  EXPECT_EQ(retrieved->header.chain_id, b.header.chain_id);
}

TEST_F(ChainTestFixture, StoreAndRetrieveByHeight)
{
  Block b = makeTestBlock(makeTestHeader(/*height=*/5));

  chain_db_->storeBlock(b);

  auto retrieved = chain_db_->getBlockByHeight(5);
  ASSERT_TRUE(retrieved.has_value());
  EXPECT_EQ(retrieved->header.height, 5u);
}

TEST_F(ChainTestFixture, GetBlockReturnsNullForMissing)
{
  Crypto::Hash missing;
  for (size_t i = 0; i < 32; ++i)
    missing.data[i] = 0xFF;

  EXPECT_FALSE(chain_db_->getBlock(missing).has_value());
  EXPECT_FALSE(chain_db_->getBlockByHeight(9999).has_value());
}

TEST_F(ChainTestFixture, GetHeaderByHash)
{
  Block b = makeTestBlock(makeTestHeader(/*height=*/10));
  chain_db_->storeBlock(b);

  auto header = chain_db_->getHeader(b.hash());
  ASSERT_TRUE(header.has_value());
  EXPECT_EQ(header->height, 10u);
}

TEST_F(ChainTestFixture, GetHeaderByHeight)
{
  Block b = makeTestBlock(makeTestHeader(/*height=*/15));
  chain_db_->storeBlock(b);

  auto header = chain_db_->getHeaderByHeight(15);
  ASSERT_TRUE(header.has_value());
  EXPECT_EQ(header->height, 15u);
}

TEST_F(ChainTestFixture, GetHashByHeight)
{
  Block b = makeTestBlock(makeTestHeader(/*height=*/20));
  Crypto::Hash expected = b.hash();
  chain_db_->storeBlock(b);

  auto got = chain_db_->getHashByHeight(20);
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got->toString(), expected.toString());
}

TEST_F(ChainTestFixture, GetHashByHeightReturnsNullForMissing)
{
  EXPECT_FALSE(chain_db_->getHashByHeight(1).has_value());
}

// ============================================================================
//  Store is idempotent
// ============================================================================

TEST_F(ChainTestFixture, StoreIsIdempotent)
{
  Block b = makeTestBlock(makeTestHeader(/*height=*/1));

  chain_db_->storeBlock(b);
  chain_db_->storeBlock(b);
  chain_db_->storeBlock(b);

  EXPECT_TRUE(chain_db_->hasBlockAtHeight(1));
  EXPECT_EQ(chain_db_->blockCount(), 1u);
}

// ============================================================================
//  Chain head
// ============================================================================

TEST_F(ChainTestFixture, HeadIsEmptyInitially)
{
  auto head = chain_db_->getHead();
  EXPECT_TRUE(head.hash.isNull());
  EXPECT_EQ(head.height, 0u);
}

TEST_F(ChainTestFixture, SetAndGetHead)
{
  Crypto::Hash h;
  for (size_t i = 0; i < 32; ++i)
    h.data[i] = static_cast<uint8_t>(0xAB);

  ChainDB::ChainHead head;
  head.hash = h;
  head.height = 42;
  chain_db_->setHead(head);

  auto retrieved = chain_db_->getHead();
  EXPECT_EQ(retrieved.hash.toString(), h.toString());
  EXPECT_EQ(retrieved.height, 42u);
}

// ============================================================================
//  Chain metadata
// ============================================================================

TEST_F(ChainTestFixture, ChainIdDefaultZero)
{
  EXPECT_EQ(chain_db_->getChainId(), 0u);
}

TEST_F(ChainTestFixture, SetAndGetChainId)
{
  chain_db_->setChainId(0x434C5247);
  EXPECT_EQ(chain_db_->getChainId(), 0x434C5247u);
}

TEST_F(ChainTestFixture, GenesisHashDefaultEmpty)
{
  EXPECT_TRUE(chain_db_->getGenesisHash().isNull());
}

TEST_F(ChainTestFixture, SetAndGetGenesisHash)
{
  Crypto::Hash h;
  for (size_t i = 0; i < 32; ++i)
    h.data[i] = static_cast<uint8_t>(0xCD);
  chain_db_->setGenesisHash(h);

  EXPECT_EQ(chain_db_->getGenesisHash().toString(), h.toString());
}

// ============================================================================
//  Best peer height
// ============================================================================

TEST_F(ChainTestFixture, BestPeerHeightDefaultZero)
{
  EXPECT_EQ(chain_db_->getBestPeerHeight(), 0u);
}

TEST_F(ChainTestFixture, SetAndGetBestPeerHeight)
{
  chain_db_->setBestPeerHeight(12345);
  EXPECT_EQ(chain_db_->getBestPeerHeight(), 12345u);
}

// ============================================================================
//  Receipts
// ============================================================================

TEST_F(ChainTestFixture, StoreAndRetrieveReceipt)
{
  Crypto::Hash tx_hash;
  for (size_t i = 0; i < 32; ++i)
    tx_hash.data[i] = static_cast<uint8_t>(i);

  std::vector<uint8_t> receipt_data = {0x01, 0x02, 0x03, 0x04, 0x05};

  chain_db_->storeReceipt(tx_hash, /*block_height=*/100,
                          /*tx_index=*/3, receipt_data);

  std::vector<uint8_t> retrieved;
  ASSERT_TRUE(chain_db_->getReceipt(tx_hash, retrieved));
  EXPECT_EQ(retrieved, receipt_data);
}

TEST_F(ChainTestFixture, GetReceiptReturnsNullForMissing)
{
  Crypto::Hash missing;
  for (size_t i = 0; i < 32; ++i)
    missing.data[i] = 0xFF;

  std::vector<uint8_t> retrieved;
  EXPECT_FALSE(chain_db_->getReceipt(missing, retrieved));
}

// ============================================================================
//  Block count
// ============================================================================

TEST_F(ChainTestFixture, BlockCountStartsAtZero)
{
  EXPECT_EQ(chain_db_->blockCount(), 0u);
}

TEST_F(ChainTestFixture, BlockCountGrowsWithStores)
{
  for (uint64_t h = 1; h <= 10; ++h)
  {
    Block b = makeTestBlock(makeTestHeader(h));
    chain_db_->storeBlock(b);
  }
  EXPECT_EQ(chain_db_->blockCount(), 10u);
}

// ============================================================================
//  Persistence across "restart"
// ============================================================================

TEST_F(ChainTestFixture, DataSurvivesReopen)
{
  const auto &path = tmp_path();

  Block b = makeTestBlock(makeTestHeader(/*height=*/7));
  Crypto::Hash hash = b.hash();
  chain_db_->storeBlock(b);

  ChainDB::ChainHead head;
  head.hash = hash;
  head.height = 7;
  chain_db_->setHead(head);
  chain_db_->setChainId(0x434C5247);

  db_->close();
  db_.reset();

  auto db2 = std::make_unique<State::StateDB>(path.string(),
                                              64ULL * 1024 * 1024);
  ChainDB chain_db2(*db2);

  ASSERT_TRUE(chain_db2.hasBlock(hash));
  auto retrieved = chain_db2.getBlock(hash);
  ASSERT_TRUE(retrieved.has_value());
  EXPECT_EQ(retrieved->header.height, 7u);

  auto head2 = chain_db2.getHead();
  EXPECT_EQ(head2.height, 7u);
  EXPECT_EQ(head2.hash.toString(), hash.toString());

  EXPECT_EQ(chain_db2.getChainId(), 0x434C5247u);

  db2->close();
}