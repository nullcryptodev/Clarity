// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Chain.h"
#include "Core/ChainDB.h"
#include "Core/Block.h"

#include "Fixtures.h"

using namespace Core;
using namespace Tests;

// Initial state

TEST_F(Core_ChainFixture, HeightIsZeroInitially)
{
  EXPECT_EQ(chain_->height(), 0u);
  EXPECT_TRUE(chain_->headHash().isNull());
}

// Appending genesis (height 0)

TEST_F(Core_ChainFixture, AppendGenesis)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));

  auto result = chain_->appendBlock(genesis);
  EXPECT_EQ(result, Chain::AppendResult::Ok);

  EXPECT_EQ(chain_->height(), 0u);
  EXPECT_EQ(chain_->headHash().toString(), genesis.hash().toString());
}

TEST_F(Core_ChainFixture, AppendGenesisIsIdempotent)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));

  EXPECT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);
  EXPECT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::AlreadyHave);
}

// Appending blocks that extend the head

TEST_F(Core_ChainFixture, AppendSequenceOfBlocks)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  Crypto::Hash parent = genesis.hash();

  for (uint64_t h = 1; h <= 5; ++h)
  {
    Block b = makeBlock(makeBlockHeader(h, parent));
    EXPECT_EQ(chain_->appendBlock(b), Chain::AppendResult::Ok)
        << "height " << h;
    EXPECT_EQ(chain_->height(), h);
    parent = b.hash();
  }

  EXPECT_EQ(chain_->height(), 5u);
}

TEST_F(Core_ChainFixture, AppendHeightMustBeParentPlusOne)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  // Try to append a block at height 3 with genesis as parent.
  Block b = makeBlock(makeBlockHeader(/*height=*/3, genesis.hash()));

  EXPECT_EQ(chain_->appendBlock(b), Chain::AppendResult::InvalidParent);
  EXPECT_EQ(chain_->height(), 0u);
}

//  Unknown parent handling
//  A parent we've never seen is indistinguishable from a valid block
//  whose parent hasn't arrived yet. We report NotConnected and wait.
//  (The "parent exists but isn't head" case is a fork, covered by
//  RejectsForkFromKnownParent below.)

TEST_F(Core_ChainFixture, AppendRejectsUnknownParentHash)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  // A parent hash that's not genesis and not in our DB.
  Crypto::Hash unknown_parent;
  for (size_t i = 0; i < 32; ++i)
    unknown_parent.data[i] = 0xEE;

  Block b = makeBlock(makeBlockHeader(/*height=*/1, unknown_parent));

  EXPECT_EQ(chain_->appendBlock(b), Chain::AppendResult::NotConnected);
  EXPECT_EQ(chain_->height(), 0u);
}

TEST_F(Core_ChainFixture, AppendAlreadyHaveBlock)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  Block b = makeBlock(makeBlockHeader(/*height=*/1, genesis.hash()));
  ASSERT_EQ(chain_->appendBlock(b), Chain::AppendResult::Ok);

  EXPECT_EQ(chain_->appendBlock(b), Chain::AppendResult::AlreadyHave);
  EXPECT_EQ(chain_->height(), 1u);
}

// BFT-specific: no forks allowed

TEST_F(Core_ChainFixture, RejectsForkFromKnownParent)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  // Two blocks at height 1, both with genesis as parent.
  Block b1 = makeBlock(makeBlockHeader(/*height=*/1, genesis.hash()));
  ASSERT_EQ(chain_->appendBlock(b1), Chain::AppendResult::Ok);

  Block b2 = makeBlock(makeBlockHeader(/*height=*/1, genesis.hash()));
  b2.header.timestamp_ms += 1;

  // The chain has moved to b1's head. b2's parent (genesis) is known
  // but isn't the current head. This is a fork, which BFT rejects.
  EXPECT_EQ(chain_->appendBlock(b2), Chain::AppendResult::InvalidParent);
  EXPECT_EQ(chain_->height(), 1u);
}

// Chain head persistence

TEST_F(Core_ChainFixture, HeadPersistsAcrossReopen)
{
  const auto &path = tmp_path();

  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  Block b1 = makeBlock(makeBlockHeader(/*height=*/1, genesis.hash()));
  ASSERT_EQ(chain_->appendBlock(b1), Chain::AppendResult::Ok);

  Crypto::Hash expected_head = b1.hash();
  uint64_t expected_height = 1;

  // Close and reopen.
  db_->close();
  db_.reset();
  chain_db_.reset();
  chain_.reset();

  db_ = std::make_unique<State::StateDB>(path.string(),
                                         64ULL * 1024 * 1024);
  chain_db_ = std::make_unique<ChainDB>(*db_);
  chain_ = std::make_unique<Chain>(*chain_db_);

  EXPECT_EQ(chain_->height(), expected_height);
  EXPECT_EQ(chain_->headHash().toString(), expected_head.toString());
}

// Sync state

TEST_F(Core_ChainFixture, IsSyncingWhenFarBehind)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  chain_->setBestPeerHeight(100);
  EXPECT_TRUE(chain_->isSyncing());
}

TEST_F(Core_ChainFixture, NotSyncingWhenCaughtUp)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  chain_->setBestPeerHeight(3);
  EXPECT_FALSE(chain_->isSyncing());
}

TEST_F(Core_ChainFixture, NotSyncingWhenPeerBehind)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  chain_->setBestPeerHeight(0);
  EXPECT_FALSE(chain_->isSyncing());
}

// Integration with ChainDB

TEST_F(Core_ChainFixture, AppendedBlockIsRetrievable)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  Block b1 = makeBlock(makeBlockHeader(/*height=*/1, genesis.hash()));
  ASSERT_EQ(chain_->appendBlock(b1), Chain::AppendResult::Ok);

  // Retrieve through the chain wrapper.
  auto got = chain_->getBlockByHeight(1);
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got->hash().toString(), b1.hash().toString());

  // Retrieve through the raw ChainDB.
  auto raw = chain_db_->getBlock(b1.hash());
  ASSERT_TRUE(raw.has_value());
  EXPECT_EQ(raw->header.height, 1u);
}

// Long chain integrity

TEST_F(Core_ChainFixture, LongChainIntegrity)
{
  Block genesis = makeBlock(makeBlockHeader(/*height=*/0));
  ASSERT_EQ(chain_->appendBlock(genesis), Chain::AppendResult::Ok);

  Crypto::Hash parent = genesis.hash();
  std::vector<Crypto::Hash> expected_hashes = {parent};

  for (uint64_t h = 1; h <= 100; ++h)
  {
    Block b = makeBlock(makeBlockHeader(h, parent));
    ASSERT_EQ(chain_->appendBlock(b), Chain::AppendResult::Ok)
        << "height " << h;
    parent = b.hash();
    expected_hashes.push_back(parent);
  }

  EXPECT_EQ(chain_->height(), 100u);
  EXPECT_EQ(chain_->headHash().toString(), parent.toString());

  // Verify every block is retrievable by height.
  for (uint64_t h = 0; h <= 100; ++h)
  {
    auto b = chain_->getBlockByHeight(h);
    ASSERT_TRUE(b.has_value()) << "height " << h;
    EXPECT_EQ(b->header.height, h);
    EXPECT_EQ(b->hash().toString(), expected_hashes[h].toString());
  }
}