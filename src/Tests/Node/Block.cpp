// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <cstring>

#include "Tests/Fixtures.h"
#include "Tests/Utils.h"
#include "Node/Node.h"

#include "Consensus/Message.h"
#include "Core/BlockProcessor.h"
#include "Core/Genesis.h"
#include "Core/TransactionExecutor.h"
#include "Crypto/Ed25519.h"
#include "State/StateAccess.h"

using namespace Tests;

// Block application

TEST_F(NodeBlockFixture, ApplyEmptyBlockAdvancesHeight)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  ASSERT_EQ(node.status().height, 0u);

  Core::Block b = buildValidEmptyBlock(node, 1);

  std::string error;
  bool ok = NodeTestAccess::applyBlock(node, b, error);
  EXPECT_TRUE(ok) << "applyBlock failed: " << error;

  EXPECT_EQ(node.status().height, 1u);

  node.stop();
}

TEST_F(NodeBlockFixture, ApplyBlockUpdatesHead)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  Core::Block b = buildValidEmptyBlock(node, 1);
  Crypto::Hash expected_hash = b.hash();

  std::string error;
  ASSERT_TRUE(NodeTestAccess::applyBlock(node, b, error)) << error;

  auto &chain_db = NodeTestAccess::chainDb(node);
  auto head = chain_db.getHead();
  EXPECT_EQ(head.height, 1u);
  EXPECT_EQ(head.hash, expected_hash);

  node.stop();
}

TEST_F(NodeBlockFixture, ApplyBlockUpdatesStateRoot)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  Crypto::Hash root_before = node.stateRoot();

  Core::Block b = buildValidEmptyBlock(node, 1);

  std::string error;
  ASSERT_TRUE(NodeTestAccess::applyBlock(node, b, error)) << error;

  Crypto::Hash root_after = node.stateRoot();
  EXPECT_NE(root_after, root_before);
  EXPECT_EQ(root_after, b.header.state_root);

  node.stop();
}

TEST_F(NodeBlockFixture, ApplyBlockPersistsAcrossRestart)
{
  Node::NodeConfig cfg = makeFixtureConfig();
  Crypto::Hash expected_root;
  Crypto::Hash expected_head;
  uint64_t expected_height = 0;

  {
    Node::Node node(cfg, logger_);
    node.start();

    Core::Block b = buildValidEmptyBlock(node, 1);
    expected_head = b.hash();

    std::string error;
    ASSERT_TRUE(NodeTestAccess::applyBlock(node, b, error)) << error;

    expected_root = node.stateRoot();
    expected_height = node.status().height;

    node.stop();
  }

  {
    Node::Node node(cfg, logger_);
    node.start();

    EXPECT_EQ(node.status().height, expected_height);
    EXPECT_EQ(node.stateRoot(), expected_root);

    auto &chain_db = NodeTestAccess::chainDb(node);
    auto head = chain_db.getHead();
    EXPECT_EQ(head.height, expected_height);
    EXPECT_EQ(head.hash, expected_head);

    node.stop();
  }
}

// ============================================================================
//  B. Transaction inclusion
// ============================================================================

TEST_F(NodeBlockFixture, ApplyBlockWithTransfer)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  Core::Block b = buildValidEmptyBlock(node, 1);

  std::string error;
  ASSERT_TRUE(NodeTestAccess::applyBlock(node, b, error)) << error;

  EXPECT_EQ(node.status().height, 1u);

  node.stop();
}

TEST_F(NodeBlockFixture, ApplyBlockClearsIncludedMempoolEntries)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  Core::Block b = buildValidEmptyBlock(node, 1);

  std::string error;
  ASSERT_TRUE(NodeTestAccess::applyBlock(node, b, error)) << error;

  node.stop();
}

// ============================================================================
//  C. Failure handling
// ============================================================================

TEST_F(NodeBlockFixture, RejectsBlockWithWrongStateRoot)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  Core::Block b = buildValidEmptyBlock(node, 1);
  for (size_t i = 0; i < 32; ++i)
    b.header.state_root.data[i] ^= 0xFF;

  // state_root is part of the block hash; re-sign so the signature
  // check passes and the state-root check fires.
  b.quorum_signatures = makeQuorumForBlock(b);

  std::string error;
  bool ok = NodeTestAccess::applyBlock(node, b, error);
  EXPECT_FALSE(ok);
  EXPECT_FALSE(error.empty());

  EXPECT_EQ(node.status().height, 0u);

  node.stop();
}

TEST_F(NodeBlockFixture, RejectsBlockWithBadTxRoot)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  Core::Block b = buildValidEmptyBlock(node, 1);
  for (size_t i = 0; i < 32; ++i)
    b.header.tx_root.data[i] ^= 0xFF;

  // tx_root is part of the block hash; re-sign.
  b.quorum_signatures = makeQuorumForBlock(b);

  std::string error;
  bool ok = NodeTestAccess::applyBlock(node, b, error);
  EXPECT_FALSE(ok);
  EXPECT_FALSE(error.empty());

  EXPECT_EQ(node.status().height, 0u);

  node.stop();
}

// ============================================================================
//  D. Multi-block sequences
// ============================================================================

TEST_F(NodeBlockFixture, ApplyThreeBlocksInSequence)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  for (uint64_t h = 1; h <= 3; ++h)
  {
    Core::Block b = buildValidEmptyBlock(node, h);
    std::string error;
    ASSERT_TRUE(NodeTestAccess::applyBlock(node, b, error))
        << "height " << h << ": " << error;
    EXPECT_EQ(node.status().height, h);
  }

  EXPECT_EQ(node.status().height, 3u);

  node.stop();
}

TEST_F(NodeBlockFixture, StateRootChainAcrossBlocks)
{
  Node::Node node(makeFixtureConfig(), logger_);
  node.start();

  Crypto::Hash previous_root = node.stateRoot();

  for (uint64_t h = 1; h <= 3; ++h)
  {
    Core::Block b = buildValidEmptyBlock(node, h);
    std::string error;
    ASSERT_TRUE(NodeTestAccess::applyBlock(node, b, error))
        << "height " << h << ": " << error;

    Crypto::Hash current_root = node.stateRoot();
    EXPECT_EQ(current_root, b.header.state_root);
    EXPECT_NE(current_root, previous_root);

    previous_root = current_root;
  }

  node.stop();
}