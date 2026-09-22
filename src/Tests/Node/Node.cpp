// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Fixtures.h"
#include "Tests/Utils.h"

#include "Node/Node.h"

using namespace Tests;

// Construction

TEST_F(NodeTestFixture, ConstructWithValidConfig)
{
  Node::NodeConfig cfg = makeValidConfig();
  EXPECT_NO_THROW({
    Node::Node node(cfg, logger_);
  });
}

TEST_F(NodeTestFixture, ConstructRejectsInvalidConfig)
{
  Node::NodeConfig cfg = makeValidConfig();
  cfg.data_dir = ""; // invalid
  EXPECT_THROW({ Node::Node node(cfg, logger_); }, std::runtime_error);
}

// Pre-start status

TEST_F(NodeTestFixture, StatusBeforeStartReportsNotRunning)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  auto s = node.status();
  EXPECT_FALSE(s.running);
  EXPECT_EQ(s.network, Node::Network::Regtest);
  EXPECT_EQ(s.chain_id, 0x434C5247u);
  EXPECT_FALSE(s.is_validator);
  EXPECT_EQ(s.height, 0u);
}

TEST_F(NodeTestFixture, StatusBeforeStartReportsNoConsensus)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  auto s = node.status();
  EXPECT_EQ(s.consensus_height, 0u);
  EXPECT_EQ(s.consensus_round, 0u);
  // Step string is non-null even before consensus.
  EXPECT_NE(s.consensus_step, nullptr);
}

// Pre-start external API

TEST_F(NodeTestFixture, SubmitTransactionBeforeStartFails)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  Core::Transaction tx;
  std::string error;
  EXPECT_FALSE(node.submitTransaction(tx, error));
  EXPECT_FALSE(error.empty());
}

TEST_F(NodeTestFixture, StateRootBeforeStartIsNull)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  EXPECT_TRUE(node.stateRoot().isNull());
}

// Lifecycle edge cases

TEST_F(NodeTestFixture, StopBeforeStartIsSafe)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  EXPECT_NO_THROW(node.stop());
  EXPECT_NO_THROW(node.stop()); // second stop also safe
}

TEST_F(NodeTestFixture, DestructorWithoutStartIsSafe)
{
  Node::NodeConfig cfg = makeValidConfig();
  EXPECT_NO_THROW({
    Node::Node node(cfg, logger_);
    // Destructor runs here.
  });
}