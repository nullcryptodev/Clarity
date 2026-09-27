// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Fixtures.h"
#include "Tests/Utils.h"

#include "Node/Node.h"

using namespace Tests;

// Construction

TEST_F(Node_Fixture, ConstructWithValidConfig)
{
  Node::NodeConfig cfg = makeValidConfig();
  EXPECT_NO_THROW({
    Node::Node node(cfg, logger_);
  });
}

TEST_F(Node_Fixture, ConstructRejectsInvalidConfig)
{
  Node::NodeConfig cfg = makeValidConfig();
  cfg.data_dir = ""; // invalid
  EXPECT_THROW({ Node::Node node(cfg, logger_); }, std::runtime_error);
}

// Pre-start status

TEST_F(Node_Fixture, StatusBeforeStartReportsNotRunning)
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

TEST_F(Node_Fixture, StatusBeforeStartReportsNoConsensus)
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

TEST_F(Node_Fixture, SubmitTransactionBeforeStartFails)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  Core::Transaction tx;
  std::string error;

  // The node hasn't been start()ed, so mempool_ is null. The new
  // contract throws rather than returning a Rejected_* enum, because
  // "node not initialized" is a programmer error, not a mempool
  // decision. See Node::submitTransaction's doc comment.
  EXPECT_THROW(node.submitTransaction(tx, error), std::runtime_error);
}

TEST_F(Node_Fixture, StateRootBeforeStartIsNull)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  EXPECT_TRUE(node.stateRoot().isNull());
}

// Lifecycle edge cases

TEST_F(Node_Fixture, StopBeforeStartIsSafe)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  EXPECT_NO_THROW(node.stop());
  EXPECT_NO_THROW(node.stop()); // second stop also safe
}

TEST_F(Node_Fixture, DestructorWithoutStartIsSafe)
{
  Node::NodeConfig cfg = makeValidConfig();
  EXPECT_NO_THROW({
    Node::Node node(cfg, logger_);
    // Destructor runs here.
  });
}

TEST_F(Node_Fixture, SubmitTransactionReturnsMempoolResult)
{
  // Start the node so the mempool exists, then submit a malformed tx
  // and verify the return value carries the specific rejection reason
  // rather than a generic false.
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);
  node.start();

  Core::Transaction tx; // default-constructed: not well-formed
  std::string error;

  EXPECT_EQ(node.submitTransaction(tx, error),
            Core::MempoolAddResult::Rejected_Malformed);
  EXPECT_FALSE(error.empty());

  node.stop();
}

TEST_F(Node_Fixture, SubmitTransactionRejectedClearsError)
{
  // On Accepted, `error` must be cleared. On rejection, it must be
  // populated. This guards against a handler forgetting to clear
  // the string before returning success.
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);
  node.start();

  Core::Transaction tx; // malformed
  std::string error = "pre-existing";
  EXPECT_EQ(node.submitTransaction(tx, error),
            Core::MempoolAddResult::Rejected_Malformed);
  EXPECT_FALSE(error.empty());
  EXPECT_NE(error, "pre-existing");

  node.stop();
}

TEST_F(Node_Fixture, ChainDBRoundTripGenesisHeight)
{
  Node::NodeConfig cfg = makeValidConfig();
  State::StateDB db(cfg.data_dir + "/state", 64ULL * 1024 * 1024);
  Core::ChainDB chain_db(db);

  Core::GenesisConfig gcfg = Core::regtestGenesis();
  {
    State::StateAccess state(db, 0);
    Core::applyGenesis(state, gcfg);
    state.commit(0);
  }
  {
    State::StateAccess state(db, 0);
    Core::Block genesis = Core::makeGenesisBlock(state, gcfg);
    chain_db.storeBlock(genesis);

    // Direct check
    auto h = chain_db.getHashByHeight(0);
    ASSERT_TRUE(h.has_value()) << "storeBlock didn't write by-height index";

    auto b = chain_db.getBlockByHeight(0);
    ASSERT_TRUE(b.has_value());

    EXPECT_EQ(b->header.height, 0u);
  }
  db.close();
}