// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "Fixtures.h"
#include "Tests/Utils.h"

#include "Node/Node.h"

using namespace Tests;

namespace
{
  //  Node::start() is asynchronous: it posts initialization to the
  //  node's io_context and returns immediately. Genesis is written on
  //  that background thread. Any test that reads chain state, the
  //  state root, or status after start(), or that stops the node,
  //  must wait for genesis to land first or it races a
  //  partially-initialized node.
  void waitForGenesis(Node::Node &n)
  {
    for (int i = 0; i < 200; ++i)
    {
      if (!NodeTestAccess::chainDb(n).getHead().hash.isNull())
        return;
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    FAIL() << "genesis never applied after start()";
  }
} // anonymous namespace

// Start / stop lifecycle

TEST_F(Node_Fixture, StartAppliesGenesisOnEmptyDB)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  node.start();
  waitForGenesis(node);

  // After start, chain height is 0 (genesis) and state root is non-null.
  auto s = node.status();
  EXPECT_TRUE(s.running);
  EXPECT_EQ(s.height, 0u);
  EXPECT_FALSE(node.stateRoot().isNull());

  node.stop();
}

TEST_F(Node_Fixture, StartIdempotent)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  node.start();
  waitForGenesis(node);
  EXPECT_NO_THROW(node.start()); // second start is a no-op

  node.stop();
}

TEST_F(Node_Fixture, StopIsIdempotentAfterStart)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  node.start();
  waitForGenesis(node);
  EXPECT_NO_THROW(node.stop());
  EXPECT_NO_THROW(node.stop());

  auto s = node.status();
  EXPECT_FALSE(s.running);
}

TEST_F(Node_Fixture, RestartRecoversGenesisState)
{
  Node::NodeConfig cfg = makeValidConfig();
  Crypto::Hash first_root;

  {
    Node::Node node(cfg, logger_);
    node.start();
    waitForGenesis(node);
    first_root = node.stateRoot();
    node.stop();
  }

  // Second run on the same data_dir should find the existing state.
  {
    Node::Node node(cfg, logger_);
    node.start();
    waitForGenesis(node);
    EXPECT_EQ(node.stateRoot(), first_root);
    node.stop();
  }
}

TEST_F(Node_Fixture, RestartDoesNotReapplyGenesis)
{
  Node::NodeConfig cfg = makeValidConfig();

  // First run applies genesis and stores the genesis block.
  {
    Node::Node node(cfg, logger_);
    node.start();
    waitForGenesis(node);
    node.stop();
  }

  // Second run should not error and should have height 0.
  {
    Node::Node node(cfg, logger_);
    node.start();
    waitForGenesis(node);
    EXPECT_EQ(node.status().height, 0u);
    node.stop();
  }
}

// Status

TEST_F(Node_Fixture, StatusReflectsRunningState)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);

  EXPECT_FALSE(node.status().running);
  node.start();
  waitForGenesis(node);
  EXPECT_TRUE(node.status().running);
  node.stop();
  EXPECT_FALSE(node.status().running);
}

TEST_F(Node_Fixture, StatusReflectsNetwork)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);
  node.start();
  waitForGenesis(node);

  auto s = node.status();
  EXPECT_EQ(s.network, Node::Network::Regtest);
  EXPECT_EQ(s.chain_id, 0x434C5247u);

  node.stop();
}

// State root persistence

TEST_F(Node_Fixture, StateRootMatchesGenesisRoot)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);
  node.start();
  waitForGenesis(node);

  // The state root after start should match the expected regtest
  // genesis state root.
  Crypto::Hash expected =
      Core::computeGenesisStateRoot(Core::regtestGenesis());
  EXPECT_EQ(node.stateRoot(), expected);

  node.stop();
}

// Consensus (validator node, headless)

TEST_F(Node_Fixture, ValidatorNodeStartsWithConsensus)
{
  // Validator 1 is a regtest seed validator.
  Node::NodeConfig cfg = makeValidatorConfig(1);
  Node::Node node(cfg, logger_);
  node.start();
  waitForGenesis(node);

  // Consensus object exists (not null), but hasn't been started yet —
  // that happens in run(). We just verify it was constructed.
  EXPECT_NE(NodeTestAccess::consensus(node), nullptr);

  auto s = node.status();
  EXPECT_TRUE(s.is_validator);
  EXPECT_EQ(s.validator_id, 1u);

  node.stop();
}

TEST_F(Node_Fixture, NonValidatorNodeHasNoConsensus)
{
  Node::NodeConfig cfg = makeValidConfig(); // validator_id = 0
  Node::Node node(cfg, logger_);
  node.start();
  waitForGenesis(node);

  EXPECT_EQ(NodeTestAccess::consensus(node), nullptr);

  node.stop();
}

// Mempool interaction

TEST_F(Node_Fixture, SubmitTransactionAfterStart)
{
  Node::NodeConfig cfg = makeValidConfig();
  Node::Node node(cfg, logger_);
  node.start();
  waitForGenesis(node);

  // Submit a syntactically well-formed tx from an unfunded account.
  // The node should hand it off to the mempool, which returns a
  // rejection result with an explanatory message — not throw, not
  // crash, not silently accept.
  Core::Transaction tx;
  tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
  tx.chain_id = cfg.chain_id;
  tx.tx_type = Core::TxType::Transfer;
  tx.nonce = 0;
  tx.valid_until_height = 0;
  tx.from = Crypto::Address{};
  for (size_t i = 0; i < 32; ++i)
    tx.from.data[i] = 0x11;
  tx.to = Crypto::Address{};
  for (size_t i = 0; i < 32; ++i)
    tx.to.data[i] = 0x22;
  tx.token_id = NATIVE_TOKEN_ID;
  tx.amount = 100;
  tx.fee = 1;

  std::string error;
  Core::MempoolAddResult result = node.submitTransaction(tx, error);

  // Whatever rejection the mempool chose, it must be a clean
  // rejection with a message — never Accepted (no funds), never a
  // thrown exception (that would be an API-layer bug).
  EXPECT_NE(result, Core::MempoolAddResult::Accepted);
  EXPECT_FALSE(error.empty()) << "rejection must carry an error message";

  node.stop();
}