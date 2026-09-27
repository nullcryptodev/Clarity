// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Fixtures.h"
#include "Tests/Utils.h"

#include "Node/NodeConfig.h"

using namespace Tests;


TEST(Node_Config, NetworkNames)
{
  EXPECT_STREQ(Node::networkName(Node::Network::Mainnet), "mainnet");
  EXPECT_STREQ(Node::networkName(Node::Network::Testnet), "testnet");
  EXPECT_STREQ(Node::networkName(Node::Network::Regtest), "regtest");
}


TEST(Node_Config, ChainIds)
{
  EXPECT_EQ(Node::chainIdForNetwork(Node::Network::Mainnet), 0x434C5254u);
  EXPECT_EQ(Node::chainIdForNetwork(Node::Network::Testnet), 0x434C5454u);
  EXPECT_EQ(Node::chainIdForNetwork(Node::Network::Regtest), 0x434C5247u);
}

TEST(Node_Config, ValidateRejectsEmptyDataDir)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "";
  EXPECT_THROW(Node::validateConfig(cfg), std::runtime_error);
}

TEST(Node_Config, ValidateFillsChainIdFromNetwork)
{
  Node::NodeConfig cfg;
  cfg.network = Node::Network::Testnet;
  cfg.data_dir = "/tmp/x";
  cfg.chain_id = 0;
  Node::validateConfig(cfg);
  EXPECT_EQ(cfg.chain_id, 0x434C5454u);
}

TEST(Node_Config, ValidateDoesNotOverrideExplicitChainId)
{
  Node::NodeConfig cfg;
  cfg.network = Node::Network::Testnet;
  cfg.data_dir = "/tmp/x";
  cfg.chain_id = 0xDEADBEEF;
  Node::validateConfig(cfg);
  EXPECT_EQ(cfg.chain_id, 0xDEADBEEFu);
}

TEST(Node_Config, ValidateRejectsTinyBlockBytes)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "/tmp/x";
  cfg.max_block_bytes = 100;
  EXPECT_THROW(Node::validateConfig(cfg), std::runtime_error);
}

TEST(Node_Config, ValidateRejectsHugeBlockBytes)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "/tmp/x";
  cfg.max_block_bytes = 32 * 1024 * 1024;
  EXPECT_THROW(Node::validateConfig(cfg), std::runtime_error);
}

TEST(Node_Config, ValidateRejectsZeroMaxBlockTxs)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "/tmp/x";
  cfg.max_block_txs = 0;
  EXPECT_THROW(Node::validateConfig(cfg), std::runtime_error);
}

TEST(Node_Config, ValidateRejectsTinyPollInterval)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "/tmp/x";
  cfg.consensus_poll_ms = 1;
  EXPECT_THROW(Node::validateConfig(cfg), std::runtime_error);
}

TEST(Node_Config, ValidateRejectsHugePollInterval)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "/tmp/x";
  cfg.consensus_poll_ms = 10'000;
  EXPECT_THROW(Node::validateConfig(cfg), std::runtime_error);
}

TEST(Node_Config, ValidateRejectsValidatorWithoutKey)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "/tmp/x";
  cfg.validator_id = 1;
  // validator_secret_key is null
  EXPECT_THROW(Node::validateConfig(cfg), std::runtime_error);
}

TEST(Node_Config, ValidateAcceptsMinimalValidConfig)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "/tmp/x";
  EXPECT_NO_THROW(Node::validateConfig(cfg));
}

TEST(Node_Config, ValidateAcceptsValidatorWithKey)
{
  Node::NodeConfig cfg;
  cfg.data_dir = "/tmp/x";
  cfg.validator_id = 1;
  for (auto &b : cfg.validator_secret_key.data)
    b = 0xAB;
  EXPECT_NO_THROW(Node::validateConfig(cfg));
}

//  Fixture smoke test

TEST_F(Node_Fixture, MakeValidConfigIsValid)
{
  Node::NodeConfig cfg = makeValidConfig();
  EXPECT_NO_THROW(Node::validateConfig(cfg));
  EXPECT_EQ(cfg.network, Node::Network::Regtest);
  EXPECT_EQ(cfg.chain_id, 0x434C5247u);
}