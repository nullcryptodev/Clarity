// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include "Fixtures.h"
#include "Tests/Utils.h"

#include "Node/Node.h"

using namespace Tests;

namespace
{
  // Read the full contents of a file. Returns an empty vector if the
  // file doesn't exist or is empty. Used to compare keys byte-for-byte.
  std::vector<uint8_t> readFile(const std::string &path)
  {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in)
      return {};

    const auto size = in.tellg();
    if (size <= 0)
      return {};

    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> out(static_cast<size_t>(size));
    in.read(reinterpret_cast<char *>(out.data()), size);
    return out;
  }

  bool fileExists(const std::string &path)
  {
    std::error_code ec;
    return std::filesystem::exists(path, ec) && !ec;
  }
} // anonymous namespace

// ============================================================================
//  Load-or-create semantics
// ============================================================================

TEST_F(Node_Fixture, NodeKeyCreatedOnFirstP2PStart)
{
  Node::NodeConfig cfg = makeValidConfig();
  cfg.enable_p2p = true;
  cfg.p2p_port = 0; // pickFreePort not needed; we're not connecting

  const std::string path = cfg.data_dir + "/node_key";
  ASSERT_FALSE(fileExists(path)) << "fixture should start with an empty data dir";

  Node::Node node(cfg, logger_);
  node.start();

  ASSERT_TRUE(fileExists(path))
      << "node_key file should be created on first P2P start";

  auto bytes = readFile(path);
  EXPECT_EQ(bytes.size(), 32u)
      << "node_key must be exactly a 32-byte Ed25519 seed";

  // A fresh key must not be all zeros — that would mean generateKeyPair
  // returned a null key, which would silently break auth.
  bool all_zero = true;
  for (auto b : bytes)
  {
    if (b != 0)
    {
      all_zero = false;
      break;
    }
  }
  EXPECT_FALSE(all_zero) << "generated node key is all zeros";

  node.stop();
}

TEST_F(Node_Fixture, NodeKeyStableAcrossRestart)
{
  Node::NodeConfig cfg = makeValidConfig();
  cfg.enable_p2p = true;

  const std::string path = cfg.data_dir + "/node_key";

  std::vector<uint8_t> first;
  {
    Node::Node node(cfg, logger_);
    node.start();
    first = readFile(path);
    node.stop();
  }

  ASSERT_EQ(first.size(), 32u);

  std::vector<uint8_t> second;
  {
    Node::Node node(cfg, logger_);
    node.start();
    second = readFile(path);
    node.stop();
  }

  ASSERT_EQ(second.size(), 32u);
  EXPECT_EQ(first, second)
      << "node key must not change across restarts; "
         "a regenerated key breaks peer identity and the ban list";
}

TEST_F(Node_Fixture, NodeKeyConfigOverrideWins)
{
  Node::NodeConfig cfg = makeValidConfig();
  cfg.enable_p2p = true;

  // Fill with a deterministic non-zero key.
  for (size_t i = 0; i < cfg.node_secret_key.data.size(); ++i)
    cfg.node_secret_key.data[i] = uint8_t(0xC0 + i);

  const std::string path = cfg.data_dir + "/node_key";

  Node::Node node(cfg, logger_);
  node.start();

  // When the key comes from config, the config is the source of truth.
  // Writing it to disk would create two sources and an ambiguous
  // "which wins on next restart" question.
  EXPECT_FALSE(fileExists(path))
      << "node_key must not be written when node_secret_key is set in config";

  node.stop();
}

TEST_F(Node_Fixture, NodeKeyCorruptedFileRegenerates)
{
  Node::NodeConfig cfg = makeValidConfig();
  cfg.enable_p2p = true;

  const std::string path = cfg.data_dir + "/node_key";

  // Create the data dir, then write a truncated key file. The node
  // must detect the truncation, regenerate, and overwrite.
  std::filesystem::create_directories(cfg.data_dir);
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out);
    out.write("short", 5);
  }

  Node::Node node(cfg, logger_);
  node.start();

  auto bytes = readFile(path);
  EXPECT_EQ(bytes.size(), 32u)
      << "truncated node_key must be replaced with a full 32-byte key";

  node.stop();
}

TEST_F(Node_Fixture, NonP2PNodeDoesNotCreateNodeKey)
{
  Node::NodeConfig cfg = makeValidConfig();
  cfg.enable_p2p = false;

  const std::string path = cfg.data_dir + "/node_key";

  Node::Node node(cfg, logger_);
  node.start();

  EXPECT_FALSE(fileExists(path))
      << "P2P-disabled node must not write a node_key file";

  node.stop();
}

// ============================================================================
//  Precedence: validator key is used as the node key on validator nodes
// ============================================================================

TEST_F(Node_Fixture, ValidatorUsesValidatorKeyAsNodeKey)
{
  // The key precedence rule: node_secret_key (config) > validator_secret_key
  // > load-or-create from disk. On a validator, using the validator key
  // as the node key is what makes verifyPeerAuth() able to bind the peer
  // to a validator ID: the pubkey advertised in Auth derives to the
  // validator's reward_address, which the active-set lookup matches on.
  //
  // This test pins the second branch of that rule. If someone changes
  // loadOrCreateNodeKey to always generate a fresh key, this test fails
  // and ConsensusOverRealP2P (in NodeEndToEnd.cpp) would then fail
  // silently with validator_id = 0 on every peer.
  Node::NodeConfig cfg = makeValidatorConfig(1);
  cfg.enable_p2p = true;

  const std::string path = cfg.data_dir + "/node_key";

  Node::Node node(cfg, logger_);
  node.start();

  EXPECT_FALSE(fileExists(path))
      << "validator node must use its validator_secret_key as the node "
         "key; writing a separate node_key file would make the peer "
         "authenticate as a non-validator";

  node.stop();
}

TEST_F(Node_Fixture, ValidatorKeyPrecedenceOverridesDisk)
{
  // Same rule, observed differently: even if a node_key file exists on
  // disk (e.g. the data dir was used by a non-validator first), a node
  // configured as a validator must use the validator key, not the file.
  Node::NodeConfig cfg = makeValidatorConfig(1);
  cfg.enable_p2p = true;

  const std::string path = cfg.data_dir + "/node_key";

  // Pre-seed the data dir with a non-validator node_key.
  std::filesystem::create_directories(cfg.data_dir);
  {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    ASSERT_TRUE(out);
    std::array<uint8_t, 32> dummy{};
    dummy.fill(0xEE);
    out.write(reinterpret_cast<const char *>(dummy.data()), dummy.size());
  }

  Node::Node node(cfg, logger_);
  node.start();

  // The file must be untouched — the validator key wins.
  auto bytes = readFile(path);
  ASSERT_EQ(bytes.size(), 32u);
  for (auto b : bytes)
    EXPECT_EQ(b, 0xEE)
        << "validator node must not overwrite an existing node_key file; "
           "it uses its validator_secret_key instead";

  node.stop();
}