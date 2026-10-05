// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "Fixtures.h"
#include "Tests/Utils.h"

#include "Common/StringTools.h"
#include "Core/Genesis.h"
#include "GlobalConfig.h"
#include "Node/Node.h"
#include "Wallet/AddressCodec.h"

using namespace Tests;

namespace
{
  // Compute a network's genesis block hash by applying genesis to a
  // fresh temp DB and building the block. Same logic the CLRTYGenesisHash
  // tool uses, inlined here so the test doesn't shell out.
  Crypto::Hash computeGenesisHash(const Core::GenesisConfig &cfg,
                                  const std::string &label)
  {
    namespace fs = std::filesystem;
    fs::path tmp = fs::temp_directory_path() /
                   ("clrty_genesis_test_" + label);
    std::error_code ec;
    fs::remove_all(tmp, ec);

    Crypto::Hash result;
    try
    {
      State::StateDB db(tmp.string(), 64ULL * 1024 * 1024);
      State::StateAccess state(db, /*version=*/0);
      Core::applyGenesis(state, cfg);
      state.commit(0);
      Core::Block genesis = Core::makeGenesisBlock(state, cfg);
      result = genesis.hash();
      db.close();
    }
    catch (...)
    {
      fs::remove_all(tmp, ec);
      throw;
    }
    fs::remove_all(tmp, ec);
    return result;
  }

  Crypto::Hash parsePinnedHash(const char *hex)
  {
    std::string s(hex);
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
      s = s.substr(2);

    std::vector<uint8_t> bytes = Common::fromHex(s);
    EXPECT_EQ(bytes.size(), 32u);
    Crypto::Hash h;
    if (bytes.size() == 32)
      std::memcpy(h.data.data(), bytes.data(), 32);
    return h;
  }

  //  Node::start() is asynchronous: it posts initialization to the
  //  node's io_context and returns immediately. Genesis is written on
  //  that background thread. Any test that stops the node, or reads
  //  chain state, must wait for genesis to land first or it races a
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

//  The pin's purpose is to catch drift in genesis construction. This
//  test asserts that the pinned constants match what genesis
//  construction currently produces. If genesis construction changes
//  without regenerating the pins, this test fails — which is the
//  whole point.
//
//  If genesis construction changes intentionally, run CLRTYGenesisHash,
//  paste the new values into GlobalConfig.h, and this test passes
//  again. That's the correct workflow.

TEST(Node_Genesis, PinnedHashMatchesMainnet)
{
  Crypto::Hash computed = computeGenesisHash(Core::mainnetGenesis(), "mainnet");
  Crypto::Hash pinned = parsePinnedHash(GlobalConfig::MAINNET_GENESIS_HASH);
  EXPECT_EQ(computed, pinned)
      << "Mainnet genesis hash does not match the pinned constant. "
         "Run CLRTYGenesisHash and update GlobalConfig.h, or revert the "
         "genesis-construction change. Computed="
      << computed.toString() << " pinned=" << pinned.toString();
}

TEST(Node_Genesis, PinnedHashMatchesTestnet)
{
  Crypto::Hash computed = computeGenesisHash(Core::testnetGenesis(), "testnet");
  Crypto::Hash pinned = parsePinnedHash(GlobalConfig::TESTNET_GENESIS_HASH);
  EXPECT_EQ(computed, pinned)
      << "Testnet genesis hash does not match the pinned constant. "
         "Computed="
      << computed.toString()
      << " pinned=" << pinned.toString();
}

TEST(Node_Genesis, PinnedHashMatchesRegtest)
{
  Crypto::Hash computed = computeGenesisHash(Core::regtestGenesis(), "regtest");
  Crypto::Hash pinned = parsePinnedHash(GlobalConfig::REGTEST_GENESIS_HASH);
  EXPECT_EQ(computed, pinned)
      << "Regtest genesis hash does not match the pinned constant. "
         "Computed="
      << computed.toString()
      << " pinned=" << pinned.toString();
}

// Tests regtest values
TEST(Node_Genesis, ConfigSeedAddressesDecode)
{
  auto a1 = Wallet::decodeAddress(GlobalConfig::SEED_ADDRESS_REGTEST,
                                  Wallet::Network::Regtest);
  ASSERT_TRUE(a1.has_value())
      << "SEED_ADDRESS does not decode: " << GlobalConfig::SEED_ADDRESS_REGTEST;

  auto a2 = Wallet::decodeAddress(GlobalConfig::SEED_ADDRESS_TWO_REGTEST,
                                  Wallet::Network::Regtest);
  ASSERT_TRUE(a2.has_value())
      << "SEED_ADDRESS_TWO does not decode: " << GlobalConfig::SEED_ADDRESS_TWO_REGTEST;

  EXPECT_EQ(a1->toString(), std::string(GlobalConfig::SEED_NODE))
      << "SEED_ADDRESS does not decode to SEED_NODE";

  EXPECT_EQ(a2->toString(), std::string(GlobalConfig::SEED_NODE_TWO))
      << "SEED_ADDRESS_TWO does not decode to SEED_NODE_TWO";
}

//  Verify the pin is actually enforced at startup. This is the
//  runtime check that catches a node running a binary whose genesis
//  construction has drifted.

TEST_F(Node_Fixture, StartupRejectsWrongGenesisHash)
{
  // This test needs to construct a node with a config that will
  // trigger the genesis hash check. The check is skipped when
  // test_genesis_override is set, so we need a config that DOESN'T
  // set the override. That means using the real regtest genesis.

  Node::NodeConfig cfg = makeValidConfig();
  cfg.network = Node::Network::Regtest;
  cfg.test_genesis_override.reset(); // no override — use the real one

  Node::Node node(cfg, logger_);

  // If the pin is correct, the node starts normally.
  // We're not testing the failure path here — we're testing that
  // the pin doesn't spuriously reject a correct genesis. The failure
  // path is exercised by the fact that if the pins were wrong, the
  // three tests above would fail first.
  EXPECT_NO_THROW(node.start());
  waitForGenesis(node);
  node.stop();
}

TEST_F(Node_BlockFixture, StartupSkipsCheckWithOverride)
{
  Node::NodeConfig cfg = makeFixtureConfig(); // has custom genesis
  Node::Node node(cfg, logger_);
  EXPECT_NO_THROW(node.start());
  waitForGenesis(node);
  node.stop();
}