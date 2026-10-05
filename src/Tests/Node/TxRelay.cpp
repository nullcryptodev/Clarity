// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <thread>

#include "Fixtures.h"
#include "Tests/Utils.h"
#include "Node/Node.h"

#include "Core/Genesis.h"
#include "Core/Mempool.h"
#include "Core/Transaction.h"
#include "Crypto/Ed25519.h"
#include "P2P/P2PManager.h"
#include "State/StateAccess.h"
#include "State/StateDB.h"

using namespace Tests;

namespace
{
  //  Node::start() is asynchronous: it posts initialization to the
  //  node's io_context and returns immediately. Genesis is written on
  //  that background thread. Any test that reads chain state, or that
  //  stops the node, must wait for genesis to land first or it races a
  //  partially-initialized node. Mirrors the helper in
  //  SyncEndToEnd.cpp and the other Node_EndToEndFixture files.
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

// ============================================================================
//  Local submission propagates to connected peers
// ============================================================================

TEST_F(Node_EndToEndFixture, SubmittedTxPropagatesToPeers)
{
  // Two nodes with P2P enabled, both non-validators. Submit a tx on
  // node 0; node 1 should receive it via broadcast and add it to its
  // mempool.
  //
  //  Both nodes are NON-validators. If they were validators, the
  //  fixture's startNodes()-equivalent wiring would not be invoked
  //  here, but the nodes would still begin live consensus once a peer
  //  reaches Established — which is exactly what this test is not
  //  about. Non-validator configs mean no consensus engine is
  //  constructed, so the mempool state the assertions observe is
  //  stable and the relay path is tested in isolation.

  setValidatorCount(2);
  makeExtraNodes(2);
  buildGenesis();
  buildEnv();

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  nodes_.clear();
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(0, port0), logger_));
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(1, port1), logger_));

  nodes_[0]->start();
  nodes_[1]->start();
  waitForGenesis(*nodes_[0]);
  waitForGenesis(*nodes_[1]);

  NodeThreadGroup threads;
  threads.runAll(nodes_);

  bool listening =
      waitForListening(port0, std::chrono::seconds(3)) &&
      waitForListening(port1, std::chrono::seconds(3));
  if (!listening)
  {
    dumpNodeState("node0", *nodes_[0]);
    dumpNodeState("node1", *nodes_[1]);
  }
  ASSERT_TRUE(listening);

  // Dial node0 -> node1.
  NodeTestAccess::postToP2P(*nodes_[0], [&]
                            { NodeTestAccess::p2p(*nodes_[0])->connectTo("127.0.0.1", port1); });

  // Wait for both sides to be Established.
  bool e0 = waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5));
  bool e1 = e0 && waitForEstablished(*nodes_[1], 1, std::chrono::seconds(5));
  if (!e0 || !e1)
  {
    dumpNodeState("node0", *nodes_[0]);
    dumpNodeState("node1", *nodes_[1]);
  }
  ASSERT_TRUE(e0);
  ASSERT_TRUE(e1);

  // Build a signed transfer from a funded account.
  const Crypto::KeyPair alice = aliceKey();
  const Crypto::Address bob_addr = addressOf(bobKey());

  Core::Transaction tx = makeSignedTransfer(
      alice, bob_addr, /*amount=*/100, /*fee=*/500, /*nonce=*/0);

  ASSERT_EQ(NodeTestAccess::mempool(*nodes_[0]).size(), 0u);
  ASSERT_EQ(NodeTestAccess::mempool(*nodes_[1]).size(), 0u);

  // Submit on node0. This puts it in node0's mempool and broadcasts.
  std::string error;
  auto r = nodes_[0]->submitTransaction(tx, error);
  EXPECT_EQ(r, Core::MempoolAddResult::Accepted) << error;

  // node0 has it.
  EXPECT_EQ(NodeTestAccess::mempool(*nodes_[0]).size(), 1u);

  // Wait for node1 to receive it via relay.
  bool arrived = waitFor([&]
                         { return NodeTestAccess::mempool(*nodes_[1]).size() >= 1; },
                         std::chrono::seconds(3));
  if (!arrived)
  {
    dumpNodeState("node0", *nodes_[0]);
    dumpNodeState("node1", *nodes_[1]);
  }
  ASSERT_TRUE(arrived) << "node1 did not receive the relayed tx";

  // Both mempools have the same tx.
  EXPECT_TRUE(NodeTestAccess::mempool(*nodes_[1]).contains(tx.txid()));
  auto got = NodeTestAccess::mempool(*nodes_[1]).get(tx.txid());
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(got->txid(), tx.txid());

  threads.join();
}

// ============================================================================
//  Duplicate relay does not loop
// ============================================================================

TEST_F(Node_EndToEndFixture, DuplicateTxRelayIsIdempotent)
{
  // Same setup, but we submit the same tx twice. The second submit
  // should be Accepted (idempotent) but must not produce an
  // infinite broadcast loop. Node1's mempool should contain the tx
  // exactly once and never grow.
  //
  //  Both nodes are non-validators, same reasoning as
  //  SubmittedTxPropagatesToPeers. If they were validators, live
  //  consensus would commit a block containing the tx and clear both
  //  mempools before the assertions run. The relay path is
  //  independent of consensus; this test needs a static chain and a
  //  stable mempool.

  setValidatorCount(2);
  makeExtraNodes(2);
  buildGenesis();
  buildEnv();

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  nodes_.clear();
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(0, port0), logger_));
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(1, port1), logger_));

  nodes_[0]->start();
  nodes_[1]->start();
  waitForGenesis(*nodes_[0]);
  waitForGenesis(*nodes_[1]);

  NodeThreadGroup threads;
  threads.runAll(nodes_);

  ASSERT_TRUE(waitForListening(port0, std::chrono::seconds(3)));
  ASSERT_TRUE(waitForListening(port1, std::chrono::seconds(3)));

  NodeTestAccess::postToP2P(*nodes_[0], [&]
                            { NodeTestAccess::p2p(*nodes_[0])->connectTo("127.0.0.1", port1); });

  ASSERT_TRUE(waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5)));
  ASSERT_TRUE(waitForEstablished(*nodes_[1], 1, std::chrono::seconds(5)));

  const Crypto::KeyPair alice = aliceKey();
  const Crypto::Address bob_addr = addressOf(bobKey());

  Core::Transaction tx = makeSignedTransfer(
      alice, bob_addr, /*amount=*/100, /*fee=*/500, /*nonce=*/0);

  std::string error;
  ASSERT_EQ(nodes_[0]->submitTransaction(tx, error),
            Core::MempoolAddResult::Accepted)
      << error;

  // Resubmit — idempotent, no second broadcast.
  ASSERT_EQ(nodes_[0]->submitTransaction(tx, error),
            Core::MempoolAddResult::Accepted)
      << error;

  // Wait for node1 to see it.
  bool arrived = waitFor([&]
                         { return NodeTestAccess::mempool(*nodes_[1]).size() >= 1; },
                         std::chrono::seconds(3));
  ASSERT_TRUE(arrived);

  // Give the network time to settle. If the tx were looping, mempool
  // sizes would keep climbing past 1 or the test would hang.
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  EXPECT_EQ(NodeTestAccess::mempool(*nodes_[0]).size(), 1u);
  EXPECT_EQ(NodeTestAccess::mempool(*nodes_[1]).size(), 1u);

  threads.join();
}

// ============================================================================
//  Genesis construction is deterministic across fresh DBs
// ============================================================================
//
//  The pinned genesis hashes are only meaningful if genesis
//  construction is a pure function of the GenesisConfig. If
//  applyGenesis ever grows a dependency on something that varies
//  between processes — map iteration order, a system timestamp, an
//  ASLR-derived value, a thread id — the pins would still pass on
//  the build machine (where the pin was generated) and fail on a
//  differently-behaving machine, with no obvious cause.
//
//  This test builds genesis twice from the same config into two
//  fresh temp DBs and asserts both the block hash and the state root
//  match. It runs in-process, so it catches non-determinism that
//  originates from process-global state (allocator layout, RNG seed,
//  map iteration order). It does not catch non-determinism that
//  happens to produce the same result twice within one process but
//  differs across processes — but that class is much narrower, and
//  would show up as a cross-machine pin failure rather than a
//  silent one.

namespace
{
  struct GenesisResult
  {
    Crypto::Hash block_hash;
    Crypto::Hash state_root;
  };

  // Apply the given genesis config to a fresh temp DB at `path`,
  // close the DB, and return the resulting block hash and state
  // root. Mirrors the compute path in the genesis_hash tool and in
  // Node::initGenesis, so a divergence between this and either of
  // those is itself a signal.
  GenesisResult buildGenesisOnce(const Core::GenesisConfig &cfg,
                                 const std::filesystem::path &path)
  {
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::remove_all(path, ec);
    fs::create_directories(path, ec);

    GenesisResult r;
    {
      State::StateDB db(path.string(), 64ULL * 1024 * 1024);
      State::StateAccess state(db, /*version=*/0);
      Core::applyGenesis(state, cfg);
      state.commit(0);

      Core::Block genesis = Core::makeGenesisBlock(state, cfg);
      r.block_hash = genesis.hash();
      r.state_root = genesis.header.state_root;
      db.close();
    }

    fs::remove_all(path, ec);
    return r;
  }
} // anonymous namespace

TEST_F(Node_EndToEndFixture, GenesisIsDeterministicAcrossFreshDbs)
{
  // Two fresh DBs, same config, same process, in sequence. If these
  // produce different hashes, genesis construction is not a pure
  // function of the config and every pin in GlobalConfig.h is
  // suspect.

  namespace fs = std::filesystem;

  const fs::path base = tmp_dir() / "genesis_determinism";
  const fs::path path_a = base / "a";
  const fs::path path_b = base / "b";

  // Run each network in turn. Regtest is what the tests actually use,
  // but mainnet and testnet share the same applyGenesis code path and
  // are cheap, so cover all three.
  const std::vector<std::pair<std::string, Core::GenesisConfig>> networks = {
      {"mainnet", Core::mainnetGenesis()},
      {"testnet", Core::testnetGenesis()},
      {"regtest", Core::regtestGenesis()},
  };

  for (const auto &[name, cfg] : networks)
  {
    const GenesisResult a = buildGenesisOnce(cfg, path_a);
    const GenesisResult b = buildGenesisOnce(cfg, path_b);

    EXPECT_FALSE(a.block_hash.isNull())
        << name << ": first genesis block hash is null";
    EXPECT_FALSE(b.block_hash.isNull())
        << name << ": second genesis block hash is null";

    EXPECT_EQ(a.block_hash, b.block_hash)
        << name << ": genesis block hash differs across two fresh "
        << "DBs in the same process. Genesis construction is not "
        << "deterministic; the pinned hash in GlobalConfig.h is "
        << "only valid for the build machine. First="
        << a.block_hash.toString()
        << " second=" << b.block_hash.toString();

    EXPECT_EQ(a.state_root, b.state_root)
        << name << ": genesis state root differs across two fresh "
        << "DBs in the same process. First="
        << a.state_root.toString()
        << " second=" << b.state_root.toString();

    //  Sanity: the computed hash must also match the pinned constant.
    //  This is redundant with Node_Genesis.PinnedHashMatches*, but
    //  those tests use their own copy of the construction path. This
    //  one uses the fixture's genesis config, which is what
    //  Node_EndToEndFixture actually feeds to nodes. If the fixture's
    //  config ever drifts from the network config, the pins would
    //  pass on Node_Genesis and fail here.
    const Crypto::Hash pinned = Core::expectedGenesisHash(cfg);
    if (!pinned.isNull())
    {
      EXPECT_EQ(a.block_hash, pinned)
          << name << ": fixture genesis does not match the pinned "
          << "constant. Computed=" << a.block_hash.toString()
          << " pinned=" << pinned.toString();
    }
  }
}