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

#include "Core/Chain.h"
#include "Core/Genesis.h"
#include "Core/BlockProcessor.h"
#include "Crypto/Ed25519.h"
#include "P2P/P2PManager.h"
#include "State/StateAccess.h"

using namespace Tests;

namespace
{
  //  Node::start() is asynchronous: it posts initialization to the
  //  node's io_context and returns immediately. Genesis is written on
  //  that background thread. Any test that needs to read the genesis
  //  block hash from the chain DB, or that builds a block whose
  //  parent_hash has to be the genesis hash, must wait for genesis to
  //  land first.
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

  //  Read the active set from the node's state at genesis version (0).
  //  applyGenesis writes "active_set" as a global during genesis
  //  application, committed at version 0. The block being built must
  //  declare the same active_validator_count and validator_set_root
  //  that BlockProcessor::applyBlock will derive from the same state.
  std::vector<Id> readActiveSetFromState(State::StateDB &db)
  {
    std::vector<Id> ids;
    State::StateAccess state(db, /*version=*/0);

    std::vector<uint8_t> bytes;
    if (!state.getGlobal("active_set", bytes))
      return ids;

    for (size_t i = 0; i + 8 <= bytes.size(); i += 8)
    {
      uint64_t id = 0;
      for (int j = 0; j < 8; ++j)
        id |= uint64_t(bytes[i + j]) << (j * 8);
      ids.push_back(id);
    }
    return ids;
  }

  // Build a valid empty block at the given height, parented to the
  // chain's current head, signed by the seed validators. Kept local
  // because these sync tests build blocks on nodes that are started
  // without going through the consensus harness.
  Core::Block buildAndSignBlock(Node::Node &node,
                                const Core::GenesisConfig &genesis,
                                const Crypto::KeyPair &seed1,
                                const Crypto::KeyPair &seed2,
                                uint64_t height)
  {
    auto &db = NodeTestAccess::stateDb(node);
    auto &chain_db = NodeTestAccess::chainDb(node);

    const auto head = chain_db.getHead();

    //  Mirror the state-derived active set into the header, the same
    //  way BftConsensus::buildFreshBlock mirrors deps_.active_set().
    std::vector<Id> active_set = readActiveSetFromState(db);

    Core::Block b;
    b.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
    b.header.chain_id = genesis.chain_id;
    b.header.height = height;
    b.header.parent_hash = head.hash;
    b.header.timestamp_ms = 1'700'000'000'000ULL + height * 1000;
    b.header.proposer = Crypto::Address{};
    for (size_t i = 0; i < 32; ++i)
      b.header.proposer.data[i] = uint8_t(0x80 + i);
    b.header.epoch = height / Core::ROTATION_INTERVAL;
    b.header.rotation_index = height / Core::ROTATION_INTERVAL;
    b.header.commit_round = 0;
    b.header.tx_root = Core::computeTxRoot({});

    //  Non-null placeholder. isWellFormed() requires a non-null state
    //  root on any non-genesis block, but the real root can only be
    //  computed by simulating the block, which runs isWellFormed first.
    b.header.state_root.data[0] = 0x01;

    b.header.receipts_root = Crypto::Hash{};
    b.header.validator_set_root = Core::computeValidatorSetRoot(active_set);
    b.header.active_validator_count =
        static_cast<uint32_t>(active_set.size());
    b.header.tx_count = 0;
    b.header.total_fees = 0;
    b.participants = active_set;
    b.quorum_signatures.clear();

    // Simulate to compute state root.
    {
      auto txn = db.beginWrite();
      State::StateAccess state(db, txn, height);
      Core::BlockContext ctx;
      ctx.chain_id = genesis.chain_id;
      ctx.current_height = height;
      ctx.dry_run = true;
      Core::BlockResult r = Core::BlockProcessor::applyBlock(state, b, ctx);

      if (r.valid && !r.new_state_root.isNull())
        b.header.state_root = r.new_state_root;

      txn.abort();
    }

    // Sign.
    const Crypto::Hash signing_hash = Consensus::voteSigningHash(
        b.header.height, b.header.commit_round, false, b.hash());
    b.quorum_signatures.push_back({0, Crypto::sign(signing_hash, seed1.secretKey)});
    b.quorum_signatures.push_back({1, Crypto::sign(signing_hash, seed2.secretKey)});

    return b;
  }
} // anonymous namespace

// ============================================================================
//  Happy path: a behind node catches up from an ahead node
// ============================================================================

TEST_F(Node_EndToEndFixture, BehindNodeCatchesUpFromAheadNode)
{
  // Two seed validators. Node 0 will stay behind. Node 1 will be
  // pre-loaded with 5 blocks before we connect them.
  setValidatorCount(2);

  //  These tests bypass startNodes(), so they must populate dirs_,
  //  genesis_, and env_ themselves. makeConfig() reads dirs_, and the
  //  node's genesis path reads genesis_. Both must be set up before any
  //  Node is constructed or every block fails header validation.
  makeExtraNodes(2);
  buildGenesis();
  buildEnv();

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  const Crypto::KeyPair seed1 = keys_.at(0).reward_kp;
  const Crypto::KeyPair seed2 = keys_.at(1).reward_kp;

  // Pre-apply blocks on node 1's data dir before starting it with
  // P2P. Start node 1 headless, apply blocks directly, stop it.
  // Then restart it with P2P enabled.
  Node::NodeConfig cfg1_headless = makeNonValidatorConfig(1);
  cfg1_headless.enable_p2p = false;
  {
    Node::Node n1(cfg1_headless, logger_);
    n1.start();
    waitForGenesis(n1);
    for (uint64_t h = 1; h <= 5; ++h)
    {
      Core::Block b = buildAndSignBlock(n1, genesis_, seed1, seed2, h);
      std::string error;
      ASSERT_TRUE(NodeTestAccess::applyBlock(n1, b, error))
          << "height " << h << ": " << error;
    }
    EXPECT_EQ(NodeTestAccess::chain(n1).height(), 5u);
    n1.stop();
  }

  // Now start both nodes with P2P enabled on their respective ports.
  // Non-validators: no live consensus, so the test controls exactly
  // which blocks exist.
  auto cfg0 = makeNonValidatorConfigWithP2P(0, port0);
  auto cfg1 = makeNonValidatorConfigWithP2P(1, port1);

  nodes_.clear();
  nodes_.push_back(std::make_unique<Node::Node>(cfg0, logger_));
  nodes_.push_back(std::make_unique<Node::Node>(cfg1, logger_));

  nodes_[0]->start();
  nodes_[1]->start();
  waitForGenesis(*nodes_[0]);
  waitForGenesis(*nodes_[1]);

  std::thread t0([&]
                 { nodes_[0]->run(); });
  std::thread t1([&]
                 { nodes_[1]->run(); });

  bool ok = true;

  bool l0 = waitForListening(port0, std::chrono::seconds(3));
  bool l1 = waitForListening(port1, std::chrono::seconds(3));
  EXPECT_TRUE(l0) << "node0 not listening";
  EXPECT_TRUE(l1) << "node1 not listening";
  ok = ok && l0 && l1;

  // Node 0 dials node 1. Node 0 is behind (height 0) and will learn
  // node 1's best height (5) during the Version handshake, then
  // start sync after auth.
  if (ok)
  {
    NodeTestAccess::postToP2P(*nodes_[0], [&]
                              { NodeTestAccess::p2p(*nodes_[0])->connectTo("127.0.0.1", port1); });
  }

  // Wait for the peer to reach Established on both sides.
  bool e0 = ok && waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5));
  bool e1 = ok && waitForEstablished(*nodes_[1], 1, std::chrono::seconds(5));
  EXPECT_TRUE(e0) << "node0 peer never reached Established";
  EXPECT_TRUE(e1) << "node1 peer never reached Established";
  ok = ok && e0 && e1;

  // Wait for node 0 to catch up to height 5.
  bool caught_up = ok && waitForHeight(*nodes_[0], 5, std::chrono::seconds(15));
  if (!caught_up)
  {
    dumpNodeState("node0", *nodes_[0]);
    dumpNodeState("node1", *nodes_[1]);
  }
  EXPECT_TRUE(caught_up) << "node0 did not catch up to height 5";

  // Verify agreement.
  if (caught_up)
  {
    EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 5u);
    EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 5u);
    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

    for (uint64_t h = 1; h <= 5; ++h)
    {
      auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(h);
      auto h1 = NodeTestAccess::chainDb(*nodes_[1]).getHashByHeight(h);
      ASSERT_TRUE(h0.has_value());
      ASSERT_TRUE(h1.has_value());
      EXPECT_EQ(*h0, *h1) << "block hash mismatch at height " << h;
    }
  }

  nodes_[0]->stop();
  nodes_[1]->stop();
  t0.join();
  t1.join();
}

// ============================================================================
//  No-op when the peer is not ahead
// ============================================================================

TEST_F(Node_EndToEndFixture, AheadNodeDoesNotSync)
{
  // Both nodes at height 0. SyncManager should stay idle; no
  // GetHeaders should be sent, no blocks should be applied.
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

  std::thread t0([&]
                 { nodes_[0]->run(); });
  std::thread t1([&]
                 { nodes_[1]->run(); });

  waitForListening(port0, std::chrono::seconds(3));
  waitForListening(port1, std::chrono::seconds(3));

  NodeTestAccess::postToP2P(*nodes_[0], [&]
                            { NodeTestAccess::p2p(*nodes_[0])->connectTo("127.0.0.1", port1); });

  bool e0 = waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5));

  // Give sync a moment to do nothing (it shouldn't).
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  EXPECT_TRUE(e0);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 0u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 0u);
  EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

  nodes_[0]->stop();
  nodes_[1]->stop();
  t0.join();
  t1.join();
}

// ============================================================================
//  best_peer_height tracking
// ============================================================================

TEST_F(Node_EndToEndFixture, BestPeerHeightUpdatedOnEstablish)
{
  setValidatorCount(2);
  makeExtraNodes(2);
  buildGenesis();
  buildEnv();

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  // Node 1 with 3 blocks pre-applied.
  const Crypto::KeyPair seed1 = keys_.at(0).reward_kp;
  const Crypto::KeyPair seed2 = keys_.at(1).reward_kp;

  Node::NodeConfig cfg1_headless = makeNonValidatorConfig(1);
  cfg1_headless.enable_p2p = false;
  {
    Node::Node n1(cfg1_headless, logger_);
    n1.start();
    waitForGenesis(n1);
    for (uint64_t h = 1; h <= 3; ++h)
    {
      Core::Block b = buildAndSignBlock(n1, genesis_, seed1, seed2, h);
      std::string error;
      ASSERT_TRUE(NodeTestAccess::applyBlock(n1, b, error)) << error;
    }
    n1.stop();
  }

  nodes_.clear();
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(0, port0), logger_));
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(1, port1), logger_));

  nodes_[0]->start();
  nodes_[1]->start();
  waitForGenesis(*nodes_[0]);
  waitForGenesis(*nodes_[1]);

  std::thread t0([&]
                 { nodes_[0]->run(); });
  std::thread t1([&]
                 { nodes_[1]->run(); });

  waitForListening(port0, std::chrono::seconds(3));
  waitForListening(port1, std::chrono::seconds(3));

  NodeTestAccess::postToP2P(*nodes_[0], [&]
                            { NodeTestAccess::p2p(*nodes_[0])->connectTo("127.0.0.1", port1); });

  // Wait for node 0 to know about node 1's height.
  bool saw_best = waitFor([&]
                          { return NodeTestAccess::chain(*nodes_[0]).bestPeerHeight() >= 3; },
                          std::chrono::seconds(5));

  EXPECT_TRUE(saw_best) << "node0 never learned node1's best height";
  EXPECT_GE(NodeTestAccess::chain(*nodes_[0]).bestPeerHeight(), 3u);

  nodes_[0]->stop();
  nodes_[1]->stop();
  t0.join();
  t1.join();
}

// ============================================================================
//  A caught-up node learns about new blocks via periodic refresh
// ============================================================================

TEST_F(Node_EndToEndFixture, IdleNodeDiscoversNewBlocksViaRefresh)
{
  // Node 0 and node 1 both start at height 0 and connect. Node 0
  // reaches Idle (caught up). Then node 1 commits a block directly
  // (simulating a validator that produced block 1 while node 0 was
  // already caught up). Node 0 should discover the new block via
  // the periodic SyncManager::tick() refresh and catch up — WITHOUT
  // any Block message being relayed (we're bypassing broadcastBlock
  // by applying the block directly on node 1).
  //
  //  Both nodes are non-validators. If they were validators,
  //  connecting them would start live consensus and they would
  //  commit blocks before the test could observe the "idle" state.
  //  The sync-manager refresh path is independent of consensus.

  setValidatorCount(2);
  makeExtraNodes(2);
  buildGenesis();
  buildEnv();

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  const Crypto::KeyPair seed1 = keys_.at(0).reward_kp;
  const Crypto::KeyPair seed2 = keys_.at(1).reward_kp;

  nodes_.clear();
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(0, port0), logger_));
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(1, port1), logger_));

  nodes_[0]->start();
  nodes_[1]->start();
  waitForGenesis(*nodes_[0]);
  waitForGenesis(*nodes_[1]);

  std::thread t0([&]
                 { nodes_[0]->run(); });
  std::thread t1([&]
                 { nodes_[1]->run(); });

  ASSERT_TRUE(waitForListening(port0, std::chrono::seconds(3)));
  ASSERT_TRUE(waitForListening(port1, std::chrono::seconds(3)));

  NodeTestAccess::postToP2P(*nodes_[0], [&]
                            { NodeTestAccess::p2p(*nodes_[0])->connectTo("127.0.0.1", port1); });

  ASSERT_TRUE(waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5)));
  ASSERT_TRUE(waitForEstablished(*nodes_[1], 1, std::chrono::seconds(5)));

  // Both at height 0. Give sync a moment to reach Idle.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 0u);
  ASSERT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 0u);

  // Shorten the refresh interval on node 0 so the test doesn't take
  // 30 seconds. 500ms is plenty.
  NodeTestAccess::setSyncRefreshIntervalForTest(
      *nodes_[0], std::chrono::milliseconds(500));

  // Apply a block on node 1 only. No broadcast — we're simulating a
  // peer that advanced but hasn't told us yet. The sync manager on
  // node 0 must discover this on its own.
  //
  //  Node 1 is a non-validator, but applyCommittedBlock works
  //  regardless of validator status. It's the same code path a node
  //  uses when it receives a block from a peer.
  {
    Core::Block b = buildAndSignBlock(*nodes_[1], genesis_, seed1, seed2, 1);
    std::string error;
    ASSERT_TRUE(NodeTestAccess::applyBlock(*nodes_[1], b, error))
        << "applyBlock on node 1: " << error;
    EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 1u);
  }

  // Node 0 should discover block 1 within a couple of refresh cycles.
  bool caught_up = waitForHeight(*nodes_[0], 1, std::chrono::seconds(5));
  if (!caught_up)
    dumpNodeState("node0", *nodes_[0]);

  EXPECT_TRUE(caught_up)
      << "node0 did not discover the new block via periodic refresh";

  if (caught_up)
  {
    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());
    auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
    auto h1 = NodeTestAccess::chainDb(*nodes_[1]).getHashByHeight(1);
    ASSERT_TRUE(h0.has_value());
    ASSERT_TRUE(h1.has_value());
    EXPECT_EQ(*h0, *h1);
  }

  nodes_[0]->stop();
  nodes_[1]->stop();
  t0.join();
  t1.join();
}