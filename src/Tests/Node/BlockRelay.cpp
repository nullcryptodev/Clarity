// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <chrono>
#include <iostream>
#include <thread>

#include "Fixtures.h"
#include "Tests/Utils.h"
#include "Node/Node.h"

#include "Core/BlockProcessor.h"
#include "Core/Chain.h"
#include "Core/Genesis.h"
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

  // Build a signed empty block at the given height, parented to the
  // node's current head. Kept local because these tests deliberately
  // bypass the consensus harness and drive block application directly.
  //
  //  The active set is read from state at genesis version (0) and
  //  mirrored into the header. BlockProcessor::applyBlock re-derives
  //  the same active set from the same state at validation time, and
  //  rejects the block if the header disagrees. Reading it here keeps
  //  the header consistent with what the validator will compute.
  Core::Block buildSignedBlock(Node::Node &node,
                               const Core::GenesisConfig &genesis,
                               const Crypto::KeyPair &seed1,
                               const Crypto::KeyPair &seed2,
                               uint64_t height)
  {
    auto &db = NodeTestAccess::stateDb(node);
    auto &chain_db = NodeTestAccess::chainDb(node);

    const auto head = chain_db.getHead();

    //  Read the active set from genesis state.
    std::vector<Id> active_set;
    {
      State::StateAccess state(db, /*version=*/0);
      std::vector<uint8_t> bytes;
      if (state.getGlobal("active_set", bytes))
      {
        for (size_t i = 0; i + 8 <= bytes.size(); i += 8)
        {
          uint64_t id = 0;
          for (int j = 0; j < 8; ++j)
            id |= uint64_t(bytes[i + j]) << (j * 8);
          active_set.push_back(id);
        }
      }
    }

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

    const Crypto::Hash signing_hash = Consensus::voteSigningHash(
        b.header.height, b.header.commit_round, false, b.hash());
    b.quorum_signatures.push_back({0, Crypto::sign(signing_hash, seed1.secretKey)});
    b.quorum_signatures.push_back({1, Crypto::sign(signing_hash, seed2.secretKey)});

    return b;
  }

  // Print the state of every node in the group when something fails.
  // Includes the Established peer count so we can tell "connected but
  // never authenticated" from "never connected".
  void dumpAll(const char *tag,
               const std::vector<std::unique_ptr<Node::Node>> &nodes)
  {
    for (size_t i = 0; i < nodes.size(); ++i)
    {
      if (!nodes[i])
        continue;

      const auto s = nodes[i]->status();
      size_t established = 0;
      if (NodeTestAccess::p2p(*nodes[i]))
        established = NodeTestAccess::p2pSnapshot(*nodes[i]).established;
    }
  }
} // anonymous namespace

// ============================================================================
//  Block relay: one validator, two non-validators
// ============================================================================
//
//  These tests deliberately do NOT start the consensus harness. They
//  exercise the P2P + applyBlock + broadcastBlock relay path in
//  isolation, so a consensus failure can't mask a relay failure.
//
//  Because we bypass startNodes(), we manage dirs_ and nodes_
//  ourselves. env_/harness_ are unused here.

TEST_F(Node_EndToEndFixture, RelayedBlockReachesNonValidatorPeers)
{
  // Node 0: validator 1, P2P enabled, the block producer.
  // Node 1: non-validator, P2P enabled, dials node 0.
  // Node 2: non-validator, P2P enabled, dials node 0.
  //
  // We build a block on node 0 and apply it via
  // NodeTestAccess::applyBlock, then invoke
  // NodeTestAccess::broadcastBlock explicitly. In production
  // broadcastBlock is called from onBlockCommitted, which only the
  // consensus engine reaches. Nodes 1 and 2 should receive the Block
  // message, apply it, and reach the same height and state root.

  setValidatorCount(2);
  makeExtraNodes(3); // dirs_[0..2] for the three nodes below
  buildGenesis();
  buildEnv();

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();
  const uint16_t port2 = pickFreePort();

  const Crypto::KeyPair seed1 = keys_.at(0).reward_kp;
  const Crypto::KeyPair seed2 = keys_.at(1).reward_kp;

  nodes_.clear();

  // Node 0: validator 1, P2P on. Uses dirs_[0].
  nodes_.push_back(std::make_unique<Node::Node>(
      makeConfigWithP2P(0, port0), logger_));

  // Node 1: non-validator, P2P on. Uses dirs_[1].
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(1, port1), logger_));

  // Node 2: non-validator, P2P on. Uses dirs_[2].
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(2, port2), logger_));

  for (auto &n : nodes_)
    n->start();

  for (auto &n : nodes_)
    waitForGenesis(*n);

  // RAII: joins on every exit path, including ASSERT_ failure below.
  NodeThreadGroup threads;
  threads.runAll(nodes_);

  const bool listening =
      waitForListening(port0, std::chrono::seconds(3)) &&
      waitForListening(port1, std::chrono::seconds(3)) &&
      waitForListening(port2, std::chrono::seconds(3));
  if (!listening)
    dumpAll("listening", nodes_);
  ASSERT_TRUE(listening) << "nodes not listening";

  // Nodes 1 and 2 dial node 0.
  NodeTestAccess::postToP2P(*nodes_[1], [&]
                            { NodeTestAccess::p2p(*nodes_[1])->connectTo("127.0.0.1", port0); });
  NodeTestAccess::postToP2P(*nodes_[2], [&]
                            { NodeTestAccess::p2p(*nodes_[2])->connectTo("127.0.0.1", port0); });

  // Wait for each side separately so a failure tells us which one.
  const bool e0 = waitForEstablished(*nodes_[0], 2, std::chrono::seconds(10));
  const bool e1 = e0 && waitForEstablished(*nodes_[1], 1, std::chrono::seconds(10));
  const bool e2 = e0 && waitForEstablished(*nodes_[2], 1, std::chrono::seconds(10));

  if (!e0 || !e1 || !e2)
    dumpAll("establish", nodes_);

  ASSERT_TRUE(e0) << "node0 did not see 2 Established peers";
  ASSERT_TRUE(e1) << "node1 did not see an Established peer";
  ASSERT_TRUE(e2) << "node2 did not see an Established peer";

  // Before the relay: everyone at height 0.
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 0u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 0u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[2]).height(), 0u);

  // Node 0 builds and applies block 1, then broadcasts it.
  {
    Core::Block b = buildSignedBlock(*nodes_[0], genesis_, seed1, seed2, 1);
    std::string error;
    ASSERT_TRUE(NodeTestAccess::applyBlock(*nodes_[0], b, error))
        << "applyBlock on node 0: " << error;
    EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);

    NodeTestAccess::broadcastBlock(*nodes_[0], b);
  }

  // Wait for both non-validators to reach height 1.
  const bool ok1 = waitForHeight(*nodes_[1], 1, std::chrono::seconds(5));
  const bool ok2 = waitForHeight(*nodes_[2], 1, std::chrono::seconds(5));

  if (!ok1 || !ok2)
    dumpAll("relay", nodes_);

  EXPECT_TRUE(ok1) << "node1 did not receive relayed block";
  EXPECT_TRUE(ok2) << "node2 did not receive relayed block";

  // Verify agreement.
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 1u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[2]).height(), 1u);

  EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());
  EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[2]->stateRoot());

  const auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
  const auto h1 = NodeTestAccess::chainDb(*nodes_[1]).getHashByHeight(1);
  const auto h2 = NodeTestAccess::chainDb(*nodes_[2]).getHashByHeight(1);
  ASSERT_TRUE(h0.has_value());
  ASSERT_TRUE(h1.has_value());
  ASSERT_TRUE(h2.has_value());
  EXPECT_EQ(*h0, *h1);
  EXPECT_EQ(*h0, *h2);

  threads.join();
}

// ============================================================================
//  Duplicate block does not loop
// ============================================================================

TEST_F(Node_EndToEndFixture, DuplicateRelayIsIdempotent)
{
  setValidatorCount(2);
  makeExtraNodes(2); // dirs_[0] for the validator, dirs_[1] for the peer
  buildGenesis();
  buildEnv();

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  const Crypto::KeyPair seed1 = keys_.at(0).reward_kp;
  const Crypto::KeyPair seed2 = keys_.at(1).reward_kp;

  nodes_.clear();

  // Node 0: validator, P2P on. Uses dirs_[0].
  nodes_.push_back(std::make_unique<Node::Node>(
      makeConfigWithP2P(0, port0), logger_));

  // Node 1: non-validator, P2P on. Uses dirs_[1].
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(1, port1), logger_));

  for (auto &n : nodes_)
    n->start();

  for (auto &n : nodes_)
    waitForGenesis(*n);

  NodeThreadGroup threads;
  threads.runAll(nodes_);

  const bool listening =
      waitForListening(port0, std::chrono::seconds(3)) &&
      waitForListening(port1, std::chrono::seconds(3));
  if (!listening)
    dumpAll("listening", nodes_);
  ASSERT_TRUE(listening) << "nodes not listening";

  NodeTestAccess::postToP2P(*nodes_[1], [&]
                            { NodeTestAccess::p2p(*nodes_[1])->connectTo("127.0.0.1", port0); });

  const bool e0 = waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5));
  const bool e1 = e0 && waitForEstablished(*nodes_[1], 1, std::chrono::seconds(5));

  if (!e0 || !e1)
    dumpAll("establish", nodes_);

  ASSERT_TRUE(e0) << "node0 did not see an Established peer";
  ASSERT_TRUE(e1) << "node1 did not see an Established peer";

  const Core::Block b = buildSignedBlock(*nodes_[0], genesis_, seed1, seed2, 1);

  std::string error;
  ASSERT_TRUE(NodeTestAccess::applyBlock(*nodes_[0], b, error));

  // Broadcast twice. The second is a no-op on the receiving side
  // because the block hash is already in the chain DB.
  NodeTestAccess::broadcastBlock(*nodes_[0], b);
  NodeTestAccess::broadcastBlock(*nodes_[0], b);

  const bool ok = waitForHeight(*nodes_[1], 1, std::chrono::seconds(5));
  if (!ok)
    dumpAll("relay", nodes_);
  ASSERT_TRUE(ok) << "node1 did not receive relayed block";

  // Give the network time to settle — if the duplicate were looping,
  // heights would keep climbing or the test would hang.
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 1u);
  EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

  threads.join();
}