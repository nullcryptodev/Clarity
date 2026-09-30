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
  // Build a signed empty block at the given height, parented to the
  // node's current head. Same shape as the helper in SyncEndToEnd.cpp.
  Core::Block buildSignedBlock(Node::Node &node,
                               const Core::GenesisConfig &genesis,
                               const Crypto::KeyPair &seed1,
                               const Crypto::KeyPair &seed2,
                               uint64_t height)
  {
    auto &db = NodeTestAccess::stateDb(node);
    auto &chain_db = NodeTestAccess::chainDb(node);

    auto head = chain_db.getHead();

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
    b.header.state_root = Crypto::Hash{};
    b.header.receipts_root = Crypto::Hash{};
    b.header.validator_set_root = Core::computeValidatorSetRoot({1, 2});
    b.header.active_validator_count = 2;
    b.header.tx_count = 0;
    b.header.total_fees = 0;
    b.participants = {1, 2};
    b.quorum_signatures.clear();

    {
      auto txn = db.beginWrite();
      State::StateAccess state(db, txn, height);
      Core::BlockContext ctx;
      ctx.chain_id = genesis.chain_id;
      ctx.current_height = height;
      ctx.dry_run = true;
      Core::BlockResult r = Core::BlockProcessor::applyBlock(state, b, ctx);
      txn.abort();
      if (r.valid)
        b.header.state_root = r.new_state_root;
    }

    Crypto::Hash signing_hash = Consensus::voteSigningHash(
        b.header.height, b.header.commit_round, false, b.hash());
    b.quorum_signatures.push_back({0, Crypto::sign(signing_hash, seed1.secretKey)});
    b.quorum_signatures.push_back({1, Crypto::sign(signing_hash, seed2.secretKey)});

    return b;
  }

  // Print the state of every node in the group when something fails.
  // Extends dumpNodeState with the established count so we can tell
  // "peer connected but never authenticated" from "peer never connected".
  void dumpAll(const char *tag,
               const std::vector<std::unique_ptr<Node::Node>> &nodes)
  {
    for (size_t i = 0; i < nodes.size(); ++i)
    {
      if (!nodes[i])
        continue;

      auto s = nodes[i]->status();
      size_t established = 0;
      if (NodeTestAccess::p2p(*nodes[i]))
      {
        established = NodeTestAccess::p2pSnapshot(*nodes[i]).established;
      }
    }
  }
} // anonymous namespace

// ============================================================================
//  Block relay: one validator, two non-validators
// ============================================================================

TEST_F(Node_EndToEndFixture, RelayedBlockReachesNonValidatorPeers)
{
  // Node 0: validator 1, P2P enabled, the block producer.
  // Node 1: non-validator, P2P enabled, dials node 0.
  // Node 2: non-validator, P2P enabled, dials node 0.
  //
  // We do not run consensus. Instead we build a block on node 0
  // and apply it directly via NodeTestAccess::applyBlock, which is
  // the same path consensus uses for the apply step. To exercise the
  // broadcast, we invoke NodeTestAccess::broadcastBlock explicitly —
  // in production this is called from onBlockCommitted, which only
  // the consensus engine reaches. Nodes 1 and 2 should receive the
  // Block message, apply it, and reach the same height and state root.

  makeValidators(2); // seeds 1 and 2; only used for block signing below
  makeExtraNodes(1); // one extra dir for the second non-validator

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();
  const uint16_t port2 = pickFreePort();

  const Crypto::KeyPair seed1 = deterministicValidatorKey(1);
  const Crypto::KeyPair seed2 = deterministicValidatorKey(2);

  nodes_.clear();
  consensuses_.clear();
  offline_.assign(3, false);

  // Node 0: validator 1, P2P on.
  nodes_.push_back(std::make_unique<Node::Node>(
      makeConfigWithP2P(0, port0), logger_));

  // Node 1: non-validator, P2P on. Uses dirs_[1] (the validator 2
  // dir, unused here since we don't start consensus).
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(1, port1), logger_));

  // Node 2: non-validator, P2P on. Uses dirs_[2], created by
  // makeExtraNodes(1).
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(2, port2), logger_));

  for (auto &n : nodes_)
    n->start();

  // RAII: joins on every exit path, including ASSERT_ failure below.
  NodeThreadGroup threads;
  threads.runAll(nodes_);

  bool listening =
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
  bool e0 = waitForEstablished(*nodes_[0], 2, std::chrono::seconds(10));
  bool e1 = e0 && waitForEstablished(*nodes_[1], 1, std::chrono::seconds(10));
  bool e2 = e0 && waitForEstablished(*nodes_[2], 1, std::chrono::seconds(10));

  if (!e0 || !e1 || !e2)
    dumpAll("establish", nodes_);

  ASSERT_TRUE(e0) << "node0 did not see 2 Established peers";
  ASSERT_TRUE(e1) << "node1 did not see an Established peer";
  ASSERT_TRUE(e2) << "node2 did not see an Established peer";

  // Before the relay: everyone at height 0.
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 0u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 0u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[2]).height(), 0u);

  // Node 0 builds and applies block 1, then broadcasts it. This
  // mirrors the production flow: consensus → applyCommittedBlock →
  // onBlockCommitted → broadcastBlock.
  {
    Core::Block b = buildSignedBlock(*nodes_[0], genesis_, seed1, seed2, 1);
    std::string error;
    ASSERT_TRUE(NodeTestAccess::applyBlock(*nodes_[0], b, error))
        << "applyBlock on node 0: " << error;
    EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);

    NodeTestAccess::broadcastBlock(*nodes_[0], b);
  }

  // Wait for both non-validators to reach height 1.
  bool ok1 = waitForHeight(*nodes_[1], 1, std::chrono::seconds(5));
  bool ok2 = waitForHeight(*nodes_[2], 1, std::chrono::seconds(5));

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

  auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
  auto h1 = NodeTestAccess::chainDb(*nodes_[1]).getHashByHeight(1);
  auto h2 = NodeTestAccess::chainDb(*nodes_[2]).getHashByHeight(1);
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
  makeValidators(2);
  makeExtraNodes(1); // dirs_[2] for the non-validator

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  const Crypto::KeyPair seed1 = deterministicValidatorKey(1);
  const Crypto::KeyPair seed2 = deterministicValidatorKey(2);

  nodes_.clear();
  consensuses_.clear();
  offline_.assign(2, false);

  // Node 0: validator, P2P on.
  nodes_.push_back(std::make_unique<Node::Node>(
      makeConfigWithP2P(0, port0), logger_));

  // Node 1: non-validator, P2P on.
  nodes_.push_back(std::make_unique<Node::Node>(
      makeNonValidatorConfigWithP2P(2, port1), logger_));

  for (auto &n : nodes_)
    n->start();

  NodeThreadGroup threads;
  threads.runAll(nodes_);

  bool listening =
      waitForListening(port0, std::chrono::seconds(3)) &&
      waitForListening(port1, std::chrono::seconds(3));
  if (!listening)
    dumpAll("listening", nodes_);
  ASSERT_TRUE(listening) << "nodes not listening";

  NodeTestAccess::postToP2P(*nodes_[1], [&]
                            { NodeTestAccess::p2p(*nodes_[1])->connectTo("127.0.0.1", port0); });

  bool e0 = waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5));
  bool e1 = e0 && waitForEstablished(*nodes_[1], 1, std::chrono::seconds(5));

  if (!e0 || !e1)
    dumpAll("establish", nodes_);

  ASSERT_TRUE(e0) << "node0 did not see an Established peer";
  ASSERT_TRUE(e1) << "node1 did not see an Established peer";

  Core::Block b = buildSignedBlock(*nodes_[0], genesis_, seed1, seed2, 1);

  std::string error;
  ASSERT_TRUE(NodeTestAccess::applyBlock(*nodes_[0], b, error));

  // Broadcast twice. The second is a no-op on the receiving side
  // because the block hash is already in the chain DB.
  NodeTestAccess::broadcastBlock(*nodes_[0], b);
  NodeTestAccess::broadcastBlock(*nodes_[0], b);

  bool ok = waitForHeight(*nodes_[1], 1, std::chrono::seconds(5));
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