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

#include "Core/Mempool.h"
#include "Core/Transaction.h"
#include "Crypto/Ed25519.h"
#include "P2P/P2PManager.h"

using namespace Tests;

// ============================================================================
//  Local submission propagates to connected peers
// ============================================================================

TEST_F(Node_EndToEndFixture, SubmittedTxPropagatesToPeers)
{
  // Two validators with P2P enabled. Submit a tx on node 0; node 1
  // should receive it via broadcast and add it to its mempool.
  //
  // We do NOT start consensus — the mempool is orthogonal to block
  // production, and this test is only about the relay path.

  makeValidators(2);

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  nodes_.clear();
  consensuses_.clear();
  offline_.assign(2, false);

  nodes_.push_back(std::make_unique<Node::Node>(
      makeConfigWithP2P(0, port0), logger_));
  nodes_.push_back(std::make_unique<Node::Node>(
      makeConfigWithP2P(1, port1), logger_));

  nodes_[0]->start();
  nodes_[1]->start();

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

  makeValidators(2);

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  nodes_.clear();
  consensuses_.clear();
  offline_.assign(2, false);

  nodes_.push_back(std::make_unique<Node::Node>(
      makeConfigWithP2P(0, port0), logger_));
  nodes_.push_back(std::make_unique<Node::Node>(
      makeConfigWithP2P(1, port1), logger_));

  nodes_[0]->start();
  nodes_[1]->start();

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