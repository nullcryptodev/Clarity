// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <future>
#include <iostream>
#include <memory>
#include <queue>
#include <thread>

#include <boost/asio.hpp>

#include "Tests/Fixtures.h"
#include "Tests/Utils.h"
#include "Node/Node.h"

#include "Consensus/BftConsensus.h"
#include "Consensus/Message.h"
#include "Consensus/Types.h"
#include "Core/Block.h"
#include "Core/BlockProcessor.h"
#include "Core/ChainDB.h"
#include "Core/Genesis.h"
#include "Core/Mempool.h"
#include "Core/Transaction.h"
#include "Core/TransactionTypes.h"
#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"
#include "P2P/P2PManager.h"
#include "State/StateAccess.h"

using namespace Tests;

// In-process consensus tests

TEST_F(NodeEndToEndFixture, TwoNodesCommitOneBlock)
{
  makeValidators(2);
  startNodes();

  ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 0u);
  ASSERT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 0u);

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 1u);

  if (NodeTestAccess::chain(*nodes_[0]).height() == 1u &&
      NodeTestAccess::chain(*nodes_[1]).height() == 1u)
  {
    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());
    auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
    auto h1 = NodeTestAccess::chainDb(*nodes_[1]).getHashByHeight(1);
    ASSERT_TRUE(h0.has_value());
    ASSERT_TRUE(h1.has_value());
    EXPECT_EQ(*h0, *h1);
  }

  stopNodes();
}

TEST_F(NodeEndToEndFixture, RestartPreservesChainAfterBlock)
{
  makeValidators(2);

  Crypto::Hash root_after_block;
  Crypto::Hash block_hash;

  {
    startNodes();
    startAllConsensus(1);
    deliverAll();
    advanceTimers();

    ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
    root_after_block = nodes_[0]->stateRoot();
    auto h = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
    ASSERT_TRUE(h.has_value());
    block_hash = *h;

    stopNodes();
  }

  startNodes();

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_EQ(nodes_[0]->stateRoot(), root_after_block);

  auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
  ASSERT_TRUE(h0.has_value());
  EXPECT_EQ(*h0, block_hash);

  stopNodes();
}

TEST_F(NodeEndToEndFixture, FourValidatorsOneOfflineReachesQuorum)
{
  makeValidators(4);
  startNodes();
  setOffline(3, true);

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 1u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[2]).height(), 1u);
  EXPECT_EQ(NodeTestAccess::chain(*nodes_[3]).height(), 0u);

  EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());
  EXPECT_EQ(nodes_[1]->stateRoot(), nodes_[2]->stateRoot());

  auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
  auto h1 = NodeTestAccess::chainDb(*nodes_[1]).getHashByHeight(1);
  auto h2 = NodeTestAccess::chainDb(*nodes_[2]).getHashByHeight(1);
  ASSERT_TRUE(h0.has_value());
  ASSERT_TRUE(h1.has_value());
  ASSERT_TRUE(h2.has_value());
  EXPECT_EQ(*h0, *h1);
  EXPECT_EQ(*h1, *h2);

  auto block = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(1);
  ASSERT_TRUE(block.has_value());
  EXPECT_EQ(block->participants.size(), 4u);
  EXPECT_EQ(block->quorum_signatures.size(), 3u);

  stopNodes();
}

TEST_F(NodeEndToEndFixture, FourValidatorsTwoOfflineNoCommit)
{
  makeValidators(4);
  startNodes();
  setOffline(2, true);
  setOffline(3, true);

  startAllConsensus(1);
  deliverAll();

  for (int i = 0; i < 5; ++i)
    advanceTimers();

  for (size_t i = 0; i < 4; ++i)
  {
    EXPECT_EQ(NodeTestAccess::chain(*nodes_[i]).height(), 0u)
        << "node " << i << " committed without quorum";
  }

  stopNodes();
}

// Mempool-to-block tests

TEST_F(NodeEndToEndFixture, SubmittedTransactionLandsInBlock)
{
  makeValidators(2);
  startNodes();

  const Crypto::KeyPair alice = aliceKey();
  const Crypto::KeyPair bob = bobKey();
  const Crypto::Address alice_addr = addressOf(alice);
  const Crypto::Address bob_addr = addressOf(bob);

  const uint64_t alice_balance_before = balanceOf(*nodes_[0], alice_addr);
  const uint64_t bob_balance_before = balanceOf(*nodes_[0], bob_addr);

  ASSERT_GT(alice_balance_before, 0u) << "alice should be funded in genesis";

  Core::Transaction tx = makeSignedTransfer(
      alice, bob_addr, /*amount=*/100, /*fee=*/500, /*nonce=*/0);

  std::string error;
  ASSERT_TRUE(nodes_[0]->submitTransaction(tx, error)) << error;

  ASSERT_EQ(NodeTestAccess::mempool(*nodes_[0]).size(), 1u);

  ASSERT_TRUE(nodes_[1]->submitTransaction(tx, error)) << error;

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  ASSERT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 1u);

  auto block0 = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(1);
  auto block1 = NodeTestAccess::chainDb(*nodes_[1]).getBlockByHeight(1);
  ASSERT_TRUE(block0.has_value());
  ASSERT_TRUE(block1.has_value());
  EXPECT_EQ(block0->transactions.size(), 1u);
  EXPECT_EQ(block1->transactions.size(), 1u);
  EXPECT_EQ(block0->transactions[0].txid(), tx.txid());
  EXPECT_EQ(block1->transactions[0].txid(), tx.txid());

  const uint64_t alice_balance_after = balanceOf(*nodes_[0], alice_addr);
  const uint64_t bob_balance_after = balanceOf(*nodes_[0], bob_addr);

  EXPECT_EQ(alice_balance_after, alice_balance_before - 100 - 500);
  EXPECT_EQ(bob_balance_after, bob_balance_before + 100);

  EXPECT_EQ(nonceOf(*nodes_[0], alice_addr), 1u);

  EXPECT_EQ(NodeTestAccess::mempool(*nodes_[0]).size(), 0u);
  EXPECT_EQ(NodeTestAccess::mempool(*nodes_[1]).size(), 0u);

  stopNodes();
}

TEST_F(NodeEndToEndFixture, CommittedTransactionNotReincluded)
{
  makeValidators(2);
  startNodes();

  const Crypto::KeyPair alice = aliceKey();
  const Crypto::KeyPair bob = bobKey();

  Core::Transaction tx = makeSignedTransfer(
      alice, addressOf(bob), /*amount=*/100, /*fee=*/500, /*nonce=*/0);

  std::string error;
  ASSERT_TRUE(nodes_[0]->submitTransaction(tx, error)) << error;
  ASSERT_TRUE(nodes_[1]->submitTransaction(tx, error)) << error;

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  auto block1 = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(1);
  ASSERT_TRUE(block1.has_value());
  ASSERT_EQ(block1->transactions.size(), 1u);

  ASSERT_EQ(NodeTestAccess::mempool(*nodes_[0]).size(), 0u);
  ASSERT_EQ(NodeTestAccess::mempool(*nodes_[1]).size(), 0u);

  bool resubmitted = nodes_[0]->submitTransaction(tx, error);
  EXPECT_FALSE(resubmitted) << "nonce-reused tx should be rejected";
  EXPECT_FALSE(error.empty());

  stopNodes();
}

// StateView lifetime

TEST_F(NodeEndToEndFixture, StateViewLifetimeIsIndependent)
{
  makeValidators(2);
  startNodes();

  const Crypto::Address alice_addr = addressOf(aliceKey());

  auto view1 = NodeTestAccess::makeStateView(*nodes_[0]);
  ASSERT_NE(view1, nullptr);
  const uint64_t balance1 = view1->getAccount(alice_addr).balance;
  EXPECT_GT(balance1, 0u);

  auto view2 = NodeTestAccess::makeStateView(*nodes_[0]);
  ASSERT_NE(view2, nullptr);
  const uint64_t balance2 = view2->getAccount(alice_addr).balance;
  EXPECT_EQ(balance2, balance1);

  const uint64_t balance1_again = view1->getAccount(alice_addr).balance;
  EXPECT_EQ(balance1_again, balance1);

  stopNodes();
}

// State and chain head atomicity

TEST_F(NodeEndToEndFixture, StateAndChainHeadAgreeAfterCommit)
{
  makeValidators(2);
  startNodes();

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);

  auto head = NodeTestAccess::chainDb(*nodes_[0]).getHead();
  auto block = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(1);
  ASSERT_TRUE(block.has_value());
  EXPECT_EQ(head.height, 1u);
  EXPECT_EQ(head.hash, block->hash());

  EXPECT_EQ(nodes_[0]->stateRoot(), block->header.state_root);

  auto head1 = NodeTestAccess::chainDb(*nodes_[1]).getHead();
  auto block1 = NodeTestAccess::chainDb(*nodes_[1]).getBlockByHeight(1);
  ASSERT_TRUE(block1.has_value());
  EXPECT_EQ(head1.hash, block1->hash());
  EXPECT_EQ(nodes_[1]->stateRoot(), block1->header.state_root);

  stopNodes();
  startNodes();

  auto head_after = NodeTestAccess::chainDb(*nodes_[0]).getHead();
  auto block_after = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(1);
  ASSERT_TRUE(block_after.has_value());
  EXPECT_EQ(head_after.hash, block_after->hash());
  EXPECT_EQ(nodes_[0]->stateRoot(), block_after->header.state_root);

  stopNodes();
}

// Consensus resume after restart

TEST_F(NodeEndToEndFixture, ConsensusResumesAfterRestart)
{
  makeValidators(2);

  Crypto::Hash block1_hash;
  Crypto::Hash root_after_block1;

  {
    startNodes();
    startAllConsensus(1);
    deliverAll();
    advanceTimers();

    ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
    ASSERT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 1u);

    auto b1 = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(1);
    ASSERT_TRUE(b1.has_value());
    block1_hash = b1->hash();
    root_after_block1 = nodes_[0]->stateRoot();

    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

    stopNodes();
  }

  {
    startNodes();

    ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
    ASSERT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 1u);
    EXPECT_EQ(nodes_[0]->stateRoot(), root_after_block1);
    EXPECT_EQ(nodes_[1]->stateRoot(), root_after_block1);

    startAllConsensus(2);
    deliverAll();
    advanceTimers();

    ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 2u);
    ASSERT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 2u);

    auto b2_0 = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(2);
    auto b2_1 = NodeTestAccess::chainDb(*nodes_[1]).getBlockByHeight(2);
    ASSERT_TRUE(b2_0.has_value());
    ASSERT_TRUE(b2_1.has_value());
    EXPECT_EQ(b2_0->hash(), b2_1->hash());
    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

    EXPECT_EQ(b2_0->header.parent_hash, block1_hash);
    EXPECT_EQ(nodes_[0]->stateRoot(), b2_0->header.state_root);

    stopNodes();
  }
}

// Crash injection

TEST_F(NodeEndToEndFixture, InjectionInsideTxnLeavesNothingPersisted)
{
  makeValidators(2);
  startNodes();

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  const Crypto::Hash root_after_block1 = nodes_[0]->stateRoot();
  const Crypto::Hash block1_hash =
      NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(1)->hash();

  nodes_[0]->setFailPointForTest(Node::Node::FailPoint::InsideTxn);

  Core::Block b2;
  b2.header.height = 2;
  b2.header.parent_hash = block1_hash;

  std::string error;
  bool ok = NodeTestAccess::applyBlock(*nodes_[0], b2, error);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(error.find("InsideTxn") != std::string::npos)
      << "unexpected error: " << error;

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_EQ(nodes_[0]->stateRoot(), root_after_block1);

  stopNodes();
  startNodes();

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_EQ(nodes_[0]->stateRoot(), root_after_block1);

  auto head = NodeTestAccess::chainDb(*nodes_[0]).getHead();
  EXPECT_EQ(head.height, 1u);
  EXPECT_EQ(head.hash, block1_hash);

  stopNodes();
}

// Real P2P consensus

TEST_F(NodeEndToEndFixture, ConsensusOverRealP2P)
{
  makeValidators(2);

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  nodes_.clear();
  consensuses_.clear();
  offline_.assign(2, false);

  nodes_.push_back(
      std::make_unique<Node::Node>(makeConfigWithP2P(0, port0), logger_));
  nodes_.push_back(
      std::make_unique<Node::Node>(makeConfigWithP2P(1, port1), logger_));

  nodes_[0]->start();
  nodes_[1]->start();

  std::thread t0([&]
                 { nodes_[0]->run(); });
  std::thread t1([&]
                 { nodes_[1]->run(); });

  bool ok = true;

  // Both nodes listening.
  bool l0 = waitForListening(port0, std::chrono::seconds(3));
  bool l1 = waitForListening(port1, std::chrono::seconds(3));
  EXPECT_TRUE(l0) << "node0 not listening on " << port0;
  EXPECT_TRUE(l1) << "node1 not listening on " << port1;
  ok = ok && l0 && l1;

  // Dial node0 -> node1.
  if (ok)
  {
    NodeTestAccess::postToP2P(*nodes_[0], [&]
                              { NodeTestAccess::p2p(*nodes_[0])
                                    ->connectTo("127.0.0.1", port1); });
  }

  // Wait for the handshake to reach Established on both sides.
  bool e0 = ok && waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5));
  bool e1 = ok && waitForEstablished(*nodes_[1], 1, std::chrono::seconds(5));
  EXPECT_TRUE(e0) << "node0 peer never reached Established";
  EXPECT_TRUE(e1) << "node1 peer never reached Established";
  ok = ok && e0 && e1;

  // Wait for consensus to start on both sides. Consensus is deferred
  // until the node has enough peers to form a quorum; for a two-node
  // network with bftQuorum(2) = 2, one peer suffices.
  bool s0 = ok && waitForConsensusStarted(*nodes_[0], std::chrono::seconds(3));
  bool s1 = ok && waitForConsensusStarted(*nodes_[1], std::chrono::seconds(3));
  EXPECT_TRUE(s0) << "node0 did not start consensus";
  EXPECT_TRUE(s1) << "node1 did not start consensus";
  ok = ok && s0 && s1;

  // Wait for a consensus round to commit block 1.
  bool c0 = ok && waitForHeight(*nodes_[0], 1, std::chrono::seconds(15));
  if (!c0)
  {
    dumpNodeState("node0", *nodes_[0]);
    dumpNodeState("node1", *nodes_[1]);
  }
  EXPECT_TRUE(c0) << "node0 did not commit block 1";
  ok = ok && c0;

  bool c1 = ok && waitForHeight(*nodes_[1], 1, std::chrono::seconds(15));
  if (!c1)
  {
    dumpNodeState("node0", *nodes_[0]);
    dumpNodeState("node1", *nodes_[1]);
  }
  EXPECT_TRUE(c1) << "node1 did not commit block 1";
  ok = ok && c1;

  // If both committed, verify agreement.
  if (ok)
  {
    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

    auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
    auto h1 = NodeTestAccess::chainDb(*nodes_[1]).getHashByHeight(1);
    ASSERT_TRUE(h0.has_value());
    ASSERT_TRUE(h1.has_value());
    EXPECT_EQ(*h0, *h1);
  }

  // Shutdown always runs.
  nodes_[0]->stop();
  nodes_[1]->stop();
  t0.join();
  t1.join();
}