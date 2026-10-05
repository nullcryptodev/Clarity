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

#include "Fixtures.h"
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

// ============================================================================
//  In-process consensus
// ============================================================================

TEST_F(Node_EndToEndFixture, TwoNodesCommitOneBlock)
{
  setValidatorCount(2);
  startNodes();

  ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), 0u);
  ASSERT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), 0u);

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  const Height h0 = NodeTestAccess::chain(*nodes_[0]).height();
  const Height h1 = NodeTestAccess::chain(*nodes_[1]).height();
  EXPECT_GE(h0, 1u);
  EXPECT_GE(h1, 1u);
  EXPECT_EQ(h0, h1);

  if (h0 >= 1u && h1 >= 1u)
  {
    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

    for (Height h = 1; h <= h0; ++h)
    {
      auto hh0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(h);
      auto hh1 = NodeTestAccess::chainDb(*nodes_[1]).getHashByHeight(h);
      ASSERT_TRUE(hh0.has_value());
      ASSERT_TRUE(hh1.has_value());
      EXPECT_EQ(*hh0, *hh1) << "block hash mismatch at height " << h;
    }
  }

  stopNodes();
}

TEST_F(Node_EndToEndFixture, RestartPreservesChainAfterBlock)
{
  setValidatorCount(2);

  Crypto::Hash root_after_block;
  Crypto::Hash block1_hash;
  Height committed_height = 0;

  {
    startNodes();
    startAllConsensus(1);
    deliverAll();
    advanceTimers();

    committed_height = NodeTestAccess::chain(*nodes_[0]).height();
    ASSERT_GE(committed_height, 1u);
    root_after_block = nodes_[0]->stateRoot();
    auto h = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
    ASSERT_TRUE(h.has_value());
    block1_hash = *h;

    stopNodes();
  }

  startNodes();

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), committed_height);
  EXPECT_EQ(nodes_[0]->stateRoot(), root_after_block);

  auto h0 = NodeTestAccess::chainDb(*nodes_[0]).getHashByHeight(1);
  ASSERT_TRUE(h0.has_value());
  EXPECT_EQ(*h0, block1_hash);

  stopNodes();
}

TEST_F(Node_EndToEndFixture, FourValidatorsOneOfflineReachesQuorum)
{
  setValidatorCount(4);
  startNodes();
  setOffline(3, true);

  startAllConsensus(1);

  for (int i = 0;
       i < 10 && NodeTestAccess::chain(*nodes_[0]).height() < 1;
       ++i)
  {
    deliverAll();
    advanceTimers();
  }

  EXPECT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_GE(NodeTestAccess::chain(*nodes_[1]).height(), 1u);
  EXPECT_GE(NodeTestAccess::chain(*nodes_[2]).height(), 1u);
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

TEST_F(Node_EndToEndFixture, FourValidatorsTwoOfflineNoCommit)
{
  setValidatorCount(4);
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

// ============================================================================
//  Mempool-to-block
// ============================================================================

TEST_F(Node_EndToEndFixture, SubmittedTransactionLandsInBlock)
{
  setValidatorCount(2);
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
  ASSERT_EQ(nodes_[0]->submitTransaction(tx, error),
            Core::MempoolAddResult::Accepted)
      << error;

  ASSERT_EQ(NodeTestAccess::mempool(*nodes_[0]).size(), 1u);

  ASSERT_EQ(nodes_[1]->submitTransaction(tx, error),
            Core::MempoolAddResult::Accepted)
      << error;

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  ASSERT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(),
            NodeTestAccess::chain(*nodes_[1]).height());

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

TEST_F(Node_EndToEndFixture, CommittedTransactionNotReincluded)
{
  setValidatorCount(2);
  startNodes();

  const Crypto::KeyPair alice = aliceKey();
  const Crypto::KeyPair bob = bobKey();

  Core::Transaction tx = makeSignedTransfer(
      alice, addressOf(bob), /*amount=*/100, /*fee=*/500, /*nonce=*/0);

  std::string error;
  ASSERT_EQ(nodes_[0]->submitTransaction(tx, error),
            Core::MempoolAddResult::Accepted)
      << error;
  ASSERT_EQ(nodes_[1]->submitTransaction(tx, error),
            Core::MempoolAddResult::Accepted)
      << error;

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  ASSERT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  auto block1 = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(1);
  ASSERT_TRUE(block1.has_value());
  ASSERT_EQ(block1->transactions.size(), 1u);

  ASSERT_EQ(NodeTestAccess::mempool(*nodes_[0]).size(), 0u);
  ASSERT_EQ(NodeTestAccess::mempool(*nodes_[1]).size(), 0u);

  Core::MempoolAddResult resubmitted =
      nodes_[0]->submitTransaction(tx, error);
  EXPECT_EQ(resubmitted, Core::MempoolAddResult::Rejected_NonceTooLow)
      << "expected NonceTooLow, got " << Core::mempoolAddResultName(resubmitted);
  EXPECT_FALSE(error.empty());

  stopNodes();
}

// ============================================================================
//  StateView lifetime
// ============================================================================

TEST_F(Node_EndToEndFixture, StateViewLifetimeIsIndependent)
{
  setValidatorCount(2);
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

// ============================================================================
//  State and chain head atomicity
// ============================================================================

TEST_F(Node_EndToEndFixture, StateAndChainHeadAgreeAfterCommit)
{
  setValidatorCount(2);
  startNodes();

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  ASSERT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);

  //  Compare the head against the block at the *current* height, not
  //  a hardcoded height. The harness may commit more than one block
  //  per advanceTimers() call.
  auto head = NodeTestAccess::chainDb(*nodes_[0]).getHead();
  auto block = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(head.height);
  ASSERT_TRUE(block.has_value());
  EXPECT_EQ(head.height, NodeTestAccess::chain(*nodes_[0]).height());
  EXPECT_EQ(head.hash, block->hash());
  EXPECT_EQ(nodes_[0]->stateRoot(), block->header.state_root);

  auto head1 = NodeTestAccess::chainDb(*nodes_[1]).getHead();
  auto block1 = NodeTestAccess::chainDb(*nodes_[1]).getBlockByHeight(head1.height);
  ASSERT_TRUE(block1.has_value());
  EXPECT_EQ(head1.hash, block1->hash());
  EXPECT_EQ(nodes_[1]->stateRoot(), block1->header.state_root);

  stopNodes();
  startNodes();

  auto head_after = NodeTestAccess::chainDb(*nodes_[0]).getHead();
  auto block_after =
      NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(head_after.height);
  ASSERT_TRUE(block_after.has_value());
  EXPECT_EQ(head_after.hash, block_after->hash());
  EXPECT_EQ(nodes_[0]->stateRoot(), block_after->header.state_root);

  stopNodes();
}

// ============================================================================
//  Consensus resume after restart
// ============================================================================

TEST_F(Node_EndToEndFixture, ConsensusResumesAfterRestart)
{
  setValidatorCount(2);

  Crypto::Hash root_after_block1;
  Height committed_height = 0;

  {
    startNodes();
    startAllConsensus(1);
    deliverAll();
    advanceTimers();

    committed_height = NodeTestAccess::chain(*nodes_[0]).height();
    ASSERT_GE(committed_height, 1u);
    ASSERT_EQ(NodeTestAccess::chain(*nodes_[0]).height(),
              NodeTestAccess::chain(*nodes_[1]).height());

    root_after_block1 = nodes_[0]->stateRoot();
    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

    stopNodes();
  }

  {
    startNodes();

    EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), committed_height);
    EXPECT_EQ(NodeTestAccess::chain(*nodes_[1]).height(), committed_height);
    EXPECT_EQ(nodes_[0]->stateRoot(), root_after_block1);
    EXPECT_EQ(nodes_[1]->stateRoot(), root_after_block1);

    startAllConsensus(committed_height + 1);
    deliverAll();
    advanceTimers();

    const Height next_height = NodeTestAccess::chain(*nodes_[0]).height();
    EXPECT_GT(next_height, committed_height);
    EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(),
              NodeTestAccess::chain(*nodes_[1]).height());

    //  Fetch the newest block by its current height, not by
    //  committed_height + 1. The chain may have advanced past that.
    auto b_new = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(NodeTestAccess::chain(*nodes_[0]).height());
    ASSERT_TRUE(b_new.has_value());

    auto b_prev = NodeTestAccess::chainDb(*nodes_[0]).getBlockByHeight(b_new->header.height - 1);
    ASSERT_TRUE(b_prev.has_value());
    EXPECT_EQ(b_new->header.parent_hash, b_prev->hash());
    EXPECT_EQ(nodes_[0]->stateRoot(), b_new->header.state_root);

    auto b_new_peer = NodeTestAccess::chainDb(*nodes_[1]).getBlockByHeight(b_new->header.height);
    ASSERT_TRUE(b_new_peer.has_value());
    EXPECT_EQ(b_new->hash(), b_new_peer->hash());
    EXPECT_EQ(nodes_[0]->stateRoot(), nodes_[1]->stateRoot());

    stopNodes();
  }
}

// ============================================================================
//  Crash injection
// ============================================================================

TEST_F(Node_EndToEndFixture, InjectionInsideTxnLeavesNothingPersisted)
{
  setValidatorCount(2);
  startNodes();

  startAllConsensus(1);
  deliverAll();
  advanceTimers();

  ASSERT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  const Height committed_height = NodeTestAccess::chain(*nodes_[0]).height();
  const Crypto::Hash root_at_checkpoint = nodes_[0]->stateRoot();
  const Crypto::Hash head_hash_at_checkpoint =
      NodeTestAccess::chainDb(*nodes_[0]).getHead().hash;

  nodes_[0]->setFailPointForTest(Node::Node::FailPoint::InsideTxn);

  Core::Block b_next;
  b_next.header.height = committed_height + 1;
  b_next.header.parent_hash = head_hash_at_checkpoint;

  std::string error;
  bool ok = NodeTestAccess::applyBlock(*nodes_[0], b_next, error);
  EXPECT_FALSE(ok);
  EXPECT_TRUE(error.find("InsideTxn") != std::string::npos)
      << "unexpected error: " << error;

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), committed_height);
  EXPECT_EQ(nodes_[0]->stateRoot(), root_at_checkpoint);

  stopNodes();
  startNodes();

  EXPECT_EQ(NodeTestAccess::chain(*nodes_[0]).height(), committed_height);
  EXPECT_EQ(nodes_[0]->stateRoot(), root_at_checkpoint);

  auto head = NodeTestAccess::chainDb(*nodes_[0]).getHead();
  EXPECT_EQ(head.height, committed_height);
  EXPECT_EQ(head.hash, head_hash_at_checkpoint);

  stopNodes();
}

// ============================================================================
//  Real P2P consensus
// ============================================================================

TEST_F(Node_EndToEndFixture, ConsensusOverRealP2P)
{
  setValidatorCount(2);

  const uint16_t port0 = pickFreePort();
  const uint16_t port1 = pickFreePort();

  makeExtraNodes(2);

  //  This test drives real Node instances with their own consensus
  //  engines. It bypasses startNodes() because it needs P2P-enabled
  //  configs, and it builds the genesis explicitly.
  std::vector<Crypto::KeyPair> keys;
  for (size_t i = 0; i < 2; ++i)
    keys.push_back(deterministicValidatorKey(i + 1));

  genesis_ = makeGenesis(keys);

  env_.makeValidators(2);
  env_.setChainId(genesis_.chain_id);
  env_.setNowMs(1'700'000'000'000ULL);
  env_.setCurrentHeight(0);

  nodes_.clear();
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

  bool l0 = waitForListening(port0, std::chrono::seconds(3));
  bool l1 = waitForListening(port1, std::chrono::seconds(3));
  EXPECT_TRUE(l0) << "node0 not listening on " << port0;
  EXPECT_TRUE(l1) << "node1 not listening on " << port1;
  ok = ok && l0 && l1;

  if (ok)
  {
    NodeTestAccess::postToP2P(*nodes_[0], [&]
                              { NodeTestAccess::p2p(*nodes_[0])->connectTo("127.0.0.1", port1); });
  }

  bool e0 = ok && waitForEstablished(*nodes_[0], 1, std::chrono::seconds(5));
  bool e1 = ok && waitForEstablished(*nodes_[1], 1, std::chrono::seconds(5));
  EXPECT_TRUE(e0) << "node0 peer never reached Established";
  EXPECT_TRUE(e1) << "node1 peer never reached Established";
  ok = ok && e0 && e1;

  bool s0 = ok && waitForConsensusStarted(*nodes_[0], std::chrono::seconds(3));
  bool s1 = ok && waitForConsensusStarted(*nodes_[1], std::chrono::seconds(3));
  EXPECT_TRUE(s0) << "node0 did not start consensus";
  EXPECT_TRUE(s1) << "node1 did not start consensus";
  ok = ok && s0 && s1;

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

  if (ok)
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

TEST_F(Node_EndToEndFixture, ChainRecoversFromLostQuorum)
{
  setValidatorCount(6);
  setActiveCount(4);
  startNodes();

  setOffline(2, true);
  setOffline(3, true);

  startAllConsensus(1);

  //  EMERGENCY_ROTATION_ROUNDS is 30. The harness advances the round
  //  by one per advanceTimers() pass, so we need at least 30 passes
  //  to reach the threshold, plus extra to accumulate timeout votes,
  //  assemble a certificate, and propose on the emergency set.
  for (int i = 0;
       i < 200 && NodeTestAccess::chain(*nodes_[0]).height() < 1;
       ++i)
  {
    deliverAll();
    advanceTimers();
  }

  EXPECT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  EXPECT_GE(NodeTestAccess::chain(*nodes_[1]).height(), 1u);

  stopNodes();
}

// ============================================================================
//  Reward-address update preserves the consensus key
// ============================================================================

TEST_F(Node_EndToEndFixture, UpdateRewardAddressDoesNotRotateConsensusKey)
{
  //  Requires distinct reward and consensus keys per validator.
  setSplitKeys(true);
  setValidatorCount(2);
  startNodes();

  startAllConsensus(1);
  deliverAll();
  advanceTimers();
  ASSERT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  const Height h1 = NodeTestAccess::chain(*nodes_[0]).height();

  Core::ValidatorInfo before;
  {
    State::StateAccess state(NodeTestAccess::stateDb(*nodes_[0]), h1);
    ASSERT_TRUE(state.getValidator(1, before));
  }

  const Crypto::PublicKey consensus_before = before.effectiveConsensusKey();
  const Crypto::Address reward_before = before.reward_address;

  ASSERT_NE(consensus_before, reward_before)
      << "test requires a validator with split reward and consensus keys";

  //  In split-key mode, the reward key is
  //  deterministicValidatorKey(1); the consensus key is derived
  //  separately by the fixture. The update tx is signed by the
  //  reward key (the identity that appears in tx.from).
  //
  //  Redirect to alice, a non-validator. Redirecting to another
  //  validator's reward address (e.g. addressOf(deterministicValidatorKey(2)))
  //  collides with that validator's reward address and is correctly
  //  rejected by executeUpdateRewardAddress. The block containing the
  //  rejected update then fails applyBlock, simulateBlock returns
  //  nullopt, and the proposer bails — which is what
  //  RewardsRedirectAfterUpdateRewardAddress already documents.
  const Crypto::KeyPair seed1_reward_key = deterministicValidatorKey(1);
  const Crypto::Address new_reward = addressOf(aliceKey());

  const uint64_t nonce = nonceOf(*nodes_[0], reward_before);

  Core::Transaction tx;
  tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
  tx.chain_id = genesis_.chain_id;
  tx.tx_type = Core::TxType::UpdateRewardAddress;
  tx.nonce = nonce;
  tx.from = reward_before;
  tx.fee = 1'000;
  tx.payload.resize(32);
  std::memcpy(tx.payload.data(), new_reward.data.data(), 32);

  Crypto::Hash sighash = tx.txid();
  tx.signature = Crypto::sign(sighash, seed1_reward_key.secretKey);

  std::string error;
  ASSERT_EQ(nodes_[0]->submitTransaction(tx, error),
            Core::MempoolAddResult::Accepted)
      << error;
  ASSERT_EQ(nodes_[1]->submitTransaction(tx, error),
            Core::MempoolAddResult::Accepted)
      << error;

  startAllConsensus(h1 + 1);
  deliverAll();
  advanceTimers();
  ASSERT_GT(NodeTestAccess::chain(*nodes_[0]).height(), h1);
  const Height h2 = NodeTestAccess::chain(*nodes_[0]).height();

  Core::ValidatorInfo after;
  {
    State::StateAccess state(NodeTestAccess::stateDb(*nodes_[0]), h2);
    ASSERT_TRUE(state.getValidator(1, after));
  }

  EXPECT_EQ(after.reward_address, new_reward);
  EXPECT_EQ(after.effectiveConsensusKey(), consensus_before);
  EXPECT_EQ(after.consensus_key, consensus_before)
      << "consensus_key must be pinned to the old effective key";

  EXPECT_FALSE(after.consensus_key.isNull());

  uint64_t found_id = 0;
  {
    State::StateAccess state(NodeTestAccess::stateDb(*nodes_[0]), h2);
    EXPECT_TRUE(state.getValidatorByAddress(new_reward, found_id));
    EXPECT_EQ(found_id, 1u);
  }

  stopNodes();
}

// ============================================================================
//  Runtime registration pins the consensus key
// ============================================================================

TEST_F(Node_EndToEndFixture, RegisterValidatorSetsExplicitConsensusKey)
{
  setValidatorCount(2);
  startNodes();

  startAllConsensus(1);
  deliverAll();
  advanceTimers();
  ASSERT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  Height h = NodeTestAccess::chain(*nodes_[0]).height();

  const Crypto::KeyPair node3 = Crypto::generateKeyPair();
  const Crypto::Address node3_reward = addressOf(node3);

  //  A distinct consensus key. Registering with the reward key would
  //  make consensus_key == reward_address, which is exactly the case
  //  the test is trying to distinguish from.
  const Crypto::KeyPair node3_consensus = Crypto::generateKeyPair();
  const Crypto::PublicKey consensus_pub = node3_consensus.publicKey;

  const Crypto::KeyPair seed1 = deterministicValidatorKey(1);
  const Crypto::Address seed1_reward = addressOf(seed1);
  const uint64_t fund_amount =
      GlobalConfig::VALIDATOR_MIN_STAKE +
      GlobalConfig::ATOMIC_UNITS_PER_COIN;

  {
    const uint64_t nonce = nonceOf(*nodes_[0], seed1_reward);
    Core::Transaction fund = makeSignedTransfer(
        seed1, node3_reward, fund_amount, 1'000, nonce);
    std::string error;
    ASSERT_EQ(nodes_[0]->submitTransaction(fund, error),
              Core::MempoolAddResult::Accepted)
        << error;
    ASSERT_EQ(nodes_[1]->submitTransaction(fund, error),
              Core::MempoolAddResult::Accepted)
        << error;

    startAllConsensus(h + 1);
    deliverAll();
    advanceTimers();
    ASSERT_GT(NodeTestAccess::chain(*nodes_[0]).height(), h);
    h = NodeTestAccess::chain(*nodes_[0]).height();
  }

  {
    const uint64_t nonce = nonceOf(*nodes_[0], node3_reward);
    Core::Transaction reg;
    reg.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
    reg.chain_id = genesis_.chain_id;
    reg.tx_type = Core::TxType::RegisterValidator;
    reg.nonce = nonce;
    reg.from = node3_reward;
    reg.amount = GlobalConfig::VALIDATOR_MIN_STAKE;
    reg.fee = 1'000;
    reg.payload.resize(32);
    std::memcpy(reg.payload.data(), consensus_pub.data.data(), 32);

    Crypto::Hash sighash = reg.txid();
    reg.signature = Crypto::sign(sighash, node3.secretKey);

    std::string error;
    ASSERT_EQ(nodes_[0]->submitTransaction(reg, error),
              Core::MempoolAddResult::Accepted)
        << error;
    ASSERT_EQ(nodes_[1]->submitTransaction(reg, error),
              Core::MempoolAddResult::Accepted)
        << error;

    startAllConsensus(h + 1);
    deliverAll();
    advanceTimers();
    ASSERT_GT(NodeTestAccess::chain(*nodes_[0]).height(), h);
    h = NodeTestAccess::chain(*nodes_[0]).height();
  }

  uint64_t node3_id = 0;
  {
    State::StateAccess state(NodeTestAccess::stateDb(*nodes_[0]), h);
    ASSERT_TRUE(state.getValidatorByAddress(node3_reward, node3_id));
    ASSERT_GT(node3_id, 2u);
  }

  Core::ValidatorInfo v;
  {
    State::StateAccess state(NodeTestAccess::stateDb(*nodes_[0]), h);
    ASSERT_TRUE(state.getValidator(node3_id, v));
  }

  EXPECT_FALSE(v.consensus_key.isNull())
      << "executeRegisterValidator must set consensus_key explicitly";
  EXPECT_EQ(v.consensus_key, consensus_pub);
  EXPECT_EQ(v.effectiveConsensusKey(), consensus_pub);
  EXPECT_NE(v.effectiveConsensusKey(), v.reward_address)
      << "the two keys must be distinct for this test to be meaningful";

  std::vector<uint8_t> set_bytes;
  {
    State::StateAccess state(NodeTestAccess::stateDb(*nodes_[0]), h);
    ASSERT_TRUE(state.getGlobal("active_set", set_bytes));
  }
  size_t active_count = set_bytes.size() / 8;
  EXPECT_EQ(active_count, 2u)
      << "new validator should not be in the active set yet";

  stopNodes();
}

// ============================================================================
//  Reward redirect changes payout destination
// ============================================================================

TEST_F(Node_EndToEndFixture, RewardsRedirectAfterUpdateRewardAddress)
{
  setValidatorCount(2);
  startNodes();

  startAllConsensus(1);
  deliverAll();
  advanceTimers();
  ASSERT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  Height h = NodeTestAccess::chain(*nodes_[0]).height();

  const Crypto::KeyPair seed1_kp = deterministicValidatorKey(1);
  const Crypto::Address seed1_reward = addressOf(seed1_kp);

  //  Redirect to alice, a non-validator. Redirecting to seed2's
  //  address would collide with validator 2's reward address and be
  //  correctly rejected by executeUpdateRewardAddress.
  const Crypto::Address new_reward = addressOf(aliceKey());

  const uint64_t seed1_before = balanceOf(*nodes_[0], seed1_reward);
  const uint64_t new_reward_before = balanceOf(*nodes_[0], new_reward);

  {
    const uint64_t nonce = nonceOf(*nodes_[0], seed1_reward);

    Core::Transaction tx;
    tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
    tx.chain_id = genesis_.chain_id;
    tx.tx_type = Core::TxType::UpdateRewardAddress;
    tx.nonce = nonce;
    tx.from = seed1_reward;
    tx.fee = 1'000;
    tx.payload.resize(32);
    std::memcpy(tx.payload.data(), new_reward.data.data(), 32);

    Crypto::Hash sighash = tx.txid();
    tx.signature = Crypto::sign(sighash, seed1_kp.secretKey);

    std::string error;
    ASSERT_EQ(nodes_[0]->submitTransaction(tx, error),
              Core::MempoolAddResult::Accepted)
        << error;
    ASSERT_EQ(nodes_[1]->submitTransaction(tx, error),
              Core::MempoolAddResult::Accepted)
        << error;

    startAllConsensus(h + 1);
    deliverAll();
    advanceTimers();
    ASSERT_GT(NodeTestAccess::chain(*nodes_[0]).height(), h);
    h = NodeTestAccess::chain(*nodes_[0]).height();
  }

  const uint64_t seed1_after_update = balanceOf(*nodes_[0], seed1_reward);
  const uint64_t new_reward_after_update = balanceOf(*nodes_[0], new_reward);

  for (int i = 0; i < 5; ++i)
  {
    const Height next = NodeTestAccess::chain(*nodes_[0]).height() + 1;
    startAllConsensus(next);
    deliverAll();
    advanceTimers();
  }
  deliverAll();

  const uint64_t seed1_after = balanceOf(*nodes_[0], seed1_reward);
  const uint64_t new_reward_after = balanceOf(*nodes_[0], new_reward);

  const uint64_t seed1_growth = seed1_after - seed1_after_update;
  const uint64_t new_reward_growth = new_reward_after - new_reward_after_update;

  EXPECT_EQ(seed1_growth, 0u)
      << "seed1's balance should not grow after redirecting its reward";

  EXPECT_GT(new_reward_growth, 0u)
      << "new_reward should have accumulated rewards";

  stopNodes();
}

TEST_F(Node_EndToEndFixture, TempSplitKeySmoke)
{
  setSplitKeys(true);
  setValidatorCount(2);
  startNodes();
  startAllConsensus(1);
  deliverAll();
  advanceTimers();
  ASSERT_GE(NodeTestAccess::chain(*nodes_[0]).height(), 1u);
  stopNodes();
}