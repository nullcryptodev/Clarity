#pragma once

#include "Tests/Utils.h"

namespace Tests
{

  // NodeTestAccess - Friend of Node. Provides static helpers that
  // reach into private members so tests can drive subsystem behavior directly.

  class NodeTestAccess
  {
  public:
    static Core::Chain &chain(Node::Node &n) { return *n.chain_; }
    static Core::ChainDB &chainDb(Node::Node &n) { return *n.chain_db_; }
    static Core::Mempool &mempool(Node::Node &n) { return *n.mempool_; }
    static State::StateDB &stateDb(Node::Node &n) { return *n.state_db_; }
    static Consensus::BftConsensus *consensus(Node::Node &n) { return n.consensus_.get(); }
    static P2P::P2PManager *p2p(Node::Node &n) { return n.p2p_.get(); }

    // True if consensus has been started on this node. Used by
    // tests that need to know when the node has enough peers to
    // proceed. For a validator node with P2P enabled, this flips
    // to true once enough peers connect.
    static bool consensusStarted(Node::Node &n)
    {
      return n.consensus_started_.load();
    }

    static void broadcastBlock(Node::Node &n, const Core::Block &b)
    {
      n.broadcastBlock(b);
    }

    static bool applyBlock(Node::Node &n, const Core::Block &b, std::string &error)
    {
      return n.applyCommittedBlock(b, error);
    }

    static void pollConsensus(Node::Node &n)
    {
      if (n.consensus_)
        n.consensus_->pollTimers();
    }

    static void expireConsensusTimer(Node::Node &n)
    {
      if (n.consensus_)
        n.consensus_->forceTimerExpiryForTest();
    }

    static void startConsensusAt(Node::Node &n, Height h)
    {
      if (n.consensus_)
        n.consensus_->start(h);
    }

    static std::vector<Core::Transaction> selectTransactionsForProposal(
        Node::Node &n, uint64_t max_bytes, uint64_t max_txs)
    {
      return n.selectTransactionsForProposal(max_bytes, max_txs);
    }

    static std::unique_ptr<Core::StateView> makeStateView(Node::Node &n)
    {
      return n.makeStateView();
    }

    // Post a callable to the node's P2P io_context. Used by tests
    // that need to run P2P-manager methods on the event loop thread.
    template <typename F>
    static void postToP2P(Node::Node &n, F &&f)
    {
      if (n.p2p_)
        n.p2p_->post(std::forward<F>(f));
    }

    // Set the refresh interval for every SyncManager on the node.
    // Must be called on the io_context thread (it touches
    // sync_managers_, which is io_context-thread-only). Tests that
    // want to exercise the Idle refresh path use this to shorten the
    // 30-second default.
    static void setSyncRefreshIntervalForTest(Node::Node &n,
                                              std::chrono::milliseconds ms)
    {
      n.post([&n, ms]
             {
               for (auto &[id, mgr] : n.sync_managers_)
               {
                 if (mgr)
                   mgr->setRefreshInterval(ms);
               } });
    }

    // Snapshot the P2P manager's state. Returns a default-constructed
    // snapshot if P2P is disabled. Must be called with the returned
    // callable executed on the P2P event loop thread — see the
    // waitForEstablished helper in NodeEndToEndTests for the pattern.
    static P2P::P2PManager::Snapshot p2pSnapshot(Node::Node &n)
    {
      if (!n.p2p_)
        return {};
      return n.p2p_->snapshot();
    }
  };
}