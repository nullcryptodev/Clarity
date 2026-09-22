// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

#include "NodeConfig.h"
#include "GlobalConfig.h"

#include "Consensus/BftConsensus.h"
#include "Core/BlockProcessor.h"
#include "Core/Chain.h"
#include "Core/ChainDB.h"
#include "Core/Genesis.h"
#include "Core/Mempool.h"
#include "Core/StateViewFromAccess.h"
#include "P2P/P2PManager.h"
#include "State/StateAccess.h"
#include "State/StateDB.h"

namespace Logging
{
  class ILogger;
  class LoggerRef;
}

namespace Tests
{
  class NodeTestAccess;
}

namespace Node
{

  class Node
  {
  public:
    Node(NodeConfig config, Logging::ILogger &logger);
    ~Node();

    Node(const Node &) = delete;
    Node &operator=(const Node &) = delete;

    void start();
    void run();
    void stop();

    template <typename F>
    void post(F &&f)
    {
      if (p2p_)
        p2p_->post(std::forward<F>(f));
    }

    struct Status
    {
      uint64_t height{0};
      uint64_t best_peer_height{0};
      size_t peer_count{0};
      size_t mempool_size{0};
      size_t mempool_bytes{0};
      bool is_validator{false};
      uint64_t validator_id{0};
      uint64_t consensus_height{0};
      uint32_t consensus_round{0};
      const char *consensus_step{"unknown"};
      Network network{Network::Regtest};
      uint64_t chain_id{0};
      bool running{false};
    };

    Status status() const;

    bool submitTransaction(const Core::Transaction &tx, std::string &error);
    Crypto::Hash stateRoot() const;

    // Test-only crash injection.
    enum class FailPoint
    {
      None,
      InsideTxn, // after beginWrite, before txn.commit()
    };

    void setFailPointForTest(FailPoint fp) { fail_point_for_test_ = fp; }

  private:
    friend class Tests::NodeTestAccess;

    void initStorage();
    void initGenesis();
    void initP2P();
    void initConsensus();

    void onP2PMessage(const P2P::Message &msg, P2P::PeerId from);
    void onP2PPeerConnected(P2P::PeerId id);
    void onP2PPeerDisconnected(P2P::PeerId id, const std::string &reason);

    void handleIncomingProposal(const P2P::Message &msg);
    void handleIncomingVote(const P2P::Message &msg, bool is_precommit);
    void handleIncomingTx(const P2P::Message &msg);
    void handleIncomingBlock(const P2P::Message &msg);
    void handleGetHeaders(const P2P::Message &msg, P2P::PeerId from);
    void handleGetBlocks(const P2P::Message &msg, P2P::PeerId from);

    Consensus::Dependencies buildConsensusDeps();
    Consensus::Callbacks buildConsensusCallbacks();

    Id getMyValidatorId() const;
    Crypto::Signature signHash(const Crypto::Hash &hash);
    Height getCurrentHeight() const;
    std::vector<Id> getActiveSet() const;
    std::optional<Crypto::PublicKey> getSignerPublicKey(Index idx) const;

    void onConsensusProposal(const Consensus::Proposal &p);
    void onConsensusVote(const Consensus::Vote &v, bool is_precommit);
    std::vector<Core::Transaction> selectTransactionsForProposal(
        uint64_t max_bytes, uint64_t max_txs);
    void onBlockCommitted(const Core::Block &block);
    void onHeightAdvanced(Height height);

    void scheduleConsensusPoll();
    void onConsensusPoll();

    // Start consensus if we have enough peers to form a quorum.
    // Idempotent — safe to call multiple times. Called from run() and
    // from onP2PPeerConnected(). Without this, the proposer broadcasts
    // into an empty peer table and the first round fails on every node.
    void maybeStartConsensus();

    bool applyCommittedBlock(const Core::Block &block, std::string &error);

    std::vector<Id> loadActiveSetFromState(
        State::StateAccess &state) const;

    std::unique_ptr<Core::StateView> makeStateView() const;

    Core::GenesisConfig genesisConfig() const;

    NodeConfig config_;
    Logging::ILogger &logger_;
    std::unique_ptr<Logging::LoggerRef> log_;

    std::unique_ptr<State::StateDB> state_db_;
    std::unique_ptr<Core::ChainDB> chain_db_;
    std::unique_ptr<Core::Chain> chain_;

    std::unique_ptr<Core::Mempool> mempool_;

    std::unique_ptr<P2P::P2PManager> p2p_;

    std::unique_ptr<Consensus::BftConsensus> consensus_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    std::atomic<bool> consensus_started_{false};
    uint64_t active_set_height_{0};
    mutable std::mutex status_mutex_;

    FailPoint fail_point_for_test_{FailPoint::None};
  };

} // namespace Node