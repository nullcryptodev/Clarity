// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/signal_set.hpp>

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
#include "P2P/AuthMessage.h"
#include "P2P/SyncManager.h"
#include "State/SparseMerkleTree.h"
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
      Consensus::Step consensus_step_ordinal{Consensus::Step::NewHeight};
      Network network{Network::Regtest};
      uint64_t chain_id{0};
      bool running{false};

      // ---- P2P counters ----
      size_t peers_total{0};
      size_t peers_inbound{0};
      size_t peers_outbound{0};
      size_t peers_established{0};
      size_t peers_banned{0};
      size_t addresses_known{0};

      // ---- Aggregate rate limiter (config) ----
      uint32_t aggregate_rate_limit_burst{0};
      uint32_t aggregate_rate_limit_per_second{0};
      bool aggregate_rate_limit_enabled{false};

      // ---- Consensus detail ----
      size_t consensus_prevotes{0};
      size_t consensus_precommits{0};
      uint32_t consensus_consecutive_timeouts{0};
      bool consensus_emergency_rotation{false};
      bool consensus_is_proposer{false};
    };

    Status status() const;

    // Submit a transaction to the mempool. Returns the raw result code
    // so callers can distinguish rejection reasons. `error` is populated
    // with a human-readable name on non-accepted results; on Accepted it
    // is cleared.
    Core::MempoolAddResult submitTransaction(const Core::Transaction &tx,
                                             std::string &error);

    Crypto::Hash stateRoot() const;

    //  Snapshot of the SMT's cumulative counters. Read by the metrics
    //  handler. Returns a value copy, so the caller doesn't need to
    //  hold any lock or worry about the tree mutating underneath.
    //
    //  The counters are for the tree attached to the most recent
    //  StateAccess constructed by this node. Because the node opens a
    //  fresh StateAccess for every block application and every RPC
    //  call, the counters reflect the sum of writes since the DB was
    //  opened, not since the tree object was constructed. Under the
    //  compressed tree each block's writes are O(K log N) where K is
    //  the number of state-changing transactions in the block.
    State::SparseMerkleTree::Stats smtStats() const;

    // Test-only crash injection.
    enum class FailPoint
    {
      None,
      InsideTxn, // after beginWrite, before txn.commit()
    };

    void setFailPointForTest(FailPoint fp) { fail_point_for_test_ = fp; }

    const Core::Chain &chain() const { return *chain_; }
    const Core::Mempool &mempool() const { return *mempool_; }
    State::StateDB &stateDB() const { return *state_db_; }
    Core::ChainDB &chainDB() const { return *chain_db_; }

    // Data directory path. Read by the metrics handler to compute
    // the on-disk size of the state and chain databases.
    const std::string &dataDir() const noexcept { return config_.data_dir; }

    // Forwarding method for RPC. Returns an empty vector if P2P is
    // disabled or not initialized.
    std::vector<P2P::P2PManager::PeerInfo> p2pPeerList() const;

    // Given a peer's public key, return the validator ID whose reward
    // address matches it, or 0 if no active validator claims it.
    uint64_t validatorIdForAddress(const Crypto::PublicKey &pk) const;

    //  The retention window the node is using, in blocks. Read by the
    //  metrics handler and by the RPC getSmtHistoryWindow method.
    //  Resolved at construction from NodeConfig (which validateConfig
    //  has already filled from the network default).
    uint64_t smtHistoryBlocks() const noexcept
    {
      return config_.smt_history_blocks;
    }

  private:
    friend class Tests::NodeTestAccess;

    void initStorage();
    void initGenesis();
    void initMempool();
    void initP2P();
    void initConsensus();

    void onP2PMessage(const P2P::Message &msg, P2P::PeerId from);
    void onP2PPeerConnected(P2P::PeerId id);
    void onP2PPeerDisconnected(P2P::PeerId id, const std::string &reason);

    void handleIncomingProposal(const P2P::Message &msg);
    void handleIncomingVote(const P2P::Message &msg, bool is_precommit);
    void handleIncomingTx(const P2P::Message &msg);
    void handleIncomingBlock(const P2P::Message &msg, P2P::PeerId from);
    void handleGetHeaders(const P2P::Message &msg, P2P::PeerId from);
    void handleGetBlocks(const P2P::Message &msg, P2P::PeerId from);
    void handleGetProof(const P2P::Message &msg, P2P::PeerId from);

    void onP2PPeerEstablished(const P2P::P2PManager::PeerEstablishedInfo &info);
    void handleIncomingHeaders(const P2P::Message &msg, P2P::PeerId from);
    void handleIncomingBlocks(const P2P::Message &msg, P2P::PeerId from);

    void broadcastBlock(const Core::Block &block);
    void broadcastTransaction(const Core::Transaction &tx);

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
    bool onBlockCommitted(const Core::Block &block);
    void onHeightAdvanced(Height height);

    void onConsensusPoll();

    std::unique_ptr<State::StateAccess> makeStateAccess(uint64_t version) const;

    void maybeStartConsensus();

    bool applyCommittedBlock(const Core::Block &block, std::string &error);

    P2P::AuthMessage buildAuthMessageForPeer(P2P::Peer &peer);
    bool verifyPeerAuth(P2P::Peer &peer,
                        const P2P::AuthMessage &msg,
                        uint64_t &outValidatorId);

    std::vector<Id> loadActiveSetFromState(
        State::StateAccess &state) const;

    std::unique_ptr<Core::StateView> makeStateView() const;

    Core::GenesisConfig genesisConfig() const;

    void loadOrCreateNodeKey();

    void updateBestPeerHeight();

    void onSyncTick();

    void armConsensusPollTimer();
    void onConsensusPollTimer(const boost::system::error_code &ec);

    void armSyncTickTimer();
    void onSyncTickTimer(const boost::system::error_code &ec);

    // ---- Write-ahead log helpers ----

    static std::vector<uint8_t> walVoteKey(Height height,
                                           Round round,
                                           Id signer_id);
    static std::vector<uint8_t> walLockKey(Height height, Round round);
    static std::vector<uint8_t> walPrefixForHeightOrLower(Height max_height);

    static std::vector<uint8_t> walEncodeVoteRecord(const Consensus::Vote &v,
                                                    bool is_precommit);
    static bool walDecodeVoteRecord(const std::vector<uint8_t> &bytes,
                                    Consensus::Vote &out_v,
                                    bool &out_is_precommit);

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

    //  The height at which the most recent history prune ran. The
    //  prune itself is throttled: applyCommittedBlock() runs it only
    //  when the block height has advanced since the last successful
    //  prune, which prevents re-pruning on a re-applied block. On a
    //  healthy chain the throttle never fires: heights are monotonic.
    uint64_t last_prune_height_{0};

    FailPoint fail_point_for_test_{FailPoint::None};

    Crypto::SecretKey node_key_{};
    bool node_key_loaded_{false};

    std::unordered_map<P2P::PeerId, std::unique_ptr<P2P::SyncManager>>
        sync_managers_;

    std::unordered_map<P2P::PeerId, uint64_t> peer_heights_;

    std::unique_ptr<boost::asio::steady_timer> consensus_timer_;
    std::unique_ptr<boost::asio::steady_timer> sync_timer_;

    std::unique_ptr<boost::asio::signal_set> signals_;

    static constexpr uint32_t SYNC_TICK_INTERVAL_MS = 200;
  };

} // namespace Node