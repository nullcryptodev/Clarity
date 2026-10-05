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

    // Submit a transaction to the mempool. Returns the raw result code
    // so callers can distinguish rejection reasons. `error` is populated
    // with a human-readable name on non-accepted results; on Accepted it
    // is cleared.
    Core::MempoolAddResult submitTransaction(const Core::Transaction &tx,
                                             std::string &error);

    Crypto::Hash stateRoot() const;

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

    // Forwarding method for RPC. Returns an empty vector if P2P is
    // disabled or not initialized. Thread-safe: P2PManager::peerList
    // posts to the event loop and blocks.
    std::vector<P2P::P2PManager::PeerInfo> p2pPeerList() const;

    // Given a peer's public key, return the validator ID whose reward
    // address matches it, or 0 if no active validator claims it.
    // Called from the P2P auth path on the event loop thread.
    uint64_t validatorIdForAddress(const Crypto::PublicKey &pk) const;
    
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

    void onP2PPeerEstablished(const P2P::P2PManager::PeerEstablishedInfo &info);
    void handleIncomingHeaders(const P2P::Message &msg, P2P::PeerId from);
    void handleIncomingBlocks(const P2P::Message &msg, P2P::PeerId from);

    // Broadcast a freshly committed block to every Established peer.
    // Called from onBlockCommitted after applyCommittedBlock succeeds.
    // No-op if P2P is disabled or there are no Established peers.
    void broadcastBlock(const Core::Block &block);

    // Broadcast a transaction to every Established peer. Called after
    // a successful mempool add, from both submitTransaction (local
    // submission) and handleIncomingTx (relay). Symmetric with
    // broadcastBlock.
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
    void onBlockCommitted(const Core::Block &block);
    void onHeightAdvanced(Height height);

    void onConsensusPoll();

    // Start consensus if we have enough peers to form a quorum.
    // Idempotent — safe to call multiple times. Called from run() and
    // from onP2PPeerConnected(). Without this, the proposer broadcasts
    // into an empty peer table and the first round fails on every node.
    void maybeStartConsensus();

    bool applyCommittedBlock(const Core::Block &block, std::string &error);

    // Auth callbacks for P2P. Wired in initP2P().
    P2P::AuthMessage buildAuthMessageForPeer(P2P::Peer &peer);
    bool verifyPeerAuth(P2P::Peer &peer,
                        const P2P::AuthMessage &msg,
                        uint64_t &outValidatorId);

    std::vector<Id> loadActiveSetFromState(
        State::StateAccess &state) const;

    std::unique_ptr<Core::StateView> makeStateView() const;

    Core::GenesisConfig genesisConfig() const;

    // Load <data_dir>/node_key, or generate and persist a fresh key
    // on first run. Cached in node_key_ after the first call.
    void loadOrCreateNodeKey();

    void updateBestPeerHeight();

    void onSyncTick();

    // Timer-driven poll loops. Each timer's handler does one tick of
    // work, then re-arms the timer. Cancelled in stop().
    //
    // These replace an earlier post-and-sleep pattern that blocked
    // the io_context thread for the sleep duration and made shutdown
    // wait for up to one full interval. The timer approach leaves the
    // io_context free to service I/O between ticks, and cancel() wakes
    // the handler immediately on shutdown.
    void armConsensusPollTimer();
    void onConsensusPollTimer(const boost::system::error_code &ec);

    void armSyncTickTimer();
    void onSyncTickTimer(const boost::system::error_code &ec);

    // ---- Write-ahead log helpers ----
    //
    //  Key layout (big-endian for prefix scans):
    //
    //    vote: [u64 height][u32 kind=0][u64 round][u64 signer_id]
    //    lock: [u64 height][u32 kind=1][u64 round]
    //
    //  Height first, so wal_truncate can prefix-scan on
    //  "height <= H".
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
    mutable std::mutex status_mutex_;

    FailPoint fail_point_for_test_{FailPoint::None};

    // The key used to sign P2P Auth messages. Either config_.node_secret_key
    // (if set) or the key loaded/created by loadOrCreateNodeKey().
    Crypto::SecretKey node_key_{};
    bool node_key_loaded_{false};

    // One sync manager per Established peer, keyed by PeerId. Created
    // in onP2PPeerEstablished, destroyed in onP2PPeerDisconnected.
    // All accesses happen on the P2P io_context thread, so no lock
    // is needed.
    std::unordered_map<P2P::PeerId, std::unique_ptr<P2P::SyncManager>>
        sync_managers_;

    std::unordered_map<P2P::PeerId, uint64_t> peer_heights_;

    // Timer-driven poll loops. Both use the P2P io_context's executor.
    // Constructed lazily in run(), cancelled in stop(). The `armed_`
    // flags guard against stop() racing with a handler that's mid-flight:
    // the handler checks its flag before re-arming, so a cancel that
    // happens between the work and the re-arm is honored.
    std::unique_ptr<boost::asio::steady_timer> consensus_timer_;
    std::unique_ptr<boost::asio::steady_timer> sync_timer_;

    // Sync tick interval. Every tick, each peer's SyncManager::tick()
    // is called, which drives both timeout detection and Idle refresh.
    // 200ms is frequent enough for a 30s refresh interval and cheap
    // when there's nothing to do (each tick is a timestamp comparison
    // when Idle).
    static constexpr uint32_t SYNC_TICK_INTERVAL_MS = 200;
  };

} // namespace Node