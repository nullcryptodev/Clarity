// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <boost/asio.hpp>

#include "AddressBook.h"
#include "BanList.h"
#include "Config.h"
#include "Message.h"
#include "Peer.h"
#include "PeerTable.h"
#include "WorkerPool.h"
#include "AuthMessage.h"
#include "AggregateLimiter.h"

#include "Crypto/Types.h"

namespace Logging
{
  class ILogger;
  class LoggerRef;
}

namespace P2P
{
  using boost::asio::ip::tcp;

  //  P2PManager
  //
  //  The P2P layer's main entry point. Owns the event loop, the peer table,
  //  the ban list, the address book, and the worker pool.
  //
  //  Lifecycle:
  //    P2PManager mgr(config, logger, dataDir);
  //    mgr.onMessage         = ...;
  //    mgr.onPeerConnected   = ...;
  //    mgr.onPeerDisconnected= ...;
  //    mgr.start(seeds);
  //    mgr.run();     // blocks until stop()
  //    mgr.stop();    // safe from any thread
  //
  //  Threading:
  //    - `run()` runs the event loop on the calling thread.
  //    - All other public methods must run on the event loop thread, OR be
  //      posted via `post()` from another thread.
  //    - `stop()` is the only exception: safe from any thread.
  //
  //  Snapshot vs. peerList:
  //    `snapshot()` returns aggregate counters that are safe to read
  //    from any thread. It does not iterate the peer table — the
  //    table is only mutated on the event loop, so a direct read
  //    from a worker thread would be a data race. The counters are
  //    mirrored into std::atomic<size_t> members that are updated
  //    at the three points where the table changes (peer added,
  //    peer removed, peer reached Established).
  //
  //    `peerList()` posts to the event loop and waits, so it sees a
  //    consistent view of the table. It is the right call for
  //    anything that needs per-peer fields (RPC `getPeers`), and
  //    the wrong call for a metrics scrape (it can block for up to
  //    2 seconds if the event loop is busy).

  class P2PManager
  {
  public:
    P2PManager(const P2PConfig &config,
               Logging::ILogger &logger,
               std::string dataDir);
    ~P2PManager();

    P2PManager(const P2PManager &) = delete;
    P2PManager &operator=(const P2PManager &) = delete;

    // ------------------------------------------------------------------
    //  Lifecycle
    // ------------------------------------------------------------------

    // Start listening (if configured) and dial seeds.
    // Call from the event loop thread before run().
    void start(const std::vector<std::string> &seeds = {});

    // Stop everything. Thread-safe. Idempotent.
    void stop();

    // Run the event loop. Blocks until stop() is called.
    void run();

    // Post a callable to run on the event loop thread.
    // Safe to call from any thread.
    template <typename F>
    void post(F &&f)
    {
      boost::asio::post(io_, std::forward<F>(f));
    }

    // ------------------------------------------------------------------
    //  Peer management (event loop thread only)
    // ------------------------------------------------------------------

    // Dial a specific peer.
    void connectTo(const std::string &host, uint16_t port);

    // Send a message to one peer.
    void sendTo(PeerId id, Message msg);

    // Broadcast to all established peers.
    // If `exclude` is set, skip that peer (useful to avoid echoes).
    void broadcast(const Message &msg, PeerId exclude = INVALID_PEER_ID);

    // Current peer count. Reads an atomic counter — safe from any
    // thread, does not touch the peer table.
    size_t peerCount() const noexcept
    {
      return peers_total_.load(std::memory_order_relaxed);
    }

    // Look up a peer by id. Returns nullptr if not found.
    // Event loop thread only — the peer table is not thread-safe.
    Peer *findPeer(PeerId id) const { return peers_.find(id); }

    // ------------------------------------------------------------------
    //  Worker pool
    //
    //  Submit CPU-heavy work to the worker threads. The callback runs on
    //  the event loop thread (it's posted automatically).
    //
    //  Work:     callable with no arguments, returning Result.
    //  Callback: callable taking Result (or nothing, if Result is void).
    // ------------------------------------------------------------------

    template <typename Work, typename Callback>
    void submitWork(Work &&work, Callback &&cb)
    {
      workers_.submit(
          std::forward<Work>(work),
          [this, cb = std::forward<Callback>(cb)](auto &&result) mutable
          {
            // Post the callback to the event loop. Capture by value to
            // outlive the worker thread's stack.
            using Result = std::decay_t<decltype(result)>;
            Result r = std::forward<decltype(result)>(result);
            boost::asio::post(io_,
                              [cb = std::move(cb), r = std::move(r)]() mutable
                              {
                                cb(std::move(r));
                              });
          });
    }

    // ------------------------------------------------------------------
    //  Node events (set by the node before start())
    // ------------------------------------------------------------------

    // Fired for every non-control message received from a peer.
    std::function<void(const Message &, PeerId)> onMessage;

    // Fired when a peer's TCP connection is established (before handshake).
    std::function<void(PeerId)> onPeerConnected;

    // Fired when a peer disconnects, with a reason string.
    std::function<void(PeerId, const std::string &)> onPeerDisconnected;

    // ------------------------------------------------------------------
    //  Introspection
    // ------------------------------------------------------------------

    //  Snapshot
    //
    //  Aggregate counters, safe to read from any thread. Every field
    //  is either an atomic read (the peer counters) or a mutex-guarded
    //  read of a small collection (address book, ban list). None of
    //  them iterate the peer table, so this method is safe to call
    //  concurrently with the event loop.
    //
    //  Values are approximate by at most one peer transition: a
    //  peer added to the table but not yet reflected in the atomic
    //  is not counted. For a metrics scrape or an RPC status call,
    //  that approximation is what a gauge wants anyway — the
    //  alternative is a snapshot that blocks on the event loop.
    struct Snapshot
    {
      size_t inbound = 0;
      size_t outbound = 0;
      size_t established = 0;
      size_t total = 0;
      size_t knownAddresses = 0;
      size_t banned = 0;
      size_t workerQueue = 0;
      uint32_t aggregateBurst = 0;
      uint32_t aggregatePerSecond = 0;
      bool aggregateEnabled = false;
    };

    Snapshot snapshot() const;

    // Per-peer snapshot for RPC introspection. Aggregated by
    // peerList(). Fields are copied out of the Peer at the moment of
    // the call and are not kept in sync afterward.
    struct PeerInfo
    {
      PeerId id{INVALID_PEER_ID};
      std::string ip;
      uint16_t port{0};
      bool inbound{false};
      std::string state; // "connecting", "handshaking", "established", "closing"
      uint64_t best_height{0};
      uint64_t validator_id{0};
      std::string agent; // agent string from the version handshake
      uint64_t connected_at_ms{0};
      uint64_t last_recv_ms{0};
      uint64_t last_send_ms{0};
      uint32_t misbehaviors{0};
    };

    // Snapshot of every currently known peer. Thread-safety: this
    // schedules a read on the event loop and waits for the result. It
    // must not be called from the event loop thread itself (that
    // would deadlock). RPC handlers run on RPC worker threads, which
    // satisfies the constraint.
    //
    // Returns an empty vector if the manager is stopping or the
    // event loop has exited.
    std::vector<PeerInfo> peerList();

    // ------------------------------------------------------------------
    //  Authentication (set by the node before start())
    //
    //  Peer authentication is a signed challenge/response exchange that
    //  runs after Verack and before Established. The manager doesn't
    //  know the node's key or the validator index — it just forwards
    //  these callbacks to each Peer at creation time. See AuthMessage.h
    //  for the protocol.
    // ------------------------------------------------------------------

    // Builds this node's Auth message for a peer. Called once per peer,
    // on the event loop thread, when the peer enters AuthPending.
    std::function<AuthMessage(Peer &)> buildAuthMessage;

    // Verifies a peer's Auth message. Returns true if the signature is
    // valid and the pubkey is acceptable. On success, outValidatorId is
    // set to the validator ID bound to this pubkey, or 0 if the peer is
    // authenticated but not a validator. Called on the event loop thread.
    std::function<bool(Peer &, const AuthMessage &, uint64_t &outValidatorId)>
        verifyAuth;

    // Returns the node's Ed25519 identity public key — the one carried
    // in the Auth message. Called by each Peer once, during session
    // key derivation. If unset, session key derivation fails and the
    // peer is force-closed with "encryption: key derivation failed".
    //
    // The manager doesn't own this key; it's the same key the node
    // already uses to build the Auth message. The callback exists so
    // the Peer can obtain it without a second source of truth.
    std::function<Crypto::PublicKey(Peer &)> getOurIdentityPubkey;

    // Fired when a peer completes the full handshake — TCP, Version,
    // Verack, and Auth. At this point the peer has a verified identity
    // and can exchange application messages. `info` carries the
    // identity data the node needs to decide what to do with the peer
    // (create a SyncManager, associate the peer with a validator ID,
    // report it via RPC).
    struct PeerEstablishedInfo
    {
      PeerId id{INVALID_PEER_ID};
      uint64_t best_height{0};
      uint64_t validator_id{0}; // 0 for an authenticated non-validator
      std::string agent;
      Crypto::PublicKey pubkey;
    };
    std::function<void(const PeerEstablishedInfo &)> onPeerEstablished;

    // Returns the node's current chain height. Called when building the
    // Version message for a new peer. If unset, the height defaults to 0.
    std::function<uint64_t()> getChainHeight;

    boost::asio::io_context::executor_type executor() noexcept { return io_.get_executor(); }

  private:
    // ------------------------------------------------------------------
    //  Accept loop
    // ------------------------------------------------------------------

    void startAccept();
    void handleAccept(const boost::system::error_code &ec, tcp::socket socket);

    // ------------------------------------------------------------------
    //  Outbound connector
    // ------------------------------------------------------------------

    void maintainOutbound();
    void connectToAddressBook();

    // ------------------------------------------------------------------
    //  Peer lifecycle
    // ------------------------------------------------------------------

    PeerPtr createPeer(tcp::socket socket, PeerDirection dir);
    void removePeer(PeerId id);

    PeerId nextPeerId() noexcept { return nextPeerId_++; }

    // ------------------------------------------------------------------
    //  Peer callbacks
    // ------------------------------------------------------------------

    void handlePeerConnected(Peer &peer);
    void handlePeerDisconnected(Peer &peer);
    void handlePeerMessage(Peer &peer, const Message &msg);
    void handlePeerMisbehaving(Peer &peer, uint32_t score, int reason);

    //  Peer deduplication
    //
    //  Called when a peer transitions to Established. Checks whether
    //  we already have an Established peer with the same authenticated
    //  pubkey; if so, decides which to keep and closes the other.
    //
    //  Returns true if the calling peer should be treated as
    //  established (either it's the only one, or it won the tie-break).
    //  Returns false if the calling peer should be closed and dropped.
    bool deduplicatePeer(Peer &peer);

    // ------------------------------------------------------------------
    //  Periodic maintenance
    // ------------------------------------------------------------------

    void scheduleMaintenance();
    void runMaintenance();

    // ------------------------------------------------------------------
    //  Members
    // ------------------------------------------------------------------

    P2PConfig config_;
    Logging::ILogger &logger_;
    std::unique_ptr<Logging::LoggerRef> log_;

    boost::asio::io_context io_;
    std::unique_ptr<tcp::acceptor> acceptor_;
    std::unique_ptr<boost::asio::io_context::work> workGuard_;

    PeerTable peers_;
    PeerId nextPeerId_ = 1;
    uint64_t networkNonce_ = 0;

    //  Established peers, keyed by authenticated pubkey.
    //
    //  Populated in onEstablished after a peer finishes the Auth
    //  exchange. Used to detect duplicate connections when two nodes
    //  dial each other at the same time.
    //
    //  Only touched on the event loop thread; no lock needed.
    std::unordered_map<Crypto::PublicKey, PeerId> established_by_pubkey_;

    BanList banList_;
    AddressBook addressBook_;

    WorkerPool workers_;

    boost::asio::steady_timer maintenanceTimer_;
    std::atomic<bool> stopping_{false};

    //  Peer-count atomics.
    //
    //  These mirror the state of peers_ but are readable from any
    //  thread without synchronization. The peer table itself is only
    //  mutated on the event loop; snapshot() is called from RPC worker
    //  threads (via Node::status()), so a direct read of the table
    //  from snapshot() would be a data race. The atomics close that
    //  race with negligible cost: each is incremented or decremented
    //  once per peer add/remove/establish.
    //
    //  A read is approximate by at most one peer transition — the
    //  window between a peer being added to the table and the
    //  corresponding atomic update. That's exactly what a gauge
    //  wants; a metrics scrape does not need an atomic view of the
    //  peer set.
    //
    //  relaxed ordering is correct: these counters don't guard any
    //  other memory. A reader that sees the count never relies on
    //  seeing writes to other data after it.
    std::atomic<size_t> peers_total_{0};
    std::atomic<size_t> peers_inbound_{0};
    std::atomic<size_t> peers_outbound_{0};
    std::atomic<size_t> peers_established_{0};

    // Node-wide inbound work budget. Shared by every Peer; the
    // lifetime rule is the reverse of the address book's — this must
    // be constructed before any Peer and must outlive every Peer.
    // It lives as a direct member, constructed in the initializer
    // list, so its destruction order relative to peers_ is
    // guaranteed: members are destroyed in reverse declaration
    // order, and peers_ is declared above this, so peers_ is
    // destroyed first. That's the right order.
    AggregateLimiter aggregateLimiter_;
  };

} // namespace P2P