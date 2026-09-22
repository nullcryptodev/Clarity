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

#include <boost/asio.hpp>

#include "AddressBook.h"
#include "BanList.h"
#include "Config.h"
#include "Message.h"
#include "Peer.h"
#include "PeerTable.h"
#include "WorkerPool.h"

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

    // Current peer count.
    size_t peerCount() const noexcept { return peers_.size(); }

    // Look up a peer by id. Returns nullptr if not found.
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
    //  Introspection (event loop thread only)
    // ------------------------------------------------------------------

    struct Snapshot
    {
      size_t inbound = 0;
      size_t outbound = 0;
      size_t established = 0;
      size_t total = 0;
      size_t knownAddresses = 0;
      size_t banned = 0;
      size_t workerQueue = 0;
    };

    Snapshot snapshot() const;

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

    BanList banList_;
    AddressBook addressBook_;

    WorkerPool workers_;

    boost::asio::steady_timer maintenanceTimer_;
    std::atomic<bool> stopping_{false};
  };

} // namespace P2P