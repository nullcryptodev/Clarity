// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "P2PManager.h"
#include "Nonce.h"
#include "VersionMessage.h"
#include "Logging/ILogger.h"
#include "Logging/LoggerRef.h"

#include <chrono>
#include <stdexcept>

using namespace std::chrono_literals;

namespace P2P
{

  //  Construction / Destruction

  P2PManager::P2PManager(const P2PConfig &config,
                         Logging::ILogger &logger,
                         std::string dataDir)
      : config_(config), logger_(logger), log_(std::make_unique<Logging::LoggerRef>(logger, "P2P")), io_(), banList_(dataDir + "/p2p_bans.txt",
                                                                                                                     config.banThreshold,
                                                                                                                     config.banDurationSec),
        addressBook_(dataDir + "/p2p_addresses.txt"), workers_(config.workerThreads), maintenanceTimer_(io_)
  {
    networkNonce_ = generateNetworkNonce();

    // Keep io_.run() alive when there's no pending work.
    workGuard_ = std::make_unique<boost::asio::io_context::work>(io_);

    (*log_)(Logging::INFO)
        << "P2P initialized: nonce=0x" << std::hex << networkNonce_ << std::dec
        << " workers=" << workers_.threadCount()
        << " knownAddresses=" << addressBook_.size()
        << " banned=" << banList_.size();
  }

  P2PManager::~P2PManager()
  {
    stop();
  }

  //  Lifecycle

  void P2PManager::start(const std::vector<std::string> &seeds)
  {
    // Seed the address book.
    for (const auto &s : seeds)
    {
      // Parse "host:port". Use rfind so IPv6 addresses with colons work
      // if we ever support them.
      auto colon = s.rfind(':');
      if (colon == std::string::npos)
      {
        (*log_)(Logging::WARNING) << "malformed seed '" << s << "'";
        continue;
      }

      std::string host = s.substr(0, colon);
      uint16_t port;
      try
      {
        port = static_cast<uint16_t>(std::stoi(s.substr(colon + 1)));
      }
      catch (const std::exception &)
      {
        (*log_)(Logging::WARNING) << "malformed seed port in '" << s << "'";
        continue;
      }

      addressBook_.add(host, port, /*isSeed=*/true);
    }

    // Start listening.
    if (config_.listenPort != 0)
    {
      try
      {
        tcp::endpoint ep(config_.listenOnIPv6 ? tcp::v6() : tcp::v4(),
                         config_.listenPort);
        acceptor_ = std::make_unique<tcp::acceptor>(io_, ep);
        startAccept();
        (*log_)(Logging::INFO) << "listening on port " << config_.listenPort;
      }
      catch (const std::exception &e)
      {
        (*log_)(Logging::ERROR)
            << "failed to listen on port " << config_.listenPort
            << ": " << e.what();
        throw;
      }
    }

    // Kick off outbound maintenance.
    maintainOutbound();
    scheduleMaintenance();
  }

  void P2PManager::stop()
  {
    // First caller wins. Subsequent callers return immediately.
    bool expected = false;
    if (!stopping_.compare_exchange_strong(expected, true))
    {
      return;
    }

    (*log_)(Logging::INFO) << "P2P shutting down";

    // Post the actual shutdown to the event loop so it runs on the right
    // thread. This makes stop() safe to call from anywhere.
    boost::asio::post(io_, [this]
                      {
    // Stop accepting new connections.
    if (acceptor_) {
      boost::system::error_code ec;
      acceptor_->close(ec);
      acceptor_.reset();
    }

    // Disconnect all peers gracefully.
    auto peers = peers_.all();
    for (auto& p : peers) {
      p->disconnect("manager shutdown");
    }

    // Persist state.
    addressBook_.save();
    banList_.save();

    // Cancel the maintenance timer and release the work guard so
    // io_.run() can return.
    maintenanceTimer_.cancel();
    workGuard_.reset();
    io_.stop(); });
  }

  void P2PManager::run()
  {
    (*log_)(Logging::INFO) << "P2P event loop starting";
    io_.run();
    (*log_)(Logging::INFO) << "P2P event loop stopped";
  }

  //  Accept

  void P2PManager::startAccept()
  {
    acceptor_->async_accept(
        [this](const boost::system::error_code &ec, tcp::socket socket)
        {
          handleAccept(ec, std::move(socket));
        });
  }

  void P2PManager::handleAccept(const boost::system::error_code &ec,
                                tcp::socket socket)
  {
    if (ec)
    {
      if (ec != boost::asio::error::operation_aborted)
      {
        (*log_)(Logging::WARNING) << "accept error: " << ec.message();
      }
      return; // acceptor is closed, no point re-arming
    }

    // Enforce max inbound peers.
    if (peers_.countInbound() >= config_.maxInbound)
    {
      (*log_)(Logging::DEBUGGING) << "rejecting inbound (max reached)";
      boost::system::error_code ignored;
      socket.close(ignored);
    }
    else
    {
      auto peer = createPeer(std::move(socket), PeerDirection::Inbound);

      // Reject banned IPs.
      if (banList_.isBanned(peer->remoteIp()))
      {
        (*log_)(Logging::DEBUGGING)
            << "rejecting inbound from banned IP " << peer->remoteIp();
        peer->forceClose("banned");
      }
      else
      {
        peer->startInbound();
      }
    }

    // Re-arm accept for the next connection.
    startAccept();
  }

  //  Outbound

  void P2PManager::maintainOutbound()
  {
    if (stopping_.load())
      return;

    size_t current = peers_.countOutbound();
    if (current >= config_.targetOutbound)
      return;

    size_t need = config_.targetOutbound - current;
    auto candidates = addressBook_.pickRandom(need * 2); // over-fetch

    for (const auto &addr : candidates)
    {
      if (peers_.countOutbound() >= config_.maxOutbound)
        break;
      if (banList_.isBanned(addr.ip))
        continue;
      if (peers_.hasPeerWithIp(addr.ip))
        continue;
      connectTo(addr.ip, addr.port);
    }
  }

  void P2PManager::connectTo(const std::string &host, uint16_t port)
  {
    try
    {
      tcp::resolver resolver(io_);
      auto endpoints = resolver.resolve(host, std::to_string(port));
      if (endpoints.empty())
      {
        (*log_)(Logging::DEBUGGING)
            << "no endpoints resolved for " << host << ":" << port;
        return;
      }

      tcp::socket socket(io_);
      auto peer = createPeer(std::move(socket), PeerDirection::Outbound);
      peer->startConnect(*endpoints.begin());
    }
    catch (const std::exception &e)
    {
      (*log_)(Logging::DEBUGGING)
          << "resolve failed for " << host << ":" << port << ": " << e.what();
    }
  }

  //  Peer lifecycle

  PeerPtr P2PManager::createPeer(tcp::socket socket, PeerDirection dir)
  {
    PeerId id = nextPeerId();

    // LoggerRef is not copyable; construct a fresh one per peer.
    Logging::LoggerRef log(logger_, "P2P:" + std::to_string(id));

    auto peer = std::make_shared<Peer>(id, std::move(socket), dir, config_, log);

    peer->onConnected = [this](Peer &p)
    { handlePeerConnected(p); };
    peer->onDisconnected = [this](Peer &p)
    { handlePeerDisconnected(p); };
    peer->onMessage = [this](Peer &p, const Message &m)
    {
      handlePeerMessage(p, m);
    };
    peer->onMisbehaving = [this](Peer &p, uint32_t s, int r)
    {
      handlePeerMisbehaving(p, s, r);
    };

    // The peer asks us for its Version message at handshake time.
    // Fill in our network identity, protocol version, and listening port.
    // Without this, the default-constructed VersionMessage carries
    // protocolVersion = 0, every peer rejects us as "protocol too old",
    // and no connection ever reaches the Established state.
    peer->buildVersionMessage = [this]()
    {
      using namespace std::chrono;
      VersionMessage v;
      v.protocolVersion = config_.protocolVersion;
      v.networkNonce = networkNonce_;
      v.timestamp = duration_cast<seconds>(
                        system_clock::now().time_since_epoch())
                        .count();
      v.listenPort = config_.listenPort != 0
                         ? config_.listenPort
                         : config_.defaultPort;
      v.agentString = config_.agentString;
      v.bestHeight = 0; // TODO: plumb node height through a setter.
      v.peerNonce = 0;
      return v;
    };

    peers_.add(peer);
    return peer;
  }

  void P2PManager::removePeer(PeerId id)
  {
    peers_.remove(id);
  }

  //  Peer callbacks

  void P2PManager::handlePeerConnected(Peer &peer)
  {
    (*log_)(Logging::DEBUGGING) << "peer " << peer.id() << " connected ("
                                << peer.remoteIp() << ":" << peer.remotePort()
                                << ")";
    if (onPeerConnected)
      onPeerConnected(peer.id());
  }

  void P2PManager::handlePeerDisconnected(Peer &peer)
  {
    const auto id = peer.id();
    const auto ip = peer.remoteIp();
    const auto port = peer.remotePort();
    const auto score = peer.stats().misbehaviors;
    const auto reason = peer.isClosed() ? "closed" : "disconnected";

    (*log_)(Logging::INFO) << "peer " << id << " (" << ip << ":" << port
                           << ") disconnected: " << reason
                           << " (misbehaviors=" << score << ")";

    // Persist ban if the peer crossed the threshold.
    if (score >= config_.banThreshold)
    {
      banList_.ban(ip, BanReason::Other);
      (*log_)(Logging::WARNING) << "banned " << ip << " (score=" << score << ")";
    }

    // Notify the node.
    if (onPeerDisconnected)
      onPeerDisconnected(id, reason);

    // Defer removal to avoid destroying the peer while we're inside its
    // callback stack. Posting to the event loop ensures we return first.
    boost::asio::post(io_, [this, id]
                      { removePeer(id); });
  }

  void P2PManager::handlePeerMessage(Peer &peer, const Message &msg)
  {
    // ---- Self-connection detection ----
    // The version message contains the sender's network nonce. If it matches
    // ours, we've connected to ourselves. Close gracefully (no ban).
    if (msg.type == MessageType::Version)
    {
      VersionMessage v;
      if (deserializeVersion(msg.payload.data(), msg.payload.size(), v))
      {
        if (v.networkNonce == networkNonce_)
        {
          (*log_)(Logging::WARNING)
              << "self-connection detected from " << peer.remoteIp();
          peer.forceClose("self-connection");
          return;
        }
      }
    }

    // ---- GetPeers: reply with our known addresses ----
    if (msg.type == MessageType::GetPeers)
    {
      auto addrs = addressBook_.pickRandom(100);
      std::vector<PeerAddressEntry> entries;
      entries.reserve(addrs.size());
      for (const auto &a : addrs)
      {
        entries.push_back({a.ip, a.port});
      }
      peer.send(Message(MessageType::Peers, serializePeers(entries)));
      return;
    }

    // ---- Peers: learn new addresses ----
    if (msg.type == MessageType::Peers)
    {
      std::vector<PeerAddressEntry> entries;
      if (deserializePeers(msg.payload.data(), msg.payload.size(), entries))
      {
        size_t added = 0;
        for (const auto &e : entries)
        {
          if (e.port != 0 && !e.ip.empty())
          {
            addressBook_.add(e.ip, e.port);
            ++added;
          }
        }
        (*log_)(Logging::DEBUGGING)
            << "learned " << added << " peers from " << peer.remoteIp();
      }
      return;
    }

    // ---- Forward everything else to the node ----
    if (onMessage)
      onMessage(msg, peer.id());
  }

  void P2PManager::handlePeerMisbehaving(Peer &peer, uint32_t score, int reason)
  {
    const auto ip = peer.remoteIp();
    const bool banned = banList_.recordMisbehavior(ip, score);

    if (banned)
    {
      (*log_)(Logging::WARNING)
          << "banned " << ip
          << " (score=" << peer.stats().misbehaviors
          << " reason=" << reason << ")";
    }
    else
    {
      (*log_)(Logging::DEBUGGING)
          << "misbehavior from " << ip
          << " (score +" << score
          << " total=" << peer.stats().misbehaviors
          << " reason=" << reason << ")";
    }
  }

  //  Maintenance

  void P2PManager::scheduleMaintenance()
  {
    maintenanceTimer_.expires_after(30s);
    maintenanceTimer_.async_wait([this](const boost::system::error_code &ec)
                                 {
    if (ec || stopping_.load()) return;
    runMaintenance();
    scheduleMaintenance(); });
  }

  void P2PManager::runMaintenance()
  {
    // Persist address book and ban list.
    addressBook_.save();
    banList_.save();

    // Purge stale entries.
    addressBook_.purgeStale(7 * 24 * 3600); // 7 days
    banList_.purgeExpired();

    // Keep the outbound target satisfied.
    maintainOutbound();

    // Log a snapshot.
    auto snap = snapshot();
    (*log_)(Logging::DEBUGGING)
        << "peers: in=" << snap.inbound
        << " out=" << snap.outbound
        << " est=" << snap.established
        << " total=" << snap.total
        << " addr=" << snap.knownAddresses
        << " banned=" << snap.banned
        << " workerQueue=" << snap.workerQueue;
  }

  //  Send

  void P2PManager::sendTo(PeerId id, Message msg)
  {
    if (auto *p = peers_.find(id))
    {
      p->send(std::move(msg));
    }
  }

  void P2PManager::broadcast(const Message &msg, PeerId exclude)
  {
    for (auto &[id, peer] : peers_)
    {
      if (id == exclude)
        continue;
      if (!peer->isOperational())
        continue;
      peer->send(msg);
    }
  }

  //  Introspection

  P2PManager::Snapshot P2PManager::snapshot() const
  {
    Snapshot s;
    s.inbound = peers_.countInbound();
    s.outbound = peers_.countOutbound();
    s.established = peers_.countByState(PeerState::Established);
    s.total = peers_.size();
    s.knownAddresses = addressBook_.size();
    s.banned = banList_.size();
    s.workerQueue = workers_.pendingJobs();
    return s;
  }

} // namespace P2P