// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "Config.h"
#include "Message.h"
#include "PeerState.h"
#include "PeerStats.h"

#include "Logging/LoggerRef.h"

namespace P2P
{
  using boost::asio::ip::tcp;

  // TODO remove, use Id
  using PeerId = uint64_t;
  inline constexpr PeerId INVALID_PEER_ID = 0;

  struct VersionMessage; // forward decl

  enum class PeerDirection : uint8_t
  {
    Inbound,
    Outbound,
  };

  class Peer : public std::enable_shared_from_this<Peer>
  {
  public:
    Peer(PeerId id,
         tcp::socket socket,
         PeerDirection direction,
         const P2PConfig &config,
         Logging::LoggerRef log);
    ~Peer();

    Peer(const Peer &) = delete;
    Peer &operator=(const Peer &) = delete;

    // ---- Identity ----

    PeerId id() const noexcept { return id_; }
    PeerDirection direction() const noexcept { return direction_; }
    PeerState state() const noexcept { return state_; }

    const std::string &remoteIp() const noexcept { return remoteIp_; }
    uint16_t remotePort() const noexcept { return remotePort_; }

    const std::string &agent() const noexcept { return agent_; }
    uint64_t bestHeight() const noexcept { return bestHeight_; }
    uint32_t protocolVersion() const noexcept { return protocolVersion_; }

    PeerStats &stats() noexcept { return stats_; }
    const PeerStats &stats() const noexcept { return stats_; }

    bool isOperational() const noexcept { return state_ == PeerState::Established; }
    bool isClosed() const noexcept { return state_ == PeerState::Closed; }

    // ---- Lifecycle ----

    void startConnect(const tcp::endpoint &endpoint);
    void startInbound();
    bool send(Message msg);
    void disconnect(std::string reason);
    void forceClose(std::string reason);

    // Report misbehavior. Called by P2PManager or by the peer itself.
    void reportMisbehavior(uint32_t score, int reason);

    // ---- Events (set by P2PManager) ----

    std::function<void(Peer &)> onConnected;
    std::function<void(Peer &)> onDisconnected;
    std::function<void(Peer &, const Message &)> onMessage;
    std::function<void(Peer &, uint32_t, int)> onMisbehaving;

    // Fills in our version message. Called by the peer when it's time
    // to send one. The manager knows our best height, nonce, agent, etc.
    std::function<VersionMessage()> buildVersionMessage;

  private:
    // ---- Asio callbacks ----
    void handleConnect(const boost::system::error_code &ec);
    void handleReadHeader(const boost::system::error_code &ec, size_t n);
    void handleWrite(const boost::system::error_code &ec, size_t n);

    // ---- State machine ----
    void beginHandshake();
    void transitionTo(PeerState s);
    void processIncoming(Message msg);
    void handleVersion(Message &msg);
    void handleVerack();
    void handlePing();
    void handlePong();
    void handleGetPeers();
    void handlePeers(Message &msg);
    void handleDisconnect();

    // ---- Timers ----
    void armHandshakeTimer();
    void armPingTimer();

    // ---- Send machinery ----
    void startRead();
    void startWriteIfNeeded();
    void drainSendQueue();
    size_t sendQueueBytes() const;

    // ---- Helpers ----
    void updateRemoteEndpoint();
    std::string endpointString() const;

    // ---- Members ----

    PeerId id_;
    tcp::socket socket_;
    PeerDirection direction_;
    PeerState state_ = PeerState::Connecting;
    const P2PConfig &config_;
    Logging::LoggerRef log_;

    // Remote endpoint
    std::string remoteIp_;
    uint16_t remotePort_ = 0;

    // Peer's advertised identity (from version message)
    std::string agent_;
    uint64_t bestHeight_ = 0;
    uint32_t protocolVersion_ = 0;
    uint64_t peerNonce_ = 0;
    uint16_t peerListenPort_ = 0;

    // Buffers
    std::array<uint8_t, MESSAGE_HEADER_SIZE> headerBuffer_{};
    std::vector<uint8_t> bodyBuffer_;
    MessageDecoder decoder_;

    // Send queue
    std::deque<std::vector<uint8_t>> sendQueue_;
    bool writeInProgress_ = false;

    // Timers
    boost::asio::steady_timer handshakeTimer_;
    boost::asio::steady_timer pingTimer_;
    boost::asio::steady_timer pongTimer_;
    std::chrono::steady_clock::time_point lastPingSent_;

    // Stats
    PeerStats stats_;
    int64_t connectStartedAt_ = 0;

    // Shutdown
    std::string closeReason_;
    bool reportedDisconnect_ = false;
  };

  using PeerPtr = std::shared_ptr<Peer>;

} // namespace P2P