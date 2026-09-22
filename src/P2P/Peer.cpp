// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Peer.h"
#include "VersionMessage.h"

#include <chrono>

using namespace std::chrono_literals;

namespace P2P
{
  namespace
  {
    int64_t nowUnix() noexcept
    {
      using namespace std::chrono;
      return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
    }

    constexpr int REASON_BAD_MAGIC = 1;
    constexpr int REASON_OVERSIZE = 2;
    constexpr int REASON_BAD_MESSAGE = 3;
    constexpr int REASON_HANDSHAKE_ORDER = 4;
    constexpr int REASON_PING_TIMEOUT = 5;
    constexpr int REASON_SELF_CONNECTION = 6;
    constexpr int REASON_VERSION_INVALID = 7;
  } // anonymous namespace

  //  Construction

  Peer::Peer(PeerId id,
             tcp::socket socket,
             PeerDirection direction,
             const P2PConfig &config,
             Logging::LoggerRef log)
      : id_(id), socket_(std::move(socket)), direction_(direction), config_(config), log_(log), decoder_(config.magic, config.maxMessageSize), handshakeTimer_(socket_.get_executor()), pingTimer_(socket_.get_executor()), pongTimer_(socket_.get_executor())
  {
    connectStartedAt_ = nowUnix();
    stats_.connectedAt = connectStartedAt_;
  }

  Peer::~Peer()
  {
    if (!isClosed())
    {
      boost::system::error_code ec;
      socket_.close(ec);
    }
  }

  //  Lifecycle

  void Peer::startConnect(const tcp::endpoint &endpoint)
  {
    transitionTo(PeerState::Connecting);

    auto self = shared_from_this();

    handshakeTimer_.expires_after(std::chrono::milliseconds(config_.connectTimeoutMs));
    handshakeTimer_.async_wait([self](const boost::system::error_code &ec)
                               {
    if (!ec && self->state_ == PeerState::Connecting) {
      self->log_(Logging::WARNING) << "connect timeout to " << self->endpointString();
      self->forceClose("connect timeout");
    } });

    socket_.async_connect(endpoint,
                          [self](const boost::system::error_code &ec)
                          {
                            self->handleConnect(ec);
                          });
  }

  void Peer::startInbound()
  {
    updateRemoteEndpoint();

    log_(Logging::INFO) << "inbound connection from " << endpointString();

    beginHandshake();
  }

  void Peer::handleConnect(const boost::system::error_code &ec)
  {
    if (ec)
    {
      log_(Logging::DEBUGGING) << "connect failed to " << endpointString()
                               << ": " << ec.message();
      forceClose("connect failed");
      return;
    }

    updateRemoteEndpoint();

    log_(Logging::INFO) << "connected to " << endpointString();

    beginHandshake();
  }

  void Peer::beginHandshake()
  {
    transitionTo(PeerState::Handshaking);
    if (onConnected)
      onConnected(*this);

    VersionMessage v;
    if (buildVersionMessage)
    {
      v = buildVersionMessage();
    }
    send(Message(MessageType::Version, serializeVersion(v)));

    armHandshakeTimer();
    startRead();
  }

  //  Reading

  void Peer::startRead()
  {
    auto self = shared_from_this();
    boost::asio::async_read(socket_,
                            boost::asio::buffer(headerBuffer_),
                            [self](const boost::system::error_code &ec, size_t n)
                            {
                              self->handleReadHeader(ec, n);
                            });
  }

  void Peer::handleReadHeader(const boost::system::error_code &ec, size_t /*n*/)
  {
    if (ec)
    {
      if (ec != boost::asio::error::operation_aborted)
      {
        log_(Logging::DEBUGGING) << "read header failed from "
                                 << endpointString() << ": " << ec.message();
      }
      forceClose("read error");
      return;
    }

    const uint8_t *p = headerBuffer_.data();
    uint32_t magic = uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    uint16_t type = uint16_t(p[4]) | (uint16_t(p[5]) << 8);
    uint32_t size = uint32_t(p[6]) | (uint32_t(p[7]) << 8) | (uint32_t(p[8]) << 16) | (uint32_t(p[9]) << 24);

    if (magic != config_.magic)
    {
      log_(Logging::WARNING) << "bad magic from " << endpointString();
      reportMisbehavior(config_.banThreshold, REASON_BAD_MAGIC);
      forceClose("bad magic");
      return;
    }

    if (size > config_.maxMessageSize)
    {
      log_(Logging::WARNING) << "oversize message (" << size << ") from "
                             << endpointString();
      reportMisbehavior(config_.banThreshold, REASON_OVERSIZE);
      forceClose("oversize message");
      return;
    }

    stats_.bytesRecv += MESSAGE_HEADER_SIZE;

    // Zero-length body: async_read on a zero-length buffer has
    // implementation-defined completion semantics on some asio
    // versions and may not fire at all. Dispatch the message
    // directly instead. This covers Verack, Ping, Pong, GetPeers,
    // and Disconnect — the control messages that have no payload.
    if (size == 0)
    {
      stats_.messagesRecv++;
      stats_.lastMessageAt = nowUnix();

      Message msg;
      msg.type = static_cast<MessageType>(type);
      msg.payload.clear();

      processIncoming(std::move(msg));
      if (!isClosed())
        startRead();
      return;
    }

    bodyBuffer_.resize(size);
    auto self = shared_from_this();

    boost::asio::async_read(socket_,
                            boost::asio::buffer(bodyBuffer_),
                            [self, type](const boost::system::error_code &ec2, size_t n)
                            {
                              if (ec2)
                              {
                                if (ec2 != boost::asio::error::operation_aborted)
                                {
                                  self->log_(Logging::DEBUGGING) << "read body failed: " << ec2.message();
                                }
                                self->forceClose("read error");
                                return;
                              }

                              self->stats_.bytesRecv += n;
                              self->stats_.messagesRecv++;
                              self->stats_.lastMessageAt = nowUnix();

                              Message msg;
                              msg.type = static_cast<MessageType>(type);
                              msg.payload = std::move(self->bodyBuffer_);
                              self->bodyBuffer_.clear();

                              self->processIncoming(std::move(msg));
                              if (!self->isClosed())
                              {
                                self->startRead();
                              }
                            });
  }

  //  Message handling

  void Peer::processIncoming(Message msg)
  {
    switch (msg.type)
    {
    case MessageType::Version:
      handleVersion(msg);
      return;
    case MessageType::Verack:
      handleVerack();
      return;
    case MessageType::Ping:
      handlePing();
      return;
    case MessageType::Pong:
      handlePong();
      return;
    case MessageType::GetPeers:
      handleGetPeers();
      return;
    case MessageType::Peers:
      handlePeers(msg);
      return;
    case MessageType::Disconnect:
      handleDisconnect();
      return;
    default:
      break;
    }

    if (state_ != PeerState::Established)
    {
      log_(Logging::WARNING) << "message " << messageTypeName(msg.type)
                             << " before handshake from " << endpointString();
      reportMisbehavior(20, REASON_HANDSHAKE_ORDER);
      return;
    }

    if (onMessage)
      onMessage(*this, msg);
  }

  //  Handshake

  void Peer::handleVersion(Message &msg)
  {
    if (state_ != PeerState::Handshaking)
    {
      log_(Logging::WARNING) << "unexpected version from " << endpointString();
      reportMisbehavior(50, REASON_HANDSHAKE_ORDER);
      forceClose("unexpected version");
      return;
    }

    VersionMessage v;
    if (!deserializeVersion(msg.payload.data(), msg.payload.size(), v))
    {
      log_(Logging::WARNING) << "malformed version from " << endpointString();
      reportMisbehavior(50, REASON_VERSION_INVALID);
      forceClose("malformed version");
      return;
    }

    if (v.protocolVersion < GlobalConfig::MIN_PROTOCOL_VERSION)
    {
      log_(Logging::WARNING) << "peer " << endpointString()
                             << " has old protocol " << v.protocolVersion;
      reportMisbehavior(50, REASON_VERSION_INVALID);
      forceClose("protocol too old");
      return;
    }

    int64_t now = nowUnix();
    if (v.timestamp < now - 3600 || v.timestamp > now + 3600)
    {
      log_(Logging::WARNING) << "peer " << endpointString()
                             << " has bad timestamp " << v.timestamp;
      reportMisbehavior(20, REASON_VERSION_INVALID);
    }

    agent_ = v.agentString;
    bestHeight_ = v.bestHeight;
    protocolVersion_ = v.protocolVersion;
    peerNonce_ = v.networkNonce;
    peerListenPort_ = v.listenPort;

    stats_.peerProtocol = v.protocolVersion;
    stats_.peerBestHeight = v.bestHeight;
    stats_.peerNonce = v.networkNonce;

    log_(Logging::INFO) << "peer " << endpointString()
                        << " version=" << v.protocolVersion
                        << " agent=\"" << v.agentString << "\""
                        << " height=" << v.bestHeight;

    send(Message::verack());
    transitionTo(PeerState::VerackPending);

    // Forward the version up so P2PManager can check for self-connection.
    if (onMessage)
      onMessage(*this, msg);
  }

  void Peer::handleVerack()
  {
    if (state_ != PeerState::VerackPending)
    {
      log_(Logging::WARNING) << "unexpected verack from " << endpointString();
      reportMisbehavior(20, REASON_HANDSHAKE_ORDER);
      return;
    }

    handshakeTimer_.cancel();
    transitionTo(PeerState::Established);

    log_(Logging::INFO) << "handshake complete with " << endpointString();

    armPingTimer();
  }

  //  Ping / Pong

  void Peer::handlePing()
  {
    send(Message::pong());
  }

  void Peer::handlePong()
  {
    pongTimer_.cancel();

    auto now = std::chrono::steady_clock::now();
    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(
                   now - lastPingSent_)
                   .count();
    stats_.pingTimeMs = rtt;
    stats_.lastPongAt = nowUnix();
  }

  void Peer::armPingTimer()
  {
    auto self = shared_from_this();
    pingTimer_.expires_after(std::chrono::milliseconds(config_.pingIntervalMs));
    pingTimer_.async_wait([self](const boost::system::error_code &ec)
                          {
    if (ec || self->isClosed()) return;

    self->lastPingSent_ = std::chrono::steady_clock::now();
    self->stats_.lastPingAt = nowUnix();
    self->send(Message::ping());

    self->pongTimer_.expires_after(
        std::chrono::milliseconds(self->config_.pongTimeoutMs));
    self->pongTimer_.async_wait([self](const boost::system::error_code& ec2) {
      if (ec2 || self->isClosed()) return;
      self->log_(Logging::WARNING) << "pong timeout from " << self->endpointString();
      self->reportMisbehavior(20, REASON_PING_TIMEOUT);
      self->forceClose("pong timeout");
    });

    self->armPingTimer(); });
  }

  //  Peers exchange

  void Peer::handleGetPeers()
  {
    if (onMessage)
      onMessage(*this, Message(MessageType::GetPeers));
  }

  void Peer::handlePeers(Message &msg)
  {
    if (onMessage)
      onMessage(*this, msg);
  }

  void Peer::handleDisconnect()
  {
    disconnect("peer sent disconnect");
  }

  //  Writing

  bool Peer::send(Message msg)
  {
    if (isClosed() || state_ == PeerState::Disconnecting)
    {
      return false;
    }

    if (msg.payload.size() > config_.maxMessageSize)
    {
      log_(Logging::WARNING) << "refusing oversize send to " << endpointString();
      return false;
    }

    auto encoded = encodeMessage(msg, config_.magic, config_.maxMessageSize);

    if (sendQueueBytes() + encoded.size() > config_.maxSendQueueBytes)
    {
      log_(Logging::WARNING) << "send queue full for " << endpointString()
                             << " (" << sendQueueBytes() << " bytes)";
      forceClose("send queue overflow");
      return false;
    }

    stats_.bytesSent += encoded.size();
    stats_.messagesSent++;

    sendQueue_.push_back(std::move(encoded));
    startWriteIfNeeded();
    return true;
  }

  size_t Peer::sendQueueBytes() const
  {
    size_t total = 0;
    for (const auto &m : sendQueue_)
      total += m.size();
    return total;
  }

  void Peer::startWriteIfNeeded()
  {
    if (writeInProgress_ || sendQueue_.empty() || isClosed())
      return;

    writeInProgress_ = true;
    auto self = shared_from_this();

    boost::asio::async_write(socket_,
                             boost::asio::buffer(sendQueue_.front()),
                             [self](const boost::system::error_code &ec, size_t n)
                             {
                               self->handleWrite(ec, n);
                             });
  }

  void Peer::handleWrite(const boost::system::error_code &ec, size_t /*n*/)
  {
    writeInProgress_ = false;

    if (ec)
    {
      log_(Logging::DEBUGGING) << "write failed to " << endpointString()
                               << ": " << ec.message();
      forceClose("write error");
      return;
    }

    if (!sendQueue_.empty())
      sendQueue_.pop_front();
    drainSendQueue();
  }

  void Peer::drainSendQueue()
  {
    if (sendQueue_.empty())
    {
      if (state_ == PeerState::Disconnecting)
      {
        forceClose(closeReason_);
      }
      return;
    }
    startWriteIfNeeded();
  }

  //  Shutdown

  void Peer::disconnect(std::string reason)
  {
    if (isClosed() || state_ == PeerState::Disconnecting)
      return;

    closeReason_ = std::move(reason);
    transitionTo(PeerState::Disconnecting);
    drainSendQueue();
  }

  void Peer::forceClose(std::string reason)
  {
    if (isClosed())
      return;

    closeReason_ = std::move(reason);
    transitionTo(PeerState::Closed);

    boost::system::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_both, ec);
    socket_.close(ec);

    handshakeTimer_.cancel();
    pingTimer_.cancel();
    pongTimer_.cancel();

    if (!reportedDisconnect_)
    {
      reportedDisconnect_ = true;
      if (onDisconnected)
        onDisconnected(*this);
    }
  }

  //  State machine

  void Peer::transitionTo(PeerState s)
  {
    if (state_ == s)
      return;
    log_(Logging::DEBUGGING) << "peer " << endpointString()
                             << " " << peerStateName(state_)
                             << " -> " << peerStateName(s);
    state_ = s;
  }

  void Peer::armHandshakeTimer()
  {
    auto self = shared_from_this();
    handshakeTimer_.expires_after(std::chrono::milliseconds(config_.handshakeTimeoutMs));
    handshakeTimer_.async_wait([self](const boost::system::error_code &ec)
                               {
    if (ec || self->isClosed()) return;
    if (self->state_ == PeerState::Handshaking ||
        self->state_ == PeerState::VerackPending) {
      self->log_(Logging::WARNING) << "handshake timeout with "
                                   << self->endpointString();
      self->forceClose("handshake timeout");
    } });
  }

  //  Misbehavior

  void Peer::reportMisbehavior(uint32_t score, int reason)
  {
    stats_.misbehaviors += score;
    stats_.lastBanReason = static_cast<uint32_t>(reason);
    if (onMisbehaving)
      onMisbehaving(*this, score, reason);
  }

  //  Helpers

  void Peer::updateRemoteEndpoint()
  {
    try
    {
      auto ep = socket_.remote_endpoint();
      remoteIp_ = ep.address().to_string();
      remotePort_ = ep.port();
    }
    catch (const std::exception &)
    {
      // Socket not connected (or closed). Leave as-is.
    }
  }

  std::string Peer::endpointString() const
  {
    if (remoteIp_.empty())
      return "<unknown>";
    return remoteIp_ + ":" + std::to_string(remotePort_);
  }

} // namespace P2P