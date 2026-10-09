// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Peer.h"
#include "VersionMessage.h"
#include "AggregateLimiter.h"

#include "Crypto/Chacha20Poly1305.h"
#include "Crypto/SessionKey.h"
#include "Crypto/SecureZero.h"

#include <chrono>
#include <cstring>

using namespace std::chrono_literals;

namespace P2P
{
  namespace
  {
    inline constexpr bool isConsensusType(MessageType t) noexcept
    {
      return t == MessageType::Proposal ||
             t == MessageType::Prevote ||
             t == MessageType::Precommit;
    }

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
    constexpr int REASON_RATE_LIMIT = 8;
    constexpr int REASON_AUTH_FAILED = 9;
    // No REASON_ENCRYPTION. Encryption failures deliberately do NOT
    // report misbehavior — see P2P-ENCRYPTION.md §7. A session-key
    // disagreement, a tag mismatch, or a corrupted wire byte is not
    // evidence of misbehavior, and a ban would punish a peer that
    // tripped over a bug in our own code. All encryption failures
    // call forceClose directly.
  } // anonymous namespace

  //  Construction

  Peer::Peer(PeerId id,
             tcp::socket socket,
             PeerDirection direction,
             const P2PConfig &config,
             Logging::LoggerRef log,
             AggregateLimiter *aggregateLimiter)
      : id_(id), socket_(std::move(socket)), direction_(direction), config_(config), log_(log), decoder_(config.magic, config.maxMessageSize), handshakeTimer_(socket_.get_executor()), pingTimer_(socket_.get_executor()), pongTimer_(socket_.get_executor()),
        msgBucket_(config.rateLimitBurst, config.rateLimitPerSecond),
        consensusBucket_(config.consensusRateLimitBurst, config.consensusRateLimitPerSecond),
        aggregateLimiter_(aggregateLimiter),
        ephemeralKeypair_(Crypto::generateX25519KeyPair())
  {
    connectStartedAt_ = nowUnix();
    stats_.connectedAt = connectStartedAt_;
  }

  Peer::~Peer()
  {
    // Zero the ephemeral secret if it hasn't been zeroed by
    // deriveSessionKeys. The two paths are mutually exclusive in
    // practice (derivation happens before any Established peer is
    // destructed), but the double-zero is harmless and the case where
    // the handshake aborted before derivation is the one where this
    // destructor is the only place the secret gets cleaned up.
    Crypto::secureZero(ephemeralKeypair_.secretKey.data(),
                       ephemeralKeypair_.secretKey.size());

    // Zero the session keys. They are secret material for the life of
    // the session, and a closed peer's keys should not linger.
    Crypto::secureZero(sessionKeys_.sessionKey.data(),
                       sessionKeys_.sessionKey.size());
    Crypto::secureZero(sessionKeys_.lowerNonceKey.data(),
                       sessionKeys_.lowerNonceKey.size());
    Crypto::secureZero(sessionKeys_.higherNonceKey.data(),
                       sessionKeys_.higherNonceKey.size());

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
    localNonce_ = v.networkNonce;
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

    const MessageType mt = static_cast<MessageType>(type);

    // Aggregate budget. Checked before the per-peer bucket and before
    // the body read, for the same reason the per-peer bucket is: a
    // peer that floods expensive-to-serve types must be shed before
    // its body allocates. This is a node-wide budget — a trip means
    // the *node* is saturated, not that this peer misbehaved, so we
    // close without reporting misbehavior. See AggregateLimiter.h.
    if (aggregateLimiter_ && !aggregateLimiter_->allow(mt))
    {
      log_(Logging::WARNING)
          << "aggregate rate limit exceeded, closing " << endpointString()
          << " (type=" << messageTypeName(mt) << ")";
      forceClose("aggregate rate limit");
      return;
    }

    // The cost is determined by the message type, which we know from
    // the 10-byte header. We consume BEFORE reading the body, so a peer
    // that floods us with expensive-to-serve message types gets cut off
    // before the body even arrives.
    if (isConsensusType(mt))
    {
      // Consensus types are charged only to the consensus bucket,
      // which is checked after the body read (see the body-read lambda).
      // The general bucket is not debited, so consensus traffic can't
      // starve other messages.
    }
    else
    {
      const uint32_t cost = messageCost(mt);
      if (!msgBucket_.tryConsume(cost))
      {
        reportMisbehavior(1, REASON_RATE_LIMIT);
        forceClose("rate limit exceeded");
        return;
      }
    }

    stats_.bytesRecv += MESSAGE_HEADER_SIZE;

    // Zero-length body: async_read on a zero-length buffer has
    // implementation-defined completion semantics on some asio
    // versions and may not fire at all. Dispatch the message directly.
    //
    // After step 6, no post-handshake message has a zero-length body:
    // every encrypted message carries at least a 16-byte MAC. The only
    // messages that reach this branch are pre-encryption control
    // messages (Verack, Ping, Pong, GetPeers, Disconnect). AuthReady
    // used to reach this branch when it was plaintext with an empty
    // payload; now it carries a MAC and goes through the body-read
    // path below.
    if (size == 0)
    {
      stats_.messagesRecv++;
      stats_.lastMessageAt = nowUnix();

      Message msg;
      msg.type = static_cast<MessageType>(type);
      msg.payload.clear();

      // A zero-length body on an encrypted session is a protocol
      // violation: the MAC alone is 16 bytes, so no legitimate
      // encrypted message has length 0. If we reach here with the
      // inbound cipher active, close.
      if (inboundCipher_ == SessionCipherState::Encrypted)
      {
        log_(Logging::WARNING)
            << "zero-length body on encrypted session from "
            << endpointString() << " (type=" << messageTypeName(mt) << ")";
        forceClose("encryption: zero-length body");
        return;
      }

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

                              // Stricter limit for consensus traffic.
                              // Non-validator peers have no legitimate
                              // reason to send proposals or votes.
                              if (msg.type == MessageType::Proposal ||
                                  msg.type == MessageType::Prevote ||
                                  msg.type == MessageType::Precommit)
                              {
                                if (!self->consensusBucket_.tryConsume())
                                {
                                  self->log_(Logging::WARNING)
                                      << "consensus rate limit exceeded by "
                                      << self->endpointString();
                                  self->reportMisbehavior(1, REASON_RATE_LIMIT);
                                  self->forceClose("consensus rate limit exceeded");
                                  return;
                                }
                              }

                              // Decrypt if this session direction is
                              // encrypted, or if the message is the
                              // transition message (AuthReady) that
                              // flips the state.
                              //
                              // The AuthReady case is special: at the
                              // moment its body arrives, inboundCipher_
                              // is still Plaintext (the flip happens
                              // after successful decryption). We use
                              // the message type to decide whether to
                              // attempt decryption, and the successful
                              // decrypt is what flips the state.
                              //
                              // Every other message type uses the
                              // cipher state directly. Once encrypted,
                              // there is no fallback to plaintext —
                              // a fallback would let an attacker force
                              // plaintext by corrupting ciphertext.
                              const bool transitionMessage =
                                  (msg.type == MessageType::AuthReady &&
                                   self->state_ == PeerState::AuthReadyPending);

                              const bool shouldDecrypt =
                                  self->inboundCipher_ == SessionCipherState::Encrypted ||
                                  transitionMessage;

                              if (shouldDecrypt)
                              {
                                if (!self->decryptInbound(msg))
                                {
                                  self->forceClose("encryption: decrypt failed");
                                  return;
                                }
                                if (transitionMessage)
                                {
                                  self->inboundCipher_ = SessionCipherState::Encrypted;
                                }
                              }

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
    case MessageType::Auth:
      handleAuth(msg);
      return;
    case MessageType::AuthReady:
      handleAuthReady(msg);
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

    log_(Logging::DEBUGGING) << "peer " << endpointString()
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

    // Do not transition to Established yet — both sides must
    // authenticate first. Re-arm the handshake timer for the auth
    // phase so a peer that stalls here still times out.
    transitionTo(PeerState::AuthPending);
    armHandshakeTimer();

    log_(Logging::DEBUGGING) << "verack received from " << endpointString()
                             << ", starting auth exchange";

    sendAuth();
  }

  void Peer::sendAuth()
  {
    if (!buildAuthMessage)
    {
      log_(Logging::WARNING) << "no buildAuthMessage callback set for "
                             << endpointString();
      forceClose("auth not configured");
      return;
    }

    AuthMessage a = buildAuthMessage();
    send(Message(MessageType::Auth, serializeAuth(a)));
  }

  void Peer::handleAuth(Message &msg)
  {
    if (state_ != PeerState::AuthPending)
    {
      log_(Logging::WARNING) << "unexpected auth from " << endpointString();
      reportMisbehavior(50, REASON_HANDSHAKE_ORDER);
      forceClose("unexpected auth");
      return;
    }

    AuthMessage a;
    if (!deserializeAuth(msg.payload.data(), msg.payload.size(), a))
    {
      log_(Logging::WARNING) << "malformed auth from " << endpointString();
      reportMisbehavior(config_.banThreshold, REASON_AUTH_FAILED);
      forceClose("malformed auth");
      return;
    }

    if (!verifyAuth)
    {
      log_(Logging::WARNING) << "no verifyAuth callback set for "
                             << endpointString();
      forceClose("auth not configured");
      return;
    }

    uint64_t validatorId = 0;
    if (!verifyAuth(a, validatorId))
    {
      log_(Logging::WARNING) << "auth failed for " << endpointString();
      reportMisbehavior(config_.banThreshold, REASON_AUTH_FAILED);
      forceClose("auth failed");
      return;
    }

    peerPubkey_ = a.pubkey;
    peerEphemeralPubkey_ = a.ephemeralPubkey;
    peerValidatorId_ = validatorId;

    log_(Logging::DEBUGGING) << "peer " << endpointString()
                             << " authenticated"
                             << " validator_id=" << validatorId
                             << " pubkey=" << a.pubkey.toString().substr(0, 16)
                             << " eph=" << a.ephemeralPubkey.toString().substr(0, 16);

    // Do NOT transition to Established yet. The peer must still send
    // and receive AuthReady before the session is usable. The
    // handshake timer remains armed for the AuthReady phase.
    transitionTo(PeerState::AuthReadyPending);
    armHandshakeTimer();

    sendAuthReady();
  }

  void Peer::sendAuthReady()
  {
    // Derive the session keys. This is the last point at which the
    // peer's ephemeral key and our own are both available — after
    // this, the ephemeral secret is wiped.
    if (!deriveSessionKeys())
    {
      forceClose("encryption: key derivation failed");
      return;
    }

    // Flip the outbound cipher state BEFORE calling send, so that
    // send() encrypts this message. The AuthReady is the first
    // encrypted message on the wire, and its successful decryption
    // at the peer is what confirms the two sides derived the same
    // session keys.
    outboundCipher_ = SessionCipherState::Encrypted;

    Message msg(MessageType::AuthReady);
    if (!send(std::move(msg)))
    {
      // send() already force-closed if the encryption failed; this
      // branch is for the send() return value in general. Nothing
      // more to do.
      forceClose("encryption: failed to send authready");
    }
  }

  void Peer::handleAuthReady(Message &msg)
  {
    if (state_ != PeerState::AuthReadyPending)
    {
      // AuthReady before Auth, or after Established, or during
      // Disconnecting — all protocol violations. Score and close;
      // the violation is unambiguous.
      log_(Logging::WARNING) << "unexpected authready from "
                             << endpointString();
      reportMisbehavior(50, REASON_HANDSHAKE_ORDER);
      forceClose("unexpected authready");
      return;
    }

    // The message payload has already been decrypted by the read
    // path (see the body-read lambda in handleReadHeader). A
    // successful decryption is what flipped inboundCipher_ to
    // Encrypted. The plaintext of AuthReady must be empty — it is a
    // key-confirmation signal, not a data-bearing message.
    if (!msg.payload.empty())
    {
      log_(Logging::WARNING)
          << "authready plaintext is non-empty from " << endpointString()
          << " (" << msg.payload.size() << " bytes)";
      forceClose("encryption: authready payload non-empty");
      return;
    }

    handshakeTimer_.cancel();
    transitionTo(PeerState::Established);

    log_(Logging::DEBUGGING)
        << "encrypted session established with " << endpointString();

    armPingTimer();

    if (onEstablished)
      onEstablished(*this);
  }

  //  Session encryption

  bool Peer::deriveSessionKeys()
  {
    if (sessionKeysValid_)
      return true;

    // Compute the shared secret. The peer's ephemeral public key
    // arrived in its Auth message. Our ephemeral secret is still
    // valid here — it is wiped by this function on success.
    uint8_t shared[Crypto::X25519_KEY_SIZE];
    if (!Crypto::x25519(ephemeralKeypair_.secretKey.data(),
                        peerEphemeralPubkey_.data.data(),
                        shared))
    {
      // All-zero shared secret: the peer's ephemeral public key is a
      // low-order point. A peer that has passed Auth with a bad
      // ephemeral key is either broken or malicious.
      log_(Logging::WARNING)
          << "x25519 produced a zero shared secret with " << endpointString()
          << " — peer ephemeral key is low-order";
      return false;
    }

    // Our own identity public key is supplied by the node layer via
    // the getOurIdentityPubkey callback. It's the same key already
    // used to build the Auth message.
    if (!getOurIdentityPubkey)
    {
      log_(Logging::WARNING)
          << "no getOurIdentityPubkey callback set for " << endpointString();
      Crypto::secureZero(shared, sizeof(shared));
      return false;
    }
    const Crypto::PublicKey ourIdentity = getOurIdentityPubkey();

    // Canonical A/B ordering by network nonce. Both sides compute the
    // same A/B from the two nonces exchanged in Version, so they agree
    // without negotiation.
    weAreLowerNonce_ = (localNonce_ < peerNonce_);

    sessionKeys_ = Crypto::deriveSessionKeys(
        shared,
        ephemeralKeypair_.publicKey.data(),
        peerEphemeralPubkey_.data.data(),
        ourIdentity.data.data(),
        peerPubkey_.data.data(),
        localNonce_,
        peerNonce_,
        weAreLowerNonce_);

    Crypto::secureZero(shared, sizeof(shared));

    // Wipe the ephemeral secret now. The shared secret is folded into
    // the session keys; the ephemeral secret's only purpose was to
    // produce it. Keeping it around would let a memory disclosure of
    // this Peer retroactively re-derive the session keys.
    Crypto::secureZero(ephemeralKeypair_.secretKey.data(),
                       ephemeralKeypair_.secretKey.size());

    sessionKeysValid_ = true;
    return true;
  }

  void Peer::buildNonce(uint64_t counter,
                        uint8_t out[Crypto::AEAD_NONCE_SIZE]) const noexcept
  {
    // 24-byte XChaCha20 nonce. The low 8 bytes are the counter,
    // little-endian; the remaining 16 bytes are zero.
    //
    // The security argument: within a single session, the key is
    // fresh (derived from a fresh X25519 ephemeral exchange), and the
    // counter is strictly increasing per direction. So no (key, nonce)
    // pair is ever reused. Across sessions, the key changes, so a
    // repeat of the same nonce bytes is harmless.
    //
    // The 24-byte width of XChaCha20's nonce means the counter could
    // be 24 bytes; using 8 is a deliberate choice so the counter's
    // wrap point is at 2^64 rather than something that depends on the
    // library's internal counter width. The remaining 16 bytes being
    // zero is a constant; there is no reason to fill them with
    // anything.
    for (int i = 0; i < 8; ++i)
      out[i] = static_cast<uint8_t>(counter >> (8 * i));
    for (int i = 8; i < static_cast<int>(Crypto::AEAD_NONCE_SIZE); ++i)
      out[i] = 0;
  }

  uint8_t Peer::directionTag(bool asSender) const noexcept
  {
    // The AAD direction tag distinguishes the two directions of the
    // same session, so a ciphertext cannot be reflected from one
    // direction to the other. The tag is a property of "which side is
    // the sender": 0x00 if the sender is the lower-nonce side, 0x01
    // if the sender is the higher-nonce side.
    //
    // `asSender` is "am I the sender of the message being tagged".
    // For our outbound messages it's true; for inbound messages (where
    // we are constructing the AAD to verify) it's false.
    //
    // Both sides agree because both compute weAreLowerNonce_ from the
    // same two nonces. See deriveSessionKeys in SessionKey.cpp.
    const bool senderIsLower = weAreLowerNonce_ ? asSender : !asSender;
    return senderIsLower ? uint8_t{0x00} : uint8_t{0x01};
  }

  bool Peer::encryptOutbound(Message &msg)
  {
    if (!sessionKeysValid_)
    {
      log_(Logging::WARNING)
          << "encryptOutbound called with no session keys for "
          << endpointString();
      return false;
    }

    // Nonce overflow check. Checked before use; a counter at
    // UINT64_MAX still sends one more message, and the next send
    // fails. Unreachable in practice (2^64 messages), but the check
    // is one comparison and nonce reuse is catastrophic.
    if (outboundNonce_ == UINT64_MAX)
    {
      log_(Logging::WARNING)
          << "outbound nonce exhausted for " << endpointString();
      return false;
    }

    // Build the AAD. 3 bytes: message type (LE uint16) || direction
    // tag. Binding the type means the outer wire header's type field
    // is not trusted — the receiver verifies it against the AAD.
    // Binding the direction prevents cross-direction reflection.
    uint8_t aad[3];
    aad[0] = static_cast<uint8_t>(static_cast<uint16_t>(msg.type) & 0xFF);
    aad[1] = static_cast<uint8_t>((static_cast<uint16_t>(msg.type) >> 8) & 0xFF);
    aad[2] = directionTag(/*asSender=*/true);

    uint8_t nonce[Crypto::AEAD_NONCE_SIZE];
    buildNonce(outboundNonce_, nonce);

    const uint8_t *key = sessionKeys_.forSend(weAreLowerNonce_);

    // The wire layout is [ciphertext][mac]. Total length is
    // plaintext.size() + AEAD_MAC_SIZE.
    std::vector<uint8_t> framed(msg.payload.size() + Crypto::AEAD_MAC_SIZE);

    const uint8_t *plaintextPtr =
        msg.payload.empty() ? nullptr : msg.payload.data();

    if (!Crypto::aeadEncrypt(plaintextPtr, msg.payload.size(),
                             aad, sizeof(aad),
                             key, nonce,
                             framed.data(),
                             framed.data() + msg.payload.size()))
    {
      log_(Logging::WARNING)
          << "aeadEncrypt failed for " << endpointString()
          << " (type=" << messageTypeName(msg.type) << ")";
      return false;
    }

    msg.payload = std::move(framed);
    outboundNonce_++;
    return true;
  }

  bool Peer::decryptInbound(Message &msg)
  {
    if (!sessionKeysValid_)
    {
      log_(Logging::WARNING)
          << "decryptInbound called with no session keys for "
          << endpointString();
      return false;
    }

    // Sanity bound on the inbound nonce. A peer that exceeds this many
    // messages on one session is either broken or attacking; the
    // connection is torn down before the counter can wrap.
    if (inboundNonce_ >= config_.maxInboundNonce)
    {
      log_(Logging::WARNING)
          << "inbound nonce exceeds bound for " << endpointString()
          << " (" << inboundNonce_ << ")";
      return false;
    }

    // The framed payload is [ciphertext][mac]. A payload shorter than
    // the MAC size cannot contain a valid frame.
    if (msg.payload.size() < Crypto::AEAD_MAC_SIZE)
    {
      log_(Logging::WARNING)
          << "ciphertext too short from " << endpointString()
          << " (" << msg.payload.size() << " bytes)";
      return false;
    }

    uint8_t aad[3];
    aad[0] = static_cast<uint8_t>(static_cast<uint16_t>(msg.type) & 0xFF);
    aad[1] = static_cast<uint8_t>((static_cast<uint16_t>(msg.type) >> 8) & 0xFF);
    aad[2] = directionTag(/*asSender=*/false);

    uint8_t nonce[Crypto::AEAD_NONCE_SIZE];
    buildNonce(inboundNonce_, nonce);

    const uint8_t *key = sessionKeys_.forReceive(weAreLowerNonce_);

    const size_t ciphertextLen = msg.payload.size() - Crypto::AEAD_MAC_SIZE;
    const uint8_t *ciphertext = msg.payload.data();
    const uint8_t *mac = msg.payload.data() + ciphertextLen;

    std::vector<uint8_t> plaintext(ciphertextLen);

    const uint8_t *ciphertextPtr = (ciphertextLen == 0) ? nullptr : ciphertext;
    uint8_t *plaintextPtr = (ciphertextLen == 0) ? nullptr : plaintext.data();

    if (!Crypto::aeadDecrypt(ciphertextPtr, ciphertextLen,
                             aad, sizeof(aad),
                             key, nonce,
                             mac,
                             plaintextPtr))
    {
      // Do not distinguish "wrong key", "wrong nonce", "wrong AAD",
      // or "tampered ciphertext". All of them mean the same thing at
      // this layer: the peer and we disagree about the session. Log
      // and let the caller force-close.
      log_(Logging::WARNING)
          << "AEAD decryption failed for " << endpointString()
          << " (type=" << messageTypeName(msg.type)
          << " size=" << msg.payload.size() << ")";
      return false;
    }

    msg.payload = std::move(plaintext);
    inboundNonce_++;
    return true;
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

    // Encrypt before the size check, because the size check applies
    // to the ciphertext size on the wire. The plaintext length is
    // what the caller controls; the wire size is plaintext + MAC.
    if (outboundCipher_ == SessionCipherState::Encrypted)
    {
      if (!encryptOutbound(msg))
      {
        forceClose("encryption: outbound encrypt failed");
        return false;
      }
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
        self->state_ == PeerState::VerackPending ||
        self->state_ == PeerState::AuthPending ||
        self->state_ == PeerState::AuthReadyPending) {
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