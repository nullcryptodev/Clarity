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
#include "AuthMessage.h"

#include "Common/RateLimiter.h"

#include "Crypto/Chacha20Poly1305.h"
#include "Crypto/Ed25519.h"
#include "Crypto/SessionKey.h"
#include "Crypto/X25519.h"

#include "Logging/LoggerRef.h"

namespace P2P
{
  using boost::asio::ip::tcp;

  // TODO remove, use Id
  using PeerId = uint64_t;
  inline constexpr PeerId INVALID_PEER_ID = 0;

  struct VersionMessage;  // forward decl
  class AggregateLimiter; // forward decl

  enum class PeerDirection : uint8_t
  {
    Inbound,
    Outbound,
  };

  // Whether a given direction on this peer's session is still
  // plaintext or has transitioned to encrypted. The two directions
  // transition independently: the write path flips to Encrypted the
  // moment we send our AuthReady, and the read path flips the moment
  // we successfully decrypt the peer's AuthReady. Between those two
  // events the session is half-encrypted on the wire, which is why
  // the flags are per-direction and not a single peer-wide state.
  enum class SessionCipherState : uint8_t
  {
    Plaintext,
    Encrypted,
  };

  class Peer : public std::enable_shared_from_this<Peer>
  {
  public:
    Peer(PeerId id,
         tcp::socket socket,
         PeerDirection direction,
         const P2PConfig &config,
         Logging::LoggerRef log,
         AggregateLimiter *aggregateLimiter = nullptr);
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

    uint64_t validatorId() const noexcept { return peerValidatorId_; }
    const Crypto::PublicKey &pubkey() const noexcept { return peerPubkey_; }
    const Crypto::X25519KeyPair &ephemeralKeypair() const noexcept { return ephemeralKeypair_; }

    // The peer's ephemeral X25519 public key, from its Auth message.
    // Populated in handleAuth. Read by deriveSessionKeys.
    const Crypto::PublicKey &ephemeralPubkey() const noexcept
    {
      return peerEphemeralPubkey_;
    }

    uint64_t localNonce() const noexcept { return localNonce_; }
    uint64_t peerNonce() const noexcept { return peerNonce_; }

    // True once both directions have transitioned to Encrypted. For
    // RPC introspection and tests. A peer in Established but not
    // encrypted is a state that should never be observable, but the
    // accessor makes it possible to check.
    bool sessionIsEncrypted() const noexcept
    {
      return outboundCipher_ == SessionCipherState::Encrypted &&
             inboundCipher_ == SessionCipherState::Encrypted;
    }

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

    // Fills in our Auth message. Set by P2PManager, which holds the
    // node's signing key and both nonces. The peer's ephemeral public
    // key is populated by the manager-supplied callback.
    std::function<AuthMessage()> buildAuthMessage;

    // Verifies the peer's Auth message. Returns true if the signature
    // is valid AND the pubkey is acceptable (validator or not, per
    // policy). On success, outValidatorId is set to the validator ID
    // bound to this pubkey, or 0 if the peer is authenticated but not
    // a validator. Set by P2PManager; carries the Node lookup.
    std::function<bool(const AuthMessage &, uint64_t &outValidatorId)>
        verifyAuth;

    // Returns our own Ed25519 identity public key — the one carried in
    // the Auth message. Set by P2PManager. Called once per session,
    // during deriveSessionKeys. If unset, session key derivation
    // fails and the handshake is torn down.
    std::function<Crypto::PublicKey()> getOurIdentityPubkey;

    // Fired exactly once, after the peer transitions to Established.
    // That is: after both sides have exchanged and verified Auth and
    // AuthReady. Used by P2PManager to notify the node that a peer is
    // now ready to exchange application messages (sync, block gossip,
    // transaction relay).
    std::function<void(Peer &)> onEstablished;

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
    void handleAuth(Message &msg);
    void handleAuthReady(Message &msg);
    void sendAuth();
    void sendAuthReady();

    // ---- Timers ----
    void armHandshakeTimer();
    void armPingTimer();

    // ---- Send machinery ----
    void startRead();
    void startWriteIfNeeded();
    void drainSendQueue();
    size_t sendQueueBytes() const;

    // ---- Session encryption ----

    // Compute the session keys from (shared secret, both ephemeral
    // public keys, both identity public keys, both nonces). Wipes the
    // ephemeral secret on success. Returns false on any failure, in
    // which case the caller must force-close.
    bool deriveSessionKeys();

    // Encrypt the message payload in place, replacing it with the
    // framed ciphertext (ciphertext || mac). Increments the outbound
    // nonce on success. Returns false on failure; the caller must
    // force-close and must NOT send the message.
    bool encryptOutbound(Message &msg);

    // Decrypt the message payload in place, replacing it with the
    // plaintext. Increments the inbound nonce on success. Returns
    // false on failure; the caller must force-close and must NOT
    // dispatch the message.
    bool decryptInbound(Message &msg);

    // Build the 24-byte XChaCha20 nonce from a 64-bit counter. The
    // low 8 bytes are the counter (little-endian); the high 16 bytes
    // are zero. Reusing this construction across sessions would be
    // catastrophic, but each session has a fresh key, so the nonce
    // only needs to be unique within a session — and it is, because
    // the counter never wraps (see the bound checks in encryptOutbound
    // and decryptInbound).
    void buildNonce(uint64_t counter, uint8_t out[Crypto::AEAD_NONCE_SIZE]) const noexcept;

    // Direction tag for the AAD. 0x00 for messages sent by the
    // lower-nonce side, 0x01 for the higher-nonce side. `asSender`
    // distinguishes "what tag do I use when I send" from "what tag do
    // I expect when I receive".
    uint8_t directionTag(bool asSender) const noexcept;

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
    // The networkNonce we sent in our Version message. Used to build
    // the auth challenge. Captured from the VersionMessage returned by
    // buildVersionMessage() in beginHandshake().
    uint64_t localNonce_ = 0;

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

    // Rate limiters. One bucket for all inbound messages, one
    // stricter bucket for consensus messages only. Both are disabled
    // when their config pair is zero.
    //
    // NOT thread-safe by design (see Common/RateLimiter.h). Safe here
    // because they are only touched from the socket's read completion
    // handlers, and asio guarantees at most one completion handler per
    // socket runs at a time. If the socket is ever wrapped in a strand
    // (needed to allow concurrent read/write on the same socket, or to
    // multiplex multiple logical peers onto one socket), this is still
    // safe; if the buckets are ever shared across Peers, it is not.
    Common::RateLimiter msgBucket_;
    Common::RateLimiter consensusBucket_;

    // Node-wide aggregate budget. Shared across all peers, owned by
    // P2PManager. May be null (P2P-only tests that construct a Peer
    // directly). Not owned; P2PManager constructs the limiter before
    // any Peer and destroys it after all Peers are gone.
    //
    // Charged in handleReadHeader, after the magic/size checks and
    // before the per-peer bucket and body read. A trip closes the
    // connection WITHOUT reporting misbehavior — see AggregateLimiter.h.
    AggregateLimiter *aggregateLimiter_ = nullptr;

    // Authentication. Populated from the peer's Auth message.
    // peerValidatorId_ is 0 for an authenticated non-validator.
    Crypto::PublicKey peerPubkey_;
    Crypto::PublicKey peerEphemeralPubkey_{};
    uint64_t peerValidatorId_ = 0;

    // Our ephemeral X25519 keypair for this session. Generated in the
    // constructor, used to build our Auth message (via
    // getOurEphemeralPubkey, exposed through the manager's
    // buildAuthMessage callback) and to derive the session keys after
    // the peer's Auth arrives. The secret is wiped by
    // deriveSessionKeys on success, and by the destructor if the
    // handshake aborts before derivation. Never persisted, never
    // leaves this Peer.
    Crypto::X25519KeyPair ephemeralKeypair_;

    // Session keys, derived in sendAuthReady after the peer's Auth has
    // been received. Held for the lifetime of the session. The
    // ephemeral secret is zeroed immediately after derivation, because
    // the shared secret is already folded into these keys.
    Crypto::DerivedSessionKeys sessionKeys_{};
    bool sessionKeysValid_ = false;
    bool weAreLowerNonce_ = false;

    // Cipher state, per direction. Independent transitions — see the
    // enum comment.
    SessionCipherState outboundCipher_ = SessionCipherState::Plaintext;
    SessionCipherState inboundCipher_ = SessionCipherState::Plaintext;

    // Per-direction nonce counters. Outbound increments on each
    // encrypted send; inbound on each successfully decrypted receive.
    // Both start at 0. The AuthReady uses counter 0 in each direction;
    // the first application message uses 1; and so on.
    uint64_t outboundNonce_ = 0;
    uint64_t inboundNonce_ = 0;

    // Shutdown
    std::string closeReason_;
    bool reportedDisconnect_ = false;
  };

  using PeerPtr = std::shared_ptr<Peer>;

} // namespace P2P