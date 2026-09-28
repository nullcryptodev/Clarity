#pragma once

#include "Tests/Utils.h"

namespace Tests
{

  // ManagerHarness - Owns one P2PManager and its event loop thread.
  // Tracks connected and disconnected events from the callbacks.
  // All manager queries  go through the event loop via a posted
  // lambda, using a shared_ptr  promise so a timed-out query can't dangle.

  class ManagerHarness
  {
  public:
    ManagerHarness(uint16_t listen_port, const std::string &label)
    {
      data_dir_ = std::filesystem::temp_directory_path() /
                  ("clrty_p2p_mgr_" + label);
      std::filesystem::remove_all(data_dir_);
      std::filesystem::create_directories(data_dir_);

      // The harness's node identity. In production, Node provides a
      // persistent key via loadOrCreateNodeKey(); here we generate a
      // fresh one per harness. Every peer this harness talks to sees
      // the same pubkey, and we verify theirs against the signature
      // on the wire. There's no validator binding — that's a Node-
      // level policy, and the harness is a lower-level test object.
      keypair_ = Crypto::generateKeyPair();

      P2P::P2PConfig cfg;
      cfg.magic = P2P::MAGIC_REGTEST;
      cfg.listenPort = listen_port;
      cfg.targetOutbound = 0; // tests dial explicitly
      cfg.maxInbound = 8;
      cfg.maxOutbound = 8;
      cfg.workerThreads = 1;

      mgr_ = std::make_unique<P2P::P2PManager>(cfg, logger_, data_dir_.string());

      mgr_->onPeerConnected = [this](Id id)
      {
        {
          std::lock_guard<std::mutex> lock(mu_);
          connected_.push_back(id);
        }
        cv_.notify_all();
      };

      mgr_->onPeerDisconnected = [this](Id id, const std::string &reason)
      {
        {
          std::lock_guard<std::mutex> lock(mu_);
          disconnected_.push_back({id, reason});
        }
        cv_.notify_all();
      };

      mgr_->onMessage = [this](const P2P::Message &m, Id from)
      {
        {
          std::lock_guard<std::mutex> lock(mu_);
          messages_.push_back({m, from});
        }
        cv_.notify_all();
      };

      // ---- Auth wiring ----
      //
      // Without these two callbacks, every peer's Auth exchange fails
      // (buildAuthMessage returns a null message, verifyAuth returns
      // false), and no handshake ever reaches Established. The
      // ManagerHarness tests exist to exercise the P2PManager's peer
      // table, ban list, address book, and event callbacks — all of
      // which sit downstream of a successful handshake. So the
      // harness has to speak the auth protocol.
      //
      // The protocol is the same as Node::buildAuthMessageForPeer /
      // Node::verifyPeerAuth, minus the validator lookup. The
      // orderNonces / computeAuthChallenge helpers are shared with
      // Node, so the wire format can't drift between the two.

      mgr_->buildAuthMessage = [this](P2P::Peer &peer) -> P2P::AuthMessage
      {
        P2P::AuthMessage a;
        a.pubkey = keypair_.publicKey;

        const uint64_t my_nonce = peer.localNonce();
        const uint64_t their_nonce = peer.peerNonce();

        P2P::AuthNonces nonces = P2P::orderNonces(
            peer.direction(), my_nonce, their_nonce);

        Crypto::Hash challenge = P2P::computeAuthChallenge(nonces, a.pubkey);
        a.signature = Crypto::sign(challenge, keypair_.secretKey);
        return a;
      };

      mgr_->verifyAuth = [](P2P::Peer &peer,
                            const P2P::AuthMessage &a,
                            uint64_t &outValidatorId) -> bool
      {
        // The harness never claims validator status. A real Node
        // would look the pubkey up in the active set here; the
        // harness is testing the P2P layer, not validator binding.
        outValidatorId = 0;

        if (a.pubkey.isNull() || a.signature.isNull())
          return false;

        const uint64_t my_nonce = peer.localNonce();
        const uint64_t their_nonce = peer.peerNonce();

        P2P::AuthNonces nonces = P2P::orderNonces(
            peer.direction(), my_nonce, their_nonce);

        Crypto::Hash challenge = P2P::computeAuthChallenge(nonces, a.pubkey);
        return Crypto::verify(challenge, a.pubkey, a.signature);
      };

      mgr_->start({});
      thread_ = std::thread([this]
                            { mgr_->run(); });
    }

    ~ManagerHarness()
    {
      stop();
    }

    ManagerHarness(const ManagerHarness &) = delete;
    ManagerHarness &operator=(const ManagerHarness &) = delete;

    void stop()
    {
      if (!mgr_)
        return;
      mgr_->stop();
      if (thread_.joinable())
        thread_.join();
      mgr_.reset();
    }

    P2P::P2PManager &mgr() { return *mgr_; }

    // ---- Wait helpers ----

    bool waitForConnected(size_t count, std::chrono::milliseconds timeout)
    {
      std::unique_lock<std::mutex> lock(mu_);
      return cv_.wait_for(lock, timeout, [&]
                          { return connected_.size() >= count; });
    }

    bool waitForDisconnected(size_t count, std::chrono::milliseconds timeout)
    {
      std::unique_lock<std::mutex> lock(mu_);
      return cv_.wait_for(lock, timeout, [&]
                          { return disconnected_.size() >= count; });
    }

    bool waitForMessage(size_t count, std::chrono::milliseconds timeout)
    {
      std::unique_lock<std::mutex> lock(mu_);
      return cv_.wait_for(lock, timeout, [&]
                          { return messages_.size() >= count; });
    }

    // Wait until at least `count` messages of the given type have arrived.
    bool waitForMessageOfType(P2P::MessageType type, size_t count,
                              std::chrono::milliseconds timeout)
    {
      std::unique_lock<std::mutex> lock(mu_);
      return cv_.wait_for(lock, timeout, [&]
                          {
        size_t n = 0;
        for (const auto &m : messages_)
        if (m.first.type == type)
          ++n;
        return n >= count; });
    }

    // Wait until the manager reports `want` peers in the Established
    // state, or the timeout expires. Posts a query to the event loop
    // each iteration; the shared_ptr promise prevents a dangling
    // reference if the query outlives this stack frame.
    bool waitForEstablished(size_t want, std::chrono::milliseconds timeout)
    {
      auto deadline = std::chrono::steady_clock::now() + timeout;
      while (std::chrono::steady_clock::now() < deadline)
      {
        auto p = std::make_shared<std::promise<size_t>>();
        auto f = p->get_future();
        mgr_->post([this, p]
                   {
          try
          {
            p->set_value(mgr_->snapshot().established);
          }
          catch (...)
          {
            // promise already satisfied; ignore
          } });
        if (f.wait_for(200ms) == std::future_status::ready &&
            f.get() >= want)
          return true;
        std::this_thread::sleep_for(20ms);
      }
      return false;
    }

    size_t connectedCount() const
    {
      std::lock_guard<std::mutex> lock(mu_);
      return connected_.size();
    }

    size_t disconnectedCount() const
    {
      std::lock_guard<std::mutex> lock(mu_);
      return disconnected_.size();
    }

    const std::vector<std::pair<P2P::Message, Id>> &messages() const
    {
      return messages_;
    }

    const std::vector<std::pair<Id, std::string>> &disconnects() const
    {
      return disconnected_;
    }

  private:
    NoopLogger logger_;
    std::filesystem::path data_dir_;
    std::unique_ptr<P2P::P2PManager> mgr_;
    std::thread thread_;

    // The harness's node identity, used to sign and verify Auth
    // exchanges. Generated once per harness.
    Crypto::KeyPair keypair_;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::vector<Id> connected_;
    std::vector<std::pair<Id, std::string>> disconnected_;
    std::vector<std::pair<P2P::Message, Id>> messages_;
  };
}