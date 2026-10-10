// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Node.h"

#include "Core/Genesis.h"
#include "Core/TransactionExecutor.h"
#include "Core/ValidatorRotation.h"
#include "Core/EquivocationProof.h"
#include "Consensus/Message.h"
#include "P2P/MessageTypes.h"
#include "P2P/VersionMessage.h"
#include "P2P/ProofMessages.h"

#include "Crypto/Ed25519.h"
#include "Logging/ILogger.h"
#include "Logging/LoggerRef.h"
#include "Crypto/Random.h"

#include <fstream>
#include <chrono>
#include <filesystem>
#include <stdexcept>

using namespace std::chrono_literals;

namespace Node
{
  namespace
  {
    constexpr uint32_t WAL_KIND_VOTE = 0;
    constexpr uint32_t WAL_KIND_LOCK = 1;

    void writeU32BE(std::vector<uint8_t> &out, uint32_t v)
    {
      out.push_back(uint8_t((v >> 24) & 0xFF));
      out.push_back(uint8_t((v >> 16) & 0xFF));
      out.push_back(uint8_t((v >> 8) & 0xFF));
      out.push_back(uint8_t((v) & 0xFF));
    }

    void writeU64BE(std::vector<uint8_t> &out, uint64_t v)
    {
      for (int i = 7; i >= 0; --i)
        out.push_back(uint8_t((v >> (i * 8)) & 0xFF));
    }

    uint32_t readU32BE(const uint8_t *p)
    {
      return (uint32_t(p[0]) << 24) |
             (uint32_t(p[1]) << 16) |
             (uint32_t(p[2]) << 8) |
             (uint32_t(p[3]));
    }

    uint64_t readU64BE(const uint8_t *p)
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v = (v << 8) | uint64_t(p[i]);
      return v;
    }
  } // anonymous namespace

  //  Construction / Destruction

  Node::Node(NodeConfig config, Logging::ILogger &logger)
      : config_(std::move(config)), logger_(logger), log_(std::make_unique<Logging::LoggerRef>(logger, "Node"))
  {
    validateConfig(config_);

    (*log_)(Logging::DEBUGGING)
        << "Node constructing: network=" << networkName(config_.network)
        << " chain_id=0x" << std::hex << config_.chain_id << std::dec
        << " data_dir=" << config_.data_dir
        << " validator_id=" << config_.validator_id;
  }

  Node::~Node()
  {
    stop();
  }

  //  Lifecycle

  void Node::start()
  {
    if (running_.exchange(true))
    {
      (*log_)(Logging::WARNING) << "start() called but node is already running";
      return;
    }

    (*log_)(Logging::INFO) << "Node starting...";

    try
    {
      initStorage();
      initGenesis();
      initMempool();
      initP2P();
      initConsensus();
    }
    catch (const std::exception &e)
    {
      (*log_)(Logging::ERROR) << "Node startup failed: " << e.what();
      running_ = false;
      throw;
    }

    (*log_)(Logging::DEBUGGING)
        << "Node started at height " << chain_->height()
        << " (validator: " << (config_.validator_id != 0 ? "yes" : "no") << ")";
  }

  void Node::run()
  {
    if (!running_)
    {
      throw std::runtime_error("Node::run() called without start()");
    }

    (*log_)(Logging::INFO) << "Node entering event loop";

    // Kick off P2P listening and connection attempts.
    p2p_->start(config_.seeds);

    //  Install signal handling on the P2P io_context.
    //
    //  asio's signal_set catches SIGINT and SIGTERM via a self-pipe
    //  and delivers the notification as an event on the io_context.
    //  The callback below runs on the event loop thread — the same
    //  thread that services P2P I/O and consensus ticks — so it is
    //  safe to take locks, join threads, and call node methods.
    signals_ = std::make_unique<boost::asio::signal_set>(
        p2p_->executor(), SIGINT, SIGTERM);
    signals_->async_wait(
        [this](const boost::system::error_code &ec, int signum)
        {
          if (ec)
            return;
          (*log_)(Logging::INFO) << "Received signal " << signum
                                 << ", shutting down";
          stop();
        });

    armConsensusPollTimer();
    armSyncTickTimer();

    // Run the event loop. Blocks until stop() is called.
    p2p_->run();

    (*log_)(Logging::INFO) << "Node event loop exited";
  }

  void Node::stop()
  {
    if (stopping_.exchange(true))
      return;

    if (!running_)
      return;

    (*log_)(Logging::INFO) << "Node stopping";

    if (consensus_timer_)
      consensus_timer_->cancel();
    if (sync_timer_)
      sync_timer_->cancel();

    if (signals_)
      signals_->cancel();

    if (consensus_)
      consensus_->stop();

    if (p2p_)
      p2p_->stop();

    if (state_db_)
      state_db_->flush();

    running_ = false;
    (*log_)(Logging::INFO) << "Node stopped";
  }

  void Node::maybeStartConsensus()
  {
    if (!consensus_)
      return;

    if (chain_ && chain_->isSyncing())
    {
      (*log_)(Logging::DEBUGGING)
          << "Consensus deferred: syncing (height=" << chain_->height()
          << " best_peer=" << chain_->bestPeerHeight() << ")";
      consensus_started_ = false;
      return;
    }

    if (consensus_started_.exchange(true))
      return;

    size_t established = 0;
    if (p2p_)
    {
      established = p2p_->snapshot().established;
    }

    auto active = getActiveSet();
    const size_t quorum = Core::bftQuorum(active.size());
    const size_t reachable = 1 + established;

    if (reachable < quorum)
    {
      (*log_)(Logging::DEBUGGING)
          << "Consensus deferred: quorum=" << quorum
          << " reachable=" << reachable
          << " (established=" << established << ")";
      consensus_started_ = false;
      return;
    }

    Height next_height = chain_->height() + 1;
    consensus_->start(next_height);

    (*log_)(Logging::DEBUGGING)
        << "Consensus started at height " << next_height
        << " (quorum=" << quorum
        << " reachable=" << reachable
        << " established=" << established << ")";
  }

  //  Subsystem initialization

  void Node::initStorage()
  {
    (*log_)(Logging::INFO) << "Initializing storage...";

    std::filesystem::create_directories(config_.data_dir);

    std::string state_path = config_.data_dir + "/state";
    state_db_ = std::make_unique<State::StateDB>(state_path,
                                                 config_.state_map_size);

    chain_db_ = std::make_unique<Core::ChainDB>(*state_db_);
    chain_ = std::make_unique<Core::Chain>(*chain_db_);
    mempool_ = std::make_unique<Core::Mempool>(*state_db_);

    (*log_)(Logging::DEBUGGING)
        << "Storage opened: state at " << state_path
        << " top height=" << chain_->height();
  }

  void Node::initMempool()
  {
    if (!mempool_)
      return;

    auto view = makeStateView();
    if (!view)
    {
      (*log_)(Logging::WARNING)
          << "initMempool: could not build state view, skipping load";
      return;
    }

    mempool_->load(*view);

    (*log_)(Logging::INFO)
        << "Mempool loaded: " << Logging::BRIGHT_GREEN << mempool_->size() << " pending txs";
  }

  void Node::initGenesis()
  {
    if (!config_.apply_genesis_on_start)
      return;

    Core::GenesisConfig cfg = genesisConfig();

    //  Inspect the existing DB state first. This is a read-only
    //  check; use a short-lived autocommit StateAccess for it. The
    //  ReadTxn it holds is released when the StateAccess goes out
    //  of scope.
    bool db_initialized = false;
    {
      auto head = chain_db_->getHead();
      db_initialized = (head.height > 0) || !head.hash.isNull() ||
                       !chain_db_->getGenesisHash().isNull();
    }

    if (db_initialized)
    {
      if (chain_db_->getChainId() != config_.chain_id)
        throw std::runtime_error(
            "node: chain ID mismatch — DB is from a different network");
      if (chain_db_->getGenesisHash().isNull())
        throw std::runtime_error(
            "node: DB is initialized but has no genesis hash — corrupted");
      return;
    }

    (*log_)(Logging::INFO)
        << "Empty state detected, applying genesis for "
        << networkName(config_.network);

    //  Genesis is one atomic write: the entire genesis state, the
    //  genesis block, and the chain head all live in a single MDBX
    //  write txn. Either all of it commits, or none of it does.
    //
    //  This also sidesteps the MDBX_TXN_OVERLAPPING problem that
    //  arises when an autocommit StateAccess holds a read txn and
    //  then tries to write through db_.rawPut(). Under a bound
    //  write txn, every read and write goes through the write txn
    //  and no read txn is ever opened.
    Crypto::Hash genesis_hash;

    {
      auto txn = state_db_->beginWrite();
      State::StateAccess state(*state_db_, txn, /*version=*/0);

      Core::applyGenesis(state, cfg);
      state.commit(0);

      Core::Block genesis = Core::makeGenesisBlock(state, cfg);
      genesis_hash = genesis.hash();

      // Pinned-hash check: refuse to start if genesis construction
      // has drifted from the canonical value. Skipped when the
      // caller supplied a genesis override — that's a test or a
      // private chain, and the override is explicitly saying "use
      // this genesis, not the network's."
      if (!config_.test_genesis_override.has_value())
      {
        Crypto::Hash expected = Core::expectedGenesisHash(cfg);
        if (!expected.isNull() && genesis_hash != expected)
        {
          throw std::runtime_error(
              "node: genesis hash mismatch — genesis construction has "
              "changed since this network was defined. "
              "Expected " +
              expected.toString() +
              ", got " + genesis_hash.toString() +
              ". This is a consensus-breaking change; do not proceed.");
        }

        if (expected.isNull())
        {
          (*log_)(Logging::WARNING)
              << "No pinned genesis hash for chain_id 0x"
              << std::hex << cfg.chain_id << std::dec
              << ". Computed hash: " << genesis_hash.toString()
              << ". Consider pinning it in GlobalConfig to catch future "
                 "genesis-construction drift.";
        }
      }

      chain_db_->storeBlockTxn(txn, genesis, genesis_hash);

      Core::ChainDB::ChainHead ghead;
      ghead.hash = genesis_hash;
      ghead.height = 0;
      chain_db_->setHeadTxn(txn, ghead);

      txn.commit();
    }

    //  Wipe any stale consensus WAL. A fresh DB is a fresh chain;
    //  any WAL rows from a previous life reference blocks whose
    //  height and hash no longer correspond to anything on the
    //  current chain. If they survived, the consensus engine would
    //  replay them at start() and force this validator to vote for
    //  a block that no other node recognises, deadlocking the
    //  round.
    state_db_->wipeConsensusWal();

    chain_db_->setChainId(config_.chain_id);
    chain_db_->setGenesisHash(genesis_hash);

    (*log_)(Logging::INFO)
        << "Genesis applied: block hash="
        << genesis_hash.toString().substr(0, 16);
  }

  void Node::initP2P()
  {
    if (!config_.enable_p2p)
    {
      (*log_)(Logging::INFO) << "P2P disabled by config, skipping";
      return;
    }

    (*log_)(Logging::INFO) << "Initializing P2P...";

    loadOrCreateNodeKey();

    P2P::P2PConfig p2p_cfg;

    p2p_cfg.magic = P2P::magicForNetwork(static_cast<int>(config_.network));
    p2p_cfg.agentString = GlobalConfig::PROJECT_AGENT_STRING;
    p2p_cfg.protocolVersion = GlobalConfig::CURRENT_PROTOCOL_VERSION;
    p2p_cfg.listenPort = config_.p2p_port;
    p2p_cfg.dnsSeeds = config_.seeds;

    p2p_ = std::make_unique<P2P::P2PManager>(p2p_cfg, logger_, config_.data_dir);

    p2p_->onMessage = [this](const P2P::Message &m, P2P::PeerId from)
    {
      onP2PMessage(m, from);
    };
    p2p_->onPeerConnected = [this](P2P::PeerId id)
    {
      onP2PPeerConnected(id);
    };
    p2p_->onPeerDisconnected = [this](P2P::PeerId id, const std::string &reason)
    {
      onP2PPeerDisconnected(id, reason);
    };
    p2p_->buildAuthMessage = [this](P2P::Peer &peer)
    {
      return buildAuthMessageForPeer(peer);
    };
    p2p_->verifyAuth = [this](P2P::Peer &peer, const P2P::AuthMessage &a,
                              uint64_t &outValidatorId)
    {
      return verifyPeerAuth(peer, a, outValidatorId);
    };
    p2p_->getOurIdentityPubkey = [this](P2P::Peer &) -> Crypto::PublicKey
    {
      if (node_key_.isNull())
        return Crypto::PublicKey{};
      return Crypto::derivePublicKey(node_key_);
    };
    p2p_->onPeerEstablished = [this](
                                  const P2P::P2PManager::PeerEstablishedInfo &info)
    {
      onP2PPeerEstablished(info);
    };
    p2p_->getChainHeight = [this]() -> uint64_t
    {
      return chain_ ? chain_->height() : 0;
    };

    (*log_)(Logging::DEBUGGING)
        << "P2P initialized: magic=0x" << std::hex << p2p_cfg.magic << std::dec
        << " port=" << p2p_cfg.listenPort
        << " seeds=" << p2p_cfg.dnsSeeds.size();
  }

  P2P::AuthMessage Node::buildAuthMessageForPeer(P2P::Peer &peer)
  {
    P2P::AuthMessage a;

    if (node_key_.isNull())
    {
      (*log_)(Logging::ERROR)
          << "buildAuthMessageForPeer: node key is null";
      return a;
    }

    a.pubkey = Crypto::derivePublicKey(node_key_);

    const Crypto::X25519KeyPair &eph = peer.ephemeralKeypair();
    std::memcpy(a.ephemeralPubkey.data.data(),
                eph.publicKey.data(),
                a.ephemeralPubkey.data.size());

    const uint64_t my_nonce = peer.localNonce();
    const uint64_t their_nonce = peer.peerNonce();

    P2P::AuthNonces nonces = P2P::orderNonces(
        peer.direction(), my_nonce, their_nonce);

    Crypto::Hash challenge = P2P::computeAuthChallenge(
        nonces, a.pubkey, a.ephemeralPubkey);

    a.signature = Crypto::sign(challenge, node_key_);
    return a;
  }

  bool Node::verifyPeerAuth(P2P::Peer &peer,
                            const P2P::AuthMessage &a,
                            uint64_t &outValidatorId)
  {
    outValidatorId = 0;

    if (a.pubkey.isNull() || a.signature.isNull())
      return false;

    if (a.ephemeralPubkey.isNull())
      return false;

    const uint64_t my_nonce = peer.localNonce();
    const uint64_t their_nonce = peer.peerNonce();

    P2P::AuthNonces nonces = P2P::orderNonces(
        peer.direction(), my_nonce, their_nonce);

    Crypto::Hash challenge = P2P::computeAuthChallenge(
        nonces, a.pubkey, a.ephemeralPubkey);

    if (!Crypto::verify(challenge, a.pubkey, a.signature))
      return false;

    outValidatorId = validatorIdForAddress(a.pubkey);
    return true;
  }

  uint64_t Node::validatorIdForAddress(const Crypto::PublicKey &pk) const
  {
    if (pk.isNull())
      return 0;

    State::StateAccess state(*state_db_, /*version=*/0);
    auto active = loadActiveSetFromState(state);

    for (Id vid : active)
    {
      Core::ValidatorInfo v;
      if (!state.getValidator(vid, v))
        continue;
      if (v.effectiveConsensusKey() == pk)
        return vid;
    }
    return 0;
  }

  void Node::initConsensus()
  {
    if (config_.validator_id == 0)
    {
      (*log_)(Logging::WARNING) << "Not a validator, consensus disabled";
      return;
    }

    (*log_)(Logging::INFO)
        << "Initializing consensus as validator " << config_.validator_id;

    Consensus::Config consensus_cfg;
    consensus_cfg.max_block_bytes = config_.max_block_bytes;
    consensus_cfg.max_block_txs = config_.max_block_txs;
    consensus_cfg.poll_interval_ms = config_.consensus_poll_ms;

    Consensus::Dependencies deps = buildConsensusDeps();
    Consensus::Callbacks callbacks = buildConsensusCallbacks();

    consensus_ = std::make_unique<Consensus::BftConsensus>(
        std::move(deps),
        std::move(callbacks),
        consensus_cfg,
        Logging::LoggerRef(logger_, "Consensus"));
  }

  Core::GenesisConfig Node::genesisConfig() const
  {
    if (config_.test_genesis_override)
      return *config_.test_genesis_override;

    switch (config_.network)
    {
    case Network::Mainnet:
      return Core::mainnetGenesis();
    case Network::Testnet:
      return Core::testnetGenesis();
    case Network::Regtest:
      return Core::regtestGenesis();
    }
    return Core::regtestGenesis();
  }

  Node::Status Node::status() const
  {
    Status s;
    s.network = config_.network;
    s.chain_id = config_.chain_id;
    s.running = running_.load();
    s.is_validator = (config_.validator_id != 0);
    s.validator_id = config_.validator_id;

    if (chain_)
    {
      s.height = chain_->height();
      s.best_peer_height = chain_->bestPeerHeight();
    }
    if (mempool_)
    {
      s.mempool_size = mempool_->size();
      s.mempool_bytes = mempool_->bytes();
    }
    if (p2p_)
    {
      s.peer_count = p2p_->peerCount();

      const auto snap = p2p_->snapshot();
      s.peers_total = snap.total;
      s.peers_inbound = snap.inbound;
      s.peers_outbound = snap.outbound;
      s.peers_established = snap.established;
      s.peers_banned = snap.banned;
      s.addresses_known = snap.knownAddresses;
      s.aggregate_rate_limit_burst = snap.aggregateBurst;
      s.aggregate_rate_limit_per_second = snap.aggregatePerSecond;
      s.aggregate_rate_limit_enabled = snap.aggregateEnabled;
    }
    if (consensus_)
    {
      auto cs = consensus_->state();
      s.consensus_height = cs.height;
      s.consensus_round = cs.round;
      s.consensus_step = Consensus::stepName(cs.step);
      s.consensus_step_ordinal = cs.step;
      s.consensus_prevotes = cs.prevote_count;
      s.consensus_precommits = cs.precommit_count;
      s.consensus_is_proposer = cs.is_proposer;

      s.consensus_consecutive_timeouts =
          static_cast<uint32_t>(consensus_->consecutiveTimeouts());
      s.consensus_emergency_rotation =
          consensus_->emergencyRotationActive();
    }

    return s;
  }

  Consensus::Dependencies Node::buildConsensusDeps()
  {
    Consensus::Dependencies deps;
    deps.my_validator_id = [this]()
    { return getMyValidatorId(); };
    deps.sign = [this](const Crypto::Hash &h)
    { return signHash(h); };
    deps.current_height = [this]()
    { return getCurrentHeight(); };

    deps.active_set = [this](bool force_rotation) -> std::vector<Id>
    {
      State::StateAccess state(*state_db_, /*version=*/0);
      std::vector<Id> committed = getActiveSet();
      return Core::resolveActiveSet(
          state, committed, chain_->height(), force_rotation);
    };

    deps.state_lookup_validator =
        [this](Id id, Core::ValidatorInfo &out) -> bool
    {
      auto state = makeStateView();
      const bool found = state->getValidator(id, out);

      (*log_)(Logging::DEBUGGING)
          << "state_lookup_validator: id=" << id
          << " found=" << (found ? "yes" : "no")
          << (found ? " addr=" + out.reward_address.toString().substr(0, 16) : "")
          << " consensus=" << (found ? out.effectiveConsensusKey().toString().substr(0, 16) : "");

      return found;
    };

    deps.chain_id = [this]() -> uint64_t
    { return config_.chain_id; };

    deps.parent_hash = [this]() -> Crypto::Hash
    {
      return chain_db_->getHead().hash;
    };

    deps.my_address = [this]() -> Crypto::Address
    {
      State::StateAccess state(*state_db_, /*version=*/0);
      Core::ValidatorInfo v;
      if (!state.getValidator(config_.validator_id, v))
        return Crypto::Address{};
      return v.reward_address;
    };

    deps.simulate_block = [this](const Core::Block &b)
        -> std::optional<Crypto::Hash>
    {
      State::StateDB::Txn txn = state_db_->beginWrite();
      try
      {
        State::StateAccess state(*state_db_, txn, b.header.height);
        Core::BlockContext ctx;
        ctx.chain_id = config_.chain_id;
        ctx.current_height = b.header.height;
        ctx.dry_run = true;
        Core::BlockResult r = Core::BlockProcessor::applyBlock(state, b, ctx);
        txn.abort();

        if (!r.valid)
          return std::nullopt;
        return r.new_state_root;
      }
      catch (const std::exception &e)
      {
        txn.abort();
        return std::nullopt;
      }
    };

    deps.verify_slash_proof =
        [this](const std::vector<uint8_t> &payload) -> bool
    {
      State::StateAccess state(*state_db_, /*version=*/0);
      std::vector<Id> empty;
      auto result = Core::verifyEquivocationProof(payload, empty, state);
      return result.has_value();
    };

    deps.has_pending_work = [this]() -> bool
    {
      return mempool_ && mempool_->size() > 0;
    };

    deps.now_ms = []() -> uint64_t
    {
      return static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch())
              .count());
    };

    deps.wal_append_vote =
        [this](const Consensus::Vote &v, bool is_precommit)
    {
      const auto key = walVoteKey(v.height, v.round, v.signer_id);
      const auto value = walEncodeVoteRecord(v, is_precommit);
      state_db_->rawPut(State::StateDB::TBL_CONSENSUS_WAL,
                        key.data(), key.size(),
                        value.data(), value.size());
    };

    deps.wal_append_lock =
        [this](Height h, Round r, const Crypto::Hash &hash)
    {
      const auto key = walLockKey(h, r);
      state_db_->rawPut(State::StateDB::TBL_CONSENSUS_WAL,
                        key.data(), key.size(),
                        hash.data.data(), hash.data.size());
    };

    deps.wal_replay =
        [this](Height for_height,
               std::function<void(const Consensus::Vote &, bool)> on_vote,
               std::function<void(Height, Round, const Crypto::Hash &)> on_lock)
    {
      state_db_->forEachEntry(
          State::StateDB::TBL_CONSENSUS_WAL,
          [&](const std::vector<uint8_t> &key,
              const std::vector<uint8_t> &value) -> bool
          {
            if (key.size() < 12)
              return true;
            const uint64_t h = readU64BE(key.data());
            if (h != for_height)
              return true;

            const uint32_t kind = readU32BE(key.data() + 8);

            if (kind == WAL_KIND_VOTE)
            {
              if (key.size() < 28)
                return true;
              Consensus::Vote v;
              bool is_precommit = false;
              if (walDecodeVoteRecord(value, v, is_precommit))
                on_vote(v, is_precommit);
            }
            else if (kind == WAL_KIND_LOCK)
            {
              if (key.size() < 20 || value.size() != 32)
                return true;
              const Round r = readU64BE(key.data() + 12);
              Crypto::Hash hash;
              std::memcpy(hash.data.data(), value.data(), 32);
              on_lock(h, r, hash);
            }
            return true;
          });
    };

    deps.wal_truncate =
        [this](Height committed_height)
    {
      std::vector<std::vector<uint8_t>> to_delete;

      auto collect_txn = state_db_->beginWrite();
      collect_txn.forEach(
          State::StateDB::TBL_CONSENSUS_WAL,
          [&](const std::vector<uint8_t> &key,
              const std::vector<uint8_t> &) -> bool
          {
            if (key.size() < 8)
              return true;
            const uint64_t h = readU64BE(key.data());
            if (h <= committed_height)
              to_delete.push_back(key);
            return true;
          });
      collect_txn.abort();

      if (to_delete.empty())
        return;

      auto delete_txn = state_db_->beginWrite();
      for (const auto &k : to_delete)
        delete_txn.del(State::StateDB::TBL_CONSENSUS_WAL,
                       k.data(), k.size());
      delete_txn.commit();

      (*log_)(Logging::DEBUGGING)
          << "WAL truncated at height " << committed_height
          << ", removed " << to_delete.size() << " entries";
    };

    return deps;
  }

  Consensus::Callbacks Node::buildConsensusCallbacks()
  {
    Consensus::Callbacks cb;
    cb.broadcast_proposal = [this](const Consensus::Proposal &p)
    {
      onConsensusProposal(p);
    };
    cb.broadcast_prevote = [this](const Consensus::Vote &v)
    {
      onConsensusVote(v, /*is_precommit=*/false);
    };
    cb.broadcast_precommit = [this](const Consensus::Vote &v)
    {
      onConsensusVote(v, /*is_precommit=*/true);
    };
    cb.select_transactions = [this](uint64_t max_bytes, uint64_t max_txs)
    {
      return selectTransactionsForProposal(max_bytes, max_txs);
    };
    cb.on_block_committed = [this](const Core::Block &b)
    {
      return onBlockCommitted(b);
    };
    cb.on_height_advanced = [this](Height h)
    {
      onHeightAdvanced(h);
    };
    return cb;
  }

  Id Node::getMyValidatorId() const
  {
    return config_.validator_id;
  }

  Crypto::Signature Node::signHash(const Crypto::Hash &hash)
  {
    if (config_.consensus_secret_key.isNull())
    {
      return Crypto::Signature{};
    }
    return Crypto::sign(hash, config_.consensus_secret_key);
  }

  Height Node::getCurrentHeight() const
  {
    return chain_->height();
  }

  std::vector<Id> Node::getActiveSet() const
  {
    State::StateAccess state(*state_db_, /*version=*/0);
    return loadActiveSetFromState(state);
  }

  std::vector<Id> Node::loadActiveSetFromState(
      State::StateAccess &state) const
  {
    std::vector<Id> result;

    std::vector<uint8_t> set_bytes;
    if (!state.getGlobal("active_set", set_bytes))
    {
      return result;
    }

    size_t count = set_bytes.size() / 8;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i)
    {
      uint64_t id = 0;
      for (int j = 0; j < 8; ++j)
      {
        id |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);
      }
      result.push_back(id);
    }

    return result;
  }

  std::optional<Crypto::PublicKey> Node::getSignerPublicKey(Index idx) const
  {
    auto active = getActiveSet();
    if (idx >= active.size())
      return std::nullopt;

    Id vid = active[idx];

    State::StateAccess state(*state_db_, /*version=*/0);
    Core::ValidatorInfo v;
    if (!state.getValidator(vid, v))
      return std::nullopt;

    return v.effectiveConsensusKey();
  }

  void Node::onConsensusProposal(const Consensus::Proposal &p)
  {
    auto encoded = Consensus::encodeProposal(p);

    if (!p2p_)
      return;

    P2P::Message msg;
    msg.type = P2P::MessageType::Proposal;
    msg.payload = std::move(encoded);

    p2p_->broadcast(msg);
  }

  void Node::onConsensusVote(const Consensus::Vote &v, bool is_precommit)
  {
    auto encoded = Consensus::encodeVote(v);

    if (!p2p_)
      return;

    P2P::Message msg;
    msg.type = is_precommit ? P2P::MessageType::Precommit
                            : P2P::MessageType::Prevote;
    msg.payload = std::move(encoded);

    p2p_->broadcast(msg);
  }

  std::vector<Core::Transaction> Node::selectTransactionsForProposal(
      uint64_t max_bytes, uint64_t max_txs)
  {
    if (!mempool_)
      return {};

    auto state_view = makeStateView();
    if (!state_view)
      return {};

    return mempool_->selectForBlock(*state_view, max_bytes, max_txs);
  }

  std::unique_ptr<Core::StateView> Node::makeStateView() const
  {
    uint64_t version = chain_->height();
    uint64_t chain_id = config_.chain_id;

    auto state = std::make_unique<State::StateAccess>(*state_db_, version);
    return std::make_unique<Core::StateViewFromAccess>(
        std::move(state), version, chain_id);
  }

  bool Node::onBlockCommitted(const Core::Block &block)
  {
    std::string error;
    if (!applyCommittedBlock(block, error))
    {
      (*log_)(Logging::ERROR)
          << "Failed to apply committed block at height "
          << block.header.height << ": " << error;
      return false;
    }

    (*log_)(Logging::DEBUGGING)
        << "Applied committed block: height=" << block.header.height
        << " hash=" << block.hash().toString().substr(0, 16)
        << " txs=" << block.transactions.size();

    broadcastBlock(block);
    return true;
  }

  void Node::onHeightAdvanced(Height height)
  {
    (*log_)(Logging::INFO)
        << "Chain advanced to height " << Logging::BRIGHT_GREEN << height;
  }

  void Node::onConsensusPoll()
  {
    if (!consensus_started_.load())
      maybeStartConsensus();

    if (!consensus_)
      return;

    consensus_->pollTimers();

    if (config_.log_consensus_state)
    {
      auto s = consensus_->state();
      (*log_)(Logging::DEBUGGING)
          << "Consensus: h=" << s.height
          << " r=" << s.round
          << " step=" << Consensus::stepName(s.step)
          << " prevotes=" << s.prevote_count
          << " precommits=" << s.precommit_count;
    }
  }

  void Node::onP2PMessage(const P2P::Message &msg, P2P::PeerId from)
  {
    switch (msg.type)
    {
    case P2P::MessageType::Proposal:
      handleIncomingProposal(msg);
      break;
    case P2P::MessageType::Prevote:
      handleIncomingVote(msg, /*is_precommit=*/false);
      break;
    case P2P::MessageType::Precommit:
      handleIncomingVote(msg, /*is_precommit=*/true);
      break;
    case P2P::MessageType::Tx:
      handleIncomingTx(msg);
      break;
    case P2P::MessageType::Block:
      handleIncomingBlock(msg, from);
      break;
    case P2P::MessageType::GetHeaders:
      handleGetHeaders(msg, from);
      break;
    case P2P::MessageType::GetBlocks:
      handleGetBlocks(msg, from);
      break;
    case P2P::MessageType::Headers:
      handleIncomingHeaders(msg, from);
      break;
    case P2P::MessageType::GetProof:
      handleGetProof(msg, from);
      break;
    case P2P::MessageType::Blocks:
      handleIncomingBlocks(msg, from);
      break;
    default:
      (*log_)(Logging::DEBUGGING)
          << "Unhandled P2P message: "
          << P2P::messageTypeName(msg.type);
      break;
    }
  }

  void Node::onP2PPeerConnected(P2P::PeerId id)
  {
    (*log_)(Logging::INFO) << "Peer connected: " << id;
    (void)id;
  }

  void Node::onP2PPeerDisconnected(P2P::PeerId id, const std::string &reason)
  {
    (*log_)(Logging::DEBUGGING) << "Peer disconnected: " << id << " (" << reason << ")";
    sync_managers_.erase(id);
    peer_heights_.erase(id);
    updateBestPeerHeight();
  }

  void Node::handleIncomingProposal(const P2P::Message &msg)
  {
    if (!consensus_)
      return;

    Consensus::Proposal p;
    if (!Consensus::decodeProposal(msg.payload.data(), msg.payload.size(), p))
    {
      (*log_)(Logging::DEBUGGING) << "Malformed proposal received";
      return;
    }

    if (chain_ &&
        p.height == chain_->height() + 1)
    {
      Core::Block proposed_block;
      if (Core::Block::deserialize(p.block_bytes.data(),
                                   p.block_bytes.size(),
                                   proposed_block) &&
          proposed_block.header.emergency_rotation > 0)
      {
        auto held = consensus_->heldQuorumBlock(p.height);
        if (held.has_value() &&
            held->hash() != proposed_block.hash())
        {
          (*log_)(Logging::WARNING)
              << "Emergency proposal for h=" << p.height
              << " conflicts with held quorum block "
              << held->hash().toString().substr(0, 16)
              << "; applying held block";

          std::string error;
          if (applyCommittedBlock(*held, error))
          {
            broadcastBlock(*held);
            return;
          }

          (*log_)(Logging::WARNING)
              << "Held quorum block failed to apply: " << error
              << "; falling through to emergency proposal";
        }
      }
    }

    consensus_->onProposal(p);
  }

  void Node::handleIncomingVote(const P2P::Message &msg, bool is_precommit)
  {
    if (!consensus_)
      return;

    Consensus::Vote v;
    if (!Consensus::decodeVote(msg.payload.data(), msg.payload.size(), v))
    {
      (*log_)(Logging::DEBUGGING) << "Malformed vote received";
      return;
    }

    if (is_precommit)
      consensus_->onPrecommit(v);
    else
      consensus_->onPrevote(v);
  }

  void Node::handleIncomingTx(const P2P::Message &msg)
  {
    if (!mempool_)
      return;

    Core::Transaction tx;
    if (!Core::Transaction::deserialize(msg.payload.data(),
                                        msg.payload.size(),
                                        tx))
    {
      (*log_)(Logging::DEBUGGING) << "Malformed tx received";
      return;
    }

    const Crypto::Hash txid = tx.txid();
    if (mempool_->contains(txid))
      return;

    auto state_view = makeStateView();
    if (!state_view)
      return;

    auto result = mempool_->add(tx, *state_view, Core::FeeTier::Standard);

    if (result == Core::MempoolAddResult::Accepted)
    {
      (*log_)(Logging::DEBUGGING)
          << "Tx accepted to mempool: "
          << txid.toString().substr(0, 16);

      broadcastTransaction(tx);
    }
    else
    {
      (*log_)(Logging::DEBUGGING)
          << "Tx rejected: " << Core::mempoolAddResultName(result);
    }
  }

  void Node::handleIncomingBlock(const P2P::Message &msg, P2P::PeerId from)
  {
    if (!chain_ || !chain_db_)
      return;

    Core::Block block;
    if (!Core::Block::deserialize(msg.payload.data(), msg.payload.size(), block))
    {
      (*log_)(Logging::DEBUGGING) << "Malformed Block received (ignored)";
      return;
    }

    const Crypto::Hash block_hash = block.hash();

    if (chain_db_->hasBlock(block_hash))
      return;

    const uint64_t our_height = chain_->height();

    if (block.header.height <= our_height)
    {
      (*log_)(Logging::WARNING)
          << "Block at height " << block.header.height
          << " but our height is " << our_height
          << " — possible fork, scoring sender";

      if (p2p_)
      {
        auto *peer = p2p_->findPeer(from);
        if (peer)
          peer->reportMisbehavior(50, /*reason=*/0);
      }
      return;
    }

    if (block.header.height > our_height + 1)
    {
      (*log_)(Logging::DEBUGGING)
          << "Block at height " << block.header.height
          << " is ahead of our height " << our_height
          << " by more than one — dropping, sync will catch up";
      return;
    }

    std::string error;
    if (!applyCommittedBlock(block, error))
    {
      (*log_)(Logging::WARNING)
          << "Relayed block at height " << block.header.height
          << " failed to apply: " << error;
      return;
    }

    (*log_)(Logging::INFO)
        << "Applied relayed block: height=" << block.header.height
        << " hash=" << block_hash.toString().substr(0, 16);

    broadcastBlock(block);
  }

  void Node::handleGetHeaders(const P2P::Message &msg, P2P::PeerId from)
  {
    P2P::GetHeadersMessage req;
    if (!P2P::deserializeGetHeaders(msg.payload.data(), msg.payload.size(), req))
    {
      (*log_)(Logging::WARNING)
          << "Malformed GetHeaders from peer " << from;
      return;
    }

    if (!chain_ || !p2p_)
      return;

    const uint32_t limit = std::min(
        req.limit, P2P::MAX_HEADERS_PER_REQUEST);

    P2P::HeadersMessage resp;

    const uint64_t our_h = chain_->height();
    uint64_t h = req.startHeight;

    for (uint32_t i = 0; i < limit; ++i)
    {
      if (h > our_h)
        break;

      auto hash = chain_db_->getHashByHeight(h);
      if (!hash.has_value())
        break;

      P2P::HeadersEntry e;
      e.height = h;
      e.hash = *hash;
      resp.entries.push_back(e);

      ++h;
    }

    P2P::Message reply;
    reply.type = P2P::MessageType::Headers;
    reply.payload = P2P::serializeHeaders(resp);

    p2p_->sendTo(from, reply);
  }

  void Node::handleGetBlocks(const P2P::Message &msg, P2P::PeerId from)
  {
    P2P::GetBlocksMessage req;
    if (!P2P::deserializeGetBlocks(msg.payload.data(), msg.payload.size(), req))
    {
      (*log_)(Logging::WARNING)
          << "Malformed GetBlocks from peer " << from;
      return;
    }

    if (!chain_ || !p2p_)
      return;

    P2P::BlocksMessage resp;
    resp.blocks.reserve(req.hashes.size());

    for (const auto &hash : req.hashes)
    {
      auto block = chain_db_->getBlock(hash);
      if (!block.has_value())
      {
        continue;
      }
      resp.blocks.push_back(std::move(*block));
    }

    P2P::Message reply;
    reply.type = P2P::MessageType::Blocks;
    reply.payload = P2P::serializeBlocks(resp);

    p2p_->sendTo(from, reply);
  }

  bool Node::applyCommittedBlock(const Core::Block &block, std::string &error)
  {
    State::StateDB::Txn txn = state_db_->beginWrite();

    try
    {
      if (fail_point_for_test_ == FailPoint::InsideTxn)
      {
        fail_point_for_test_ = FailPoint::None;
        throw std::runtime_error("test injection: InsideTxn");
      }

      State::StateAccess state(*state_db_, txn, block.header.height);

      Core::BlockContext ctx;
      ctx.chain_id = config_.chain_id;
      ctx.current_height = block.header.height;

      Core::BlockResult result = Core::BlockProcessor::applyBlock(state, block, ctx);

      if (!result.valid)
      {
        txn.abort();
        error = "block processor rejected: " + result.error;
        return false;
      }

      state.commit(block.header.height);

      Crypto::Hash block_hash = block.hash();
      chain_db_->storeBlockTxn(txn, block, block_hash);

      Core::ChainDB::ChainHead head;
      head.hash = block_hash;
      head.height = block.header.height;
      chain_db_->setHeadTxn(txn, head);

      //  Persist the receipts. Written inside the same MDBX txn as
      //  the block and head, so a crash cannot leave a committed
      //  block whose receipts are missing. This is the write side
      //  of ChainDB::getReceipt, which the RPC reads.
      //
      //  result.receipts is populated by BlockProcessor::applyBlock
      //  in the same order as block.transactions, so the index i
      //  here matches the tx_index we write into the receipt row.
      for (size_t i = 0; i < result.receipts.size(); ++i)
      {
        const Core::Transaction &tx = block.transactions[i];
        const Core::Receipt &r = result.receipts[i];

        chain_db_->storeReceiptTxn(txn,
                                   tx.txid(),
                                   block.header.height,
                                   static_cast<uint32_t>(i),
                                   r.serializeState());
      }

      txn.commit();
    }
    catch (const std::exception &e)
    {
      txn.abort();
      error = std::string("exception in block application: ") + e.what();
      return false;
    }

    if (mempool_)
    {
      std::vector<Crypto::Hash> txids;
      txids.reserve(block.transactions.size());
      for (const auto &tx : block.transactions)
        txids.push_back(tx.txid());
      mempool_->removeIncluded(txids);
      mempool_->purgeExpired(block.header.height);
    }

    {
      State::StateAccess state(*state_db_, block.header.height);

      const uint64_t window = config_.fee_window_blocks;
      const uint64_t tip = block.header.height;

      uint64_t sum = state.getMetaU64("fees_in_window");

      if (tip >= window)
      {
        const uint64_t leaving_height = tip - window;
        auto leaving_header = chain_db_->getHeaderByHeight(leaving_height);
        if (leaving_header.has_value())
        {
          const uint64_t leaving_fees = leaving_header->total_fees;
          sum = (sum >= leaving_fees) ? (sum - leaving_fees) : 0;
        }
      }

      sum += block.header.total_fees;

      state.putMetaU64("fees_in_window", sum);
    }

    if (config_.smt_history_blocks > 0 &&
        block.header.height >= config_.smt_history_blocks &&
        block.header.height - last_prune_height_ >= 100)
    {
      const uint64_t keep_from =
          block.header.height - config_.smt_history_blocks;
      try
      {
        state_db_->pruneHistoryBefore(keep_from);
        last_prune_height_ = block.header.height;
      }
      catch (const std::exception &e)
      {
        (*log_)(Logging::WARNING)
            << "SMT history prune failed: " << e.what();
      }
    }

    state_db_->flush();
    return true;
  }

  Core::MempoolAddResult Node::submitTransaction(const Core::Transaction &tx,
                                                 std::string &error)
  {
    error.clear();

    if (!mempool_)
      throw std::runtime_error("submitTransaction: mempool not initialized");

    auto state_view = makeStateView();
    if (!state_view)
      throw std::runtime_error("submitTransaction: could not build state view");

    auto result = mempool_->add(tx, *state_view, Core::FeeTier::Standard);

    if (result != Core::MempoolAddResult::Accepted)
    {
      error = Core::mempoolAddResultName(result);
      return result;
    }

    broadcastTransaction(tx);

    return result;
  }

  Crypto::Hash Node::stateRoot() const
  {
    if (!state_db_)
      return Crypto::Hash{};
    State::StateAccess state(*state_db_, /*version=*/0);
    return state.stateRoot();
  }

  std::vector<P2P::P2PManager::PeerInfo> Node::p2pPeerList() const
  {
    if (!p2p_)
      return {};
    return p2p_->peerList();
  }

  void Node::loadOrCreateNodeKey()
  {
    if (node_key_loaded_)
      return;
    node_key_loaded_ = true;

    if (!config_.node_secret_key.isNull())
    {
      node_key_ = config_.node_secret_key;
      (*log_)(Logging::DEBUGGING)
          << "Using node_secret_key from config";
      return;
    }

    if (!config_.consensus_secret_key.isNull())
    {
      node_key_ = config_.consensus_secret_key;
      (*log_)(Logging::DEBUGGING)
          << "Using consensus_secret_key as node key";
      return;
    }

    const std::string path = config_.data_dir + "/node_key";

    {
      std::ifstream in(path, std::ios::binary);
      if (in)
      {
        std::array<uint8_t, 32> raw{};
        in.read(reinterpret_cast<char *>(raw.data()), raw.size());
        if (in.gcount() == static_cast<std::streamsize>(raw.size()))
        {
          std::memcpy(node_key_.data.data(), raw.data(), raw.size());
          (*log_)(Logging::INFO)
              << "Loaded node key from " << path;
          return;
        }
        (*log_)(Logging::WARNING)
            << "node_key file at " << path
            << " is truncated (" << in.gcount() << " bytes); regenerating";
      }
    }

    Crypto::KeyPair kp = Crypto::generateKeyPair();
    node_key_ = kp.secretKey;

    {
      std::ofstream out(path, std::ios::binary | std::ios::trunc);
      if (!out)
      {
        (*log_)(Logging::ERROR)
            << "Failed to write node key to " << path;
        return;
      }
      out.write(reinterpret_cast<const char *>(node_key_.data.data()),
                node_key_.data.size());
      out.close();

      std::error_code ec;
      std::filesystem::permissions(
          path,
          std::filesystem::perms::owner_read |
              std::filesystem::perms::owner_write,
          std::filesystem::perm_options::replace,
          ec);
      if (ec)
      {
        (*log_)(Logging::WARNING)
            << "Could not restrict permissions on " << path
            << ": " << ec.message();
      }
    }

    (*log_)(Logging::INFO)
        << "Generated new node key at " << path
        << " pubkey="
        << Crypto::derivePublicKey(node_key_).toString().substr(0, 16);
  }

  void Node::onP2PPeerEstablished(
      const P2P::P2PManager::PeerEstablishedInfo &info)
  {
    (*log_)(Logging::DEBUGGING)
        << "Peer established: " << info.id
        << " best_height=" << info.best_height
        << " validator_id=" << info.validator_id
        << " agent=\"" << info.agent << "\"";

    auto mgr = std::make_unique<P2P::SyncManager>(
        info.id, config_.max_block_bytes);

    const P2P::PeerId peer_id = info.id;

    mgr->our_height = [this]() -> uint64_t
    {
      return chain_ ? chain_->height() : 0;
    };

    if (chain_)
    {
      uint64_t current = chain_->bestPeerHeight();
      if (info.best_height > current)
        chain_->setBestPeerHeight(info.best_height);
    }
    peer_heights_[info.id] = info.best_height;
    updateBestPeerHeight();

    mgr->send = [this, peer_id](const P2P::Message &m)
    {
      if (p2p_)
        p2p_->sendTo(peer_id, m);
    };

    mgr->apply_blocks = [this](const std::vector<Core::Block> &blocks)
        -> size_t
    {
      size_t applied = 0;
      for (const auto &b : blocks)
      {
        std::string error;
        if (!applyCommittedBlock(b, error))
        {
          (*log_)(Logging::WARNING)
              << "Sync block at height " << b.header.height
              << " failed to apply: " << error;
          return applied;
        }
        ++applied;
      }
      return applied;
    };

    mgr->on_misbehavior = [this, peer_id](uint32_t score, const char *reason)
    {
      if (!p2p_)
        return;

      (*log_)(Logging::WARNING)
          << "Sync misbehavior from peer " << peer_id
          << " (+" << score << "): " << reason;

      auto *peer = p2p_->findPeer(peer_id);
      if (peer)
        peer->reportMisbehavior(score, /*reason=*/0);
    };

    sync_managers_[peer_id] = std::move(mgr);

    sync_managers_[peer_id]->start();
  }

  void Node::handleIncomingHeaders(const P2P::Message &msg, P2P::PeerId from)
  {
    auto it = sync_managers_.find(from);
    if (it == sync_managers_.end())
      return;

    P2P::HeadersMessage headers;
    if (!P2P::deserializeHeaders(msg.payload.data(), msg.payload.size(), headers))
    {
      (*log_)(Logging::WARNING)
          << "Malformed Headers from peer " << from;
      auto *peer = p2p_ ? p2p_->findPeer(from) : nullptr;
      if (peer)
        peer->reportMisbehavior(50, /*reason=*/0);
      return;
    }

    it->second->onHeaders(headers);
  }

  void Node::handleIncomingBlocks(const P2P::Message &msg, P2P::PeerId from)
  {
    auto it = sync_managers_.find(from);
    if (it == sync_managers_.end())
      return;

    P2P::BlocksMessage blocks;
    if (!P2P::deserializeBlocks(msg.payload.data(), msg.payload.size(), blocks))
    {
      (*log_)(Logging::WARNING)
          << "Malformed Blocks from peer " << from;
      auto *peer = p2p_ ? p2p_->findPeer(from) : nullptr;
      if (peer)
        peer->reportMisbehavior(50, /*reason=*/0);
      return;
    }

    it->second->onBlocks(blocks);
  }

  void Node::handleGetProof(const P2P::Message &msg, P2P::PeerId from)
  {
    P2P::GetProofMessage req;
    if (!P2P::deserializeGetProof(msg.payload.data(), msg.payload.size(), req))
    {
      (*log_)(Logging::WARNING)
          << "Malformed GetProof from peer " << from;
      return;
    }

    if (!chain_ || !p2p_)
      return;

    P2P::ProofMessage resp;

    auto key = P2P::resolveProofKey(req.key_type, req.key_bytes);
    if (!key.has_value())
    {
      resp.status = P2P::ProofMessage::Status::Malformed;
      P2P::Message reply;
      reply.type = P2P::MessageType::Proof;
      reply.payload = P2P::serializeProof(resp);
      p2p_->sendTo(from, reply);
      return;
    }

    const uint64_t resolved_version =
        (req.version == P2P::PROOF_VERSION_CURRENT)
            ? chain_->height()
            : req.version;

    resp.version = resolved_version;

    auto state = std::make_unique<State::StateAccess>(
        *state_db_, resolved_version);

    auto root = state->smtRootAtVersion(resolved_version);
    if (!root.has_value())
    {
      resp.status = P2P::ProofMessage::Status::VersionUnavailable;
      P2P::Message reply;
      reply.type = P2P::MessageType::Proof;
      reply.payload = P2P::serializeProof(resp);
      p2p_->sendTo(from, reply);
      return;
    }

    resp.state_root = *root;

    auto proof = state->proveAtVersion(*key, resolved_version);
    if (!proof.has_value())
    {
      resp.status = P2P::ProofMessage::Status::KeyNotFound;
      P2P::Message reply;
      reply.type = P2P::MessageType::Proof;
      reply.payload = P2P::serializeProof(resp);
      p2p_->sendTo(from, reply);
      return;
    }

    resp.status = P2P::ProofMessage::Status::Ok;
    resp.proof = std::move(*proof);

    P2P::Message reply;
    reply.type = P2P::MessageType::Proof;
    reply.payload = P2P::serializeProof(resp);
    p2p_->sendTo(from, reply);

    (*log_)(Logging::DEBUGGING)
        << "Served proof for peer " << from
        << " key_type=" << static_cast<int>(req.key_type)
        << " version=" << resolved_version
        << " proof_bytes=" << reply.payload.size();
  }

  void Node::updateBestPeerHeight()
  {
    if (!chain_)
      return;

    uint64_t best = 0;
    for (const auto &[id, h] : peer_heights_)
    {
      if (h > best)
        best = h;
    }

    chain_->setBestPeerHeight(best);

    (*log_)(Logging::DEBUGGING)
        << "best_peer_height updated to " << best
        << " across " << peer_heights_.size() << " peers";
  }

  void Node::broadcastBlock(const Core::Block &block)
  {
    if (!p2p_)
      return;

    P2P::Message msg;
    msg.type = P2P::MessageType::Block;
    msg.payload = block.serialize();

    p2p_->broadcast(msg);

    (*log_)(Logging::DEBUGGING)
        << "Broadcast block " << block.header.height
        << " hash=" << block.hash().toString().substr(0, 16)
        << " bytes=" << msg.payload.size();
  }

  void Node::broadcastTransaction(const Core::Transaction &tx)
  {
    if (!p2p_)
      return;

    P2P::Message msg;
    msg.type = P2P::MessageType::Tx;
    msg.payload = tx.serialize();

    p2p_->broadcast(msg);

    (*log_)(Logging::DEBUGGING)
        << "Broadcast tx " << tx.txid().toString().substr(0, 16)
        << " bytes=" << msg.payload.size();
  }

  void Node::onSyncTick()
  {
    for (auto &[id, mgr] : sync_managers_)
    {
      if (mgr)
        mgr->tick();
    }
  }

  void Node::armConsensusPollTimer()
  {
    if (!consensus_ || !p2p_ || stopping_.load())
      return;

    if (!consensus_timer_)
    {
      consensus_timer_ = std::make_unique<boost::asio::steady_timer>(
          p2p_->executor());
    }

    auto interval = std::chrono::milliseconds(config_.consensus_poll_ms);
    consensus_timer_->expires_after(interval);
    consensus_timer_->async_wait(
        [this](const boost::system::error_code &ec)
        {
          onConsensusPollTimer(ec);
        });
  }

  void Node::onConsensusPollTimer(const boost::system::error_code &ec)
  {
    if (ec == boost::asio::error::operation_aborted || stopping_.load())
      return;

    onConsensusPoll();

    armConsensusPollTimer();
  }

  void Node::armSyncTickTimer()
  {
    if (!p2p_ || stopping_.load())
      return;

    if (!sync_timer_)
    {
      sync_timer_ = std::make_unique<boost::asio::steady_timer>(
          p2p_->executor());
    }

    auto interval = std::chrono::milliseconds(SYNC_TICK_INTERVAL_MS);
    sync_timer_->expires_after(interval);
    sync_timer_->async_wait(
        [this](const boost::system::error_code &ec)
        {
          onSyncTickTimer(ec);
        });
  }

  void Node::onSyncTickTimer(const boost::system::error_code &ec)
  {
    if (ec == boost::asio::error::operation_aborted || stopping_.load())
      return;

    onSyncTick();

    armSyncTickTimer();
  }

  std::vector<uint8_t> Node::walVoteKey(Height height, Round round, Id signer_id)
  {
    std::vector<uint8_t> key;
    key.reserve(8 + 4 + 8 + 8);
    writeU64BE(key, height);
    writeU32BE(key, WAL_KIND_VOTE);
    writeU64BE(key, round);
    writeU64BE(key, signer_id);
    return key;
  }

  std::vector<uint8_t> Node::walLockKey(Height height, Round round)
  {
    std::vector<uint8_t> key;
    key.reserve(8 + 4 + 8);
    writeU64BE(key, height);
    writeU32BE(key, WAL_KIND_LOCK);
    writeU64BE(key, round);
    return key;
  }

  std::vector<uint8_t> Node::walPrefixForHeightOrLower(Height max_height)
  {
    return {};
  }

  std::vector<uint8_t> Node::walEncodeVoteRecord(const Consensus::Vote &v,
                                                 bool is_precommit)
  {
    auto bytes = Consensus::encodeVote(v);
    std::vector<uint8_t> out;
    out.reserve(1 + bytes.size());
    out.push_back(is_precommit ? 1 : 0);
    out.insert(out.end(), bytes.begin(), bytes.end());
    return out;
  }

  bool Node::walDecodeVoteRecord(const std::vector<uint8_t> &bytes,
                                 Consensus::Vote &out_v,
                                 bool &out_is_precommit)
  {
    if (bytes.empty())
      return false;

    out_is_precommit = (bytes[0] != 0);

    return Consensus::decodeVote(bytes.data() + 1,
                                 bytes.size() - 1,
                                 out_v);
  }
} // namespace Node