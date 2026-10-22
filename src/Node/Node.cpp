// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Node.h"

#include "Common/Wire.h"
#include "Core/Genesis.h"
#include "Core/TransactionExecutor.h"
#include "Core/ValidatorRotation.h"
#include "Core/EquivocationProof.h"
#include "Core/BridgeSigning.h"
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
        << " validator_id=" << config_.validator_id
        << " smt_history_blocks=" << config_.smt_history_blocks;
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

    p2p_->start(config_.seeds);

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

  std::unique_ptr<State::StateAccess>
  Node::makeStateAccess(uint64_t version) const
  {
    auto s = std::make_unique<State::StateAccess>(*state_db_, version);
    s->setHistoryWindow(config_.smt_history_blocks);
    return s;
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
        << " top height=" << chain_->height()
        << " smt_history_blocks=" << config_.smt_history_blocks;
  }

  void Node::initMempool()
  {
    if (!mempool_)
      return;

    //  ---- Verifier wiring ----
    //
    //  The mempool's bridge pre-checks are supplied by the node as
    //  callables. The mempool itself does not know how to read
    //  validator sets or bridge registrations; that is the
    //  executor's job, and its state-reading machinery is not part
    //  of the StateView interface. Rather than widen StateView
    //  (which would drag validator and bridge types into every
    //  test mock), the node installs two verifier closures here.
    //  The mempool dispatches to them from validate().
    //
    //  The StateAccess factory reads the current chain height at
    //  call time, so the verifiers see the same state the executor
    //  would apply against. A tx that fails here is one the
    //  executor will reject at apply time; admitting it would
    //  occupy a block slot and force the proposer's drop-and-retry
    //  loop to clean it up on every proposal attempt.
    //
    //  Under the validator-is-watcher model, both verifiers
    //  resolve the active validator set via
    //  Core::loadSortedActiveValidators and index it by the
    //  signature block's signer_index.
    //
    //  If the factory or a verifier is not installed (a unit test
    //  that constructs a bare Mempool, a future lightweight node
    //  that does not participate in consensus), the corresponding
    //  check is a no-op. The structural payload-shape checks in
    //  validate() still run unconditionally.

    mempool_->setStateAccessFactory(
        [this]() -> std::unique_ptr<State::StateAccess>
        {
          if (!chain_ || !state_db_)
            return nullptr;
          auto access = std::make_unique<State::StateAccess>(
              *state_db_, chain_->height());
          access->setHistoryWindow(config_.smt_history_blocks);
          return access;
        });

    mempool_->setGovernanceVerifier(
        [this](State::StateAccess &access,
               const Core::Transaction &tx) -> bool
        {
          return verifyGovernanceTxAtAdmission(access, tx);
        });

    mempool_->setBridgeAttestationVerifier(
        [this](State::StateAccess &access,
               const Core::Transaction &tx) -> bool
        {
          return verifyBridgeAttestationTxAtAdmission(access, tx);
        });

    //  ---- Load persisted entries ----

    std::vector<Crypto::Hash> stale;
    {
      auto view = makeStateView();
      if (!view)
      {
        (*log_)(Logging::WARNING)
            << "initMempool: could not build state view, skipping load";
        return;
      }

      mempool_->load(*view);
      stale = mempool_->takeStaleAfterLoad();
    }

    if (!stale.empty())
    {
      try
      {
        auto txn = state_db_->beginWrite();
        for (const auto &txid : stale)
        {
          txn.del(State::StateDB::TBL_MEMPOOL,
                  txid.data.data(), txid.data.size());
        }
        txn.commit();

        (*log_)(Logging::DEBUGGING)
            << "Mempool load pruned " << stale.size()
            << " stale entries";
      }
      catch (const std::exception &e)
      {
        (*log_)(Logging::WARNING)
            << "Mempool load prune failed: " << e.what();
      }
    }

    (*log_)(Logging::INFO)
        << "Mempool loaded: " << Logging::BRIGHT_GREEN
        << mempool_->size() << " pending txs";
  }

  void Node::initGenesis()
  {
    if (!config_.apply_genesis_on_start)
      return;

    Core::GenesisConfig cfg = genesisConfig();

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

    Crypto::Hash genesis_hash;

    {
      auto txn = state_db_->beginWrite();

      State::StateAccess state(*state_db_, txn, /*version=*/0);
      state.setHistoryWindow(config_.smt_history_blocks);

      Core::applyGenesis(state, cfg);
      state.commit(0);

      Core::Block genesis = Core::makeGenesisBlock(state, cfg);
      genesis_hash = genesis.hash();

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

    auto state = makeStateAccess(/*version=*/0);
    auto active = loadActiveSetFromState(*state);

    for (Id vid : active)
    {
      Core::ValidatorInfo v;
      if (!state->getValidator(vid, v))
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

  State::SparseMerkleTree::Stats Node::smtStats() const
  {
    if (!state_db_)
      return State::SparseMerkleTree::Stats{};
    auto s = makeStateAccess(chain_ ? chain_->height() : 0);
    return s->smtStats();
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
      auto state = makeStateAccess(/*version=*/0);
      std::vector<Id> committed = getActiveSet();
      return Core::resolveActiveSet(
          *state, committed, chain_->height(), force_rotation);
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
      auto state = makeStateAccess(/*version=*/0);
      Core::ValidatorInfo v;
      if (!state->getValidator(config_.validator_id, v))
        return Crypto::Address{};
      return v.reward_address;
    };

    deps.simulate_block =
        [this](const Core::Block &block,
               Crypto::Hash &out_state_root,
               std::vector<Core::Fill> &out_epoch_fills,
               Crypto::Hash *out_failed_txid) -> bool
    {
      auto txn = state_db_->beginWrite();

      State::StateAccess state(*state_db_, txn, block.header.height);
      state.setHistoryWindow(config_.smt_history_blocks);

      Core::BlockContext ctx;
      ctx.chain_id = config_.chain_id;
      ctx.current_height = block.header.height;
      ctx.dry_run = true;

      Core::BlockResult result =
          Core::BlockProcessor::applyBlock(state, block, ctx);

      txn.abort();

      if (!result.valid)
      {
        if (out_failed_txid)
          *out_failed_txid = result.failed_txid;

        if (out_failed_txid &&
            !out_failed_txid->isNull() &&
            mempool_)
        {
          auto view = makeStateView();
          if (view)
          {
            mempool_->reject(*out_failed_txid, *view);
          }
          else
          {
            (*log_)(Logging::WARNING)
                << "simulate_block: could not build state view to "
                << "reject " << out_failed_txid->toString().substr(0, 16);
          }
        }

        (*log_)(Logging::WARNING)
            << "simulate_block failed at h=" << block.header.height
            << ": " << result.error
            << (result.failed_txid.isNull()
                    ? ""
                    : " (tx " + result.failed_txid.toString().substr(0, 16) + ")");

        return false;
      }

      out_state_root = result.new_state_root;
      out_epoch_fills = std::move(result.epoch_fills);
      return true;
    };

    deps.verify_slash_proof =
        [this](const std::vector<uint8_t> &payload) -> bool
    {
      auto state = makeStateAccess(/*version=*/0);
      std::vector<Id> empty;
      auto result = Core::verifyEquivocationProof(payload, empty, *state);
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
            const uint64_t h = Common::readU64BE(key.data());
            if (h != for_height)
              return true;

            const uint32_t kind = Common::readU32BE(key.data() + 8);

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
              const Round r = Common::readU64BE(key.data() + 12);
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
            const uint64_t h = Common::readU64BE(key.data());
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
    auto state = makeStateAccess(/*version=*/0);
    return loadActiveSetFromState(*state);
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

    auto state = makeStateAccess(/*version=*/0);
    Core::ValidatorInfo v;
    if (!state->getValidator(vid, v))
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

    auto state = makeStateAccess(version);
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

    if (tx.tx_type == Core::TxType::BridgeAckWithdrawal &&
        tx.payload.size() >= 8)
    {
      uint64_t withdrawal_id = 0;
      for (int i = 0; i < 8; ++i)
        withdrawal_id |= uint64_t(tx.payload[i]) << (i * 8);

      auto view = makeStateView();
      if (view)
      {
        Core::BridgeWithdrawal w;
        if (view->getBridgeWithdrawal(withdrawal_id, w) && w.isReleased())
        {
          (*log_)(Logging::DEBUGGING)
              << "Dropping BridgeAckWithdrawal for already-released "
              << "withdrawal " << withdrawal_id;
          return;
        }
      }
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
      state.setHistoryWindow(config_.smt_history_blocks);

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

      if (config_.smt_history_blocks > 0 &&
          block.header.height > config_.smt_history_blocks)
      {
        const uint64_t keep_from =
            block.header.height - config_.smt_history_blocks;

        if (block.header.height != last_prune_height_)
        {
          state_db_->pruneHistoryBeforeTxn(txn, keep_from);
          last_prune_height_ = block.header.height;
        }
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
      auto state = makeStateAccess(block.header.height);

      const uint64_t window = config_.fee_window_blocks;
      const uint64_t tip = block.header.height;

      uint64_t sum = state->getMetaU64("fees_in_window");

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

      state->putMetaU64("fees_in_window", sum);
    }

    state_db_->flush();
    return true;
  }

  //  =====================================================================
  //  Bridge pre-check verifiers
  //
  //  These run inside Mempool::validate, on a StateAccess the node
  //  supplied via the factory. They mirror the executor's signature
  //  checks (TransactionExecutor.cpp), rebuilt here against the same
  //  message encoding and the same sorted active validator set.
  //
  //  Under the validator-is-watcher model, both verifiers resolve
  //  the active validator set via Core::loadSortedActiveValidators
  //  and index it by the signature block's signer_index. There is
  //  no per-chain watcher set to resolve.
  //
  //  They exist because the executor's checks, without a mempool
  //  mirror, produce the stall failure mode: a tx that cannot apply
  //  sits in the pool, every proposal includes it, the block fails
  //  simulation, the proposer drops it, a peer rebroadcasts it, the
  //  mempool re-admits it, repeat. The proposer's drop-and-retry
  //  loop is a safety net; these verifiers are the fix.
  //
  //  Both return false on any doubt (empty active set, malformed
  //  payload, missing key). A false result rejects the tx from the
  //  pool. The mempool counts the rejection under
  //  Rejected_BridgeSignature, so an operator can see them in
  //  getMempoolStats.
  //  =====================================================================

  bool Node::verifyGovernanceTxAtAdmission(
      State::StateAccess &access,
      const Core::Transaction &tx)
  {
    std::vector<Id> active = Core::loadSortedActiveValidators(access);
    if (active.empty())
      return false;

    switch (tx.tx_type)
    {
    case Core::TxType::BridgePause:
    case Core::TxType::BridgeUnpause:
    {
      if (tx.payload.size() < 8 + 2)
        return false;

      uint64_t bound_height = 0;
      for (int i = 0; i < 8; ++i)
        bound_height |= uint64_t(tx.payload[i]) << (i * 8);

      uint8_t message[8];
      for (int i = 0; i < 8; ++i)
        message[i] = uint8_t(bound_height >> (i * 8));

      const std::string_view domain =
          (tx.tx_type == Core::TxType::BridgePause) ? "bpau" : "bunp";

      const size_t sig_off = 8;
      const uint8_t *sigs = tx.payload.data() + sig_off;
      const size_t sig_len = tx.payload.size() - sig_off;

      const auto result = Core::verifyGovernanceSignaturesAt(
          access, active, domain,
          message, sizeof(message),
          sigs, sig_len,
          access.version());

      if (result != Core::GovernanceVerifyResult::Ok)
      {
        (*log_)(Logging::WARNING)
            << "verifyGovernanceTxAtAdmission: rejected "
            << Core::txTypeName(tx.tx_type)
            << " reason=" << static_cast<int>(result)
            << " active.size()=" << active.size()
            << " height=" << access.version()
            << " sig_len=" << sig_len;
      }

      return result == Core::GovernanceVerifyResult::Ok;
    }

    case Core::TxType::BridgeRegisterChain:
    {
      if (tx.payload.size() < 1 + 2)
        return false;

      const uint8_t reg_len = tx.payload[0];
      const size_t after_blob = 1 + static_cast<size_t>(reg_len);
      if (tx.payload.size() < after_blob + 2)
        return false;

      const uint8_t *msg = tx.payload.data() + 1;
      const size_t msg_len = reg_len;
      const uint8_t *sigs = tx.payload.data() + after_blob;
      const size_t sig_len = tx.payload.size() - after_blob;

      return Core::verifyGovernanceSignaturesAt(
                 access, active, "brgr",
                 msg, msg_len,
                 sigs, sig_len,
                 access.version()) ==
             Core::GovernanceVerifyResult::Ok;
    }

    default:
      return false;
    }
  }

  bool Node::verifyBridgeAttestationTxAtAdmission(
      State::StateAccess &access,
      const Core::Transaction &tx)
  {
    switch (tx.tx_type)
    {
    case Core::TxType::BridgeAckWithdrawal:
    {
      //  Layout: [8] withdrawal_id || [32] release_tx_hash ||
      //  [8] release_height || [2] count || count * 66.
      if (tx.payload.size() < 8 + 32 + 8 + 2)
        return false;

      uint64_t withdrawal_id = 0;
      for (int i = 0; i < 8; ++i)
        withdrawal_id |= uint64_t(tx.payload[i]) << (i * 8);

      Core::BridgeWithdrawal w;
      if (!access.getBridgeWithdrawal(withdrawal_id, w))
        return false;
      if (w.isReleased())
        return false;
      if (!w.isWellFormed())
        return false;

      Core::BridgeChainRegistration reg;
      if (!access.getBridgeChainRegistration(w.source_chain_id, reg))
        return false;
      if (!reg.isWellFormed())
        return false;

      //  Active validator set. Under the validator-is-watcher
      //  model there is no per-chain watcher set to resolve; every
      //  active validator is eligible to attest to every chain.
      std::vector<Id> active = Core::loadSortedActiveValidators(access);
      if (active.size() < reg.active_validator_min)
        return false;

      const size_t threshold = Core::bftQuorum(active.size());

      //  Message: Blake2b("back" || LE64(withdrawal_id)).
      uint8_t msg[8];
      for (int i = 0; i < 8; ++i)
        msg[i] = uint8_t(withdrawal_id >> (i * 8));

      const size_t sig_off = 8 + 32 + 8;
      const uint8_t *sigs = tx.payload.data() + sig_off;
      const size_t sig_len = tx.payload.size() - sig_off;

      std::vector<Core::BridgeSignatureEntry> sigs_parsed;
      if (!Core::parseBridgeSignatureBlock(sigs, sig_len, sigs_parsed))
        return false;
      if (sigs_parsed.size() < threshold)
        return false;

      std::vector<bool> seen(active.size(), false);
      for (const auto &e : sigs_parsed)
      {
        if (e.signer_index >= active.size())
          return false;
        if (seen[e.signer_index])
          return false;
        seen[e.signer_index] = true;
      }

      const Crypto::Hash hash =
          Core::bridgeSigningHash("back", msg, sizeof(msg));

      for (const auto &e : sigs_parsed)
      {
        auto pk = access.validatorKeyAtHeight(
            active[e.signer_index], access.version());
        if (!pk.has_value())
          return false;
        if (!Crypto::verify(hash, *pk, e.signature))
          return false;
      }

      return true;
    }

    case Core::TxType::BridgeMint:
    {
      //  Layout: [8] source_chain_id || [32] source_tx_hash ||
      //  [4] output_index || [32] destination || [8] amount ||
      //  [2] count || count * 66.
      constexpr size_t fixed = 8 + 32 + 4 + 32 + 8;

      if (tx.payload.size() < fixed + 2)
        return false;

      uint64_t source_chain_id = 0;
      for (int i = 0; i < 8; ++i)
        source_chain_id |= uint64_t(tx.payload[i]) << (i * 8);

      Crypto::Hash source_tx_hash;
      std::memcpy(source_tx_hash.data.data(),
                  tx.payload.data() + 8, 32);

      uint32_t output_index = 0;
      for (int i = 0; i < 4; ++i)
        output_index |= uint32_t(tx.payload[8 + 32 + i]) << (i * 8);

      Core::BridgeChainRegistration reg;
      if (!access.getBridgeChainRegistration(source_chain_id, reg))
        return false;
      if (!reg.isWellFormed() || !reg.enabled)
        return false;

      Core::TokenInfo token;
      if (!access.getToken(reg.wrapped_token_id, token))
        return false;
      if (!token.isBridged() ||
          !token.fingerprint.has_value() ||
          *token.fingerprint != reg.fingerprint)
        return false;

      uint64_t consumed_at = 0;
      if (access.getBridgeConsumed(source_chain_id, source_tx_hash,
                                   output_index, consumed_at))
        return false;

      std::vector<Id> active = Core::loadSortedActiveValidators(access);
      if (active.size() < reg.active_validator_min)
        return false;

      const size_t threshold = Core::bftQuorum(active.size());

      std::vector<uint8_t> message;
      message.reserve(fixed);

      for (int i = 0; i < 8; ++i)
        message.push_back(uint8_t(source_chain_id >> (i * 8)));

      message.insert(message.end(),
                     tx.payload.begin() + 8,
                     tx.payload.begin() + 8 + 32);

      for (int i = 0; i < 4; ++i)
        message.push_back(tx.payload[8 + 32 + i]);

      message.insert(message.end(),
                     tx.payload.begin() + 8 + 32 + 4,
                     tx.payload.begin() + 8 + 32 + 4 + 32);

      for (int i = 0; i < 8; ++i)
        message.push_back(tx.payload[8 + 32 + 4 + 32 + i]);

      const size_t sig_off = fixed;
      const uint8_t *sigs = tx.payload.data() + sig_off;
      const size_t sig_len = tx.payload.size() - sig_off;

      std::vector<Core::BridgeSignatureEntry> sigs_parsed;
      if (!Core::parseBridgeSignatureBlock(sigs, sig_len, sigs_parsed))
        return false;
      if (sigs_parsed.size() < threshold)
        return false;

      std::vector<bool> seen(active.size(), false);
      for (const auto &e : sigs_parsed)
      {
        if (e.signer_index >= active.size())
          return false;
        if (seen[e.signer_index])
          return false;
        seen[e.signer_index] = true;
      }

      const Crypto::Hash hash =
          Core::bridgeSigningHash("bmin", message.data(),
                                  message.size());

      for (const auto &e : sigs_parsed)
      {
        auto pk = access.validatorKeyAtHeight(
            active[e.signer_index], access.version());
        if (!pk.has_value())
          return false;
        if (!Crypto::verify(hash, *pk, e.signature))
          return false;
      }

      return true;
    }

    case Core::TxType::BridgeAttest:
    case Core::TxType::BridgeAckAttest:
    {
      //  Single-validator attestations. The structural shape is
      //  already enforced by validateBridgePayloadShape; the check
      //  here is a single signature against the validator's
      //  consensus key at the current tip. A single failed
      //  attestation is not a stall (the block is rebuilt without
      //  it), so this returns true and lets the executor's own
      //  check reject an invalid attestation at apply time. The
      //  proposer's drop-and-retry loop cleans it up.
      return true;
    }

    default:
      return false;
    }
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
    auto state = makeStateAccess(/*version=*/0);
    return state->stateRoot();
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

    auto state = makeStateAccess(resolved_version);

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

    auto result = state->proveAtVersion(*key, resolved_version);

    switch (result.status)
    {
    case State::ProofResultStatus::Ok:
      resp.status = P2P::ProofMessage::Status::Ok;
      resp.proof = std::move(*result.proof);
      break;
    case State::ProofResultStatus::VersionUnavailable:
      resp.status = P2P::ProofMessage::Status::VersionUnavailable;
      break;
    case State::ProofResultStatus::KeyNotFound:
      resp.status = P2P::ProofMessage::Status::KeyNotFound;
      break;
    case State::ProofResultStatus::InternalError:
      resp.status = P2P::ProofMessage::Status::Malformed;
      break;
    }

    P2P::Message reply;
    reply.type = P2P::MessageType::Proof;
    reply.payload = P2P::serializeProof(resp);
    p2p_->sendTo(from, reply);

    (*log_)(Logging::DEBUGGING)
        << "Served proof for peer " << from
        << " key_type=" << static_cast<int>(req.key_type)
        << " version=" << resolved_version
        << " status=" << static_cast<int>(resp.status)
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
    Common::putU64BE(key, height);
    Common::putU32BE(key, WAL_KIND_VOTE);
    Common::putU64BE(key, round);
    Common::putU64BE(key, signer_id);
    return key;
  }

  std::vector<uint8_t> Node::walLockKey(Height height, Round round)
  {
    std::vector<uint8_t> key;
    key.reserve(8 + 4 + 8);
    Common::putU64BE(key, height);
    Common::putU32BE(key, WAL_KIND_LOCK);
    Common::putU64BE(key, round);
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