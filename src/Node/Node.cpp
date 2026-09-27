// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Node.h"

#include "Core/Genesis.h"
#include "Core/TransactionExecutor.h"
#include "Consensus/Message.h"
#include "P2P/MessageTypes.h"
#include "P2P/VersionMessage.h"

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

    // Consensus is started lazily by the consensus poll timer:
    // onConsensusPoll checks whether enough peers are Established to
    // form a quorum and starts consensus on the first poll where the
    // condition holds. This avoids starting consensus before the first
    // peer's handshake completes, which would drop the first proposal.
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

    // Cancel the poll timers first. Handlers that are already queued
    // see the operation_aborted error and return without re-arming.
    // This matters because P2PManager::stop() below may take up to
    // one interval's worth of time to drain; we don't want the timer
    // firing more work into the middle of the shutdown.
    if (consensus_timer_)
      consensus_timer_->cancel();
    if (sync_timer_)
      sync_timer_->cancel();

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
      return; // not a validator

    // Do not start (or restart) consensus while we're behind. A
    // validator that's syncing doesn't know the current height, and
    // a proposal made on a stale parent will be rejected by every
    // up-to-date peer. Once sync catches up, the poll loop will call
    // this again and consensus will start normally.
    if (chain_ && chain_->isSyncing())
    {
      (*log_)(Logging::DEBUGGING)
          << "Consensus deferred: syncing (height=" << chain_->height()
          << " best_peer=" << chain_->bestPeerHeight() << ")";
      consensus_started_ = false;
      return;
    }

    if (consensus_started_.exchange(true))
      return; // already started

    // Count peers that have completed the handshake. peerCount()
    // includes peers that are still handshaking; broadcast() filters
    // those out, so they can't help us reach a quorum yet.
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

    (*log_)(Logging::INFO)
        << "Consensus started at height " << next_height
        << " (quorum=" << quorum
        << " reachable=" << reachable
        << " established=" << established << ")";
  }

  //  Subsystem initialization

  void Node::initStorage()
  {
    (*log_)(Logging::INFO) << "Initializing storage...";

    // Create data directory if needed.
    std::filesystem::create_directories(config_.data_dir);

    // Open the state DB.
    std::string state_path = config_.data_dir + "/state";
    state_db_ = std::make_unique<State::StateDB>(state_path,
                                                 config_.state_map_size);

    // Open the chain DB (block + receipt storage).
    std::string chain_path = config_.data_dir + "/chain";
    // ChainDB uses the same StateDB infrastructure for its tables —
    // for v1, we keep everything in one DB.
    chain_db_ = std::make_unique<Core::ChainDB>(*state_db_);

    // Chain wrapper.
    chain_ = std::make_unique<Core::Chain>(*chain_db_);

    // Mempool.
    mempool_ = std::make_unique<Core::Mempool>();

    (*log_)(Logging::DEBUGGING)
        << "Storage opened: state at " << state_path
        << " top height=" << chain_->height();
  }

  void Node::initGenesis()
  {
    if (!config_.apply_genesis_on_start)
      return;

    Core::GenesisConfig cfg = genesisConfig();

    // A StateAccess over the current committed state. Used by the
    // fresh-DB path to apply genesis, and by nothing in the initialized
    // path (which only inspects ChainDB meta).
    State::StateAccess state(*state_db_, /*version=*/0);

    auto head = chain_db_->getHead();
    const bool db_initialized = (head.height > 0) || !head.hash.isNull() ||
                                !chain_db_->getGenesisHash().isNull();

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

    // Fresh DB — apply genesis. `state` is in scope here.
    (*log_)(Logging::INFO)
        << "Empty state detected, applying genesis for "
        << networkName(config_.network);

    Core::applyGenesis(state, cfg);
    state.commit(0);

    Core::applyGenesis(state, cfg);
    state.commit(0);

    Core::Block genesis = Core::makeGenesisBlock(state, cfg);
    Crypto::Hash genesis_hash = genesis.hash();

    auto txn = state_db_->beginWrite();
    chain_db_->storeBlockTxn(txn, genesis, genesis_hash);

    Core::ChainDB::ChainHead ghead;
    ghead.hash = genesis_hash;
    ghead.height = 0;
    chain_db_->setHeadTxn(txn, ghead);
    txn.commit();

    chain_db_->setChainId(config_.chain_id);
    chain_db_->setGenesisHash(genesis_hash);

    (*log_)(Logging::INFO)
        << "Genesis applied: block hash="
        << ghead.hash.toString().substr(0, 16)
        << " state root=" << state.stateRoot().toString().substr(0, 16);
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

    // Network identity.
    p2p_cfg.magic = P2P::magicForNetwork(static_cast<int>(config_.network));
    p2p_cfg.agentString = GlobalConfig::PROJECT_AGENT_STRING;
    p2p_cfg.protocolVersion = GlobalConfig::CURRENT_PROTOCOL_VERSION;

    // Listening.
    p2p_cfg.listenPort = config_.p2p_port;

    // Bootstrap.
    p2p_cfg.dnsSeeds = config_.seeds;

    // Leave the rest at defaults.

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
      // Should not happen — initP2P calls loadOrCreateNodeKey()
      // before any peer is created. Log and return null; the peer
      // will fail auth and close.
      (*log_)(Logging::ERROR)
          << "buildAuthMessageForPeer: node key is null";
      return a;
    }

    a.pubkey = Crypto::derivePublicKey(node_key_);

    const uint64_t my_nonce = peer.localNonce();
    const uint64_t their_nonce = peer.peerNonce();

    P2P::AuthNonces nonces = P2P::orderNonces(
        peer.direction(), my_nonce, their_nonce);

    Crypto::Hash challenge = P2P::computeAuthChallenge(nonces, a.pubkey);

    a.signature = Crypto::sign(challenge, node_key_);
    return a;
  }

  bool Node::verifyPeerAuth(P2P::Peer &peer,
                            const P2P::AuthMessage &a,
                            uint64_t &outValidatorId)
  {
    outValidatorId = 0;

    // Reject null keys/sigs outright. A null sig would verify against
    // a null pubkey on some Ed25519 implementations, so guard
    // explicitly.
    if (a.pubkey.isNull() || a.signature.isNull())
      return false;

    const uint64_t my_nonce = peer.localNonce();
    const uint64_t their_nonce = peer.peerNonce();

    P2P::AuthNonces nonces = P2P::orderNonces(
        peer.direction(), my_nonce, their_nonce);

    Crypto::Hash challenge = P2P::computeAuthChallenge(nonces, a.pubkey);

    if (!Crypto::verify(challenge, a.pubkey, a.signature))
      return false;

    // Signature is valid. Now decide whether this pubkey is a
    // validator. A non-validator is still authenticated; it just
    // gets validator_id = 0.
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
      // v1 convention: the validator's signing key IS its reward
      // address. See getSignerPublicKey().
      if (v.reward_address == pk)
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

  //  Genesis config lookup

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

  //  Status

  Node::Status Node::status() const
  {
    std::lock_guard<std::mutex> lock(status_mutex_);

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
    }
    if (consensus_)
    {
      auto cs = consensus_->state();
      s.consensus_height = cs.height;
      s.consensus_round = cs.round;
      s.consensus_step = Consensus::stepName(cs.step);
    }

    return s;
  }

  //  Consensus deps

  Consensus::Dependencies Node::buildConsensusDeps()
  {
    Consensus::Dependencies deps;
    deps.my_validator_id = [this]()
    { return getMyValidatorId(); };
    deps.sign = [this](const Crypto::Hash &h)
    { return signHash(h); };
    deps.current_height = [this]()
    { return getCurrentHeight(); };
    deps.active_set = [this]()
    { return getActiveSet(); };
    deps.signer_public_key = [this](Index idx)
    { return getSignerPublicKey(idx); };

    // ---- chain_id ----
    // Needed by propose() to stamp block.header.chain_id. Without this,
    // deps_.chain_id() defaults to 0 and every proposed block carries
    // chain_id = 0, which BlockProcessor::checkHeader rejects.
    deps.chain_id = [this]() -> uint64_t
    { return config_.chain_id; };

    // ---- parent_hash ----
    // The parent of the next block is the current chain head. Read fresh
    // on each call so the proposer sees the head that was just committed.
    deps.parent_hash = [this]() -> Crypto::Hash
    {
      return chain_db_->getHead().hash;
    };

    // ---- my_address ----
    // The address that appears in the proposed block's header. For v1,
    // this is the validator's reward_address, matching the convention
    // used by getSignerPublicKey.
    deps.my_address = [this]() -> Crypto::Address
    {
      State::StateAccess state(*state_db_, /*version=*/0);
      Core::ValidatorInfo v;
      if (!state.getValidator(config_.validator_id, v))
        return Crypto::Address{};
      return v.reward_address;
    };

    // ---- simulate_block ----
    // Dry-run the block against committed state and return the resulting
    // state root. Must not commit. The BlockProcessor is invoked with
    // dry_run = true so it stops short of writing anything the caller
    // could observe; the txn is aborted unconditionally.
    //
    // This is the callback that makes propose() and validateProposal()
    // work. Without it, both return nullopt and no block is ever
    // proposed or accepted.
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
      catch (...)
      {
        txn.abort();
        return std::nullopt;
      }
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
      onBlockCommitted(b);
    };
    cb.on_height_advanced = [this](Height h)
    {
      onHeightAdvanced(h);
    };
    return cb;
  }

  //  ConsensusDependencies implementations

  Id Node::getMyValidatorId() const
  {
    return config_.validator_id;
  }

  Crypto::Signature Node::signHash(const Crypto::Hash &hash)
  {
    if (config_.validator_secret_key.isNull())
    {
      return Crypto::Signature{};
    }
    return Crypto::sign(hash, config_.validator_secret_key);
  }

  Height Node::getCurrentHeight() const
  {
    return chain_->height();
  }

  std::vector<Id> Node::getActiveSet() const
  {
    // Open a read-only StateAccess. We could cache the active set, but
    // it changes at rotation boundaries; for v1 we re-read on demand.
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

    // Read the validator from state.
    State::StateAccess state(*state_db_, /*version=*/0);
    Core::ValidatorInfo v;
    if (!state.getValidator(vid, v))
      return std::nullopt;

    // For v1, the signer's public key IS the reward address.
    // In a fuller implementation, validators would register a
    // dedicated signing key separate from their reward address.
    return v.reward_address;
  }

  //  ConsensusCallbacks implementations

  void Node::onConsensusProposal(const Consensus::Proposal &p)
  {
    // Encode and broadcast via P2P.
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

    // Build a StateView at the current height.
    auto state_view = makeStateView();
    if (!state_view)
      return {};

    return mempool_->selectForBlock(*state_view, max_bytes, max_txs);
  }

  std::unique_ptr<Core::StateView> Node::makeStateView() const
  {
    // Read at the current chain height. The StateView owns the
    // StateAccess, so it remains valid for the caller's lifetime
    // regardless of what else runs concurrently.
    uint64_t version = chain_->height();
    uint64_t chain_id = config_.chain_id;

    auto state = std::make_unique<State::StateAccess>(*state_db_, version);
    return std::make_unique<Core::StateViewFromAccess>(
        std::move(state), version, chain_id);
  }

  void Node::onBlockCommitted(const Core::Block &block)
  {
    std::string error;
    if (!applyCommittedBlock(block, error))
    {
      (*log_)(Logging::ERROR)
          << "Failed to apply committed block at height "
          << block.header.height << ": " << error;
      // In a full implementation, we would enter a recovery mode or
      // halt the node. For v1, we log and continue.
      return;
    }

    (*log_)(Logging::INFO)
        << "Applied committed block: height=" << block.header.height
        << " hash=" << block.hash().toString().substr(0, 16)
        << " txs=" << block.transactions.size();

    // Announce to peers. This is the only path by which non-validator
    // nodes learn about new blocks: they can't participate in consensus,
    // so they never see a Proposal, and they need the post-commit
    // Block message to advance.
    broadcastBlock(block);
  }

  void Node::onHeightAdvanced(Height height)
  {
    (*log_)(Logging::DEBUGGING)
        << "Chain advanced to height " << height;
  }

  void Node::onConsensusPoll()
  {
    // Try to start consensus if we haven't already. This runs on the
    // io_context thread, so snapshot() is safe to call. It's the
    // first thing we do so that consensus starts within one poll
    // interval of the first peer reaching Established.
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

  //  P2P event handlers

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

    // Do not try to start consensus here. onPeerConnected fires at
    // TCP-connect time, before the version handshake completes, so
    // broadcast() would silently drop any proposal we sent. The
    // poll loop (onConsensusPoll) retries the start every interval
    // and uses the Established count, which is the correct
    // condition.
    (void)id;
  }

  void Node::onP2PPeerDisconnected(P2P::PeerId id, const std::string &reason)
  {
    (*log_)(Logging::INFO) << "Peer disconnected: " << id << " (" << reason << ")";
    // Drop the sync manager, if any. Any in-flight request dies with
    // it; the next peer with a higher best_height will take over.
    sync_managers_.erase(id);
    peer_heights_.erase(id);
    updateBestPeerHeight();
  }

  //  Consensus message handlers

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

    // Route by message type, not by local step. A precommit received
    // during the prevote step is still a precommit — it's just early,
    // and the consensus engine will drop it. Conflating the two would
    // let precommits satisfy the prevote quorum and vice versa, which
    // breaks the safety argument.
    if (is_precommit)
      consensus_->onPrecommit(v);
    else
      consensus_->onPrevote(v);
  }

  //  Transaction and block handlers

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

    // Dedup before touching the mempool: if we already have this txid,
    // drop it silently. Without this, a broadcast from every peer
    // re-triggers a re-broadcast and the tx loops forever. The check
    // and the subsequent add are not atomic, so a race is possible
    // (two threads both see the tx as missing, both call add; add is
    // mutex-guarded and one insert wins, the other hits the
    // idempotent-accept path). The result is a duplicate broadcast,
    // which is bounded and harmless.
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

      // Propagate to peers so the tx reaches validators who can
      // include it. Every node that accepts a tx does this exactly
      // once; the `contains` check above is what breaks the loop.
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
    // Relay path. A peer that has committed a block broadcasts the
    // full block after applyCommittedBlock succeeds locally. We receive
    // it here, apply it if it's the next one we need, and re-broadcast
    // so it propagates through the network.
    //
    // Three cases:
    //
    //   Already have it       → drop silently, no re-broadcast.
    //   Height == our + 1     → apply, then re-broadcast.
    //   Height >  our + 1     → drop, rely on sync to fill the gap.
    //                           The block will arrive again after we
    //                           catch up.
    //   Height <= our height  → fork. Ban the sender. This should not
    //                           happen on a final chain; a peer that
    //                           sends it is either buggy or malicious.

    if (!chain_ || !chain_db_)
      return;

    Core::Block block;
    if (!Core::Block::deserialize(msg.payload.data(), msg.payload.size(), block))
    {
      (*log_)(Logging::DEBUGGING) << "Malformed Block received (ignored)";
      return;
    }

    const Crypto::Hash block_hash = block.hash();

    // Already have it.
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
      // Gap. Sync will fill it. Drop.
      (*log_)(Logging::DEBUGGING)
          << "Block at height " << block.header.height
          << " is ahead of our height " << our_height
          << " by more than one — dropping, sync will catch up";
      return;
    }

    // Height == our_height + 1. Apply.
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

    // Re-broadcast so the block propagates one hop further. A node
    // that's already seen it drops it silently.
    broadcastBlock(block);
  }

  void Node::handleGetHeaders(const P2P::Message &msg, P2P::PeerId from)
  {
    P2P::GetHeadersMessage req;
    if (!P2P::deserializeGetHeaders(msg.payload.data(), msg.payload.size(), req))
    {
      (*log_)(Logging::DEBUGGING)
          << "Malformed GetHeaders from peer " << from;
      return;
    }

    if (!chain_ || !p2p_)
      return;

    // Clamp the request. A peer asking for 1 million headers gets
    // MAX_HEADERS_PER_REQUEST.
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
      (*log_)(Logging::DEBUGGING)
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
        // We don't have this block. The requester will re-request it
        // from another peer, or from us later if we catch up.
        continue;
      }
      resp.blocks.push_back(std::move(*block));
    }

    P2P::Message reply;
    reply.type = P2P::MessageType::Blocks;
    reply.payload = P2P::serializeBlocks(resp);

    p2p_->sendTo(from, reply);
  }

  //  Block application

  bool Node::applyCommittedBlock(const Core::Block &block, std::string &error)
  {
    State::StateDB::Txn txn = state_db_->beginWrite();

    try
    {
      // Atomicity invariant: the state writes, the block index writes, and
      // the chain head update all happen on the same MDBX txn. Either they
      // all commit, or none of them do.
      //
      // Test injection: FailPoint::InsideTxn throws immediately after
      // beginWrite to exercise the abort path. See
      // NodeEndToEndFixture.InjectionInsideTxnLeavesNothingPersisted.
      if (fail_point_for_test_ == FailPoint::InsideTxn)
      {
        fail_point_for_test_ = FailPoint::None;
        throw std::runtime_error("test injection: InsideTxn");
      }

      State::StateAccess state(*state_db_, txn, block.header.height);

      Core::BlockContext ctx;
      ctx.chain_id = config_.chain_id;
      ctx.current_height = block.header.height;

      Core::BlockResult result =
          Core::BlockProcessor::applyBlock(state, block, ctx);

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

      txn.commit();
    }
    catch (const std::exception &e)
    {
      txn.abort();
      error = std::string("exception in block application: ") + e.what();
      return false;
    }

    // Post-commit bookkeeping 
    if (mempool_)
    {
      std::vector<Crypto::Hash> txids;
      txids.reserve(block.transactions.size());
      for (const auto &tx : block.transactions)
        txids.push_back(tx.txid());
      mempool_->removeIncluded(txids);
      mempool_->purgeExpired(block.header.height);
    }

    state_db_->flush();
    return true;
  }

  //  External API

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

    // Propagate to peers. The local mempool now has the tx; every
    // other node will learn about it through this broadcast (or from
    // one of the peers we broadcast to). If P2P is disabled, this is
    // a no-op.
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

    // Explicit override wins — tests and tooling use this.
    if (!config_.node_secret_key.isNull())
    {
      node_key_ = config_.node_secret_key;
      (*log_)(Logging::DEBUGGING)
          << "Using node_secret_key from config";
      return;
    }

    // A validator's node identity IS its validator identity. This is
    // what makes verifyPeerAuth() able to bind the peer to a validator
    // ID: the pubkey we advertise in Auth derives to the validator's
    // reward_address, which is what the active-set lookup matches on.
    //
    // Non-validator nodes fall through and get a fresh key, which
    // authenticates them as "not a validator" (validator_id = 0).
    if (!config_.validator_secret_key.isNull())
    {
      node_key_ = config_.validator_secret_key;
      (*log_)(Logging::DEBUGGING)
          << "Using validator_secret_key as node key";
      return;
    }

    // Non-validator: load or create a persistent identity.
    const std::string path = config_.data_dir + "/node_key";

    // Try to load an existing key.
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

    // Generate a fresh key and persist it.
    Crypto::KeyPair kp = Crypto::generateKeyPair();
    node_key_ = kp.secretKey;

    {
      std::ofstream out(path, std::ios::binary | std::ios::trunc);
      if (!out)
      {
        (*log_)(Logging::ERROR)
            << "Failed to write node key to " << path;
        // Fall back to the in-memory key. P2P will still work for
        // this session, but the identity won't be stable across
        // restarts. Log loudly.
        return;
      }
      out.write(reinterpret_cast<const char *>(node_key_.data.data()),
                node_key_.data.size());
      out.close();

      // Restrict permissions. Best-effort — some filesystems don't
      // support this.
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
    (*log_)(Logging::INFO)
        << "Peer established: " << info.id
        << " best_height=" << info.best_height
        << " validator_id=" << info.validator_id
        << " agent=\"" << info.agent << "\"";

    // Build the SyncManager. It has four callbacks into Node:
    //   our_height    — reads chain height fresh on every use
    //   send          — forwards to P2PManager::sendTo
    //   apply_blocks  — hands blocks to applyCommittedBlock
    //   on_misbehavior— scores the peer and, if the score crosses
    //                   the ban threshold, disconnects.
    auto mgr = std::make_unique<P2P::SyncManager>(
        info.id, config_.max_block_bytes);

    const P2P::PeerId peer_id = info.id;

    mgr->our_height = [this]() -> uint64_t
    {
      return chain_ ? chain_->height() : 0;
    };

    // Record the peer's advertised best height. Chain::setBestPeerHeight
    // persists it; Chain::isSyncing reads it. This is what feeds the
    // consensus gate above and the best_peer_height field in status().
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
          // Stop at the first failure. The count returned is
          // "blocks before the failure" — the SyncManager treats
          // any shortfall as a protocol violation and disconnects.
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

      // Reach into the peer to record the score. reportMisbehavior
      // already increments stats_.misbehaviors and invokes
      // onMisbehaving (which P2PManager turns into a ban record).
      //
      // We deliberately do NOT forceClose from here — the score
      // accumulates, and P2PManager::handlePeerDisconnected bans
      // when the accumulated score crosses banThreshold. A peer
      // that misses one request isn't banned; a peer that
      // repeatedly lies about headers is.
      auto *peer = p2p_->findPeer(peer_id);
      if (peer)
        peer->reportMisbehavior(score, /*reason=*/0);
    };

    // Record before starting so a racing message can find it.
    sync_managers_[peer_id] = std::move(mgr);

    // Kick off the initial sync. If the peer is at or below our
    // height, this is a no-op.
    sync_managers_[peer_id]->start();
  }

  void Node::handleIncomingHeaders(const P2P::Message &msg, P2P::PeerId from)
  {
    auto it = sync_managers_.find(from);
    if (it == sync_managers_.end())
      return; // Headers from a peer we didn't set up sync for

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

    // broadcast() filters to Established peers only. A peer that's
    // still handshaking or authenticating won't receive this; it will
    // get the block from sync instead once it reaches Established.
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

    // broadcast() filters to Established peers only.
    p2p_->broadcast(msg);

    (*log_)(Logging::DEBUGGING)
        << "Broadcast tx " << tx.txid().toString().substr(0, 16)
        << " bytes=" << msg.payload.size();
  }

  void Node::onSyncTick()
  {
    // Runs on the io_context thread. sync_managers_ is only touched
    // there, and asio guarantees handlers don't run concurrently, so
    // the iteration is safe. The map may be modified by a later
    // handler (onP2PPeerEstablished/Disconnected), but not by anything
    // tick() does synchronously — those callbacks post their
    // modifications to the event loop.
    for (auto &[id, mgr] : sync_managers_)
    {
      if (mgr)
        mgr->tick();
    }
  }

  void Node::armConsensusPollTimer()
  {
    // No consensus instance means no poll timer. A non-validator
    // node never needs to poll consensus.
    if (!consensus_ || !p2p_ || stopping_.load())
      return;

    if (!consensus_timer_)
    {
      // Construct once. The timer's executor is the P2P io_context,
      // so the handler runs on the event loop thread.
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
      return; // cancelled by stop()

    onConsensusPoll();

    // Re-arm for the next tick.
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
      return; // cancelled by stop()

    onSyncTick();

    // Re-arm for the next tick.
    armSyncTickTimer();
  }
} // namespace Node