// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Node.h"

#include "Core/Genesis.h"
#include "Core/TransactionExecutor.h"
#include "Consensus/Message.h"
#include "P2P/MessageTypes.h"

#include "Crypto/Ed25519.h"
#include "Logging/ILogger.h"
#include "Logging/LoggerRef.h"

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

    (*log_)(Logging::INFO)
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

    (*log_)(Logging::INFO) << "Node starting";

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

    (*log_)(Logging::INFO)
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

    // Consensus is started lazily by the poll loop: onConsensusPoll
    // checks whether enough peers are Established to form a quorum
    // and starts consensus on the first poll where the condition
    // holds. This avoids starting consensus before the first peer's
    // handshake completes, which would drop the first proposal.
    scheduleConsensusPoll();

    // Run the event loop. Blocks until stop() is called.
    p2p_->run();

    (*log_)(Logging::INFO) << "Node event loop exited";
  }

  void Node::stop()
  {
    if (stopping_.exchange(true))
    {
      return; // already stopping
    }

    if (!running_)
      return;

    (*log_)(Logging::INFO) << "Node stopping";

    // Stop consensus first (it may hold locks).
    if (consensus_)
    {
      consensus_->stop();
    }

    // Stop P2P (drains sockets, closes acceptors).
    if (p2p_)
    {
      p2p_->stop();
    }

    // Flush state and chain to disk.
    if (state_db_)
      state_db_->flush();

    running_ = false;
    (*log_)(Logging::INFO) << "Node stopped";
  }

  void Node::maybeStartConsensus()
  {
    if (!consensus_)
      return; // not a validator

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
    (*log_)(Logging::INFO) << "Initializing storage";

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

    (*log_)(Logging::INFO)
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

    Core::Block genesis = Core::makeGenesisBlock(state, cfg);
    chain_db_->storeBlock(genesis);

    Core::ChainDB::ChainHead ghead;
    ghead.hash = genesis.hash();
    ghead.height = 0;
    chain_db_->setHead(ghead);
    chain_db_->setChainId(config_.chain_id);
    chain_db_->setGenesisHash(ghead.hash);

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

    (*log_)(Logging::INFO) << "Initializing P2P";

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

    (*log_)(Logging::INFO)
        << "P2P initialized: magic=0x" << std::hex << p2p_cfg.magic << std::dec
        << " port=" << p2p_cfg.listenPort
        << " seeds=" << p2p_cfg.dnsSeeds.size();
  }

  void Node::initConsensus()
  {
    if (config_.validator_id == 0)
    {
      (*log_)(Logging::INFO) << "Not a validator, consensus disabled";
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
  }

  void Node::onHeightAdvanced(Height height)
  {
    (*log_)(Logging::DEBUGGING)
        << "Chain advanced to height " << height;
  }

  //  Consensus timer

  void Node::scheduleConsensusPoll()
  {
    if (!consensus_ || stopping_.load())
      return;

    // P2P provides the io_context we post to. When P2P is disabled,
    // the caller is responsible for driving consensus (usually by
    // calling consensus_->pollTimers() directly). Tests do this.
    if (!p2p_)
      return;

    auto interval = std::chrono::milliseconds(config_.consensus_poll_ms);
    p2p_->post([this, interval]()
               {
    std::this_thread::sleep_for(interval);
    if (stopping_.load()) return;
    onConsensusPoll();
    scheduleConsensusPoll(); });
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
      handleIncomingBlock(msg);
      break;
    case P2P::MessageType::GetHeaders:
      handleGetHeaders(msg, from);
      break;
    case P2P::MessageType::GetBlocks:
      handleGetBlocks(msg, from);
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

    auto state_view = makeStateView();
    if (!state_view)
      return;

    auto result = mempool_->add(tx, *state_view, Core::FeeTier::Standard);

    if (result == Core::MempoolAddResult::Accepted)
    {
      (*log_)(Logging::DEBUGGING)
          << "Tx accepted to mempool: "
          << tx.txid().toString().substr(0, 16);
    }
    else
    {
      (*log_)(Logging::DEBUGGING)
          << "Tx rejected: " << Core::mempoolAddResultName(result);
    }
  }

  void Node::handleIncomingBlock(const P2P::Message &msg)
  {
    // For v1, blocks arrive via consensus proposals, not as standalone
    // Block messages. If we receive one, log and ignore.
    (*log_)(Logging::DEBUGGING) << "Standalone Block message received (ignored)";
    (void)msg;
  }

  void Node::handleGetHeaders(const P2P::Message & /*msg*/, P2P::PeerId from)
  {
    // TODO: sync support. For v1, we don't serve headers.
    (void)from;
  }

  void Node::handleGetBlocks(const P2P::Message & /*msg*/, P2P::PeerId from)
  {
    // TODO: sync support. For v1, we don't serve blocks.
    (void)from;
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

  bool Node::submitTransaction(const Core::Transaction &tx, std::string &error)
  {
    if (!mempool_)
    {
      error = "mempool not initialized";
      return false;
    }

    auto state_view = makeStateView();
    if (!state_view)
    {
      error = "could not build state view";
      return false;
    }

    auto result = mempool_->add(tx, *state_view, Core::FeeTier::Standard);

    if (result == Core::MempoolAddResult::Accepted)
    {
      return true;
    }

    error = Core::mempoolAddResultName(result);
    return false;
  }

  Crypto::Hash Node::stateRoot() const
  {
    if (!state_db_)
      return Crypto::Hash{};
    State::StateAccess state(*state_db_, /*version=*/0);
    return state.stateRoot();
  }
} // namespace Node