#pragma once

#include <gtest/gtest.h>

#include "Utils.h"
#include "Tests/ConsensusHelpers.h"
#include "Tests/ConsensusHarness.h"

#include "Core/ValidatorRotation.h"
#include "Node/Node.h"

namespace Tests
{
  //  Node_Fixture
  //
  //  Owns the base temp dir. No consensus, no nodes; just the
  //  scaffolding that the derived fixtures build on.
  class Node_Fixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      static std::atomic<uint64_t> counter{0};
      tmp_dir_ = std::filesystem::temp_directory_path() /
                 ("clrty_node_test_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(tmp_dir_);
    }

    void TearDown() override
    {
      std::error_code ec;
      std::filesystem::remove_all(tmp_dir_, ec);
    }

    Node::NodeConfig makeValidConfig()
    {
      Node::NodeConfig cfg;
      cfg.network = Node::Network::Regtest;
      cfg.data_dir = tmp_dir_.string();
      cfg.state_map_size = 64ULL * 1024 * 1024;
      cfg.chain_map_size = 64ULL * 1024 * 1024;
      cfg.p2p_port = 0;
      cfg.enable_p2p = false;
      cfg.validator_id = 0;
      cfg.apply_genesis_on_start = true;
      return cfg;
    }

    Node::NodeConfig makeValidatorConfig(uint64_t validator_id)
    {
      Node::NodeConfig cfg = makeValidConfig();
      cfg.validator_id = validator_id;
      for (size_t i = 0; i < cfg.consensus_secret_key.data.size(); ++i)
        cfg.consensus_secret_key.data[i] = uint8_t(0x80 + validator_id + i);
      return cfg;
    }

    const std::filesystem::path &tmp_dir() const { return tmp_dir_; }

    NoopLogger logger_;
    std::filesystem::path tmp_dir_;
  };

  //  Node_BlockFixture
  //
  //  Two deterministic validators, a funded genesis, and helpers
  //  for building signed empty blocks. No consensus harness.
  class Node_BlockFixture : public Node_Fixture
  {
  protected:
    void SetUp() override
    {
      Node_Fixture::SetUp();

      seed1_ = deterministicValidatorKey(1);
      seed2_ = deterministicValidatorKey(2);

      std::vector<Crypto::KeyPair> keys{seed1_, seed2_};
      genesis_ = makeGenesis(keys);
    }

    Node::NodeConfig makeFixtureConfig()
    {
      Node::NodeConfig cfg = makeValidConfig();
      cfg.test_genesis_override = genesis_;
      return cfg;
    }

    Core::Block buildValidEmptyBlock(Node::Node &node, uint64_t height)
    {
      auto &chain_db = NodeTestAccess::chainDb(node);
      const Crypto::Hash parent = chain_db.getHead().hash;

      Core::Block b = makeSkeleton(height, parent);
      Core::BlockResult sim = simulateBlock(node, b, height);
      if (sim.valid)
      {
        b.header.state_root = sim.new_state_root;
        b.quorum_signatures = makeQuorumForBlock(b);
      }
      return b;
    }

    Core::Block makeSkeleton(uint64_t height, const Crypto::Hash &parent)
    {
      Core::Block b;
      b.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
      b.header.chain_id = genesis_.chain_id;
      b.header.height = height;
      b.header.parent_hash = parent;
      b.header.timestamp_ms = 1'700'000'000'000ULL + height * 1000;
      b.header.proposer = Crypto::Address{};
      for (size_t i = 0; i < 32; ++i)
        b.header.proposer.data[i] = uint8_t(0x80 + i);
      b.header.epoch = height / Core::ROTATION_INTERVAL;
      b.header.rotation_index = height / Core::ROTATION_INTERVAL;
      b.header.commit_round = 0;
      b.header.tx_root = Core::computeTxRoot({});
      b.header.state_root = Crypto::Hash{};
      b.header.receipts_root = Crypto::Hash{};
      b.header.validator_set_root = Core::computeValidatorSetRoot({1, 2});
      b.header.active_validator_count = 2;
      b.header.tx_count = 0;
      b.header.total_fees = 0;
      b.participants = {1, 2};
      b.quorum_signatures.clear();
      return b;
    }

    std::vector<Crypto::ValidatorSignature>
    makeQuorumForBlock(const Core::Block &block)
    {
      const Crypto::Hash signing_hash = Consensus::voteSigningHash(
          block.header.height, block.header.commit_round,
          /*is_nil=*/false, block.hash());

      std::vector<Crypto::ValidatorSignature> sigs;
      sigs.reserve(2);
      sigs.push_back({0, Crypto::sign(signing_hash, seed1_.secretKey)});
      sigs.push_back({1, Crypto::sign(signing_hash, seed2_.secretKey)});
      return sigs;
    }

    Core::BlockResult simulateBlock(Node::Node &node, const Core::Block &b,
                                    uint64_t height)
    {
      auto &db = NodeTestAccess::stateDb(node);
      auto txn = db.beginWrite();
      State::StateAccess scratch(db, txn, height);

      Core::BlockContext ctx;
      ctx.chain_id = genesis_.chain_id;
      ctx.current_height = height;
      ctx.dry_run = true;

      Core::BlockResult r = Core::BlockProcessor::applyBlock(scratch, b, ctx);
      txn.abort();
      return r;
    }

    Crypto::KeyPair seed1_;
    Crypto::KeyPair seed2_;
    Core::GenesisConfig genesis_;
  };

  //  Node_EndToEndFixture
  //
  //  Node objects driven by the ConsensusHarness.
  //
  //  State is layered:
  //
  //    KeySet        — the reward + consensus keypair for each
  //                    validator, plus its address. Single source of
  //                    truth for what a test validator is.
  //    env_          — the consensus-side view: validator list,
  //                    active set, network identity. Populated from
  //                    KeySet.
  //    genesis_      — the state-side view: funded accounts and
  //                    validator records. Built from KeySet.
  //    nodes_        — real Node objects, each configured from KeySet
  //                    and genesis_.
  //    harness_      — the driver that steps consensus and routes
  //                    committed blocks through nodes_[i].
  //
  //  Everything else is derived: makeConfig reads KeySet; the fan-out
  //  callbacks and onBlockCommitted route through harness_ + nodes_;
  //  startNodes() builds KeySet, genesis_, env_, nodes_, harness_ in
  //  that order.
  class Node_EndToEndFixture : public Node_Fixture
  {
  protected:
    struct KeySet
    {
      //  One entry per validator. ID is 1-based.
      struct Entry
      {
        Id id{0};
        Crypto::KeyPair reward_kp{};      // funds + identity
        Crypto::Address reward_address{}; // == reward_kp.publicKey
        Crypto::KeyPair consensus_kp{};   // votes + proposals
      };

      std::vector<Entry> entries;

      const Entry &at(size_t i) const { return entries[i]; }
      size_t size() const { return entries.size(); }
    };

    void SetUp() override
    {
      Node_Fixture::SetUp();

      validators_n_ = 2;
      active_n_ = 0;
      split_keys_ = false;

      buildKeySet();
      env_.makeValidators(validators_n_);
    }

    void TearDown() override
    {
      stopNodes();
      for (auto &d : dirs_)
      {
        std::error_code ec;
        std::filesystem::remove_all(d, ec);
      }
      dirs_.clear();
      Node_Fixture::TearDown();
    }

    //  ---- Configuration API used by tests ----

    void setValidatorCount(size_t n)
    {
      validators_n_ = n;
      buildKeySet();
    }

    void setActiveCount(size_t n) { active_n_ = n; }

    void setSplitKeys(bool split)
    {
      split_keys_ = split;
      buildKeySet();
    }

    //  ---- Key material ----

    void buildKeySet()
    {
      keys_.entries.clear();
      keys_.entries.reserve(validators_n_);

      for (size_t i = 0; i < validators_n_; ++i)
      {
        KeySet::Entry e;
        e.id = static_cast<Id>(i + 1);
        e.reward_kp = deterministicValidatorKey(e.id);
        e.reward_address = addressOf(e.reward_kp);

        //  Consensus key. In split-key mode it is a distinct key;
        //  otherwise it is the reward key (single-key mode).
        if (split_keys_)
        {
          for (size_t j = 0; j < e.consensus_kp.secretKey.data.size(); ++j)
            e.consensus_kp.secretKey.data[j] =
                static_cast<uint8_t>(0x40 + i + j);
          e.consensus_kp.publicKey =
              Crypto::derivePublicKey(e.consensus_kp.secretKey);
        }
        else
        {
          e.consensus_kp = e.reward_kp;
        }

        keys_.entries.push_back(std::move(e));
      }

      active_n_ = 0;
    }

    //  ---- Node config ----

    Node::NodeConfig makeConfig(size_t index)
    {
      const auto &e = keys_.at(index);

      Node::NodeConfig cfg;
      cfg.network = Node::Network::Regtest;
      cfg.data_dir = dirs_.at(index).string();
      cfg.state_map_size = 64ULL * 1024 * 1024;
      cfg.chain_map_size = 64ULL * 1024 * 1024;
      cfg.enable_p2p = false;
      cfg.validator_id = e.id;
      cfg.consensus_secret_key = e.consensus_kp.secretKey;
      cfg.apply_genesis_on_start = true;
      cfg.test_genesis_override = genesis_;
      return cfg;
    }

    Node::NodeConfig makeConfigWithP2P(size_t index, uint16_t port)
    {
      auto cfg = makeConfig(index);
      cfg.enable_p2p = true;
      cfg.p2p_port = port;
      cfg.seeds.clear();
      return cfg;
    }

    Node::NodeConfig makeNonValidatorConfig(size_t dir_index)
    {
      Node::NodeConfig cfg;
      cfg.network = Node::Network::Regtest;
      cfg.data_dir = dirs_.at(dir_index).string();
      cfg.state_map_size = 64ULL * 1024 * 1024;
      cfg.chain_map_size = 64ULL * 1024 * 1024;
      cfg.enable_p2p = false;
      cfg.validator_id = 0;
      cfg.apply_genesis_on_start = true;
      cfg.test_genesis_override = genesis_;
      return cfg;
    }

    Node::NodeConfig makeNonValidatorConfigWithP2P(size_t dir_index, uint16_t port)
    {
      auto cfg = makeNonValidatorConfig(dir_index);
      cfg.enable_p2p = true;
      cfg.p2p_port = port;
      cfg.seeds.clear();
      return cfg;
    }

    //  ---- Directories ----

    std::filesystem::path makeNodeDir(size_t idx)
    {
      auto d = std::filesystem::temp_directory_path() /
               (tmp_dir().filename().string() + "_n" + std::to_string(idx));
      std::filesystem::remove_all(d);
      std::filesystem::create_directories(d);
      return d;
    }

    void makeExtraNodes(size_t count)
    {
      for (size_t i = 0; i < count; ++i)
        dirs_.push_back(makeNodeDir(dirs_.size()));
    }

    //  ---- Genesis + env construction ----

    void buildGenesis()
    {
      std::vector<Crypto::KeyPair> reward_keys;
      std::vector<Crypto::KeyPair> consensus_keys;
      reward_keys.reserve(keys_.size());
      consensus_keys.reserve(keys_.size());

      for (const auto &e : keys_.entries)
      {
        reward_keys.push_back(e.reward_kp);
        consensus_keys.push_back(e.consensus_kp);
      }

      genesis_ = makeGenesis(reward_keys, consensus_keys,
                             /*active_count=*/effectiveActiveCount());
    }

    void buildEnv()
    {
      env_.makeValidators(validators_n_);

      //  Override the env's default reward-key-derived validators with
      //  the fixture's key material. In split-key mode, the env must
      //  sign with the consensus key while reporting the reward address.
      for (size_t i = 0; i < validators_n_; ++i)
      {
        const auto &e = keys_.at(i);
        env_.overrideValidator(i, e.consensus_kp, e.reward_address);
      }

      env_.setChainId(genesis_.chain_id);
      env_.setParentHash(Crypto::Hash{});
      env_.setNowMs(1'700'000'000'000ULL);
      env_.setCurrentHeight(0);

      const size_t active_count = effectiveActiveCount();
      if (active_count < validators_n_)
      {
        std::vector<Id> active_ids;
        active_ids.reserve(active_count);
        for (size_t i = 0; i < active_count; ++i)
          active_ids.push_back(keys_.at(i).id);
        env_.setActiveIds(active_ids);
      }
    }

    size_t effectiveActiveCount() const
    {
      return active_n_ == 0 ? validators_n_ : active_n_;
    }

    //  ---- Node-side callbacks for the harness ----

    void attachNodeBackend(size_t index, Node::Node *n)
    {
      ConsensusTestEnv::NodeBackend backend;

      //  Active set. Delegates to Core::resolveActiveSet against
      //  the node's real state DB at the node's current chain height.
      //  This must produce the same value BlockProcessor::applyBlock
      //  computes when it validates a block, or the emergency
      //  proposal's active_validator_count and validator_set_root
      //  will disagree with the simulation and the block will be
      //  rejected. The node's own buildConsensusDeps uses this exact
      //  derivation.
      backend.active_set = [n](bool force_rotation) -> std::vector<Id>
      {
        auto &db = NodeTestAccess::stateDb(*n);
        State::StateAccess state(db, 0);

        //  Load the committed active set from state. Same encoding
        //  as Node::loadActiveSetFromState and
        //  BlockProcessor::loadActiveSet.
        std::vector<Id> committed;
        std::vector<uint8_t> set_bytes;
        if (state.getGlobal("active_set", set_bytes))
        {
          const size_t count = set_bytes.size() / 8;
          committed.reserve(count);
          for (size_t i = 0; i < count; ++i)
          {
            uint64_t id = 0;
            for (int j = 0; j < 8; ++j)
              id |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);
            committed.push_back(id);
          }
        }

        const Height height = NodeTestAccess::chain(*n).height();
        return Core::resolveActiveSet(state, committed, height, force_rotation);
      };

      backend.simulate_block =
          [n](const Core::Block &b) -> std::optional<Crypto::Hash>
      {
        auto &db = NodeTestAccess::stateDb(*n);
        auto txn = db.beginWrite();
        State::StateAccess scratch(db, txn, b.header.height);

        Core::BlockContext ctx;
        ctx.chain_id = b.header.chain_id;
        ctx.current_height = b.header.height;
        ctx.dry_run = true;

        Core::BlockResult r = Core::BlockProcessor::applyBlock(scratch, b, ctx);
        txn.abort();

        if (!r.valid)
          return std::nullopt;
        return r.new_state_root;
      };

      backend.parent_hash = [n]() -> Crypto::Hash
      {
        return NodeTestAccess::chainDb(*n).getHead().hash;
      };

      backend.lookup_validator =
          [n](Id id, Core::ValidatorInfo &out) -> bool
      {
        auto &db = NodeTestAccess::stateDb(*n);
        State::StateAccess state(db, 0);
        const bool ok = state.getValidator(id, out);
        return ok;
      };

      env_.attachNodeBackend(index, std::move(backend));
    }

    //  ---- Startup / shutdown ----

    void startNodes()
    {
      stopNodes();

      while (dirs_.size() < validators_n_)
        dirs_.push_back(makeNodeDir(dirs_.size()));

      buildGenesis();
      buildEnv();

      for (size_t i = 0; i < validators_n_; ++i)
      {
        nodes_.push_back(std::make_unique<Node::Node>(makeConfig(i), logger_));
        attachNodeBackend(i, nodes_.back().get());
      }

      harness_ = std::make_unique<ConsensusHarness>(
          env_, validators_n_, consensus_logger_);

      installFanOutCallbacks();
      installNodeCallbacks();

      for (auto &n : nodes_)
        n->start();
    }

    void stopNodes()
    {
      if (harness_)
      {
        harness_->stopAll();
        harness_.reset();
      }
      for (auto &n : nodes_)
        if (n)
          n->stop();
      nodes_.clear();
    }

    //  ---- Harness wiring ----

    void installFanOutCallbacks()
    {
      harness_->setOnProposal(
          [this](size_t from, const Consensus::Proposal &p)
          {
            for (size_t to = 0; to < validators_n_; ++to)
              if (to != from)
                harness_->enqueueProposal(from, to, p, /*is_emergency=*/false);
          });

      harness_->setOnPrevote(
          [this](size_t from, const Consensus::Vote &v)
          {
            for (size_t to = 0; to < validators_n_; ++to)
              if (to != from)
                harness_->enqueueVote(from, to, Envelope::Prevote, v);
          });

      harness_->setOnPrecommit(
          [this](size_t from, const Consensus::Vote &v)
          {
            for (size_t to = 0; to < validators_n_; ++to)
              if (to != from)
                harness_->enqueueVote(from, to, Envelope::Precommit, v);
          });

      harness_->setOnTimeoutVote(
          [this](size_t from, const Consensus::TimeoutVote &tv)
          {
            for (size_t to = 0; to < validators_n_; ++to)
              if (to != from)
                harness_->enqueueTimeoutVote(from, to, tv);
          });
    }

    void installNodeCallbacks()
    {
      harness_->setOnBlockCommitted(
          [this](size_t index, const Core::Block &b)
          {
            Node::Node &n = *nodes_[index];
            std::string error;
            if (!NodeTestAccess::applyBlock(n, b, error))
              ADD_FAILURE() << "applyBlock failed on node " << index
                            << " for height " << b.header.height
                            << ": " << error;
          });

      harness_->setSelectTransactions(
          [this](size_t index, uint64_t max_bytes, uint64_t max_txs)
          {
            return NodeTestAccess::selectTransactionsForProposal(
                *nodes_[index], max_bytes, max_txs);
          });
    }

    //  ---- Harness delegation ----

    void setOffline(size_t index, bool offline)
    {
      if (harness_)
        harness_->setOffline(index, offline);
    }

    std::vector<Id> activeIds() const { return env_.activeIds(); }
    void setEmergencyIds(std::vector<Id> ids)
    {
      env_.setEmergencyIds(std::move(ids));
    }

    void startAllConsensus(Height h)
    {
      harness_->startAll(h);
      harness_->deliverAll();
    }

    void deliverAll()
    {
      if (harness_)
        harness_->deliverAll();
    }

    void advanceTimers()
    {
      if (harness_)
        harness_->advanceAllTimers();
    }

    Height heightOf(size_t i) const { return harness_->heightOf(i); }

    //  ---- Mempool / state helpers ----

    uint64_t balanceOf(Node::Node &node, const Crypto::Address &addr)
    {
      auto &db = NodeTestAccess::stateDb(node);
      State::StateAccess state(db, 0);
      return state.getAccount(addr).balance;
    }

    uint64_t nonceOf(Node::Node &node, const Crypto::Address &addr)
    {
      auto &db = NodeTestAccess::stateDb(node);
      State::StateAccess state(db, 0);
      return state.getAccount(addr).nonce;
    }

    Core::Transaction makeSignedTransfer(const Crypto::KeyPair &from,
                                         const Crypto::Address &to,
                                         uint64_t amount, uint64_t fee,
                                         uint64_t nonce)
    {
      Core::Transaction tx;
      tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
      tx.chain_id = genesis_.chain_id;
      tx.tx_type = Core::TxType::Transfer;
      tx.nonce = nonce;
      tx.valid_until_height = 0;
      tx.from = addressOf(from);
      tx.to = to;
      tx.token_id = NATIVE_TOKEN_ID;
      tx.amount = amount;
      tx.fee = fee;
      tx.signature = Crypto::sign(tx.txid(), from.secretKey);
      return tx;
    }

    //  ---- P2P helpers ----

    bool waitForListening(uint16_t port, std::chrono::milliseconds timeout)
    {
      return waitFor([port]
                     { return canConnect(port); }, timeout);
    }

    bool waitForPeers(Node::Node &n, size_t want,
                      std::chrono::milliseconds timeout)
    {
      return waitFor([&n, want]
                     { return n.status().peer_count >= want; }, timeout);
    }

    bool waitForEstablished(Node::Node &n, size_t want,
                            std::chrono::milliseconds timeout)
    {
      auto deadline = std::chrono::steady_clock::now() + timeout;
      while (std::chrono::steady_clock::now() < deadline)
      {
        auto p = std::make_shared<std::promise<size_t>>();
        auto f = p->get_future();
        NodeTestAccess::postToP2P(n, [&n, p]
                                  {
          try { p->set_value(NodeTestAccess::p2pSnapshot(n).established); }
          catch (...) {} });
        if (f.wait_for(std::chrono::milliseconds(200)) ==
                std::future_status::ready &&
            f.get() >= want)
          return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      return false;
    }

    bool waitForConsensusStarted(Node::Node &n,
                                 std::chrono::milliseconds timeout)
    {
      return waitFor([&n]
                     { return NodeTestAccess::consensusStarted(n); }, timeout);
    }

    bool waitForHeight(Node::Node &n, uint64_t want,
                       std::chrono::milliseconds timeout)
    {
      return waitFor([&n, want]
                     { return n.status().height >= want; }, timeout);
    }

    bool waitForMatchingStateRoots(Node::Node &a, Node::Node &b,
                                   std::chrono::milliseconds timeout)
    {
      return waitFor([&a, &b]
                     { return a.stateRoot() == b.stateRoot(); }, timeout);
    }

    void dumpNodeState(const char *tag, Node::Node &n)
    {
      auto s = n.status();
      std::cerr << "[" << tag << "]"
                << " height=" << s.height
                << " peers=" << s.peer_count
                << " cons_h=" << s.consensus_height
                << " cons_r=" << s.consensus_round
                << " cons_step=" << s.consensus_step
                << " consensus_started="
                << (NodeTestAccess::consensusStarted(n) ? "yes" : "no")
                << "\n";
    }

    //  ---- Members ----

    size_t validators_n_{0};
    size_t active_n_{0};
    bool split_keys_{false};

    KeySet keys_;
    Core::GenesisConfig genesis_;
    std::vector<std::filesystem::path> dirs_;

    ConsensusTestEnv env_;
    std::unique_ptr<ConsensusHarness> harness_;
    StdErrLogger consensus_logger_;
    std::vector<std::unique_ptr<Node::Node>> nodes_;
  };

  class NodeThreadGroup
  {
  public:
    NodeThreadGroup() = default;
    ~NodeThreadGroup() { join(); }

    NodeThreadGroup(const NodeThreadGroup &) = delete;
    NodeThreadGroup &operator=(const NodeThreadGroup &) = delete;

    void runAll(std::vector<std::unique_ptr<Node::Node>> &nodes)
    {
      nodes_ = &nodes;
      threads_.reserve(nodes.size());
      for (auto &n : nodes)
        if (n)
          threads_.emplace_back([&n]
                                { n->run(); });
    }

    void join()
    {
      if (nodes_)
        for (auto &n : *nodes_)
          if (n)
            n->stop();
      for (auto &t : threads_)
        if (t.joinable())
          t.join();
      threads_.clear();
      nodes_ = nullptr;
    }

  private:
    std::vector<std::unique_ptr<Node::Node>> *nodes_{nullptr};
    std::vector<std::thread> threads_;
  };
}