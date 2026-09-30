#pragma once

#include <gtest/gtest.h>

#include "Utils.h"

namespace Tests
{
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
      cfg.enable_p2p = false; // headless for tests
      cfg.validator_id = 0;
      cfg.apply_genesis_on_start = true;
      return cfg;
    }

    // Config for a validator node, headless.
    Node::NodeConfig makeValidatorConfig(uint64_t validator_id)
    {
      Node::NodeConfig cfg = makeValidConfig();
      cfg.validator_id = validator_id;
      // Fill the secret key with a deterministic non-zero value
      // (the tests don't need a real signature chain here).
      for (size_t i = 0; i < cfg.validator_secret_key.data.size(); ++i)
        cfg.validator_secret_key.data[i] = uint8_t(0x80 + validator_id + i);
      return cfg;
    }

    const std::filesystem::path &tmp_dir() const { return tmp_dir_; }

    NoopLogger logger_;
    std::filesystem::path tmp_dir_;
  };

  class Node_BlockFixture : public Node_Fixture
  {
  protected:
    void SetUp() override
    {
      Node_Fixture::SetUp();

      // Two seed validators, deterministic keys.
      seed1_ = deterministicValidatorKey(1);
      seed2_ = deterministicValidatorKey(2);

      // Genesis config with those seeds.
      genesis_ = Core::GenesisConfig{};
      genesis_.chain_id = 0x434C5247;
      genesis_.timestamp_ms = 1'700'000'000'000ULL;

      constexpr uint64_t INITIAL =
          GlobalConfig::GENESIS_SUPPLY * GlobalConfig::ATOMIC_UNITS_PER_COIN;

      Crypto::Address fund_addr;
      std::fill(fund_addr.data.begin(), fund_addr.data.end(), 0x01);
      genesis_.accounts.push_back({fund_addr, INITIAL, "test fund"});

      genesis_.validators.push_back(
          {1, addressOf(seed1_), seed1_.publicKey, true});
      genesis_.validators.push_back(
          {2, addressOf(seed2_), seed2_.publicKey, true});

      genesis_.initial_total_supply = INITIAL;
      genesis_.initial_active_set_size = 2;
    }

    // Config with the fixture's genesis override.
    Node::NodeConfig makeFixtureConfig()
    {
      Node::NodeConfig cfg = makeValidConfig();
      cfg.test_genesis_override = genesis_;
      return cfg;
    }

    // Build a valid empty block at the given height, parented to the
    // current chain head. Simulates on a scratch txn to compute the
    // state root, then signs the block with both seed keys.
    Core::Block buildValidEmptyBlock(Node::Node &node, uint64_t height)
    {
      auto &chain_db = NodeTestAccess::chainDb(node);
      auto head = chain_db.getHead();
      Crypto::Hash parent = head.hash;

      Core::Block b = makeSkeleton(height, parent);

      Core::BlockResult sim = simulateBlock(node, b, height);
      if (!sim.valid)
      {
        return b; // ← returns skeleton with null state_root
      }

      b.header.state_root = sim.new_state_root;
      b.quorum_signatures = makeQuorumForBlock(b);
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

    std::vector<Crypto::ValidatorSignature> makeQuorumForBlock(const Core::Block &block)
    {
      size_t needed = Core::bftQuorum(2);
      std::vector<Crypto::ValidatorSignature> sigs;
      sigs.reserve(needed);

      Crypto::Hash signing_hash = Consensus::voteSigningHash(
          block.header.height,
          block.header.commit_round,
          /*is_nil=*/false,
          block.hash());

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

  class Node_EndToEndFixture : public Node_Fixture
  {
  protected:
    void SetUp() override
    {
      Node_Fixture::SetUp();
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

    void makeValidators(size_t n)
    {
      validators_.clear();
      for (size_t i = 0; i < n; ++i)
        validators_.push_back(deterministicValidatorKey(i + 1));
      genesis_ = makeTestGenesis(validators_);

      dirs_.clear();
      for (size_t i = 0; i < n; ++i)
      {
        auto d = std::filesystem::temp_directory_path() /
                 (tmp_dir().filename().string() + "_n" + std::to_string(i));
        std::filesystem::remove_all(d);
        std::filesystem::create_directories(d);
        dirs_.push_back(d);
      }
    }

    Node::NodeConfig makeConfig(size_t index)
    {
      Node::NodeConfig cfg;
      cfg.network = Node::Network::Regtest;
      cfg.data_dir = dirs_[index].string();
      cfg.state_map_size = 64ULL * 1024 * 1024;
      cfg.chain_map_size = 64ULL * 1024 * 1024;
      cfg.enable_p2p = false;
      cfg.validator_id = static_cast<uint64_t>(index + 1);
      cfg.validator_secret_key = validators_[index].secretKey;
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

    void makeExtraNodes(size_t count)
    {
      // Adds `count` new data dirs to dirs_ (after the validator dirs).
      // Used by tests that need more nodes than validators.
      for (size_t i = 0; i < count; ++i)
      {
        size_t idx = dirs_.size();
        auto d = std::filesystem::temp_directory_path() /
                 (tmp_dir().filename().string() + "_x" + std::to_string(idx));
        std::filesystem::remove_all(d);
        std::filesystem::create_directories(d);
        dirs_.push_back(d);
      }
    }

    Node::NodeConfig makeNonValidatorConfig(size_t dir_index)
    {
      Node::NodeConfig cfg;
      cfg.network = Node::Network::Regtest;
      cfg.data_dir = dirs_[dir_index].string();
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

    void startNodes()
    {
      nodes_.clear();
      consensuses_.clear();
      offline_.assign(validators_.size(), false);

      for (size_t i = 0; i < validators_.size(); ++i)
      {
        nodes_.push_back(std::make_unique<Node::Node>(makeConfig(i), logger_));
        nodes_[i]->start();
      }

      for (size_t i = 0; i < validators_.size(); ++i)
      {
        consensuses_.push_back(std::make_unique<Consensus::BftConsensus>(
            makeDeps(i),
            makeCallbacksFor(i),
            Consensus::Config{},
            Logging::LoggerRef(consensus_logger_, "Consensus" + std::to_string(i))));
      }
    }

    void stopNodes()
    {
      for (auto &c : consensuses_)
      {
        if (c)
          c->stop();
      }
      consensuses_.clear();
      for (auto &n : nodes_)
      {
        if (n)
          n->stop();
      }
      nodes_.clear();
    }

    void setOffline(size_t index, bool offline)
    {
      offline_[index] = offline;
    }

    Consensus::Dependencies makeDeps(size_t index)
    {
      Consensus::Dependencies deps;

      const Crypto::KeyPair &kp = validators_[index];
      const Id vid = static_cast<Id>(index + 1);
      Node::Node &node_ref = *nodes_[index];

      deps.my_validator_id = [vid]() -> Id
      { return vid; };

      deps.sign = [kp](const Crypto::Hash &h) -> Crypto::Signature
      {
        return Crypto::sign(h, kp.secretKey);
      };

      deps.current_height = [&node_ref]() -> Height
      {
        return NodeTestAccess::chain(node_ref).height();
      };

      deps.active_set = [this](bool /*force_rotation*/) -> std::vector<Id>
      {
        std::vector<Id> ids;
        for (size_t i = 0; i < validators_.size(); ++i)
          ids.push_back(static_cast<Id>(i + 1));
        return ids;
      };

      deps.signer_public_key =
          [this](Index idx) -> std::optional<Crypto::PublicKey>
      {
        if (idx >= validators_.size())
          return std::nullopt;
        return validators_[idx].publicKey;
      };

      deps.chain_id = [this]() -> uint64_t
      { return genesis_.chain_id; };

      deps.parent_hash = [&node_ref]() -> Crypto::Hash
      {
        return NodeTestAccess::chainDb(node_ref).getHead().hash;
      };

      deps.my_address = [kp]() -> Crypto::Address
      {
        return addressOf(kp);
      };

      deps.simulate_block = [&node_ref, this](const Core::Block &b)
          -> std::optional<Crypto::Hash>
      {
        auto &db = NodeTestAccess::stateDb(node_ref);
        auto txn = db.beginWrite();
        State::StateAccess state(db, txn, b.header.height);
        Core::BlockContext ctx;
        ctx.chain_id = genesis_.chain_id;
        ctx.current_height = b.header.height;
        ctx.dry_run = true;
        Core::BlockResult r = Core::BlockProcessor::applyBlock(state, b, ctx);
        txn.abort();
        if (!r.valid)
          return std::nullopt;
        return r.new_state_root;
      };

      return deps;
    }

    Consensus::Callbacks makeCallbacksFor(size_t index)
    {
      Consensus::Callbacks cb;
      const size_t n = validators_.size();

      auto fanOut = [this, index, n](Envelope::Kind kind,
                                     const Consensus::Proposal *p,
                                     const Consensus::Vote *v)
      {
        if (offline_[index])
          return;
        for (size_t to = 0; to < n; ++to)
        {
          if (to == index)
            continue;
          if (offline_[to])
            continue;
          Envelope e;
          e.kind = kind;
          e.to = to;
          e.from = index;
          if (p)
            e.proposal = *p;
          if (v)
            e.vote = *v;
          queue_.push(e);
        }
      };

      cb.broadcast_proposal = [fanOut](const Consensus::Proposal &p)
      {
        fanOut(Envelope::Proposal, &p, nullptr);
      };
      cb.broadcast_prevote = [fanOut](const Consensus::Vote &v)
      {
        fanOut(Envelope::Prevote, nullptr, &v);
      };
      cb.broadcast_precommit = [fanOut](const Consensus::Vote &v)
      {
        fanOut(Envelope::Precommit, nullptr, &v);
      };

      cb.select_transactions = [this, index](uint64_t max_bytes, uint64_t max_txs)
      {
        return NodeTestAccess::selectTransactionsForProposal(
            *nodes_[index], max_bytes, max_txs);
      };

      cb.on_block_committed = [this, index](const Core::Block &b)
      {
        Node::Node &n = *nodes_[index];
        std::string error;
        if (!NodeTestAccess::applyBlock(n, b, error))
        {
          ADD_FAILURE() << "applyBlock failed on node " << index
                        << ": " << error;
        }
      };
      cb.on_height_advanced = [](Height) {};
      return cb;
    }

    void deliverAll()
    {
      constexpr size_t MAX = 100'000;
      size_t n = 0;
      while (!queue_.empty())
      {
        if (++n > MAX)
          FAIL() << "message loop did not settle";
        Envelope e = queue_.front();
        queue_.pop();
        if (offline_[e.to])
          continue;
        auto &c = *consensuses_[e.to];
        switch (e.kind)
        {
        case Envelope::Proposal:
          c.onProposal(e.proposal);
          break;
        case Envelope::Prevote:
          c.onPrevote(e.vote);
          break;
        case Envelope::Precommit:
          c.onPrecommit(e.vote);
          break;
        case Envelope::Restart:
          c.start(e.restart_height);
          break;
        }
      }
    }

    void startAllConsensus(Height h)
    {
      for (size_t i = 0; i < consensuses_.size(); ++i)
        if (!offline_[i])
          consensuses_[i]->start(h);
      deliverAll();
    }

    void advanceTimers()
    {
      for (size_t i = 0; i < consensuses_.size(); ++i)
        if (!offline_[i])
          consensuses_[i]->forceTimerExpiryForTest();
      for (size_t i = 0; i < consensuses_.size(); ++i)
        if (!offline_[i])
          consensuses_[i]->pollTimers();
      deliverAll();
    }

    void dumpState(const char *tag)
    {
      for (size_t i = 0; i < consensuses_.size(); ++i)
      {
        auto s = consensuses_[i]->state();
        std::cerr << "[" << tag << "] c" << i
                  << " h=" << s.height
                  << " r=" << s.round
                  << " step=" << stepNameLocal(s.step)
                  << " pv=" << s.prevote_count
                  << " pc=" << s.precommit_count
                  << (offline_[i] ? " OFFLINE" : "")
                  << "\n";
      }
    }

    // ---- helpers for the mempool tests ----

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
                                         uint64_t amount,
                                         uint64_t fee,
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

      Crypto::Hash signing_hash = tx.txid();
      tx.signature = Crypto::sign(signing_hash, from.secretKey);
      return tx;
    }

    // ---- helpers for the P2P test ----

    bool waitForListening(uint16_t port, std::chrono::milliseconds timeout)
    {
      return waitFor([port]
                     { return canConnect(port); },
                     timeout);
    }

    bool waitForPeers(Node::Node &n, size_t want, std::chrono::milliseconds timeout)
    {
      return waitFor([&n, want]
                     { return n.status().peer_count >= want; },
                     timeout);
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
        try
        {
          p->set_value(NodeTestAccess::p2pSnapshot(n).established);
        }
        catch (...)
        {
          // promise already satisfied; ignore
        } });
        if (f.wait_for(std::chrono::milliseconds(200)) == std::future_status::ready &&
            f.get() >= want)
        {
          return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
      }
      return false;
    }

    bool waitForConsensusStarted(Node::Node &n, std::chrono::milliseconds timeout)
    {
      return waitFor([&n]
                     { return NodeTestAccess::consensusStarted(n); },
                     timeout);
    }

    bool waitForHeight(Node::Node &n, uint64_t want, std::chrono::milliseconds timeout)
    {
      return waitFor([&n, want]
                     { return n.status().height >= want; },
                     timeout);
    }

    bool waitForHeightAtLeast(Node::Node &n, uint64_t want,
                              std::chrono::milliseconds timeout)
    {
      return waitFor([&n, want]
                     { return n.status().height >= want; },
                     timeout);
    }

    bool waitForMatchingStateRoots(Node::Node &a, Node::Node &b,
                                   std::chrono::milliseconds timeout)
    {
      return waitFor([&a, &b]
                     { return a.stateRoot() == b.stateRoot(); },
                     timeout);
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

    // ---- members ----
    std::vector<Crypto::KeyPair> validators_;
    std::vector<std::filesystem::path> dirs_;
    std::vector<bool> offline_;
    Core::GenesisConfig genesis_;

    NoopLogger consensus_logger_;

    std::vector<std::unique_ptr<Node::Node>> nodes_;
    std::vector<std::unique_ptr<Consensus::BftConsensus>> consensuses_;
    std::queue<Envelope> queue_;
  };

  // RAII wrapper for a group of Node io_context threads. Guarantees
  // that stop() is called on every node and every thread is joined,
  // even if a test fails mid-body with an ASSERT_*. Without this,
  // an ASSERT_* that fires while threads are still running destroys
  // the std::thread objects while they're joinable, which calls
  // std::terminate.
  class NodeThreadGroup
  {
  public:
    NodeThreadGroup() = default;

    ~NodeThreadGroup()
    {
      join();
    }

    NodeThreadGroup(const NodeThreadGroup &) = delete;
    NodeThreadGroup &operator=(const NodeThreadGroup &) = delete;

    void runAll(std::vector<std::unique_ptr<Node::Node>> &nodes)
    {
      nodes_ = &nodes;
      threads_.reserve(nodes.size());
      for (auto &n : nodes)
      {
        if (n)
          threads_.emplace_back([&n]
                                { n->run(); });
      }
    }

    void join()
    {
      if (nodes_)
      {
        for (auto &n : *nodes_)
          if (n)
            n->stop();
      }

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