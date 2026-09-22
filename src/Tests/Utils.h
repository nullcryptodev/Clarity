#pragma once

#include <atomic>
#include <filesystem>
#include <memory>
#include <string>

#include "Logger.h"
#include "TransactionBuilder.h"

#include "Consensus/BftConsensus.h"

#include "Core/Block.h"
#include "Core/Chain.h"
#include "Core/Mempool.h"
#include "Core/StateView.h"
#include "Core/RewardCalculator.h"
#include "Core/TransactionExecutor.h"

#include "Crypto/Ed25519.h"

#include "Node/Node.h"

#include "P2P/Config.h"
#include "P2P/Message.h"
#include "P2P/P2PManager.h"

#include "Serialization/ISerializer.h"

#include "State/StateAccess.h"
#include "State/StateDB.h"

using namespace std::chrono_literals;

namespace Tests
{
  // Test global values

  constexpr uint64_t EXEC_CHAIN_ID = 0x434C5247;
  constexpr uint32_t TEST_MAGIC = 0x434C5247; // 'CLRG'
  constexpr uint32_t TEST_MAX_SIZE = 32 * 1024 * 1024;

  // Helpers

  Crypto::Hash makeHash(uint64_t n);
  Crypto::Address makeAddress(uint64_t n);
  Crypto::Signature makeSignature(uint8_t seed);
  std::vector<uint8_t> proofValue(uint64_t n, size_t len = 32);
  uint64_t readU64Global(State::StateAccess &s, const std::string &name);
  void createKVBinarySerializer(Serialization::MemoryInputStream &stream);
  Core::Block makeBlock(uint64_t height);
  P2P::Message roundTripThroughWire(const P2P::Message &in);
  uint16_t pickFreePort();
  Crypto::KeyPair deterministicValidatorKey(uint64_t id);
  Crypto::KeyPair aliceKey();
  Crypto::KeyPair bobKey();
  Crypto::Address addressOf(const Crypto::KeyPair &kp);
  Core::GenesisConfig makeTestGenesis(const std::vector<Crypto::KeyPair> &validators);
  const char *stepNameLocal(Consensus::Step s);
  bool canConnect(uint16_t port);
  std::string toHex(const uint8_t *data, size_t len);
  bool fromHex(const std::string &hex, uint8_t *out, size_t out_len);
  uint64_t feeRateOf(const Core::Transaction &tx);
  Core::RewardContext makeContext();
  Core::ValidatorRegistry makeRegistry(size_t n);
  std::vector<uint8_t> makeCreatePoolPayload(uint32_t token_b, uint64_t amount_b, uint16_t fee_bps);
  std::vector<uint8_t> makeCreateTokenPayload(
      const std::string &name,
      const std::string &symbol,
      uint8_t decimals = 8,
      uint8_t backing = 0,
      uint64_t max_supply = 0,
      uint16_t royalty_bps = 0,
      std::optional<Crypto::Hash> fingerprint = std::nullopt);
  std::vector<uint8_t> makeAddLiquidityPayload(uint64_t pool_id, uint64_t amount_b);
  std::vector<uint8_t> makeSwapPayload(uint64_t pool_id, uint64_t min_amount_out);
  std::vector<uint8_t> makeRemoveLiquidityPayload(uint64_t position_id);
  std::vector<uint8_t> makeCancelOrderPayload(uint64_t order_id);
  std::vector<uint8_t> makeRegisterValidatorPayload();
  void appendOrderCondition(std::vector<uint8_t> &p,
                                   Core::OrderConditionType type,
                                   uint64_t param1,
                                   uint32_t param2 = 0);
  std::vector<uint8_t> makeCreateOrderPayload(
      uint32_t buy_token,
      uint64_t min_buy_amount,
      uint8_t mode,
      uint64_t expires_at,
      const std::vector<uint8_t> &condition_bytes = {});
  uint64_t expectedSwapOutput(uint64_t reserve_in,
                                     uint64_t reserve_out,
                                     uint64_t amount_in,
                                     uint16_t fee_bps);
  uint64_t expectedInitialLiquidity(uint64_t amount_a, uint64_t amount_b);
  Core::BlockHeader makeTestHeader(uint64_t height = 1,
                                          const Crypto::Hash &parent = Crypto::Hash{},
                                          uint64_t chain_id = 0x434C5247);
  Core::Block makeTestBlock(Core::BlockHeader header,
                                   std::vector<Core::Transaction> txs = {},
                                   std::vector<Id> participants = {});
  Crypto::KeyPair makeTestKeyPair();
  Core::Transaction makeTestTx(const Crypto::KeyPair &kp,
                                      uint64_t nonce,
                                      uint64_t amount,
                                      uint64_t fee,
                                      uint64_t chain_id = 0x434C5247);
  Core::Transaction makeTx();
  Core::TokenInfo makeToken();
  Core::BlockHeader makeHeader();
  Core::Transaction makeSimpleTx(uint64_t nonce);

  // Templates

  template <typename Pred>
  bool waitFor(Pred &&pred, std::chrono::milliseconds timeout)
  {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
      if (pred())
        return true;
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return false;
  }

  // Structs

  struct Envelope
  {
    enum Kind
    {
      Proposal,
      Prevote,
      Precommit
    } kind;
    size_t to;
    size_t from;
    Consensus::Proposal proposal;
    Consensus::Vote vote;
  };

  //  Registry builder for rotation tests.
  //  Validators are numbered 1..N. Active set starts as the first M
  //  validators. Uptime scores default to 10'000 (perfect). Callers can
  //  override per-validator state via the helpers below.

  struct RotationBuilder
  {
    Core::ValidatorRegistry reg;

    explicit RotationBuilder(size_t total_validators = 0,
                             size_t active_count = 0)
    {
      // Index 0 sentinel.
      reg.validators.push_back(Core::ValidatorInfo{});
      reg.next_id = 1;

      for (size_t i = 0; i < total_validators; ++i)
      {
        Core::ValidatorInfo v;
        v.id = static_cast<Id>(i + 1);
        v.stake = Core::VALIDATOR_MIN_STAKE;
        v.uptime_score = 10'000;
        v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
        v.is_active = false;
        v.registered_at_height = 1;
        v.last_active_at = 1;
        v.became_active_at = 0;
        reg.validators.push_back(v);
        reg.next_id = v.id + 1;
      }

      for (size_t i = 0; i < active_count && i < total_validators; ++i)
      {
        Id vid = static_cast<Id>(i + 1);
        auto *v = reg.find(vid);
        if (v)
        {
          v->is_active = true;
          v->became_active_at = 1;
          reg.active_set.push_back(vid);
        }
      }
    }

    // Set an arbitrary uptime for a validator.
    void setUptime(Id id, uint16_t uptime)
    {
      if (auto *v = reg.find(id))
        v->uptime_score = uptime;
    }

    // Set last_active_at (for rotation fairness tie-breaking).
    void setLastActive(Id id, uint64_t h)
    {
      if (auto *v = reg.find(id))
        v->last_active_at = h;
    }

    // Set became_active_at (for removal priority tie-breaking).
    void setBecameActive(Id id, uint64_t h)
    {
      if (auto *v = reg.find(id))
        v->became_active_at = h;
    }

    // Mark a validator as a seed.
    void setSeed(Id id, bool seed = true)
    {
      if (auto *v = reg.find(id))
        v->is_seed = seed;
    }

    // Set last_seen_height for offline detection.
    void setLastSeen(Id id, uint64_t h)
    {
      if (auto *v = reg.find(id))
        v->last_seen_height = h;
    }

    // Set current target_size in the registry.
    void setTargetSize(uint64_t t) { reg.target_size = t; }
  };

  struct TestValidator
  {
    Id id{0};
    Crypto::KeyPair kp{};
    Crypto::Address address{};

    static TestValidator make(Id id)
    {
      TestValidator v;
      v.id = id;

      // Deterministic seed derived from the validator ID. This makes
      // the network reproducible: two runs with the same validator
      // count produce the same blocks.
      Crypto::SecretKey seed;
      for (int i = 0; i < 8; ++i)
        seed.data[i] = uint8_t(id >> (i * 8));
      for (size_t i = 8; i < 32; ++i)
        seed.data[i] = uint8_t(0xA5 + i); // arbitrary fill

      v.kp = Crypto::generateKeyPairFromSeed(seed);
      std::memcpy(v.address.data.data(),
                  v.kp.publicKey.data.data(), 32);
      return v;
    }

    Crypto::Signature sign(const Crypto::Hash &h) const
    {
      return Crypto::sign(h, kp.secretKey);
    }

    Crypto::PublicKey pubkey() const
    {
      return kp.publicKey;
    }
  };

  // Test classes

  //  ConsensusNetwork
  //
  //  Owns N BftConsensus instances and a shared message queue. Each
  //  instance's broadcast callbacks push envelopes into the queue
  //  instead of delivering directly. deliverAll() drains the queue
  //  until it's empty, which settles a full round deterministically.
  //
  //  The network never advances time on its own. Tests drive timers
  //  explicitly via advanceAllTimers().

  class ConsensusNetwork
  {
  public:
    explicit ConsensusNetwork(size_t n, Logging::ILogger &logger)
        : logger_(logger), log_ref_(std::make_unique<Logging::LoggerRef>(logger, "net"))
    {
      validators_.reserve(n);
      for (size_t i = 0; i < n; ++i)
        validators_.push_back(TestValidator::make(static_cast<Id>(i + 1)));

      instances_.reserve(n);
      committed_.resize(n);
      offline_.assign(n, false);
      height_advances_.resize(n);

      for (size_t i = 0; i < n; ++i)
        instances_.push_back(makeInstance(i));
    }

    // ---- Lifecycle ----

    void startAll(Height height)
    {
      for (size_t i = 0; i < instances_.size(); ++i)
      {
        if (!offline_[i])
          instances_[i]->start(height);
      }
      deliverAll();
    }

    void stopAll()
    {
      for (auto &inst : instances_)
        inst->stop();
    }

    // Deliver every queued message, including any messages those
    // deliveries generate, until the queue is empty.
    void deliverAll()
    {
      // Guard against pathological loops; a healthy round settles
      // in far fewer than this.
      constexpr size_t MAX_ROUNDS = 10'000;
      size_t iterations = 0;

      while (!queue_.empty())
      {
        if (++iterations > MAX_ROUNDS)
          throw std::runtime_error("ConsensusNetwork::deliverAll: message loop did not settle");

        Envelope env = queue_.front();
        queue_.pop();

        if (offline_[env.to])
          continue;

        switch (env.kind)
        {
        case Envelope::Proposal:
          instances_[env.to]->onProposal(env.proposal);
          break;
        case Envelope::Prevote:
          instances_[env.to]->onPrevote(env.vote);
          break;
        case Envelope::Precommit:
          instances_[env.to]->onPrecommit(env.vote);
          break;
        }
      }
    }

    void advanceAllTimers()
    {
      // Everyone's timer expires at the same logical instant, so
      // each instance transitions through its own timeout before any
      // of them see the others' broadcasts. This is the model that
      // matches a real network where wall-clock time moves forward
      // for all nodes in parallel.
      for (size_t i = 0; i < instances_.size(); ++i)
      {
        if (offline_[i])
          continue;
        instances_[i]->forceTimerExpiryForTest();
      }

      for (size_t i = 0; i < instances_.size(); ++i)
      {
        if (offline_[i])
          continue;
        instances_[i]->pollTimers();
      }

      deliverAll();
    }

    // ---- Introspection ----

    Consensus::BftConsensus &instance(size_t i) { return *instances_[i]; }

    const std::vector<Core::Block> &committed(size_t i) const
    {
      return committed_[i];
    }

    const std::vector<Height> &heightAdvances(size_t i) const
    {
      return height_advances_[i];
    }

    const TestValidator &validator(size_t i) const
    {
      return validators_[i];
    }

    size_t size() const { return instances_.size(); }

    // ---- Offline control ----

    void setOffline(size_t i, bool offline)
    {
      offline_[i] = offline;
    }

    bool isOffline(size_t i) const { return offline_[i]; }

  private:
    struct Envelope
    {
      enum Kind
      {
        Proposal,
        Prevote,
        Precommit
      } kind;

      size_t to{0};
      size_t from{0};

      Consensus::Proposal proposal{};
      Consensus::Vote vote{};
    };

    Consensus::Dependencies makeDeps(size_t index)
    {
      Consensus::Dependencies deps;
      deps.my_validator_id = [this, index]() -> Id
      { return validators_[index].id; };
      deps.sign = [this, index](const Crypto::Hash &h) -> Crypto::Signature
      { return validators_[index].sign(h); };
      deps.current_height = []() -> Height
      { return 0; };
      deps.active_set = [this]() -> std::vector<Id>
      {
        std::vector<Id> ids;
        ids.reserve(validators_.size());
        for (const auto &v : validators_)
          ids.push_back(v.id);
        return ids;
      };
      deps.signer_public_key =
          [this](Index idx) -> std::optional<Crypto::PublicKey>
      {
        if (idx >= validators_.size())
          return std::nullopt;
        return validators_[idx].pubkey();
      };
      deps.chain_id = []() -> uint64_t
      { return 0x434C5247; };
      deps.parent_hash = []() -> Crypto::Hash
      { return Crypto::Hash{}; };
      deps.simulate_block =
          [](const Core::Block &b) -> std::optional<Crypto::Hash>
      { return b.header.state_root; };
      deps.my_address = [this, index]() -> Crypto::Address
      { return validators_[index].address; };
      deps.now_ms = [this]() -> uint64_t
      {
        return 1'700'000'000'000ULL + proposed_count_++;
      };
      return deps;
    }

    Consensus::Callbacks makeCallbacks(size_t index)
    {
      Consensus::Callbacks cb;

      cb.broadcast_proposal = [this, index](const Consensus::Proposal &p)
      {
        if (offline_[index])
          return;
        for (size_t to = 0; to < instances_.size(); ++to)
        {
          if (to == index || offline_[to])
            continue;
          Envelope env;
          env.kind = Envelope::Proposal;
          env.to = to;
          env.from = index;
          env.proposal = p;
          queue_.push(std::move(env));
        }
      };

      cb.broadcast_prevote = [this, index](const Consensus::Vote &v)
      {
        if (offline_[index])
          return;
        for (size_t to = 0; to < instances_.size(); ++to)
        {
          if (to == index || offline_[to])
            continue;
          Envelope env;
          env.kind = Envelope::Prevote;
          env.to = to;
          env.from = index;
          env.vote = v;
          queue_.push(std::move(env));
        }
      };

      cb.broadcast_precommit = [this, index](const Consensus::Vote &v)
      {
        if (offline_[index])
          return;
        for (size_t to = 0; to < instances_.size(); ++to)
        {
          if (to == index || offline_[to])
            continue;
          Envelope env;
          env.kind = Envelope::Precommit;
          env.to = to;
          env.from = index;
          env.vote = v;
          queue_.push(std::move(env));
        }
      };

      cb.select_transactions = [](uint64_t, uint64_t)
      { return std::vector<Core::Transaction>{}; };

      cb.on_block_committed = [this, index](const Core::Block &b)
      { committed_[index].push_back(b); };

      cb.on_height_advanced = [this, index](Height h)
      { height_advances_[index].push_back(h); };

      return cb;
    }

    std::unique_ptr<Consensus::BftConsensus> makeInstance(size_t index)
    {
      return std::make_unique<Consensus::BftConsensus>(
          makeDeps(index),
          makeCallbacks(index),
          Consensus::Config{},
          *log_ref_);
    }

    Logging::ILogger &logger_;
    std::unique_ptr<Logging::LoggerRef> log_ref_;
    std::vector<TestValidator> validators_;
    std::vector<std::unique_ptr<Consensus::BftConsensus>> instances_;
    std::vector<std::vector<Core::Block>> committed_;
    std::vector<std::vector<Height>> height_advances_;
    uint64_t proposed_count_{0};
    std::vector<bool> offline_;
    std::queue<Envelope> queue_;
  };

  // MockStateView - In-memory StateView for testing. Callers
  // set account balances and nonces, then pass it to
  // Mempool::add() or selectForBlock().

  class MockStateView : public Core::StateView
  {
  public:
    MockStateView() = default;

    Core::Account getAccount(const Crypto::Address &address) const override
    {
      auto it = accounts_.find(address.toString());
      if (it != accounts_.end())
        return it->second;
      return Core::Account{};
    }

    uint64_t getTokenBalance(const Crypto::Address & /*address*/,
                             Id /*token_id*/) const override
    {
      return 0;
    }

    uint64_t currentHeight() const override { return height_; }
    uint64_t chainId() const override { return chain_id_; }

    // ---- Test helpers ----

    void setBalance(const Crypto::Address &addr, uint64_t balance)
    {
      auto &a = accounts_[addr.toString()];
      a.balance = balance;
      a.recalculateStaked(Core::AUTO_STAKE_THRESHOLD);
    }

    void setNonce(const Crypto::Address &addr, uint64_t nonce)
    {
      accounts_[addr.toString()].nonce = nonce;
    }

    void setHeight(uint64_t h) { height_ = h; }
    void setChainId(uint64_t id) { chain_id_ = id; }

  private:
    std::unordered_map<std::string, Core::Account> accounts_;
    uint64_t height_ = 0;
    uint64_t chain_id_ = 0x434C5247; // regtest
  };

  // NodeTestAccess - Friend of Node. Provides static helpers that
  // reach into private members so tests can drive subsystem behavior directly.

  class NodeTestAccess
  {
  public:
    static Core::Chain &chain(Node::Node &n) { return *n.chain_; }
    static Core::ChainDB &chainDb(Node::Node &n) { return *n.chain_db_; }
    static Core::Mempool &mempool(Node::Node &n) { return *n.mempool_; }
    static State::StateDB &stateDb(Node::Node &n) { return *n.state_db_; }
    static Consensus::BftConsensus *consensus(Node::Node &n) { return n.consensus_.get(); }
    static P2P::P2PManager *p2p(Node::Node &n) { return n.p2p_.get(); }

    // True if consensus has been started on this node. Used by
    // tests that need to know when the node has enough peers to
    // proceed. For a validator node with P2P enabled, this flips
    // to true once enough peers connect.
    static bool consensusStarted(Node::Node &n)
    {
      return n.consensus_started_.load();
    }

    static bool applyBlock(Node::Node &n, const Core::Block &b, std::string &error)
    {
      return n.applyCommittedBlock(b, error);
    }

    static void pollConsensus(Node::Node &n)
    {
      if (n.consensus_)
        n.consensus_->pollTimers();
    }

    static void expireConsensusTimer(Node::Node &n)
    {
      if (n.consensus_)
        n.consensus_->forceTimerExpiryForTest();
    }

    static void startConsensusAt(Node::Node &n, Height h)
    {
      if (n.consensus_)
        n.consensus_->start(h);
    }

    static std::vector<Core::Transaction> selectTransactionsForProposal(
        Node::Node &n, uint64_t max_bytes, uint64_t max_txs)
    {
      return n.selectTransactionsForProposal(max_bytes, max_txs);
    }

    static std::unique_ptr<Core::StateView> makeStateView(Node::Node &n)
    {
      return n.makeStateView();
    }

    // Post a callable to the node's P2P io_context. Used by tests
    // that need to run P2P-manager methods on the event loop thread.
    template <typename F>
    static void postToP2P(Node::Node &n, F &&f)
    {
      if (n.p2p_)
        n.p2p_->post(std::forward<F>(f));
    }

    // Snapshot the P2P manager's state. Returns a default-constructed
    // snapshot if P2P is disabled. Must be called with the returned
    // callable executed on the P2P event loop thread — see the
    // waitForEstablished helper in NodeEndToEndTests for the pattern.
    static P2P::P2PManager::Snapshot p2pSnapshot(Node::Node &n)
    {
      if (!n.p2p_)
        return {};
      return n.p2p_->snapshot();
    }
  };

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

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::vector<Id> connected_;
    std::vector<std::pair<Id, std::string>> disconnected_;
    std::vector<std::pair<P2P::Message, Id>> messages_;
  };

  // TempFile creates a unique temp file path, removes it on destruction.
  // The file itself is not created; the fixture's code does that.

  class TempFile
  {
  public:
    TempFile(const std::string &prefix = "clrty_p2p_test")
    {
      static std::atomic<uint64_t> counter{0};
      path_ = std::filesystem::temp_directory_path() /
              (prefix + "_" + std::to_string(counter.fetch_add(1)) + ".tmp");
      std::filesystem::remove(path_);
    }

    ~TempFile()
    {
      std::error_code ec;
      std::filesystem::remove(path_, ec);
    }

    TempFile(const TempFile &) = delete;
    TempFile &operator=(const TempFile &) = delete;

    std::string path() const { return path_.string(); }

  private:
    std::filesystem::path path_;
  };

  class TempDB
  {
  public:
    TempDB()
    {
      static std::atomic<uint64_t> counter{0};
      path_ = std::filesystem::temp_directory_path() /
              ("clrty_state_test_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(path_);
      db_ = std::make_unique<State::StateDB>(path_.string(), 64ULL * 1024 * 1024);
    }

    ~TempDB()
    {
      if (db_)
      {
        db_->close();
        db_.reset();
      }
      std::error_code ec;
      std::filesystem::remove_all(path_, ec);
    }

    TempDB(const TempDB &) = delete;
    TempDB &operator=(const TempDB &) = delete;

    State::StateDB &db() { return *db_; }
    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
    std::unique_ptr<State::StateDB> db_;
  };

}