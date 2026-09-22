#pragma once

#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include "TransactionBuilder.h"
#include "Utils.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Types.h"

#include "Node/NodeConfig.h"

#include "State/StateDB.h"
#include "State/SparseMerkleTree.h"

#include "Serialization/SerializationTools.h"

using namespace std::chrono_literals;

namespace Tests
{

  class NodeTestFixture : public testing::Test
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

  class ConsensusTestFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      log_ref_ = std::make_unique<Logging::LoggerRef>(logger_, "consensus-test");
    }

    void TearDown() override
    {
      consensus_.reset();
      log_ref_.reset();
    }

    void makeValidators(size_t n)
    {
      validators_.clear();
      for (size_t i = 0; i < n; ++i)
        validators_.push_back(TestValidator::make(static_cast<Id>(i + 1)));
    }

    std::vector<Id> activeIds() const
    {
      std::vector<Id> ids;
      for (const auto &v : validators_)
        ids.push_back(v.id);
      return ids;
    }

    Consensus::Dependencies makeDeps(size_t local_index)
    {
      Consensus::Dependencies deps;
      deps.my_validator_id = [this, local_index]() -> Id
      {
        if (local_index == SIZE_MAX || local_index >= validators_.size())
          return INVALID_ID;
        return validators_[local_index].id;
      };
      deps.sign = [this, local_index](const Crypto::Hash &h) -> Crypto::Signature
      {
        if (local_index == SIZE_MAX || local_index >= validators_.size())
          return Crypto::Signature{};
        return validators_[local_index].sign(h);
      };
      deps.current_height = [this]() -> Height
      { return current_height_; };
      deps.active_set = [this]()
      { return activeIds(); };
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
      {
        return b.header.state_root;
      };
      deps.my_address = [this, local_index]() -> Crypto::Address
      {
        if (local_index == SIZE_MAX || local_index >= validators_.size())
          return Crypto::Address{};
        return validators_[local_index].address;
      };
      deps.now_ms = []() -> uint64_t
      { return 1'700'000'000'000ULL; };
      return deps;
    }

    Consensus::Callbacks makeCallbacks()
    {
      Consensus::Callbacks cb;
      cb.broadcast_proposal = [this](const Consensus::Proposal &p)
      { broadcast_proposals.push_back(p); };
      cb.broadcast_prevote = [this](const Consensus::Vote &v)
      { broadcast_prevotes.push_back(v); };
      cb.broadcast_precommit = [this](const Consensus::Vote &v)
      { broadcast_precommits.push_back(v); };
      cb.select_transactions = [](uint64_t, uint64_t)
      { return std::vector<Core::Transaction>{}; };
      cb.on_block_committed = [this](const Core::Block &b)
      { committed_blocks.push_back(b); };
      cb.on_height_advanced = [this](Height h)
      { height_advances.push_back(h); };
      return cb;
    }

    Core::Block makeBlock(Height height,
                          const Crypto::Hash &state_root = Crypto::Hash{})
    {
      Core::Block b;
      b.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
      b.header.chain_id = 0x434C5247;
      b.header.height = height;
      b.header.parent_hash = Crypto::Hash{};
      b.header.timestamp_ms = 1'700'000'000'000ULL + height * 1000;
      b.header.proposer = Crypto::Address{};
      for (size_t i = 0; i < 32; ++i)
        b.header.proposer.data[i] = uint8_t(0x80 + i);
      b.header.tx_root = Core::computeTxRoot({});
      b.header.state_root = state_root;
      b.header.receipts_root = Crypto::Hash{};
      b.header.validator_set_root =
          Core::computeValidatorSetRoot(activeIds());
      b.header.active_validator_count =
          static_cast<uint32_t>(validators_.size());
      b.header.tx_count = 0;
      b.header.total_fees = 0;
      b.quorum_signatures.resize(Core::bftQuorum(validators_.size()));
      for (size_t i = 0; i < b.quorum_signatures.size(); ++i)
        b.quorum_signatures[i].signer_index = static_cast<uint16_t>(i);
      return b;
    }

    void makeConsensus(size_t local_index)
    {
      consensus_ = std::make_unique<Consensus::BftConsensus>(
          makeDeps(local_index),
          makeCallbacks(),
          Consensus::Config{},
          *log_ref_);
    }

    Consensus::Proposal proposeFromProposer(size_t proposer_index,
                                            Height height,
                                            Round round,
                                            const Core::Block &block)
    {
      Consensus::Proposal p;
      p.height = height;
      p.round = round;
      p.signer_index = static_cast<Index>(proposer_index);
      p.block_hash = block.hash();
      p.block_bytes = block.serialize();

      Crypto::Hash signing_hash =
          Consensus::proposalSigningHash(height, round, p.block_hash);
      p.signature = validators_[proposer_index].sign(signing_hash);
      return p;
    }

    Consensus::Vote makeSignedVote(size_t signer_index,
                                   Height height,
                                   Round round,
                                   bool is_nil,
                                   const Crypto::Hash &block_hash = Crypto::Hash{})
    {
      Consensus::Vote v;
      v.height = height;
      v.round = round;
      v.signer_index = static_cast<Index>(signer_index);
      v.is_nil = is_nil;
      v.block_hash = block_hash;

      Crypto::Hash signing_hash =
          Consensus::voteSigningHash(height, round, is_nil, block_hash);
      v.signature = validators_[signer_index].sign(signing_hash);
      return v;
    }

    void deliverPrevote(size_t signer_index,
                        Height height,
                        Round round,
                        bool is_nil,
                        const Crypto::Hash &block_hash = Crypto::Hash{})
    {
      consensus_->onPrevote(
          makeSignedVote(signer_index, height, round, is_nil, block_hash));
    }

    void deliverPrecommit(size_t signer_index,
                          Height height,
                          Round round,
                          bool is_nil,
                          const Crypto::Hash &block_hash = Crypto::Hash{})
    {
      consensus_->onPrecommit(
          makeSignedVote(signer_index, height, round, is_nil, block_hash));
    }

    NoopLogger logger_;
    std::unique_ptr<Logging::LoggerRef> log_ref_;
    std::vector<TestValidator> validators_;
    Height current_height_{0};
    std::unique_ptr<Consensus::BftConsensus> consensus_;

    std::vector<Consensus::Proposal> broadcast_proposals;
    std::vector<Consensus::Vote> broadcast_prevotes;
    std::vector<Consensus::Vote> broadcast_precommits;
    std::vector<Core::Block> committed_blocks;
    std::vector<Height> height_advances;
  };

  class ConsensusNetworkFixture : public testing::Test
  {
  protected:
    void TearDown() override
    {
      if (network_)
      {
        network_->stopAll();
        network_.reset();
      }
    }

    void makeNetwork(size_t n)
    {
      network_ = std::make_unique<ConsensusNetwork>(n, logger_);
    }

    ConsensusNetwork &net() { return *network_; }

    NoopLogger logger_;
    std::unique_ptr<ConsensusNetwork> network_;
  };

  // ExecutorTestFixture
  // One MDBX write txn per test. All state writes go through the
  // txn-bound StateAccess. TearDown aborts — nothing persists between
  // tests, and the test runs in one txn (fast).

  class ExecutorTestFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      db_ = std::make_unique<State::StateDB>(tmp_path(), 64ULL * 1024 * 1024);
      txn_.emplace(db_->beginWrite());
      state_ = std::make_unique<State::StateAccess>(*db_, *txn_, /*version=*/0);

      alice_ = Crypto::generateKeyPair();
      bob_ = Crypto::generateKeyPair();
      carol_ = Crypto::generateKeyPair();

      fund(alice_.publicKey, 1'000'000'000ULL);
      fund(bob_.publicKey, 1'000'000'000ULL);
      fund(carol_.publicKey, 1'000'000'000ULL);
    }

    void TearDown() override
    {
      // No commit, every test starts clean.
      state_.reset();
      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();
      if (db_)
      {
        db_->close();
        db_.reset();
      }
      std::error_code ec;
      std::filesystem::remove_all(tmp_path(), ec);
    }

    static const std::filesystem::path &tmp_path()
    {
      static std::atomic<uint64_t> counter{0};
      static thread_local std::filesystem::path path;
      static thread_local uint64_t id = 0;

      if (id == 0 || path.empty())
      {
        id = counter.fetch_add(1);
        path = std::filesystem::temp_directory_path() /
               ("clrty_exec_test_" + std::to_string(id));
        std::filesystem::remove_all(path);
      }
      return path;
    }

    // ---- Helpers ----

    void fund(const Crypto::Address &addr, uint64_t amount)
    {
      Core::Account acct = state_->getAccount(addr);
      acct.balance += amount;
      if (acct.created_at_height == 0)
        acct.created_at_height = 1;
      acct.recalculateStaked(Core::AUTO_STAKE_THRESHOLD);
      state_->putAccount(addr, acct);
    }

    void setBalance(const Crypto::Address &addr, uint64_t amount)
    {
      Core::Account acct = state_->getAccount(addr);
      acct.balance = amount;
      state_->putAccount(addr, acct);
    }

    uint64_t balanceOf(const Crypto::Address &addr)
    {
      return state_->getAccount(addr).balance;
    }

    uint64_t nonceOf(const Crypto::Address &addr)
    {
      return state_->getAccount(addr).nonce;
    }

    Core::Receipt run(const Core::Transaction &tx, uint64_t height = 100)
    {
      Core::TxExecutionContext ctx;
      ctx.current_height = height;
      ctx.chain_id = EXEC_CHAIN_ID;
      ctx.tx_index_in_block = 0;
      return Core::TransactionExecutor::execute(*state_, tx, ctx);
    }

    // Execute a CreatePool tx and return the newly-created pool's ID.
    // Returns 0 if the tx failed.
    uint64_t createPool(const Crypto::KeyPair &creator,
                        Id token_a,
                        uint64_t amount_a,
                        Id token_b,
                        uint64_t amount_b,
                        uint16_t fee_bps = Core::AMM_DEFAULT_FEE_BPS,
                        uint64_t nonce = 0)
    {
      Core::Transaction tx = TransactionBuilder()
                                 .type(Core::TxType::CreatePool)
                                 .from(creator)
                                 .to(Crypto::Address{})
                                 .amount(amount_a)
                                 .fee(1)
                                 .nonce(nonce)
                                 .tokenId(token_a)
                                 .chainId(EXEC_CHAIN_ID)
                                 .payload(makeCreatePoolPayload(
                                     static_cast<uint32_t>(token_b), amount_b, fee_bps))
                                 .build();

      Core::Receipt r = run(tx);
      if (r.status != Core::ReceiptStatus::Success)
        return 0;

      // Probe pool IDs for the one we just made.
      for (uint64_t id = 1; id <= 8; ++id)
      {
        Core::AmmPool p;
        if (state_->getAmmPool(id, p) &&
            p.creator == creator.publicKey &&
            p.reserve_a == std::min(amount_a, amount_b) &&
            p.reserve_b == std::max(amount_a, amount_b))
        {
          return id;
        }
      }
      return 0;
    }

    // Give an address a custom-token balance directly. Used to set
    // up mint/burn/AMM tests without going through CreateToken.
    void setTokenBalance(const Crypto::Address &addr,
                         Id token,
                         uint64_t amount)
    {
      state_->putTokenBalance(addr, token, amount);
    }

    // Write a minimal valid token directly. Used as a setup step.
    Id createTokenDirect(const Crypto::KeyPair &creator,
                         const std::string &name,
                         const std::string &symbol,
                         uint64_t max_supply = 0,
                         Id token_id = 100)
    {
      Core::TokenInfo t;
      t.id = token_id;
      t.name = name;
      t.symbol = symbol;
      t.decimals = 8;
      t.creator = creator.publicKey;
      t.maxSupply = max_supply;
      state_->putToken(t);
      return token_id;
    }
    // Write a validator record and its address index directly. Used
    // as a setup step for the unregister and update tests, since
    // running the full RegisterValidator path requires a valid
    // signature and enough balance.
    void seedValidator(const Crypto::KeyPair &owner,
                       uint64_t id,
                       bool is_seed = false,
                       bool is_active = false)
    {
      Core::ValidatorInfo v;
      v.id = id;
      v.reward_address = owner.publicKey;
      v.owner = owner.publicKey;
      v.stake = Core::VALIDATOR_MIN_STAKE;
      v.registered_at_height = 1;
      v.uptime_score = 10'000;
      v.is_seed = is_seed;
      v.is_active = is_active;
      state_->putValidator(v);
      state_->putValidatorByAddress(owner.publicKey, id);
    }

    // Set the active set to a given list.
    void setActiveSet(const std::vector<Id> &ids)
    {
      std::vector<uint8_t> bytes;
      bytes.reserve(ids.size() * 8);
      for (auto id : ids)
      {
        for (int i = 0; i < 8; ++i)
          bytes.push_back(uint8_t(id >> (i * 8)));
      }
      state_->putGlobal("active_set", bytes);
    }

    // Advance next_validator_id to a value past the given id.
    void bumpNextValidatorId(uint64_t next)
    {
      std::vector<uint8_t> bytes(8);
      for (int i = 0; i < 8; ++i)
        bytes[i] = uint8_t(next >> (i * 8));
      state_->putGlobal("next_validator_id", bytes);
    }

    // Set an account's pending rewards directly.
    void setPendingRewards(const Crypto::Address &addr, uint64_t amount)
    {
      Core::Account acct = state_->getAccount(addr);
      acct.pending_rewards = amount;
      acct.recalculateStaked(Core::AUTO_STAKE_THRESHOLD);
      state_->putAccount(addr, acct);
    }

    std::unique_ptr<State::StateDB> db_;
    std::optional<State::StateDB::Txn> txn_;
    std::unique_ptr<State::StateAccess> state_;
    Crypto::KeyPair alice_;
    Crypto::KeyPair bob_;
    Crypto::KeyPair carol_;
  };

  class MempoolTestFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      state_.setBalance(builder_.senderAddress(), 10'000'000'000ULL);
      state_.setChainId(0x434C5247);
      state_.setHeight(100);
    }

    Core::MempoolAddResult add(const Core::Transaction &tx, Core::FeeTier tier = Core::FeeTier::Standard)
    {
      return pool_.add(tx, state_, tier);
    }

    Core::MempoolAddResult addTransfer(uint64_t nonce, uint64_t fee,
                                       Core::FeeTier tier = Core::FeeTier::Standard)
    {
      Core::Transaction tx = builder_.buildTransfer(nonce, /*amount=*/1000, fee);
      return pool_.add(tx, state_, tier);
    }

    Core::Mempool pool_;
    MockStateView state_;
    TransactionBuilder builder_;
  };

  class BlockProcessorTestFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      static std::atomic<uint64_t> counter{0};
      test_dir_ = std::filesystem::temp_directory_path() /
                  ("clrty_bp_test_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(test_dir_);
      std::filesystem::create_directories(test_dir_);

      db_ = std::make_unique<State::StateDB>(test_dir_.string(),
                                             64ULL * 1024 * 1024);

      alice_ = Crypto::generateKeyPair();
      bob_ = Crypto::generateKeyPair();
      carol_ = Crypto::generateKeyPair();

      // Seed validator keypairs. These are deterministic so every
      // test run produces the same genesis and the same block hashes.
      seed1_ = deterministicKey(1);
      seed2_ = deterministicKey(2);

      genesis_config_ = makeFixtureGenesis(seed1_, seed2_);

      {
        auto t = db_->beginWrite();
        State::StateAccess s(*db_, t, 0);
        applyGenesis(s, genesis_config_);
        fundStandardAccounts(s);
        s.commit(/*version=*/0);
        t.commit();
      }

      {
        auto t = db_->beginWrite();
        State::StateAccess s(*db_, t, 0);
        Core::Block genesis = makeGenesisBlock(s, genesis_config_);
        genesis_hash_ = genesis.hash();
        t.abort();
      }
    }

    void TearDown() override
    {
      if (db_)
      {
        db_->close();
        db_.reset();
      }
      std::error_code ec;
      std::filesystem::remove_all(test_dir_, ec);
    }

    // ---- Deterministic key derivation ----

    static Crypto::KeyPair deterministicKey(uint64_t id)
    {
      Crypto::SecretKey seed;
      for (int i = 0; i < 8; ++i)
        seed.data[i] = uint8_t(id >> (i * 8));
      for (size_t i = 8; i < 32; ++i)
        seed.data[i] = uint8_t(0xC0 + i);
      return Crypto::generateKeyPairFromSeed(seed);
    }

    static Crypto::Address addressOf(const Crypto::KeyPair &kp)
    {
      Crypto::Address a;
      std::memcpy(a.data.data(), kp.publicKey.data.data(), 32);
      return a;
    }

    // ---- Fixture genesis ----

    static Core::GenesisConfig makeFixtureGenesis(const Crypto::KeyPair &seed1,
                                                  const Crypto::KeyPair &seed2)
    {
      Core::GenesisConfig cfg;
      cfg.chain_id = 0x434C5247; // regtest
      cfg.timestamp_ms = 1'700'000'000'000ULL;

      constexpr uint64_t INITIAL =
          GlobalConfig::GENESIS_SUPPLY * GlobalConfig::ATOMIC_UNITS_PER_COIN;

      Crypto::Address fund_addr;
      std::fill(fund_addr.data.begin(), fund_addr.data.end(), 0x01);
      cfg.accounts.push_back({fund_addr, INITIAL, "test fund"});

      cfg.validators.push_back({1, addressOf(seed1), seed1.publicKey, true});
      cfg.validators.push_back({2, addressOf(seed2), seed2.publicKey, true});

      cfg.initial_total_supply = INITIAL;
      cfg.initial_active_set_size = 2;
      return cfg;
    }

    // ---- State access ----

    template <typename Fn>
    void withState(Fn &&fn)
    {
      auto t = db_->beginWrite();
      State::StateAccess s(*db_, t, 0);
      fn(s);
      s.commit(/*version=*/0);
      t.commit();
    }

    template <typename Fn>
    void readState(Fn &&fn) const
    {
      auto t = db_->beginWrite();
      State::StateAccess s(*db_, t, 0);
      fn(s);
      t.abort();
    }

    // ---- State helpers ----

    uint64_t balanceOf(const Crypto::Address &addr)
    {
      uint64_t result = 0;
      readState([&](State::StateAccess &s)
                { result = s.getAccount(addr).balance; });
      return result;
    }

    uint64_t nonceOf(const Crypto::Address &addr)
    {
      uint64_t result = 0;
      readState([&](State::StateAccess &s)
                { result = s.getAccount(addr).nonce; });
      return result;
    }

    Crypto::Hash currentStateRoot()
    {
      Crypto::Hash result;
      readState([&](State::StateAccess &s)
                { result = s.stateRoot(); });
      return result;
    }

    uint64_t currentPot()
    {
      uint64_t v = 0;
      readState([&](State::StateAccess &s)
                {
          std::vector<uint8_t> b;
          if (s.getGlobal("pot", b) && b.size() == 8)
            for (int i = 0; i < 8; ++i)
              v |= uint64_t(b[i]) << (i * 8); });
      return v;
    }

    void fundStandardAccounts(State::StateAccess &state)
    {
      fundInto(state, alice_.publicKey, 1'000'000'000ULL);
      fundInto(state, bob_.publicKey, 1'000'000'000ULL);
      fundInto(state, carol_.publicKey, 1'000'000'000ULL);
    }

    void fundInto(State::StateAccess &state,
                  const Crypto::Address &addr,
                  uint64_t amount)
    {
      Core::Account acct = state.getAccount(addr);
      acct.balance += amount;
      if (acct.created_at_height == 0)
        acct.created_at_height = 1;
      acct.recalculateStaked(Core::AUTO_STAKE_THRESHOLD);
      state.putAccount(addr, acct);
    }

    static std::vector<uint8_t> encodeActiveSet(
        const std::vector<Id> &ids)
    {
      std::vector<uint8_t> out;
      out.reserve(ids.size() * 8);
      for (auto id : ids)
      {
        for (int i = 0; i < 8; ++i)
          out.push_back(uint8_t(id >> (i * 8)));
      }
      return out;
    }

    std::vector<Id> readActiveSet() const
    {
      std::vector<Id> result;
      readState([&](State::StateAccess &s)
                {
          std::vector<uint8_t> bytes;
          if (!s.getGlobal("active_set", bytes))
            return;
          size_t count = bytes.size() / 8;
          result.reserve(count);
          for (size_t i = 0; i < count; ++i)
          {
            uint64_t id = 0;
            for (int j = 0; j < 8; ++j)
              id |= uint64_t(bytes[i * 8 + j]) << (j * 8);
            result.push_back(id);
          } });
      return result;
    }

    uint64_t readActiveSetSize() const
    {
      uint64_t v = 0;
      readState([&](State::StateAccess &s)
                {
          std::vector<uint8_t> bytes;
          if (s.getGlobal("active_set_size", bytes) && bytes.size() == 8)
            for (int i = 0; i < 8; ++i)
              v |= uint64_t(bytes[i]) << (i * 8); });
      return v;
    }

    void putValidatorDirect(const Core::ValidatorInfo &v)
    {
      withState([&](State::StateAccess &s)
                { s.putValidator(v); });
    }

    bool readValidator(Id id, Core::ValidatorInfo &out) const
    {
      bool found = false;
      readState([&](State::StateAccess &s)
                { found = s.getValidator(id, out); });
      return found;
    }

    void setNextValidatorId(uint64_t next)
    {
      withState([&](State::StateAccess &s)
                {
          std::vector<uint8_t> bytes(8);
          for (int i = 0; i < 8; ++i)
            bytes[i] = uint8_t(next >> (i * 8));
          s.putGlobal("next_validator_id", bytes); });
    }

    // ---- Context ----

    Core::BlockContext makeContext(uint64_t height, bool dry_run = false)
    {
      Core::BlockContext ctx;
      ctx.chain_id = genesis_config_.chain_id;
      ctx.current_height = height;
      ctx.dry_run = dry_run;
      return ctx;
    }

    std::vector<Id> activeSet()
    {
      return {1, 2};
    }

    // ---- Receipts root ----

    static Crypto::Hash computeReceiptsRootForTest(
        const std::vector<Crypto::Hash> &tx_hashes,
        const std::vector<Core::Receipt> &receipts)
    {
      if (tx_hashes.size() != receipts.size())
        return Crypto::Hash{};
      if (tx_hashes.empty())
        return Crypto::Hash{};

      std::vector<Crypto::Hash> leaves;
      leaves.reserve(receipts.size());

      for (size_t i = 0; i < receipts.size(); ++i)
      {
        std::vector<uint8_t> buf;
        buf.reserve(4 + 32 + 1 + 8);
        buf.push_back('r');
        buf.push_back('c');
        buf.push_back('p');
        buf.push_back('t');
        const auto &th = tx_hashes[i];
        buf.insert(buf.end(), th.data.begin(), th.data.end());
        buf.push_back(static_cast<uint8_t>(receipts[i].status));
        uint64_t fee = receipts[i].fee_paid;
        for (int j = 0; j < 8; ++j)
          buf.push_back(uint8_t(fee >> (j * 8)));

        Crypto::Hash h;
        Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
        leaves.push_back(h);
      }

      return Core::computeMerkleRoot(leaves);
    }

    // ---- Transaction helper ----

    Core::Transaction makeSignedTransfer(const Crypto::KeyPair &from,
                                         const Crypto::Address &to,
                                         uint64_t amount,
                                         uint64_t fee,
                                         uint64_t nonce)
    {
      return TransactionBuilder()
          .type(Core::TxType::Transfer)
          .from(from)
          .to(to)
          .amount(amount)
          .fee(fee)
          .nonce(nonce)
          .chainId(genesis_config_.chain_id)
          .build();
    }

    // ---- Header ----

    Core::BlockHeader makeHeaderSkeleton(uint64_t height,
                                         const Crypto::Hash &parent,
                                         const std::vector<Id> &active_set)
    {
      Core::BlockHeader h;
      h.version = GlobalConfig::CURRENT_BLOCK_VERSION;
      h.chain_id = genesis_config_.chain_id;
      h.height = height;
      h.parent_hash = parent;
      h.timestamp_ms = 1'700'000'000'000ULL + height * 1000;
      h.proposer = active_set.empty() ? Crypto::Address{}
                                      : validatorAddress(active_set[0]);
      h.epoch = height / Core::ROTATION_INTERVAL;
      h.rotation_index = height / Core::ROTATION_INTERVAL;
      h.commit_round = 0;
      h.state_root = Crypto::Hash{};
      h.tx_root = Crypto::Hash{};
      h.receipts_root = Crypto::Hash{};
      h.validator_set_root = Crypto::Hash{};
      h.total_fees = 0;
      h.tx_count = 0;
      h.active_validator_count =
          static_cast<uint32_t>(active_set.size());
      return h;
    }

    Crypto::Address validatorAddress(Id id)
    {
      for (const auto &v : genesis_config_.validators)
      {
        if (v.id == id)
          return v.reward_address;
      }
      return Crypto::Address{};
    }

    // ---- Real quorum signatures ----

    // Produces a set of quorum signatures over the block's hash,
    // signed by the fixture's seed keypairs. `block` must already
    // have its final `commit_round` and `state_root` set — the
    // signature covers the block hash, which covers both.
    std::vector<Crypto::ValidatorSignature>
    makeQuorumForBlock(const Core::Block &block,
                       const std::vector<Crypto::KeyPair> &keys)
    {
      size_t needed = Core::bftQuorum(keys.size());
      std::vector<Crypto::ValidatorSignature> sigs;
      sigs.reserve(needed);

      Crypto::Hash signing_hash = Consensus::voteSigningHash(
          block.header.height,
          block.header.commit_round,
          /*is_nil=*/false,
          block.hash());

      for (size_t i = 0; i < needed; ++i)
      {
        Crypto::ValidatorSignature vs;
        vs.signer_index = static_cast<Index>(i);
        vs.signature = Crypto::sign(signing_hash, keys[i].secretKey);
        sigs.push_back(vs);
      }
      return sigs;
    }

    // ---- Block builder ----

    Core::Block makeProcessableBlock(uint64_t height,
                                     const Crypto::Hash &parent,
                                     const std::vector<Core::Transaction> &txs,
                                     const std::vector<Id> &active_set)
    {
      Core::Block b;
      b.header = makeHeaderSkeleton(height, parent, active_set);
      b.transactions = txs;
      b.header.tx_count = static_cast<uint32_t>(txs.size());
      b.header.active_validator_count =
          static_cast<uint32_t>(active_set.size());

      uint64_t total_fees = 0;
      for (const auto &tx : txs)
      {
        if (!isSystemTx(tx.tx_type))
          total_fees += tx.fee;
      }
      b.header.total_fees = total_fees;
      b.header.tx_root = computeTxRoot(txs);
      b.header.validator_set_root = Core::computeValidatorSetRoot(active_set);
      b.participants = active_set;
      b.quorum_signatures.clear();

      // Simulate on a throwaway txn. dry_run skips the signature
      // check (signatures aren't computed yet) and the state-root
      // check (state_root isn't set yet).
      Crypto::Hash sim_state_root;
      std::vector<Core::Receipt> sim_receipts;
      std::vector<Crypto::Hash> sim_tx_hashes;

      {
        auto sim_txn = db_->beginWrite();
        State::StateAccess sim_state(*db_, sim_txn, 0);

        Core::BlockContext sim_ctx = makeContext(height, /*dry_run=*/true);
        Core::BlockResult sim_result =
            Core::BlockProcessor::applyBlock(sim_state, b, sim_ctx);

        sim_state_root = sim_result.new_state_root;
        sim_receipts = sim_result.receipts;
        sim_tx_hashes = sim_result.tx_hashes;

        sim_txn.abort();
      }

      b.header.state_root = sim_state_root;
      if (!sim_tx_hashes.empty())
      {
        b.header.receipts_root =
            computeReceiptsRootForTest(sim_tx_hashes, sim_receipts);
      }
      else
      {
        b.header.receipts_root = Crypto::Hash{};
      }

      // Sign the block now that its hash is final. The fixture's
      // seed keypairs correspond to the validators in the active set
      // in order, so index i in the key list is validator i+1.
      b.quorum_signatures = makeQuorumForBlock(b, {seed1_, seed2_});

      return b;
    }

    Core::Block makeProcessableBlock(uint64_t height,
                                     const Crypto::Hash &parent,
                                     const std::vector<Core::Transaction> &txs)
    {
      return makeProcessableBlock(height, parent, txs, activeSet());
    }

    Core::BlockResult applyBlock(uint64_t height,
                                 const Crypto::Hash &parent,
                                 const std::vector<Core::Transaction> &txs,
                                 bool dry_run = false)
    {
      Core::Block b = makeProcessableBlock(height, parent, txs, activeSet());
      Core::BlockContext ctx = makeContext(height, dry_run);

      auto t = db_->beginWrite();
      State::StateAccess s(*db_, t, 0);
      Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
      if (r.valid)
      {
        s.commit(/*version=*/0);
        t.commit();
      }
      else
      {
        t.abort();
      }

      return r;
    }

    // ---- Members ----

    std::filesystem::path test_dir_;
    std::unique_ptr<State::StateDB> db_;
    Crypto::KeyPair alice_;
    Crypto::KeyPair bob_;
    Crypto::KeyPair carol_;
    Crypto::KeyPair seed1_;
    Crypto::KeyPair seed2_;
    Core::GenesisConfig genesis_config_;
    Crypto::Hash genesis_hash_;
  };

  // Test fixture that provides a fresh StateDB per test.

  class ChainTestFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      db_ = std::make_unique<State::StateDB>(tmp_path(), 64ULL * 1024 * 1024);
      chain_db_ = std::make_unique<Core::ChainDB>(*db_);
      chain_ = std::make_unique<Core::Chain>(*chain_db_);
    }

    void TearDown() override
    {
      if (db_)
      {
        db_->close();
        db_.reset();
      }
      std::error_code ec;
      std::filesystem::remove_all(tmp_path(), ec);
    }

    static const std::filesystem::path &tmp_path()
    {
      static std::atomic<uint64_t> counter{0};
      static thread_local std::filesystem::path path;
      static thread_local uint64_t id = 0;

      if (id == 0 || path.empty())
      {
        id = counter.fetch_add(1);
        path = std::filesystem::temp_directory_path() / ("clrty_chain_test_" + std::to_string(id));
        std::filesystem::remove_all(path);
      }
      return path;
    }

    std::unique_ptr<State::StateDB> db_;
    std::unique_ptr<Core::ChainDB> chain_db_;
    std::unique_ptr<Core::Chain> chain_;
  };

  class NodeBlockFixture : public NodeTestFixture
  {
  protected:
    void SetUp() override
    {
      NodeTestFixture::SetUp();

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
        // Return the skeleton unchanged; caller's applyBlock will
        // reject it and the test can inspect the error.
        return b;
      }

      b.header.state_root = sim.new_state_root;

      // Sign now that the block hash is final.
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

  class NodeEndToEndFixture : public NodeTestFixture
  {
  protected:
    void SetUp() override
    {
      NodeTestFixture::SetUp();
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
      NodeTestFixture::TearDown();
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

      deps.active_set = [this]() -> std::vector<Id>
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

  class P2PManagerFixture : public testing::Test
  {
  protected:
    static constexpr auto kWait = 2000ms;

    static bool canBindLoopback()
    {
      try
      {
        boost::asio::io_context io;
        boost::asio::ip::tcp::acceptor acc(
            io, boost::asio::ip::tcp::endpoint(
                    boost::asio::ip::tcp::v4(), 0));
        return acc.is_open();
      }
      catch (...)
      {
        return false;
      }
    }

    void SetUp() override
    {
      if (!canBindLoopback())
        GTEST_SKIP() << "loopback sockets unavailable in this environment";
    }
  };

  class BinarySerializerTestFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    // Helper to round-trip serialize/deserialize
    template <typename T>
    bool roundTrip(T &original, T &result)
    {
      std::vector<uint8_t> buffer;
      Serialization::MemoryOutputStream outStream(buffer);
      Serialization::BinarySerializer outSerializer(outStream);

      serialize_object(original, outSerializer);

      Serialization::MemoryInputStream inStream(buffer.data(), buffer.size());
      Serialization::BinarySerializer inSerializer(inStream);

      try
      {
        serialize_object(result, inSerializer);
        return true;
      }
      catch (const std::exception &)
      {
        return false;
      }
    }
  };

  class JsonSerializerTestFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    template <typename T>
    std::string toJson(const T &obj)
    {
      return Serialization::toJsonString(obj);
    }

    template <typename T>
    bool fromJson(T &obj, const std::string &json)
    {
      return Serialization::fromJsonString(obj, json);
    }
  };

  class KVBinarySerializerTestFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    // Helper to round-trip serialize/deserialize
    template <typename T>
    bool roundTrip(T &original, T &result)
    {
      std::vector<uint8_t> buffer;
      Serialization::MemoryOutputStream outStream(buffer);
      Serialization::KVBinarySerializer outSerializer(outStream);

      serialize_object(original, outSerializer);
      outSerializer.dump(outStream);

      Serialization::MemoryInputStream inStream(buffer.data(), buffer.size());
      Serialization::KVBinarySerializer inSerializer(inStream);

      try
      {
        serialize_object(result, inSerializer);
        return true;
      }
      catch (const std::exception &)
      {
        return false;
      }
    }
  };

  // one DB, one write txn held for the whole test.
  class SmtTestFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      txn_.emplace(db_.db().beginWrite());
      tree_ = std::make_unique<State::SparseMerkleTree>(db_.db());
      tree_->setTxn(&*txn_);
    }

    void TearDown() override
    {
      tree_.reset();
      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();
    }

    static Crypto::Hash makeKey(uint64_t n)
    {
      Crypto::Hash h;
      for (int i = 0; i < 8; ++i)
        h.data[i] = uint8_t(n >> (i * 8));
      for (size_t i = 8; i < 32; ++i)
        h.data[i] = 0;
      return h;
    }

    static std::vector<uint8_t> makeValue(uint64_t n, size_t len = 32)
    {
      std::vector<uint8_t> v(len);
      for (size_t i = 0; i < len; ++i)
        v[i] = uint8_t((n >> ((i % 8) * 8)) ^ (i * 7));
      return v;
    }

    Crypto::Hash update(uint64_t key_num, uint64_t value_num)
    {
      return tree_->update(makeKey(key_num), makeValue(value_num), 0);
    }

    Crypto::Hash remove(uint64_t key_num)
    {
      return tree_->remove(makeKey(key_num), 0);
    }

    std::optional<std::vector<uint8_t>> get(uint64_t key_num)
    {
      return tree_->get(makeKey(key_num));
    }

    TempDB db_;
    std::optional<State::StateDB::Txn> txn_;
    std::unique_ptr<State::SparseMerkleTree> tree_;
  };

  //  StateDBTestFixture — one DB, no txn held. Tests manage their own.

  class StateDBTestFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    TempDB db_;
  };

  //  SmtPersistenceTestFixture — owns a path, opens/closes DBs explicitly.
  //
  //  Use this for tests that need to close and reopen the DB (i.e.
  //  persistence across restart, or save-then-load across a commit
  //  boundary).

  class SmtPersistenceTestFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      static std::atomic<uint64_t> counter{0};
      path_ = std::filesystem::temp_directory_path() /
              ("clrty_smt_persist_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(path_);
    }

    void TearDown() override
    {
      std::error_code ec;
      std::filesystem::remove_all(path_, ec);
    }

    std::unique_ptr<State::StateDB> openDB()
    {
      return std::make_unique<State::StateDB>(path_.string(), 64ULL * 1024 * 1024);
    }

    const std::filesystem::path &path() const { return path_; }

    static Crypto::Hash makeKey(uint64_t n)
    {
      Crypto::Hash h;
      for (int i = 0; i < 8; ++i)
        h.data[i] = uint8_t(n >> (i * 8));
      for (size_t i = 8; i < 32; ++i)
        h.data[i] = 0;
      return h;
    }

    static std::vector<uint8_t> makeValue(uint64_t n, size_t len = 32)
    {
      std::vector<uint8_t> v(len);
      for (size_t i = 0; i < len; ++i)
        v[i] = uint8_t((n >> ((i % 8) * 8)) ^ (i * 7));
      return v;
    }

    std::filesystem::path path_;
  };

  //  StateAccessTestFixture
  //
  //  One DB and one write txn per test. The StateAccess wraps the txn.
  //  TearDown aborts — nothing persists.

  class StateAccessTestFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      txn_.emplace(db_.db().beginWrite());
      access_ = std::make_unique<State::StateAccess>(db_.db(), *txn_, 0);
    }

    void TearDown() override
    {
      access_.reset();
      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();
    }

    State::StateAccess &s() { return *access_; }
    State::StateDB &db() { return db_.db(); }

    // Rebuild the access at a specific version (height). Aborts the
    // current txn and opens a new one.
    void setVersion(uint64_t version)
    {
      access_.reset();
      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();

      txn_.emplace(db_.db().beginWrite());
      access_ = std::make_unique<State::StateAccess>(db_.db(), *txn_, version);
    }

    TempDB db_;
    std::optional<State::StateDB::Txn> txn_;
    std::unique_ptr<State::StateAccess> access_;
  };
}