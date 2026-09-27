#pragma once

#include <gtest/gtest.h>

#include "Crypto/Blake2b.h"

#include "Tests/Utils.h"

namespace Tests
{
  class Core_BlockProcessorFixture : public testing::Test
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

      // Set a placeholder state_root so the header passes isWellFormed
      // during simulation. It will be overwritten with the simulation
      // result if the simulation succeeds.
      b.header.state_root.data[0] = 0x01;

      Crypto::Hash sim_state_root;
      std::vector<Core::Receipt> sim_receipts;
      std::vector<Crypto::Hash> sim_tx_hashes;
      bool sim_valid = false;

      {
        auto sim_txn = db_->beginWrite();
        State::StateAccess sim_state(*db_, sim_txn, 0);

        Core::BlockContext sim_ctx = makeContext(height, /*dry_run=*/true);
        Core::BlockResult sim_result =
            Core::BlockProcessor::applyBlock(sim_state, b, sim_ctx);

        sim_valid = sim_result.valid;
        sim_state_root = sim_result.new_state_root;
        sim_receipts = sim_result.receipts;
        sim_tx_hashes = sim_result.tx_hashes;

        // If the simulation failed, use the state root *before* the txs
        // ran. This produces a block whose header is well-formed and
        // whose state_root matches the pre-tx state. When the caller
        // applies the block for real, the block processor will re-run
        // the failing txs and hit the same failure, returning the
        // original error ("transaction failed at index N").
        if (!sim_valid)
        {
          sim_state_root = sim_state.stateRoot();
        }

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

  class Core_ChainFixture : public testing::Test
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

  class Core_MempoolFixture : public testing::Test
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

  // Core_ExecutorFixture
  // One MDBX write txn per test. All state writes go through the
  // txn-bound StateAccess. TearDown aborts — nothing persists between
  // tests, and the test runs in one txn (fast).

  class Core_ExecutorFixture : public testing::Test
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
}