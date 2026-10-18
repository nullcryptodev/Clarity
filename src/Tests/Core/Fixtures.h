#pragma once

#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include "Crypto/Blake2b.h"
#include "Crypto/Helpers.h"

#include "Core/BridgeTypes.h"
#include "Core/BridgeWatcherTypes.h"
#include "Core/GlobalState.h"

#include "TransactionBuilder.h"
#include "Utils.h"
#include "Tests/Temp.h"

using namespace Core;
using namespace State;
using namespace Tests;

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

      validator_keys_[1] = seed1_;
      validator_keys_[2] = seed2_;

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
      //  Release the lazy reader (and its autocommit read txn)
      //  before closing the DB. The reader holds a StateAccess
      //  referencing db_; if db_ is closed first, the reader's
      //  destructor releases a txn against a dead environment.
      state_reader_.reset();

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

      //  Both validators explicitly set the consensus key to their
      //  own public key. GenesisValidator's 5th field is
      //  `consensus_key`; the fixture sets it explicitly rather than
      //  letting applyGenesis fall back to `reward_address` — the
      //  fallback happens to produce the same value here (addressOf
      //  copies the public key), but the explicit assignment
      //  decouples the fixture's signing identity from whatever
      //  `addressOf` decides to return in the future.
      //
      //  The bridge tests sign with seed1_/seed2_; the fixture
      //  needs the on-chain consensus key at genesis to be exactly
      //  seed1_.publicKey / seed2_.publicKey so the mints, acks,
      //  and governance transactions all verify.
      cfg.validators.push_back({/*id=*/1,
                                /*reward_address=*/addressOf(seed1),
                                /*node_key=*/seed1.publicKey,
                                /*is_seed=*/true,
                                /*consensus_key=*/seed1.publicKey});
      cfg.validators.push_back({/*id=*/2,
                                /*reward_address=*/addressOf(seed2),
                                /*node_key=*/seed2.publicKey,
                                /*is_seed=*/true,
                                /*consensus_key=*/seed2.publicKey});

      cfg.initial_total_supply = INITIAL;
      cfg.initial_active_set_size = 2;

      //  Enable the bridge. Under the watcher model, applyGenesis
      //  registers the two seed validators as initial bridge
      //  watchers, writes the wrapped-CCX token, and writes the CCX
      //  chain registration. Without these two lines, every bridge
      //  test sees an empty bridge state ("chain registration not
      //  present") and every bridge transaction fails its first
      //  check.
      cfg.bridge.enabled = true;
      cfg.bridge.ccx_chain_id = Core::BRIDGE_CCX_CHAIN_ID;

      return cfg;
    }

    // ---- State access ----

    template <typename Fn>
    void withState(Fn &&fn)
    {
      state_reader_.reset();
      auto t = db_->beginWrite();
      State::StateAccess s(*db_, t, 0);
      fn(s);
      s.commit(/*version=*/0);
      t.commit();
    }

    template <typename Fn>
    void readState(Fn &&fn) const
    {
      state_reader_.reset();
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

    //  Balance of a non-native token. `balanceOf` reads
    //  Account::balance (native CLRTY); token balances live in
    //  the token-balance table and need their own accessor.
    //  Returns 0 if the address has never held the token (which
    //  is the correct default — a missing balance row is zero,
    //  not an error).
    uint64_t balanceOfToken(const Crypto::Address &addr, Id token_id) const
    {
      uint64_t result = 0;
      readState([&](State::StateAccess &s)
                { result = s.getTokenBalance(addr, token_id); });
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
      acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
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

    //  ---- Bridge test helpers ----

    Id wrappedCcxTokenId() const
    {
      Core::BridgeChainRegistration reg;
      bool found = false;
      readState([&](State::StateAccess &s)
                { found = s.getBridgeChainRegistration(
                      Core::BRIDGE_CCX_CHAIN_ID, reg); });
      EXPECT_TRUE(found) << "CCX chain registration not present";
      return static_cast<Id>(reg.wrapped_token_id);
    }

    void fundWrappedCcx(const Crypto::Address &addr, uint64_t amount)
    {
      const Id token_id = wrappedCcxTokenId();
      fundToken(addr, token_id, amount);
    }

    void fundToken(const Crypto::Address &addr,
                   Id token_id,
                   uint64_t amount)
    {
      withState([&](State::StateAccess &s)
                {
        const uint64_t cur = s.getTokenBalance(addr, token_id);
        s.putTokenBalance(addr, token_id, cur + amount);
        const uint64_t supply = s.getTokenSupply(token_id);
        s.putTokenSupply(token_id, supply + amount); });
    }

    //  A GlobalStateReader backed by an autocommit StateAccess.
    //
    //  Uses autocommit mode (StateAccess(db, version)) rather than
    //  txn-bound mode (StateAccess(db, txn, version)) because a
    //  txn-bound StateAccess requires a live write txn, and holding
    //  a write txn open for the fixture's lifetime blocks every
    //  other writer — including applyBlock's simulation, which
    //  opens its own write txn. Autocommit StateAccess holds a
    //  read txn internally; many readers coexist with one writer,
    //  so makeGlobalReader and applyBlock can both work in the
    //  same test.
    //
    //  This replaces the previous implementation, which bound a
    //  write txn into the reader and reliably deadlocked on the
    //  first test that both called makeGlobalReader and then
    //  called applyBlock.
    //
    //  Lifetime contract: the returned GlobalStateReader holds a
    //  reference to `*state_reader_`. If the caller does
    //  `auto r = makeGlobalReader();` and then opens a write txn
    //  before using `r`, the write throws (StateDB forbids it).
    //  In practice every caller uses the reader inline or
    //  immediately after, so the read txn is short-lived.
    //
    //  If a caller needs to interleave reads and writes, use
    //  readState() instead — it opens and closes its own txn
    //  around the callback, guaranteeing the reader's lifetime
    //  is bounded by the callback.
    Core::GlobalStateReader makeGlobalReader()
    {
      if (!state_reader_)
      {
        state_reader_ = std::make_unique<State::StateAccess>(*db_, 0);
      }
      return Core::GlobalStateReader(*state_reader_);
    }

    //  Sign a BridgeMint payload with the given (index, keypair)
    //  pairs. Returns the [2] count || N*66 signature block.
    //
    //  The `signers` argument is a vector of (active-set index,
    //  keypair) pairs. Under the watcher model the active watcher
    //  set for the CCX chain is the two seeds sorted by watcher id
    //  (which are 1 and 2, so positions 0 and 1). A quorum mint
    //  signs with {{0, seed1_}, {1, seed2_}}.
    std::vector<uint8_t> signBridgeMintMessage(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index,
        const Crypto::Address &destination,
        uint64_t amount,
        const std::vector<std::pair<uint16_t, Crypto::KeyPair>> &signers)
    {
      //  Build the canonical message the executor verifies against.
      std::vector<uint8_t> message;
      message.reserve(8 + 32 + 4 + 32 + 8);
      for (int i = 0; i < 8; ++i)
        message.push_back(uint8_t(source_chain_id >> (i * 8)));
      message.insert(message.end(),
                     source_tx_hash.data.begin(),
                     source_tx_hash.data.end());
      for (int i = 0; i < 4; ++i)
        message.push_back(uint8_t(source_output_index >> (i * 8)));
      message.insert(message.end(),
                     destination.data.begin(),
                     destination.data.end());
      for (int i = 0; i < 8; ++i)
        message.push_back(uint8_t(amount >> (i * 8)));

      //  Compute BOTH hashes — the one we'll sign, and the one we
      //  THINK the executor computes. If they differ, this is our bug.
      const Crypto::Hash fixture_hash =
          Crypto::hashDomain("bmin", message.data(), message.size());

      //  Emulate the executor's path: domain is std::string_view, then
      //  hashDomain(domain.data(), message, len).
      std::string_view domain_sv = "bmin";
      const Crypto::Hash executor_hash =
          Crypto::hashDomain(domain_sv.data(), message.data(), message.size());

      const Crypto::Hash signing_hash = fixture_hash;

      //  Encode the signature block: [2] count LE || N * [2 index || 64 sig].
      std::vector<uint8_t> block;
      const uint16_t count = static_cast<uint16_t>(signers.size());
      block.push_back(uint8_t(count));
      block.push_back(uint8_t(count >> 8));

      for (const auto &[idx, kp] : signers)
      {
        block.push_back(uint8_t(idx));
        block.push_back(uint8_t(idx >> 8));
        const Crypto::Signature sig =
            Crypto::sign(signing_hash, kp.secretKey);
        block.insert(block.end(), sig.data.begin(), sig.data.end());
      }
      return block;
    }

    //  Build a complete BridgeMint transaction.
    Transaction makeBridgeMintTx(
        const Crypto::KeyPair &submitter,
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index,
        const Crypto::Address &destination,
        uint64_t amount,
        const std::vector<uint8_t> &signature_block,
        uint64_t nonce)
    {
      std::vector<uint8_t> payload;
      payload.reserve(8 + 32 + 4 + 32 + 8 + signature_block.size());

      for (int i = 0; i < 8; ++i)
        payload.push_back(uint8_t(source_chain_id >> (i * 8)));
      payload.insert(payload.end(),
                     source_tx_hash.data.begin(),
                     source_tx_hash.data.end());
      for (int i = 0; i < 4; ++i)
        payload.push_back(uint8_t(source_output_index >> (i * 8)));
      payload.insert(payload.end(),
                     destination.data.begin(),
                     destination.data.end());
      for (int i = 0; i < 8; ++i)
        payload.push_back(uint8_t(amount >> (i * 8)));
      payload.insert(payload.end(),
                     signature_block.begin(),
                     signature_block.end());

      return TransactionBuilder()
          .type(Core::TxType::BridgeMint)
          .from(submitter)
          .to(Crypto::Address{})
          .amount(0)
          .fee(1)
          .nonce(nonce)
          .tokenId(NATIVE_TOKEN_ID)
          .chainId(genesis_config_.chain_id)
          .payload(std::move(payload))
          .build();
    }

    //  Build a BridgeBurn transaction.
    Transaction makeBridgeBurnTx(
        const Crypto::KeyPair &from,
        uint64_t source_chain_id,
        const std::vector<uint8_t> &destination_blob,
        uint64_t amount,
        Id wrapped_token_id,
        uint64_t nonce)
    {
      std::vector<uint8_t> payload;
      payload.reserve(8 + 1 + destination_blob.size() + 8);

      for (int i = 0; i < 8; ++i)
        payload.push_back(uint8_t(source_chain_id >> (i * 8)));
      payload.push_back(static_cast<uint8_t>(destination_blob.size()));
      payload.insert(payload.end(),
                     destination_blob.begin(),
                     destination_blob.end());
      for (int i = 0; i < 8; ++i)
        payload.push_back(uint8_t(amount >> (i * 8)));

      return TransactionBuilder()
          .type(Core::TxType::BridgeBurn)
          .from(from)
          .to(Crypto::Address{})
          .amount(0)
          .fee(1)
          .nonce(nonce)
          .tokenId(wrapped_token_id)
          .chainId(genesis_config_.chain_id)
          .payload(std::move(payload))
          .build();
    }

    //  Set a validator's last_seen_height directly. Used by the
    //  emergency-rotation tests to make a validator "offline" without
    //  having to mine 20 blocks.
    void setValidatorLastSeen(Id id, uint64_t last_seen)
    {
      withState([&](State::StateAccess &s)
                {
        Core::ValidatorInfo v;
        if (s.getValidator(id, v))
        {
          v.last_seen_height = last_seen;
          s.putValidator(v);
        } });
    }

    //  Set a validator's is_active flag directly. Used when a test
    //  needs a pool candidate (is_active = false) that the emergency
    //  derivation can promote.
    void setValidatorActive(Id id, bool active)
    {
      withState([&](State::StateAccess &s)
                {
        Core::ValidatorInfo v;
        if (s.getValidator(id, v))
        {
          v.is_active = active;
          s.putValidator(v);
        } });
    }

    // Set a validator's pending_unbond_height directly. Used by the
    // unbonding tests to construct a pending-unbond validator without
    // running the full unregister path.
    void setValidatorPendingUnbond(Id id, uint64_t pending_height)
    {
      withState([&](State::StateAccess &s)
                {
    Core::ValidatorInfo v;
    if (s.getValidator(id, v))
    {
      v.pending_unbond_height = pending_height;
      s.putValidator(v);
    } });
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
        const auto receipt_bytes = receipts[i].serializeState();

        std::vector<uint8_t> buf;
        buf.reserve(4 + 32 + receipt_bytes.size());
        buf.push_back('r');
        buf.push_back('c');
        buf.push_back('p');
        buf.push_back('t');

        const auto &th = tx_hashes[i];
        buf.insert(buf.end(), th.data.begin(), th.data.end());
        buf.insert(buf.end(), receipt_bytes.begin(), receipt_bytes.end());

        Crypto::Hash h;
        Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
        leaves.push_back(h);
      }

      return Core::computeMerkleRoot(leaves);
    }

    static Crypto::Hash computeEpochFillsRootForTest(
        const std::vector<Core::Fill> &fills)
    {
      return Core::BlockProcessor::computeEpochFillsRoot(fills);
    }

    // ---- Transaction helpers ----

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

    static std::vector<uint8_t> encodeCreateOrderPayload(
        Id buy_token,
        uint64_t min_buy_amount,
        Core::OrderExecutionMode mode,
        uint32_t pool_id,
        uint64_t expires_at_height)
    {
      std::vector<uint8_t> payload;
      payload.reserve(26);

      payload.push_back(uint8_t(buy_token));
      payload.push_back(uint8_t(buy_token >> 8));
      payload.push_back(uint8_t(buy_token >> 16));
      payload.push_back(uint8_t(buy_token >> 24));

      for (int i = 0; i < 8; ++i)
        payload.push_back(uint8_t(min_buy_amount >> (i * 8)));

      payload.push_back(static_cast<uint8_t>(mode));

      payload.push_back(uint8_t(pool_id));
      payload.push_back(uint8_t(pool_id >> 8));
      payload.push_back(uint8_t(pool_id >> 16));
      payload.push_back(uint8_t(pool_id >> 24));

      for (int i = 0; i < 8; ++i)
        payload.push_back(uint8_t(expires_at_height >> (i * 8)));

      payload.push_back(0);

      return payload;
    }

    Core::Transaction makeSignedCreateOrder(
        const Crypto::KeyPair &from,
        Id sell_token, uint64_t sell_amount,
        Id buy_token, uint64_t min_buy_amount,
        Core::OrderExecutionMode mode,
        uint64_t expires_at_height,
        uint64_t nonce,
        uint32_t pool_id = 0)
    {
      return TransactionBuilder()
          .type(Core::TxType::CreateOrder)
          .from(from)
          .to(Crypto::Address{})
          .amount(sell_amount)
          .fee(1)
          .nonce(nonce)
          .tokenId(sell_token)
          .chainId(genesis_config_.chain_id)
          .payload(encodeCreateOrderPayload(
              buy_token, min_buy_amount, mode, pool_id, expires_at_height))
          .build();
    }

    // ---- Header ----

    Core::BlockHeader makeBlockHeaderSkeleton(uint64_t height,
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
      h.emergency_rotation = 0;
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

      Crypto::Address result;
      readState([&](State::StateAccess &s)
                {
        Core::ValidatorInfo v;
        if (s.getValidator(id, v))
          result = v.reward_address; });
      return result;
    }

    // ---- Real quorum signatures ----

    std::vector<Crypto::ValidatorSignature>
    makeQuorumForBlock(const Core::Block &block,
                       const std::vector<Crypto::KeyPair> &keys)
    {
      if (keys.empty())
        return {};

      size_t needed = Core::bftQuorum(keys.size());

      if (needed > keys.size())
        needed = keys.size();

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

    std::vector<Crypto::KeyPair> quorumKeysFor(
        const std::vector<Id> &active_set)
    {
      std::vector<Crypto::KeyPair> quorum_keys;
      quorum_keys.reserve(active_set.size());
      for (Id vid : active_set)
      {
        auto it = validator_keys_.find(vid);
        quorum_keys.push_back(it != validator_keys_.end()
                                  ? it->second
                                  : Crypto::KeyPair{});
      }
      return quorum_keys;
    }

    // ---- Timeout certificate builder ----

    Consensus::TimeoutCertificate makeTimeoutCertificate(
        const std::vector<Id> &committed_set,
        uint64_t height,
        uint64_t round)
    {
      Consensus::TimeoutCertificate cert;

      const size_t n = committed_set.size();
      if (n < 4)
        return cert;

      const size_t f = (n - 1) / 3;
      const size_t required = f + 1;

      const Crypto::Hash signing_hash =
          Consensus::timeoutVoteSigningHash(height, round);

      for (size_t i = 0; i < required; ++i)
      {
        const Id vid = committed_set[i];
        auto it = validator_keys_.find(vid);
        if (it == validator_keys_.end())
          continue;

        Consensus::TimeoutVote tv;
        tv.height = height;
        tv.round = round;
        tv.signer_index = static_cast<Index>(i);
        tv.signer_id = vid;
        tv.signature = Crypto::sign(signing_hash, it->second.secretKey);
        cert.votes.push_back(tv);
      }

      return cert;
    }

    // ---- Block builder ----

    Core::Block makeProcessableBlock(uint64_t height,
                                     const Crypto::Hash &parent,
                                     const std::vector<Core::Transaction> &txs,
                                     const std::vector<Id> &active_set,
                                     uint64_t emergency_rotation = 0,
                                     const std::vector<Id> &committed_set = {})
    {
      Core::Block b;
      b.header = makeBlockHeaderSkeleton(height, parent, active_set);
      b.header.emergency_rotation = emergency_rotation;
      b.transactions = txs;
      b.header.tx_count = static_cast<uint32_t>(txs.size());
      b.header.active_validator_count =
          static_cast<uint32_t>(active_set.size());

      if (emergency_rotation > 0)
      {
        const std::vector<Id> &cert_set =
            committed_set.empty() ? active_set : committed_set;
        b.header.timeout_certificate =
            makeTimeoutCertificate(cert_set, height, emergency_rotation);
        b.header.timeout_certificate_hash =
            Core::computeTimeoutCertificateHash(b.header.timeout_certificate);
      }

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

      b.header.state_root.data[0] = 0x01;

      Crypto::Hash sim_state_root;
      std::vector<Core::Receipt> sim_receipts;
      std::vector<Crypto::Hash> sim_tx_hashes;
      std::vector<Core::Fill> sim_epoch_fills;
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
        sim_epoch_fills = sim_result.epoch_fills;

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

      b.header.epoch_fills_root =
          Core::BlockProcessor::computeEpochFillsRoot(sim_epoch_fills);

      b.quorum_signatures = makeQuorumForBlock(b, quorumKeysFor(active_set));

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
      return applyPrebuiltBlock(b, dry_run);
    }

    Core::BlockResult applyBlock(uint64_t height,
                                 const Crypto::Hash &parent,
                                 const std::vector<Core::Transaction> &txs,
                                 bool dry_run,
                                 const std::vector<Id> &active_set)
    {
      Core::Block b = makeProcessableBlock(height, parent, txs, active_set);
      return applyPrebuiltBlock(b, dry_run);
    }

    Core::BlockResult applyPrebuiltBlock(const Core::Block &b,
                                         bool dry_run = false)
    {
      Core::BlockContext ctx = makeContext(b.header.height, dry_run);

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

    void registerValidatorWithKey(Id id,
                                  const Crypto::KeyPair &kp,
                                  uint64_t stake = 1'000'000'000ULL,
                                  bool is_seed = false,
                                  bool is_active = true)
    {
      Crypto::Address addr = addressOf(kp);

      Core::ValidatorInfo v;
      v.id = id;
      v.reward_address = addr;
      v.owner = addr;
      v.stake = stake;
      v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
      v.uptime_score = 10'000;
      v.registered_at_height = 1;
      v.last_seen_height = 1;
      v.is_seed = is_seed;
      v.is_active = is_active;

      withState([&](State::StateAccess &s)
                {
        s.putValidator(v);
        s.putValidatorByAddress(addr, id); });

      validator_keys_[id] = kp;
    }

    void registerPoolValidator(Id id,
                               const Crypto::KeyPair &kp,
                               uint64_t stake = 1'000'000'000ULL)
    {
      registerValidatorWithKey(id, kp, stake,
                               /*is_seed=*/false, /*is_active=*/false);
    }

    Core::Block buildSignedBlockForTest(
        uint64_t height,
        const Crypto::Hash &parent,
        const std::vector<Core::Transaction> &txs,
        const std::vector<Id> &active_set)
    {
      Core::Block block;
      block.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
      block.header.chain_id = genesis_config_.chain_id;
      block.header.height = height;
      block.header.parent_hash = parent;
      block.header.timestamp_ms = 1'700'000'000'000ULL + height * 1000;
      block.header.proposer =
          active_set.empty() ? Crypto::Address{}
                             : validatorAddress(active_set[0]);
      block.header.epoch = height / Core::ROTATION_INTERVAL;
      block.header.rotation_index = height / Core::ROTATION_INTERVAL;
      block.header.commit_round = 0;
      block.header.emergency_rotation = 0;
      block.header.tx_root = computeTxRoot(txs);
      block.header.validator_set_root =
          Core::computeValidatorSetRoot(active_set);
      block.header.total_fees = 0;
      for (const auto &tx : txs)
      {
        if (!isSystemTx(tx.tx_type))
          block.header.total_fees += tx.fee;
      }
      block.header.tx_count = static_cast<uint32_t>(txs.size());
      block.header.active_validator_count =
          static_cast<uint32_t>(active_set.size());

      block.transactions = txs;
      block.participants = active_set;

      block.header.state_root.data[0] = 0x01;
      block.header.epoch_fills_root.data[0] = 0x01;

      block.quorum_signatures =
          makeQuorumForBlock(block, quorumKeysFor(active_set));

      {
        auto txn = db_->beginWrite();
        State::StateAccess st(*db_, txn, 0);

        Core::BlockContext ctx = makeContext(height, /*dry_run=*/true);
        Core::BlockResult r =
            Core::BlockProcessor::applyBlock(st, block, ctx);

        EXPECT_TRUE(r.valid) << "dry-run failed: " << r.error;

        block.header.state_root = r.new_state_root;

        if (!r.tx_hashes.empty())
        {
          block.header.receipts_root =
              computeReceiptsRootForTest(r.tx_hashes, r.receipts);
        }
        else
        {
          block.header.receipts_root = Crypto::Hash{};
        }

        block.header.epoch_fills_root =
            Core::BlockProcessor::computeEpochFillsRoot(r.epoch_fills);

        txn.abort();
      }

      block.quorum_signatures =
          makeQuorumForBlock(block, quorumKeysFor(active_set));

      return block;
    }

    // ---- Members ----

    std::filesystem::path test_dir_;
    std::unique_ptr<State::StateDB> db_;

    Crypto::KeyPair alice_;
    Crypto::KeyPair bob_;
    Crypto::KeyPair carol_;
    Crypto::KeyPair seed1_;
    Crypto::KeyPair seed2_;

    std::unordered_map<Id, Crypto::KeyPair> validator_keys_;

    Core::GenesisConfig genesis_config_;
    Crypto::Hash genesis_hash_;

    //  Lazy reader. Holds an autocommit read txn; destroyed at
    //  TearDown (before db_ closes) and can be reset between reads
    //  if a test needs to interleave reads and writes. See
    //  makeGlobalReader for the full lifetime contract.
    mutable std::unique_ptr<State::StateAccess> state_reader_;
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
      acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
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

    void setTokenBalance(const Crypto::Address &addr,
                         Id token,
                         uint64_t amount)
    {
      state_->putTokenBalance(addr, token, amount);
    }

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

    void seedValidator(const Crypto::KeyPair &owner,
                       uint64_t id,
                       bool is_seed = false,
                       bool is_active = false)
    {
      Core::ValidatorInfo v;
      v.id = id;
      v.reward_address = owner.publicKey;
      v.owner = owner.publicKey;
      v.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
      v.registered_at_height = 1;
      v.uptime_score = 10'000;
      v.is_seed = is_seed;
      v.is_active = is_active;
      state_->putValidator(v);
      state_->putValidatorByAddress(owner.publicKey, id);
    }

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

    void bumpNextValidatorId(uint64_t next)
    {
      std::vector<uint8_t> bytes(8);
      for (int i = 0; i < 8; ++i)
        bytes[i] = uint8_t(next >> (i * 8));
      state_->putGlobal("next_validator_id", bytes);
    }

    void setPendingRewards(const Crypto::Address &addr, uint64_t amount)
    {
      Core::Account acct = state_->getAccount(addr);
      acct.pending_rewards = amount;
      acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
      state_->putAccount(addr, acct);
    }

    std::unique_ptr<State::StateDB> db_;
    std::optional<State::StateDB::Txn> txn_;
    std::unique_ptr<State::StateAccess> state_;
    Crypto::KeyPair alice_;
    Crypto::KeyPair bob_;
    Crypto::KeyPair carol_;
  };

  class Core_MatchingEngineTest : public testing::Test
  {
  protected:
    void SetUp() override
    {
      txn_ = std::make_unique<StateDB::Txn>(temp_.db().beginWrite());
      state_ = std::make_unique<StateAccess>(
          temp_.db(), *txn_, /*version=*/1);

      alice_ = makeAddress(0xA1);
      bob_ = makeAddress(0xB0);
      carol_ = makeAddress(0xC0);
      dave_ = makeAddress(0xD0);

      Account a;
      a.balance = 1'000'000;
      state_->putAccount(alice_, a);

      Account b;
      b.balance = 1'000'000;
      state_->putAccount(bob_, b);

      Account c;
      c.balance = 1'000'000;
      state_->putAccount(carol_, c);

      Account d;
      d.balance = 1'000'000;
      state_->putAccount(dave_, d);

      TokenInfo t1;
      t1.id = 1;
      t1.symbol = "T1";
      t1.decimals = 8;
      t1.maxSupply = 0;
      state_->putToken(t1);

      TokenInfo t2;
      t2.id = 2;
      t2.symbol = "T2";
      t2.decimals = 8;
      t2.maxSupply = 0;
      state_->putToken(t2);

      state_->putTokenBalance(alice_, 1, 1'000'000);
      state_->putTokenBalance(bob_, 1, 1'000'000);
      state_->putTokenBalance(carol_, 1, 1'000'000);
      state_->putTokenBalance(dave_, 1, 1'000'000);

      state_->putTokenBalance(alice_, 2, 1'000'000);
      state_->putTokenBalance(bob_, 2, 1'000'000);
      state_->putTokenBalance(carol_, 2, 1'000'000);
      state_->putTokenBalance(dave_, 2, 1'000'000);
    }

    void TearDown() override
    {
      state_.reset();

      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();
    }

    Order makeOrder(Id id, const Crypto::Address &owner,
                    uint32_t sell, uint32_t buy,
                    uint64_t sell_amount, uint64_t min_buy_amount)
    {
      Order o;
      o.id = id;
      o.owner = owner;
      o.mode = OrderExecutionMode::Passive;
      o.sell_token = sell;
      o.buy_token = buy;
      o.sell_amount = sell_amount;
      o.min_buy_amount = min_buy_amount;
      o.created_at_height = 1;
      o.order_expires_at_height = 0;
      o.filled_amount = 0;
      o.condition_count = 0;
      return o;
    }

    void restOrder(Order &o)
    {
      state_->putOrder(o);
      const uint64_t seq = state_->nextOrderSequence();
      state_->addToOrderBook(o, seq);
    }

    void lockSellToken(const Crypto::Address &owner,
                       uint32_t sell_token,
                       uint64_t amount)
    {
      if (sell_token == NATIVE_TOKEN_ID)
      {
        Account a = state_->getAccount(owner);
        a.balance -= amount;
        state_->putAccount(owner, a);
      }
      else
      {
        const uint64_t cur = state_->getTokenBalance(owner, sell_token);
        state_->putTokenBalance(owner, sell_token, cur - amount);
      }
    }

    uint64_t totalSupply() const
    {
      uint64_t sum = 0;

      for (const auto &addr : {alice_, bob_, carol_, dave_})
      {
        sum += state_->getAccount(addr).balance;
        sum += state_->getTokenBalance(addr, 1);
        sum += state_->getTokenBalance(addr, 2);
      }

      state_->forEachOrder([&](const Order &o)
                           { sum += o.remainingAmount(); });

      return sum;
    }

    TempDB temp_{1ULL * 1024 * 1024 * 1024};
    std::unique_ptr<StateDB::Txn> txn_;
    std::unique_ptr<StateAccess> state_;

    Crypto::Address alice_;
    Crypto::Address bob_;
    Crypto::Address carol_;
    Crypto::Address dave_;
  };
}