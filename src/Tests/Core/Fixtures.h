#pragma once

#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include <gtest/gtest.h>

#include "Crypto/Blake2b.h"

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
        //  Leaf layout matches BlockProcessor::verifyReceiptsRoot:
        //    "rcpt" || txid(32) || Receipt::serializeState()
        //
        //  Receipt::serializeState() is
        //    status(1) || fee_paid(8 LE) || fill_count(4 LE) || fills
        //
        //  A receipt with no fills therefore contributes four extra
        //  zero bytes compared to the pre-fill layout. That is the
        //  change that made every block test fail the receipts_root
        //  check until this helper was updated to match.
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

    //  Build the payload bytes for a CreateOrder transaction.
    //
    //  Layout, matching TransactionExecutor::validateCreateOrderStructure
    //  and executeCreateOrder:
    //
    //    [4]  buy_token (LE)
    //    [8]  min_buy_amount (LE)
    //    [1]  mode
    //    [8]  expires_at_height (LE)
    //    [1]  condition_count
    //    [N]  conditions (13 bytes each)
    //
    //  This helper is intentionally separate from makeSignedCreateOrder
    //  so a test that wants to inspect or corrupt the payload can build
    //  it without building a full transaction.
    static std::vector<uint8_t> encodeCreateOrderPayload(
        Id buy_token,
        uint64_t min_buy_amount,
        Core::OrderExecutionMode mode,
        uint64_t expires_at_height)
    {
      std::vector<uint8_t> payload;
      payload.reserve(22);

      //  buy_token, u32 LE
      payload.push_back(uint8_t(buy_token));
      payload.push_back(uint8_t(buy_token >> 8));
      payload.push_back(uint8_t(buy_token >> 16));
      payload.push_back(uint8_t(buy_token >> 24));

      //  min_buy_amount, u64 LE
      for (int i = 0; i < 8; ++i)
        payload.push_back(uint8_t(min_buy_amount >> (i * 8)));

      //  mode, u8
      payload.push_back(static_cast<uint8_t>(mode));

      //  expires_at_height, u64 LE
      for (int i = 0; i < 8; ++i)
        payload.push_back(uint8_t(expires_at_height >> (i * 8)));

      //  condition_count, u8
      payload.push_back(0);

      return payload;
    }

    //  Build a signed CreateOrder transaction.
    //
    //  Parameter order mirrors the fields a caller usually thinks
    //  about: who is selling, what they are selling, for what, and
    //  under what conditions. The two token ids are named by the
    //  order's own frame (sell_token, buy_token), not the canonical
    //  pair frame; the executor handles the canonicalization.
    Core::Transaction makeSignedCreateOrder(
        const Crypto::KeyPair &from,
        Id sell_token, uint64_t sell_amount,
        Id buy_token, uint64_t min_buy_amount,
        Core::OrderExecutionMode mode,
        uint64_t expires_at_height,
        uint64_t nonce)
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
              buy_token, min_buy_amount, mode, expires_at_height))
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
      // Genesis validators are in the config.
      for (const auto &v : genesis_config_.validators)
      {
        if (v.id == id)
          return v.reward_address;
      }

      // Post-genesis validators (like the slash-test targets) are only
      // in state.
      Crypto::Address result;
      readState([&](State::StateAccess &s)
                {
        Core::ValidatorInfo v;
        if (s.getValidator(id, v))
          result = v.reward_address; });
      return result;
    }

    // ---- Real quorum signatures ----

    // Produces a set of quorum signatures over the block's hash,
    // signed by the given keypairs. `block` must already have its
    // final `commit_round`, `emergency_rotation`, `timeout_certificate`,
    // and `state_root` set — the signature covers the block hash,
    // which covers all of those.
    //
    // Signature i is produced by keys[i], and is tagged with
    // signer_index i. The caller is responsible for passing a key list
    // whose i-th entry corresponds to active_set[i]; that's what
    // BlockProcessor::checkQuorum verifies against.
    //
    // Empty key set: returns an empty signature list. bftQuorum(0)
    // evaluates to 1 by the formula, and the old code would then index
    // keys[0] on a zero-length vector. That was a segfault.
    std::vector<Crypto::ValidatorSignature>
    makeQuorumForBlock(const Core::Block &block,
                       const std::vector<Crypto::KeyPair> &keys)
    {
      if (keys.empty())
        return {};

      size_t needed = Core::bftQuorum(keys.size());

      //  Defensive: bftQuorum(n) can exceed n for pathological n
      //  (bftQuorum(0) = 1). The empty case is handled above; this
      //  cap protects against a future change to bftQuorum's formula
      //  that would make it exceed n for some small n > 0.
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

    //  Resolve the signing key for each active-set entry. Every
    //  validator in the set must have a key registered; a missing key
    //  produces a default-constructed KeyPair whose signature will
    //  fail verification. That's a loud failure at checkQuorum, which
    //  is where test bugs should surface.
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

    //  Build a valid timeout certificate for the given committed set,
    //  height, and round. Every vote is signed by the corresponding
    //  validator's registered key. Returns an empty certificate if
    //  the committed set is too small (< 4) — that's below the
    //  minimum verifyTimeoutCertificate will accept, so building one
    //  is a test bug, not a runtime failure. Callers that pass a
    //  too-small set will see isWellFormed reject the resulting
    //  block with the same "certificate empty" error they'd get for
    //  a genuinely missing certificate, which is a good enough
    //  failure mode.
    //
    //  Signer indices are positions in the committed set, matching
    //  what verifyTimeoutCertificate expects. Signer ids are the
    //  validator ids at those positions, matching Vote's convention.
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
    //
    //  `emergency_rotation` is set before simulation so that the
    //  dry-run applyBlock derives the same emergency active set the
    //  real application will. The certificate and its hash must be
    //  set before the quorum signatures are produced, because the
    //  block hash covers both, and the signatures cover the block
    //  hash.
    //
    //  `committed_set` is the set the certificate's signers are drawn
    //  from. For a non-emergency block it's ignored (no certificate
    //  is built). For an emergency block it MUST be the committed
    //  set, not the emergency set — the certificate is evidence that
    //  the committed set stalled, so its signatures come from the
    //  committed set. Passing the emergency set here would produce a
    //  certificate that verifyTimeoutCertificate rejects.
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

      //  Emergency certificate. Set before anything that reads the
      //  block hash (simulation, signing). A block with
      //  emergency_rotation > 0 but no certificate fails
      //  BlockHeader::isWellFormed, which is correct — the flag is a
      //  claim that needs evidence.
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

    //  Apply a pre-built block. Used by the emergency-rotation tests,
    //  which need to control the header's emergency_rotation field
    //  before application.
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

    // Register a non-seed validator with a known keypair so its
    // quorum signature can be produced by the fixture. Also inserts
    // the key into validator_keys_ so makeProcessableBlock can sign
    // for it.
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

    //  Register a pool candidate. Not active, but eligible to be
    //  promoted by the emergency rotation. The last_seen_height is
    //  set recent so the candidate passes isOffline() — a fresh
    //  registration is by definition online.
    void registerPoolValidator(Id id,
                               const Crypto::KeyPair &kp,
                               uint64_t stake = 1'000'000'000ULL)
    {
      registerValidatorWithKey(id, kp, stake,
                               /*is_seed=*/false, /*is_active=*/false);
    }

    //  Build a block for the two matching-engine tests. Runs a
    //  dry-run simulation to fill in the header's state_root and
    //  receipts_root, then re-signs so the quorum signatures cover
    //  the final header. The resulting block has a well-formed
    //  header and roots that match what the non-dry-run apply path
    //  will compute.
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

      //  Non-null placeholder roots so isWellFormed passes during
      //  simulation. They are overwritten below with the values the
      //  dry-run actually computes.
      block.header.state_root.data[0] = 0x01;

      //  Sign with the placeholder roots so the block hash is
      //  well-defined for the simulation. The signature is
      //  provisional and is replaced after the real roots are
      //  written in.
      block.quorum_signatures =
          makeQuorumForBlock(block, quorumKeysFor(active_set));

      //  Dry-run to compute the real roots. Aborts; nothing persists.
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

        txn.abort();
      }

      //  Re-sign: both roots are part of the block hash.
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
      v.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
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

  //  Member order matters: temp_ is declared first so it is
  //  destroyed last. state_ and txn_ must be destroyed before
  //  temp_'s destructor closes the DB, because StateAccess holds
  //  a StateDB::ReadTxn and a reference to txn_, and Txn holds a
  //  live MDBX_txn. If temp_ were declared last, its destructor
  //  would run first and close the env out from under the other
  //  two, which aborts inside MDBX.

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

      //  Fund both sides. Native CLRTY (id 0) lives in
      //  Account.balance; token 1 and token 2 live in the
      //  token-balance table.
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

      //  Two tokens. Token 1 is the pair's base (lower id),
      //  token 2 is the quote (higher id).
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

      //  Seed the sequence counter so the first test order gets
      //  sequence 1 and the second gets 2. Without an explicit
      //  seed, nextOrderSequence() reads 0 from a missing global
      //  and returns 1 on the first call; either way the tests
      //  below do not depend on the absolute value, only on the
      //  ordering, so leaving this comment is enough.
    }

    void TearDown() override
    {
      //  Destroy the txn-bound StateAccess first, so its
      //  ReadTxn (if any) is released. Then abort the txn if it is
      //  still open. Txn's destructor would abort anyway, but
      //  being explicit means a test failure inside a test body
      //  cannot leave a half-committed txn behind that confuses
      //  the next test.
      state_.reset();

      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();

      //  temp_ goes out of scope last and cleans up the DB
      //  directory. Its destructor calls db_->close() and
      //  remove_all(path_).
    }

    //  Build a Passive order. The caller is responsible for
    //  charging the sell-token lock separately when the test
    //  needs the lock to have been taken (which is what the real
    //  TransactionExecutor does before calling the matcher).
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

    //  Place a resting maker: persist the record, allocate a
    //  sequence, add to the book. Mirrors what TransactionExecutor
    //  does for a Passive order that did not cross.
    void restOrder(Order &o)
    {
      state_->putOrder(o);
      const uint64_t seq = state_->nextOrderSequence();
      state_->addToOrderBook(o, seq);
    }

    //  Debit the sell-token lock, mirroring TransactionExecutor's
    //  lock step. Tests that care about balance invariants call
    //  this; tests that only care about book mechanics can skip it.
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

    //  Sum of spendable + locked across all four accounts and both
    //  tokens. Used to assert the supply invariant after every
    //  fill. The test fixtures never mint or burn mid-test, so this
    //  is constant modulo fees, and the matcher charges no fee on a
    //  fill (only on cancellation).
    uint64_t totalSupply() const
    {
      uint64_t sum = 0;

      for (const auto &addr : {alice_, bob_, carol_, dave_})
      {
        //  Native
        sum += state_->getAccount(addr).balance;

        //  Tokens 1 and 2
        sum += state_->getTokenBalance(addr, 1);
        sum += state_->getTokenBalance(addr, 2);
      }

      //  Locked amounts live on the order records themselves.
      //  Every open order has (sell_amount - filled_amount) of its
      //  sell token still locked.
      state_->forEachOrder([&](const Order &o)
                           { sum += o.remainingAmount(); });

      return sum;
    }

    //  Member order is load-bearing. Do not reorder.
    TempDB temp_;
    std::unique_ptr<StateDB::Txn> txn_;
    std::unique_ptr<StateAccess> state_;

    Crypto::Address alice_;
    Crypto::Address bob_;
    Crypto::Address carol_;
    Crypto::Address dave_;
  };
}