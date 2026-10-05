#pragma once

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "Consensus/BftConsensus.h"

#include "Core/Block.h"
#include "Core/Genesis.h"
#include "Core/ValidatorTypes.h"

#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"

#include "GlobalConfig.h"
#include "Logging/LoggerRef.h"

namespace Tests
{
  struct Envelope
  {
    enum Kind
    {
      Proposal = 0x11,
      Prevote = 0x22,
      Precommit = 0x33,
      TimeoutVote = 0x44,
      Restart = 0x55,
    } kind{Proposal};

    size_t from{0};
    size_t to{0};
    Consensus::Proposal proposal{};
    Consensus::Vote vote{};
    Consensus::TimeoutVote timeout_vote{};
    Height restart_height{0};

    bool is_emergency{false};
  };

  //  TestValidator
  //
  //  Key derivation MUST match Fixtures.h's deterministicValidatorKey():
  //  secretKey.data[i] = 0x80 + validator_id + i
  struct TestValidator
  {
    Id id{0};
    Crypto::KeyPair kp{};
    Crypto::Address address{};

    static TestValidator make(Id id)
    {
      TestValidator v;
      v.id = id;

      for (size_t i = 0; i < v.kp.secretKey.data.size(); ++i)
        v.kp.secretKey.data[i] = static_cast<uint8_t>(0x80 + id + i);

      v.kp.publicKey = Crypto::derivePublicKey(v.kp.secretKey);
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

  //  ConsensusTestEnv
  //
  //  Two modes: stub (default) and node-backed (via attachNodeBackend).
  //  See Fixtures.h for the node end-to-end usage.
  class ConsensusTestEnv
  {
  public:
    //  Per-index backend. All callbacks are optional. When present,
    //  they replace the env's stub behavior for that index. This is
    //  what makes a node end-to-end test see its node's real chain
    //  state instead of the in-memory test-validator list.
    struct NodeBackend
    {
      //  Resolve the active set for a given force_rotation flag. In
      //  node-backed mode this must delegate to Core::resolveActiveSet
      //  against the node's state DB at the node's current height,
      //  matching what BlockProcessor::applyBlock derives when it
      //  validates an emergency block. If this doesn't match, the
      //  emergency proposal's active_validator_count and
      //  validator_set_root will disagree with the state, and the
      //  simulation will reject the block.
      std::function<std::vector<Id>(bool force_rotation)> active_set;

      std::function<std::optional<Crypto::Hash>(const Core::Block &)>
          simulate_block;
      std::function<Crypto::Hash()> parent_hash;
      std::function<bool(Id, Core::ValidatorInfo &)> lookup_validator;
    };

    ConsensusTestEnv() = default;
    ~ConsensusTestEnv() = default;

    ConsensusTestEnv(const ConsensusTestEnv &) = delete;
    ConsensusTestEnv &operator=(const ConsensusTestEnv &) = delete;
    ConsensusTestEnv(ConsensusTestEnv &&) = delete;
    ConsensusTestEnv &operator=(ConsensusTestEnv &&) = delete;

    //  ---- Validator set ----

    void overrideValidator(size_t index, const Crypto::KeyPair &consensus_kp,
                           const Crypto::Address &reward_address)
    {
      validators_[index].kp = consensus_kp;
      validators_[index].address = reward_address;
    }

    void makeValidators(size_t n)
    {
      validators_.clear();
      validators_.reserve(n);
      for (size_t i = 0; i < n; ++i)
        validators_.push_back(TestValidator::make(static_cast<Id>(i + 1)));

      if (!active_ids_explicit_)
      {
        active_ids_.clear();
        for (const auto &v : validators_)
          active_ids_.push_back(v.id);
      }
    }

    void setActiveIds(std::vector<Id> ids)
    {
      active_ids_ = std::move(ids);
      active_ids_explicit_ = true;
    }

    const std::vector<TestValidator> &validators() const
    {
      return validators_;
    }

    std::vector<TestValidator> &validators()
    {
      return validators_;
    }

    const TestValidator &validator(size_t i) const
    {
      return validators_[i];
    }

    std::vector<Id> activeIds() const
    {
      if (!active_ids_.empty())
        return active_ids_;
      std::vector<Id> ids;
      ids.reserve(validators_.size());
      for (const auto &v : validators_)
        ids.push_back(v.id);
      return ids;
    }

    //  ---- Emergency set ----
    //
    //  Stub-mode only. Node-backed mode uses the per-index backend's
    //  active_set callback instead, which derives the emergency set
    //  from the node's state.

    void setEmergencyIds(std::vector<Id> ids)
    {
      emergency_ids_ = std::move(ids);
    }

    const std::vector<Id> &emergencyIds() const
    {
      return emergency_ids_;
    }

    //  ---- Network identity and clock ----

    void setChainId(uint64_t v) { chain_id_ = v; }
    uint64_t chainId() const { return chain_id_; }

    void setParentHash(const Crypto::Hash &h) { parent_hash_ = h; }
    const Crypto::Hash &parentHash() const { return parent_hash_; }

    void setNowMs(uint64_t v) { now_ms_ = v; }
    uint64_t nowMs() const { return now_ms_; }

    void setCurrentHeight(Height h) { current_height_ = h; }
    Height currentHeight() const { return current_height_; }

    //  ---- Per-index node backends ----

    void attachNodeBackend(size_t index, NodeBackend backend)
    {
      backends_[index] = std::move(backend);
    }

    //  ---- Per-instance callbacks ----

    std::function<void(const Consensus::Proposal &)> on_proposal;
    std::function<void(const Consensus::Vote &)> on_prevote;
    std::function<void(const Consensus::Vote &)> on_precommit;
    std::function<void(const Consensus::TimeoutVote &)> on_timeout_vote;
    std::function<std::vector<Core::Transaction>(uint64_t, uint64_t)>
        select_transactions;
    std::function<void(const Core::Block &)> on_block_committed;
    std::function<void(Height)> on_height_advanced;

    //  ---- Builders ----

    Consensus::Dependencies makeDeps(size_t local_index)
    {
      Consensus::Dependencies deps;

      deps.my_validator_id = [this, local_index]() -> Id
      {
        if (local_index == SIZE_MAX || local_index >= validators_.size())
          return INVALID_ID;
        return validators_[local_index].id;
      };

      deps.sign = [this, local_index](const Crypto::Hash &h)
          -> Crypto::Signature
      {
        if (local_index == SIZE_MAX || local_index >= validators_.size())
          return Crypto::Signature{};
        return validators_[local_index].sign(h);
      };

      deps.current_height = [this]() -> Height
      { return current_height_; };

      //  Active set. If the caller attached a per-index backend,
      //  route through it — that gives the node's real state-derived
      //  view, which is what BlockProcessor uses when validating
      //  emergency blocks. Otherwise fall back to the in-memory
      //  stub list.
      deps.active_set = [this, local_index](bool force_rotation) -> std::vector<Id>
      {
        auto it = backends_.find(local_index);
        if (it != backends_.end() && it->second.active_set)
          return it->second.active_set(force_rotation);

        if (force_rotation && !emergency_ids_.empty())
          return emergency_ids_;
        return activeIds();
      };

      deps.chain_id = [this]() -> uint64_t
      { return chain_id_; };

      deps.parent_hash = [this, local_index]() -> Crypto::Hash
      {
        auto it = backends_.find(local_index);
        if (it != backends_.end() && it->second.parent_hash)
          return it->second.parent_hash();
        return parent_hash_;
      };

      deps.simulate_block =
          [this, local_index](const Core::Block &b)
          -> std::optional<Crypto::Hash>
      {
        auto it = backends_.find(local_index);
        if (it != backends_.end() && it->second.simulate_block)
          return it->second.simulate_block(b);
        return b.header.state_root;
      };

      deps.my_address = [this, local_index]() -> Crypto::Address
      {
        if (local_index == SIZE_MAX || local_index >= validators_.size())
          return Crypto::Address{};
        return validators_[local_index].address;
      };

      deps.now_ms = [this]() -> uint64_t
      { return now_ms_; };

      deps.state_lookup_validator =
          [this, local_index](Id id, Core::ValidatorInfo &out) -> bool
      {
        auto it = backends_.find(local_index);
        if (it != backends_.end() && it->second.lookup_validator)
          return it->second.lookup_validator(id, out);

        for (const auto &v : validators_)
        {
          if (v.id == id)
          {
            out.id = id;
            std::memcpy(out.reward_address.data.data(),
                        v.address.data.data(), 32);
            out.owner = out.reward_address;
            out.consensus_key = v.pubkey();
            out.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
            out.uptime_score = 10'000;
            out.is_active = true;
            out.is_seed = true;
            return true;
          }
        }
        return false;
      };

      return deps;
    }

    Consensus::Callbacks makeCallbacks() const
    {
      Consensus::Callbacks cb;
      cb.broadcast_proposal = on_proposal;
      cb.broadcast_prevote = on_prevote;
      cb.broadcast_precommit = on_precommit;
      cb.broadcast_timeout_vote = on_timeout_vote;
      cb.select_transactions = select_transactions;
      cb.on_block_committed = on_block_committed;
      cb.on_height_advanced = on_height_advanced;
      return cb;
    }

    //  ---- Test helpers ----

    Consensus::Proposal proposeFromProposer(size_t proposer_index,
                                            Height height,
                                            Round round,
                                            const Core::Block &block) const
    {
      Consensus::Proposal p;
      p.height = height;
      p.round = round;
      p.signer_index = static_cast<Index>(proposer_index);
      p.signer_id = validators_[proposer_index].id;
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
                                   const Crypto::Hash &block_hash = Crypto::Hash{}) const
    {
      Consensus::Vote v;
      v.height = height;
      v.round = round;
      v.signer_index = static_cast<Index>(signer_index);
      v.signer_id = validators_[signer_index].id;
      v.is_nil = is_nil;
      v.block_hash = block_hash;

      Crypto::Hash signing_hash =
          Consensus::voteSigningHash(height, round, is_nil, block_hash);
      v.signature = validators_[signer_index].sign(signing_hash);
      return v;
    }

    Crypto::Signature signForValidator(Index signer_index,
                                       const Crypto::Hash &hash) const
    {
      if (signer_index >= validators_.size())
        return Crypto::Signature{};
      return validators_[signer_index].sign(hash);
    }

    Consensus::TimeoutVote makeTimeoutVote(Index signer_index,
                                           Height height,
                                           Round round) const
    {
      const Crypto::Hash signing_hash =
          Consensus::timeoutVoteSigningHash(height, round);

      Consensus::TimeoutVote tv;
      tv.height = height;
      tv.round = round;
      tv.signer_index = signer_index;
      if (signer_index < validators_.size())
        tv.signer_id = validators_[signer_index].id;
      tv.signature = signForValidator(signer_index, signing_hash);
      return tv;
    }

  private:
    std::vector<TestValidator> validators_;
    std::vector<Id> active_ids_;
    std::vector<Id> emergency_ids_;
    std::unordered_map<size_t, NodeBackend> backends_;

    bool active_ids_explicit_{false};
    uint64_t chain_id_{0x434C5247};
    Crypto::Hash parent_hash_{};
    uint64_t now_ms_{1'700'000'000'000ULL};
    Height current_height_{0};
  };
}