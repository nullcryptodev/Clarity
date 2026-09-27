#pragma once

#include <gtest/gtest.h>

#include "Tests/Utils.h"

namespace Tests
{
  class Consensus_BftFixture : public testing::Test
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

  class Consensus_NetworkFixture : public testing::Test
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
}