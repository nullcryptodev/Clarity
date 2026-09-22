// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

#include "Message.h"
#include "Types.h"
#include "ProposerSelection.h"

#include "Common/RoundTimer.h"

#include "Core/Block.h"
#include "Core/ValidatorTypes.h"
#include "Crypto/Types.h"

#include "Logging/LoggerRef.h"

namespace Consensus
{
  struct Callbacks
  {
    std::function<void(const Proposal &)> broadcast_proposal;

    // Prevotes and precommits are distinct message types on the wire.
    // The callbacks are split so the caller (the node) can tag the
    // outbound P2P message with the correct type. A single
    // broadcast_vote(Vote) callback would lose the distinction at the
    // boundary — the Vote struct carries no type field, because the
    // wire format doesn't need one when the message type is carried
    // alongside.
    std::function<void(const Vote &)> broadcast_prevote;
    std::function<void(const Vote &)> broadcast_precommit;

    std::function<std::vector<Core::Transaction>(uint64_t max_bytes,
                                                 uint64_t max_txs)>
        select_transactions;

    std::function<void(const Core::Block &)> on_block_committed;
    std::function<void(Height)> on_height_advanced;
  };

  struct Dependencies
  {
    std::function<Id()> my_validator_id;
    std::function<Crypto::Signature(const Crypto::Hash &)> sign;
    std::function<Height()> current_height;
    std::function<std::vector<Id>()> active_set;

    std::function<std::optional<Crypto::PublicKey>(Index)> signer_public_key;

    std::function<uint64_t()> chain_id;
    std::function<Crypto::Hash()> parent_hash;
    std::function<std::optional<Crypto::Hash>(const Core::Block &)> simulate_block;
    std::function<Crypto::Address()> my_address;

    std::function<uint64_t()> now_ms;
  };

  struct Config
  {
    uint64_t max_block_bytes{256 * 1024};
    uint64_t max_block_txs{5'000};
    uint64_t poll_interval_ms{100};
  };

  class BftConsensus
  {
  public:
    BftConsensus(Dependencies deps,
                 Callbacks callbacks,
                 Config config,
                 Logging::LoggerRef log);

    ~BftConsensus();

    BftConsensus(const BftConsensus &) = delete;
    BftConsensus &operator=(const BftConsensus &) = delete;

    void start(Height height);
    void stop();
    bool isRunning() const;

    // Message entry points. Prevotes and precommits are distinct
    // message types on the wire and must be routed distinctly here —
    // a precommit is not a prevote and vice versa. The step field
    // determines which bucket a vote is stored in, not the local
    // receiving state.
    void onProposal(const Proposal &p);
    void onPrevote(const Vote &v);
    void onPrecommit(const Vote &v);

    void pollTimers();
    void tryPropose();

    // Force the current round timer to expire on the next pollTimers().
    // Used by tests to drive state transitions without sleeping. In
    // production nothing calls this — a real caller just waits for
    // the timer to expire naturally.
    void forceTimerExpiryForTest();

    struct State
    {
      Height height{0};
      Round round{0};
      Step step{Step::NewHeight};
      bool is_proposer{false};
      bool locked{false};
      Crypto::Hash locked_hash{};
      Round locked_round{0};
      size_t prevote_count{0};
      size_t precommit_count{0};
    };

    State state() const;

  private:
    void enterNewHeight(Height height);
    void enterPropose(Height height, Round round);
    void enterPrevote(Height height, Round round);
    void enterPrecommit(Height height, Round round);
    void enterCommit(Height height, Round round);

    void handleProposal(const Proposal &p);
    void handlePrevote(const Vote &v);
    void handlePrecommit(const Vote &v);

    void onProposeTimeout();
    void onPrevoteTimeout();
    void onPrecommitTimeout();

    bool propose();
    bool validateProposal(const Proposal &p, Core::Block &out_block);
    std::optional<Crypto::Hash> simulateBlock(const Core::Block &block);

    bool recordVote(const Vote &v, bool is_precommit);
    std::optional<Crypto::Hash> quorumValue(bool is_precommit) const;
    size_t countVotesFor(bool is_precommit, const Crypto::Hash &block_hash) const;
    size_t countNilVotes(bool is_precommit) const;

    size_t quorumThreshold() const;
    Index mySignerIndex() const;

    void broadcastProposal(const Proposal &p);
    void broadcastPrevote(bool is_nil, const Crypto::Hash &block_hash);
    void broadcastPrecommit(bool is_nil, const Crypto::Hash &block_hash);

    void resetForNewHeight(Height height);
    void resetForNewRound(Round round);

    Dependencies deps_;
    Callbacks callbacks_;
    Config config_;
    Logging::LoggerRef log_;

    mutable std::mutex mutex_;

    Height height_{0};
    Round round_{0};
    Step step_{Step::NewHeight};
    bool running_{false};

    Id proposer_{INVALID_ID};

    bool locked_{false};
    Crypto::Hash locked_hash_{};
    Round locked_round_{0};

    bool valid_set_{false};
    Crypto::Hash valid_hash_{};
    Round valid_round_{0};

    // The proposal most recently accepted from the network, or the one
    // we ourselves proposed. Used for the round/height check in
    // enterPrevote. The block itself lives in proposals_by_hash_.
    std::optional<Proposal> proposal_;

    // Every block we've accepted as a proposal at the current height,
    // keyed by the block's hash. Retained across rounds within a
    // height: if a precommit quorum forms on a block proposed in an
    // earlier round, the block is still here for us to apply. Cleared
    // when the height advances.
    std::unordered_map<Crypto::Hash, Core::Block> proposals_by_hash_;

    std::unordered_map<Index, Vote> prevotes_;
    std::unordered_map<Index, Vote> precommits_;

    std::unique_ptr<Common::RoundTimer> round_timer_;
  };

} // namespace Consensus