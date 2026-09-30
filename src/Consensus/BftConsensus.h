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
  //  Maximum number of equivocation evidence entries retained per
  //  consensus instance. Evidence survives height transitions so
  //  that a proposer at height H+1 can still include a conflict it
  //  observed at height H. The bound prevents a peer that feeds
  //  conflicting votes from growing the buffer without limit. In
  //  practice this is never reached.
  inline constexpr size_t MAX_EQUIVOCATION_EVIDENCE = 256;

  struct RoundKey
  {
    Height height{0};
    Round round{0};

    bool operator==(const RoundKey &other) const noexcept
    {
      return height == other.height && round == other.round;
    }
  };

  struct RoundKeyHash
  {
    size_t operator()(const RoundKey &k) const noexcept
    {
      return std::hash<uint64_t>()(k.height) ^
             (std::hash<uint64_t>()(k.round) << 1);
    }
  };

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

    //  Timeout attestations, broadcast when a round times out. The
    //  node routes these to the P2P layer as their own message type;
    //  peers feed them back to onTimeoutVote.
    std::function<void(const TimeoutVote &)> broadcast_timeout_vote;

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

    //  Returns the active set. When `force_rotation` is true, the
    //  caller has observed enough consecutive round timeouts to
    //  conclude the committed set can no longer form quorum, and the
    //  derived emergency set is returned instead.
    std::function<std::vector<Id>(bool force_rotation)> active_set;

    std::function<bool(Id, Core::ValidatorInfo &)> state_lookup_validator;

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
    void onTimeoutVote(const TimeoutVote &tv);

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

    size_t equivocationCount() const;

    //  Number of consecutive rounds at the current height that ended
    //  without a commit. Reset on successful commit and on entering a
    //  new height. Drives the emergency rotation trigger.
    Round consecutiveTimeouts() const;

    //  True when consecutiveTimeouts() has reached
    //  Core::EMERGENCY_ROTATION_ROUNDS. The proposer sets
    //  block.header.emergency_rotation when this is true.
    bool emergencyRotationActive() const;

    bool verifyTimeoutCertificate(const Core::Block &block,
                                  const std::vector<Id> &committed_set,
                                  Height height) const;

    std::optional<Proposal> currentProposalForTest() const;

  private:
    void enterNewHeight(Height height);
    void enterPropose(Height height, Round round);
    void enterPrevote(Height height, Round round);
    void enterPrecommit(Height height, Round round);
    void enterCommit(Height height, Round round);

    void handleProposal(const Proposal &p);
    void handlePrevote(const Vote &v);
    void handlePrecommit(const Vote &v);

    void handleTimeoutVote(const TimeoutVote &tv);

    void onProposeTimeout();
    void onPrevoteTimeout();
    void onPrecommitTimeout();

    bool propose();
    bool validateProposal(const Proposal &p, const Core::Block &block);
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

    //  Broadcast a timeout attestation for `round`. Called from the
    //  three timeout handlers before the round advances; a no-op if
    //  we are not a validator or if no broadcast callback is wired.
    void broadcastTimeoutVote(Round round);

    //  Assemble an f+1 certificate for the smallest round at or above
    //  EMERGENCY_ROTATION_ROUNDS for which we hold enough distinct
    //  signers from the committed set. Returns false if we can't. On
    //  success, `out_round` is set to the round the certificate
    //  attests to — the proposer must stamp that value into
    //  block.header.emergency_rotation, since the verifier checks the
    //  certificate against the header's round.
    bool assembleTimeoutCertificate(Round &out_round, TimeoutCertificate &out) const;

    void resetForNewHeight(Height height);
    void resetForNewRound(Round round);

    // Deliver any stashed proposal for the current round. Called from
    // resetForNewRound after the round counter is updated.
    void drainFutureProposal();

    //  Deliver any buffered votes whose step is now current. A vote
    //  whose block isn't known yet stays buffered unless we already
    //  hold a vote from the same signer — in that case it's a
    //  potential equivocation and must reach recordVote.
    void drainPendingVotes(bool is_precommit);

    //  Deliver any buffered votes and the proposal for the current
    //  height. Called from resetForNewHeight after height_ is updated.
    void drainFutureHeightVotes();
    void drainFutureHeightProposal();

    //  True if we can verify the signature of a vote — that is, if we
    //  know which active set the round ran on, and thus which key to
    //  check the signature against.
    bool voteIsVerifiable(const Vote &v) const;

    //  Active-set resolution helpers. See the comment block in the
    //  .cpp for the design.
    bool roundUsesEmergencySet(Height height, Round round) const;
    bool roundUsesEmergencySetForVote(const Vote &v) const;

    bool useEmergencySet() const noexcept;

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

    // Proposals received for a round we haven't reached yet. Keyed by
    // round number. When resetForNewRound advances us to round N, any
    // stashed proposal for N is processed before we enter the propose
    // step.
    //
    // Why this matters: a proposer in round N+1 can send its proposal
    // while a slow validator is still finishing round N. Without the
    // queue, the slow validator's `p.round != round_` check drops the
    // proposal on the floor and the round stalls until the proposer
    // times out and tries again — which in the 2-validator case means
    // the chain never advances.
    //
    // Cleared in resetForNewHeight. Retained across rounds within a
    // height.
    std::unordered_map<Round, Proposal> future_proposals_;

    // Votes received for our current height/round but before we entered
    // the corresponding step. Delivered when we enter the step.
    std::vector<Vote> pending_prevotes_;
    std::vector<Vote> pending_precommits_;

    //  Votes received for height_ + 1 while we are still finishing
    //  height_. Under randomized delivery (and under a brief partition)
    //  a fast validator can broadcast its next-height prevotes and
    //  precommits before a slow validator has finished committing the
    //  current height. Those votes would otherwise be silently dropped
    //  by the `v.height != height_` guard, and the slow validator would
    //  have no way to form quorum at the new height except by timing
    //  out and hoping a live proposer exists.
    //
    //  We buffer at most one height ahead. A vote for height_ + 2 cannot
    //  be verified (we don't yet know the round set for height_ + 1, and
    //  the vote's signature commits to a round set we can't resolve), so
    //  buffering further ahead would just be a memory-growth vector for
    //  a peer feeding us garbage.
    //
    //  Cleared on height transition, after draining into the pending
    //  buffers for the new height.
    std::unordered_map<Height, std::vector<Vote>> future_height_prevotes_;
    std::unordered_map<Height, std::vector<Vote>> future_height_precommits_;
    std::unordered_map<Height, Proposal> future_height_proposals_;

    //  For each (height, round) we've accepted a proposal for, the
    //  block hash of that proposal. Lets vote verification look up the
    //  emergency flag from the block that the round ran on, rather
    //  than consulting the local timeout counter.
    std::unordered_map<RoundKey, Crypto::Hash, RoundKeyHash> proposal_for_round_;

    //  Evidence of equivocation seen at the current height. Appended
    //  to (never overwritten) in recordVote when a second vote from a
    //  signer conflicts with the first. Drained by the proposer when
    //  it builds a block, and erased from every node when a block
    //  containing the evidence commits.
    //
    //  Not cleared on height transition — evidence observed at height
    //  H may not be included in a block until H+1 or later. Bounded by
    //  MAX_EQUIVOCATION_EVIDENCE to prevent unbounded growth from a
    //  peer that feeds conflicting votes.
    std::vector<EquivocationEvidence> equivocations_;

    //  Timeout attestations seen at the current height, at rounds >=
    //  EMERGENCY_ROTATION_ROUNDS. Collected from the network; used by
    //  the proposer to assemble a TimeoutCertificate. Cleared on
    //  height transition, NOT on round transition — votes from
    //  earlier rounds at this height accumulate toward a certificate.
    std::vector<TimeoutVote> timeout_votes_;

    //  Consecutive rounds that ended without a commit, counted at the
    //  current height. Reset to zero when a block commits. When this
    //  reaches EMERGENCY_ROTATION_ROUNDS, the proposer for the next
    //  round sets block.header.emergency_rotation, and every node
    //  derives the emergency active set for that round's votes and
    //  block verification.
    Round consecutive_timeouts_{0};
  };

} // namespace Consensus