// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include "Message.h"
#include "Types.h"
#include "ProposerSelection.h"

#include "Common/RoundTimer.h"

#include "Core/Block.h"
#include "Core/Fill.h"
#include "Core/ValidatorTypes.h"
#include "Crypto/Types.h"

#include "Logging/LoggerRef.h"

namespace Consensus
{
  // Cap on the local equivocation-evidence buffer. Evidence survives
  // height transitions so a proposer at H+1 can still include a
  // conflict it saw at H. Evidence is deduplicated per
  // (signer, height, round), so a single equivocator cannot evict
  // honest evidence by FIFO pressure.
  inline constexpr size_t MAX_EQUIVOCATION_EVIDENCE = 256;

  // Minimum wall-clock interval between blocks, in milliseconds.
  // The engine waits this long after a commit before entering the next
  // height unless the node has pending work. Protocol-level norm, not
  // a node config, and not enforced by peers.
  inline constexpr uint64_t MIN_BLOCK_INTERVAL_MS = 10'000;

  // Key for the (height, round) -> block_hash map.
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

  // Outbound hooks. Called from the consensus thread, under the
  // consensus mutex. A callback must NOT call back into any public
  // BftConsensus method except noteChainHead() (which is lock-free).
  struct Callbacks
  {
    std::function<void(const Proposal &)> broadcast_proposal;
    std::function<void(const Vote &)> broadcast_prevote;
    std::function<void(const Vote &)> broadcast_precommit;
    std::function<void(const TimeoutVote &)> broadcast_timeout_vote;

    std::function<std::vector<Core::Transaction>(uint64_t max_bytes,
                                                 uint64_t max_txs)>
        select_transactions;

    // Apply a committed block. Returns true on success. On false the
    // engine does NOT advance the round (the block is already decided
    // by a precommit quorum): it retries the apply with backoff up to
    // Config::max_commit_retries times, then halts and fires
    // on_consensus_halt. If the block was applied by another path
    // (relay/sync), the node must call noteChainHead() so the engine
    // abandons the retry and moves on.
    std::function<bool(const Core::Block &)> on_block_committed;

    std::function<void(Height)> on_height_advanced;

    // Fired once when the engine halts itself (a committed block could
    // not be applied after all retries). The node should surface this
    // loudly (metric, log, alert); the engine stays stopped until
    // start() is called again.
    std::function<void(const std::string &reason)> on_consensus_halt;
  };

  struct Dependencies
  {
    std::function<Id()> my_validator_id;
    std::function<Crypto::Signature(const Crypto::Hash &)> sign;
    std::function<Height()> current_height;

    // Must be a pure function of (state, height, force_rotation).
    std::function<std::vector<Id>(bool force_rotation)> active_set;

    std::function<bool(Id, Core::ValidatorInfo &)> state_lookup_validator;

    std::function<uint64_t()> chain_id;
    std::function<Crypto::Hash()> parent_hash;

    //  Apply a candidate block against a copy of state and return
    //  the resulting state root. Used by the proposer to build a
    //  header and by every validator to verify a peer's proposal.
    //
    //  On success, `out_state_root` receives the post-state root and
    //  `out_epoch_fills` receives the fills produced by the epoch
    //  boundary (empty if this height was not a boundary, or if the
    //  boundary produced no routable fills). The proposer needs the
    //  fills to compute epoch_fills_root before sealing the header.
    //
    //  On failure the callback returns false and, if
    //  `out_failed_txid` is non-null, sets it to the txid of the
    //  first transaction whose execution threw. A block-level
    //  failure (bad header, bad tx_root, etc.) reports a null hash
    //  in `out_failed_txid`.
    std::function<bool(
        const Core::Block &,
        Crypto::Hash &out_state_root,
        std::vector<Core::Fill> &out_epoch_fills,
        Crypto::Hash *out_failed_txid)>
        simulate_block;

    std::function<Crypto::Address()> my_address;
    std::function<uint64_t()> now_ms;

    // Optional. Verify a Slash payload against current state. When
    // set, it replaces the "target must be in the active set" filter,
    // so validators that left the active set but are still inside
    // their unbonding window remain slashable. When unset, the
    // proposer requires only that the target is a registered validator.
    std::function<bool(const std::vector<uint8_t> &payload)>
        verify_slash_proof;

    // Optional. See pollTimers pacing.
    std::function<bool()> has_pending_work;

    // ---- Write-ahead log ----
    //
    // Only our own votes and locks are written. All must be durable
    // before returning.

    // Called after signing, before the vote is recorded or broadcast.
    std::function<void(const Vote &vote, bool is_precommit)> wal_append_vote;

    // Called before locked_ is set.
    std::function<void(Height, Round, const Crypto::Hash &)> wal_append_lock;

    // Optional but strongly recommended. Persist the block we locked
    // on, so a restarted validator can still count, re-propose and
    // commit it without fetching it from peers. Called BEFORE
    // wal_append_lock (a block without a lock is harmless; a lock
    // without its block is not).
    std::function<void(Height, const Core::Block &)> wal_append_locked_block;

    // Optional counterpart of wal_append_locked_block: the most recent
    // locked block stored for `height`, if any.
    std::function<std::optional<Core::Block>(Height)> wal_load_locked_block;

    // Replays WAL entries for `for_height`. The engine rebuilds a
    // signed-vote registry from the votes (so it can never sign a
    // second value for the same (height, round, type)), keeps the
    // highest-round lock, and resumes at the highest round it finds.
    std::function<void(Height for_height,
                       std::function<void(const Vote &, bool)> on_vote,
                       std::function<void(Height, Round, const Crypto::Hash &)> on_lock)>
        wal_replay;

    // Discard WAL entries at heights <= committed_height.
    std::function<void(Height committed_height)> wal_truncate;
  };

  struct Config
  {
    uint64_t max_block_bytes{256 * 1024};
    uint64_t max_block_txs{5'000};
    uint64_t poll_interval_ms{100};

    // Commit-apply retry policy (see Callbacks::on_block_committed).
    uint32_t max_commit_retries{5};
    uint64_t commit_retry_backoff_ms{1'000};
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

    // Idempotent. Clears the halted flag.
    void start(Height height);
    void stop();
    bool isRunning() const;

    // True after the engine halted itself on an unappliable block.
    bool halted() const;

    void onProposal(const Proposal &p);
    void onPrevote(const Vote &v);
    void onPrecommit(const Vote &v);
    void onTimeoutVote(const TimeoutVote &tv);

    // Tell the engine the chain head is now `applied_height`, applied
    // by some path other than consensus (relay, sync). Lock-free and
    // safe to call from inside any callback or from any thread. The
    // engine jumps to applied_height + 1 on its next poll, abandoning
    // any in-flight commit retry. Do not call it for blocks applied
    // through on_block_committed.
    void noteChainHead(Height applied_height);

    void pollTimers();
    void tryPropose();

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
      bool halted{false};
    };

    State state() const;

    size_t equivocationCount() const;
    Round consecutiveTimeouts() const;
    bool emergencyRotationActive() const;

    bool verifyTimeoutCertificate(const Core::Block &block,
                                  const std::vector<Id> &committed_set,
                                  Height height) const;

    std::optional<Proposal> currentProposalForTest() const;

    // A block at `height` for which we hold a precommit quorum in the
    // current round, any earlier round of this height, or an in-flight
    // commit. Note this only covers quorums THIS node has seen.
    std::optional<Core::Block> heldQuorumBlock(Height height) const;

    // Forward to deps_.simulate_block. The out-parameter is
    // optional: pass nullptr when the caller only needs to know
    // whether the block simulates (validateProposal), or a valid
    // pointer when the caller needs the failing txid (propose).
    bool simulateBlock(const Core::Block &block,
                       Crypto::Hash &out_state_root,
                       std::vector<Core::Fill> &out_epoch_fills,
                       Crypto::Hash *out_failed_txid = nullptr);

  private:
    using VoteMap = std::unordered_map<Id, Vote>;
    using SignedKey = std::tuple<Height, Round, bool>; // (height, round, is_precommit)

    enum class InsertResult
    {
      Inserted,
      Duplicate,
      Conflict
    };

    // ---- State machine ----
    void enterNewHeight(Height height);
    void enterPropose(Height height, Round round);
    void enterPrevote(Height height, Round round);
    void enterPrecommit(Height height, Round round);
    void enterCommit(Height height, Round round);

    // Apply commit_block_; retry/halt policy lives here.
    void tryApplyCommit();
    void haltConsensus(const std::string &reason);

    // ---- Message handling ----
    void handleProposal(const Proposal &p);
    void handleVote(const Vote &v, bool is_precommit);
    void handleTimeoutVote(const TimeoutVote &tv);

    void onProposeTimeout();
    void onPrevoteTimeout();
    void onPrecommitTimeout();

    // ---- Proposing ----
    bool propose();
    Core::Block buildFreshBlock() const;
    // Signature is checked by the caller (handleProposal).
    bool validateProposal(const Proposal &p, const Core::Block &block);

    // Signature + "is this the expected proposer" check against one set.
    bool verifyProposalSignatureIn(const Proposal &p, bool emergency) const;
    // Either set (used before the block, and so its flag, is known).
    bool verifyProposalSignature(const Proposal &p) const;
    // A block with the emergency flag must be proposed by the
    // emergency set's proposer. A normal block may be proposed by the
    // committed set's proposer, or (round >= EMERGENCY_ROTATION_ROUNDS)
    // by the emergency set's proposer re-proposing a locked block.
    bool proposerSetAllowed(const Proposal &p, bool block_emergency) const;
    // Which set (false = committed, true = emergency) `me` must sign
    // as for a block with this flag at `round`; nullopt if not entitled.
    std::optional<bool> proposerSetFor(Id me, Round round, bool block_emergency) const;

    // ---- Votes ----
    bool recordVote(const Vote &v, bool is_precommit);
    void recordPastPrecommit(const Vote &v);
    InsertResult insertVote(VoteMap &container, const Vote &v, Id voter_id);

    void checkPrevoteQuorum();
    void checkPrecommitQuorum();

    std::optional<Crypto::Hash> quorumValue(bool is_precommit) const;
    std::optional<Crypto::Hash> quorumValueIn(const VoteMap &container) const;
    size_t quorumThreshold(bool emergency) const;

    Id resolveVoteSigner(const Vote &v, bool &out_emergency) const;
    bool verifyVoteSignature(const Vote &v, Id signer_id) const;
    // Signer resolves and signature verifies. Does NOT require the
    // block to be known, so it is the gate for buffering.
    bool voteSignatureOk(const Vote &v, Id *out_signer = nullptr) const;
    // Counting-ready: nil, or references a block we hold.
    bool voteReady(const Vote &v) const;

    void pushPending(bool is_precommit, const Vote &v);
    bool bufferFutureVote(const Vote &v, bool is_precommit, Id signer);

    // The hash we would prevote (and re-propose) this round. Returns a
    // hash even if the block bytes are unknown (e.g. after a restart),
    // so a lock is never abandoned just because the block is missing.
    std::optional<Crypto::Hash> selectPrevoteHash() const;

    // Which set our own vote for (is_nil, hash) belongs to.
    bool ownVoteSet(bool is_nil, const Crypto::Hash &block_hash) const;

    void broadcastProposal(const Proposal &p);
    void broadcastVote(bool is_precommit, bool is_nil, const Crypto::Hash &block_hash);
    void broadcastTimeoutVote(Round round);

    // ---- Timeout certificate / emergency ----
    bool assembleTimeoutCertificate(Round &out_round,
                                    TimeoutCertificate &out) const;
    bool storeTimeoutVote(const TimeoutVote &tv);
    void retryEmergencyPropose();

    // ---- f+1 round skip ----
    void noteRoundHint(Id signer, Round round);
    void maybeSkipRound();

    // ---- Reset / drains ----
    void resetForNewHeight(Height height);
    void resetForNewRound(Round round);

    void drainFutureProposal();
    void drainFutureRoundVotes();
    void drainFutureHeightVotes();
    void drainFutureHeightProposal();
    void drainPendingVotes();

    // ---- WAL ----
    // Returns the round to resume at (highest round with a signed vote
    // or a lock), or 0.
    Round replayWalForHeight(Height height);
    void restoreOwnVotes(Round round);

    // ---- Set resolution ----
    bool roundUsesEmergencySet(Height height, Round round) const;
    bool roundUsesEmergencySetForVote(const Vote &v) const;
    bool useEmergencySet() const noexcept;
    Index indexInSet(Id id, bool emergency) const;
    std::optional<Crypto::PublicKey> resolveConsensusKey(Index idx, bool emergency) const;
    bool stepAtLeastPrevote() const noexcept;

    // ---- Members ----
    Dependencies deps_;
    Callbacks callbacks_;
    Config config_;
    Logging::LoggerRef log_;

    mutable std::mutex mutex_;

    Height height_{0};
    Round round_{0};
    Step step_{Step::NewHeight};
    bool running_{false};
    bool halted_{false};

    Id proposer_{INVALID_ID};

    bool locked_{false};
    Crypto::Hash locked_hash_{};
    Round locked_round_{0};

    bool valid_set_{false};
    Crypto::Hash valid_hash_{};
    Round valid_round_{0};

    std::optional<Proposal> proposal_;
    std::unordered_map<Crypto::Hash, Core::Block> proposals_by_hash_;

    // Current-round votes, keyed by validator id.
    VoteMap prevotes_;
    VoteMap precommits_;

    // Precommits from earlier rounds of this height. A precommit
    // quorum in ANY round commits, so these are kept (bounded).
    std::map<Round, VoteMap> past_precommits_;

    // Every vote WE signed at this height. Rebuilt from the WAL on
    // restart. Consulted before signing so we never sign a second
    // value for the same (height, round, type).
    std::map<SignedKey, Vote> signed_votes_;

    std::unique_ptr<Common::RoundTimer> round_timer_;

    static constexpr Round MAX_FUTURE_ROUNDS = 64;
    static constexpr size_t MAX_PAST_ROUNDS = 64;
    static constexpr size_t MAX_FUTURE_VOTES_PER_ROUND = 512;
    static constexpr size_t MAX_PENDING_VOTES = 4096;
    // Two per signer so a conflicting second vote still reaches
    // equivocation detection, but one signer cannot fill the buffer.
    static constexpr size_t MAX_PENDING_PER_SIGNER = 2;
    static constexpr size_t MAX_TIMEOUT_VOTES = 4096;
    static constexpr size_t MAX_TIMEOUT_VOTES_PER_SIGNER = 64;
    static constexpr uint64_t MAX_PROPOSAL_SLACK_BYTES = 64 * 1024;

    std::unordered_map<Round, Proposal> future_proposals_;

    std::vector<Vote> pending_prevotes_;
    std::vector<Vote> pending_precommits_;

    std::optional<Height> pending_height_;
    uint64_t next_propose_not_before_ms_{0};

    // In-flight commit (precommit quorum observed, block built, apply
    // not yet successful).
    std::optional<Core::Block> commit_block_;
    uint32_t commit_attempts_{0};
    uint64_t next_commit_attempt_ms_{0};

    // Next height implied by a chain advance made outside consensus;
    // 0 = none. Lock-free so it is safe to set from inside callbacks.
    std::atomic<Height> external_next_height_{0};

    std::unordered_map<Round, VoteMap> future_round_prevotes_;
    std::unordered_map<Round, VoteMap> future_round_precommits_;

    std::unordered_map<Height, VoteMap> future_height_prevotes_;
    std::unordered_map<Height, VoteMap> future_height_precommits_;
    std::unordered_map<Height, Proposal> future_height_proposals_;

    std::unordered_map<RoundKey, Crypto::Hash, RoundKeyHash> proposal_for_round_;

    std::vector<EquivocationEvidence> equivocations_;
    std::vector<TimeoutVote> timeout_votes_;

    // Highest round each (signature-verified) validator has been seen
    // at, for the f+1 round-skip rule.
    std::unordered_map<Id, Round> round_hints_;

    Round consecutive_timeouts_{0};

    static constexpr uint32_t MAX_SIMULATION_RETRIES = 15;
  };

} // namespace Consensus