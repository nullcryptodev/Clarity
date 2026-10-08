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
  // Cap on the local equivocation-evidence buffer.
  //
  // Evidence survives height transitions, so a proposer at H+1 can
  // still include a conflict it saw at H. The bound stops a peer
  // that feeds conflicting votes from growing the buffer without
  // limit. It is never reached in practice: an equivocating
  // validator is a single (height, round, signer) event, and the
  // buffer is cleared on commit of a block that includes the
  // evidence.
  inline constexpr size_t MAX_EQUIVOCATION_EVIDENCE = 256;

  //  Minimum wall-clock interval between blocks, in milliseconds.
  //
  //  The consensus engine waits this long after a commit before
  //  entering the next height, unless the node has pending work (a
  //  non-empty mempool), in which case the next block is proposed
  //  immediately.
  //
  //  The result:
  //
  //    - Idle chain: one empty heartbeat block per interval.
  //    - Active chain: blocks as fast as transactions arrive.
  //    - Transition: the next block fires the moment a tx lands
  //      in the mempool, even if the idle timer is still counting.
  //
  //  This is a protocol constant, not a node config. Making it
  //  configurable would let a single validator set its interval to
  //  zero and produce a flood of empty blocks, and the other
  //  validators would have to accept them — the pacing rule isn't
  //  enforced at consensus, so a fast-proposing validator isn't
  //  rejected by its peers. Keeping the value internal ensures every
  //  honest node paces itself the same way.
  //
  //  A validator that patches its binary to disable pacing would
  //  still be producing blocks the rest of the network accepts.
  //  That's a property of the design, not a limitation: the pacing
  //  rule is a well-behaved-node norm, and the network's protection
  //  against a node that ignores it is that everyone else is
  //  producing blocks at the same rate, so a burst from one node
  //  can't dominate the chain.
  inline constexpr uint64_t MIN_BLOCK_INTERVAL_MS = 60'000;

  // Key for the (height, round) -> block_hash map used to answer
  // "which block did this round propose?". Hashable because it's
  // used as a key in an unordered_map.
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

  // Outbound message hooks. Called from the consensus thread.
  //
  // The consensus engine never touches the network directly. Every
  // outbound message goes through a callback so the node can tag it
  // for P2P, log it, or drop it if the transport is not ready.
  struct Callbacks
  {
    std::function<void(const Proposal &)> broadcast_proposal;

    // Prevotes and precommits share a wire type but are distinct
    // message types on the P2P layer. The callbacks are split so
    // the node can route each to the correct handler on receipt.
    std::function<void(const Vote &)> broadcast_prevote;
    std::function<void(const Vote &)> broadcast_precommit;

    // Timeout attestations, broadcast when a round times out.
    // These accumulate into the certificate an emergency proposal
    // carries.
    std::function<void(const TimeoutVote &)> broadcast_timeout_vote;

    // Mempool selection for a fresh block. Returns transactions
    // the proposer should include, bounded by size and count. Not
    // called for a re-proposal: the block's transaction set is
    // fixed once it has been voted on.
    std::function<std::vector<Core::Transaction>(uint64_t max_bytes,
                                                 uint64_t max_txs)>
        select_transactions;

    // Called after a block is committed. The node applies it to
    // state, stores it, and advances the chain head.
    std::function<void(const Core::Block &)> on_block_committed;

    // Called after the commit callback. A separate hook so the
    // node can log or meter height advances independently of the
    // block-application work.
    std::function<void(Height)> on_height_advanced;
  };

  // Inbound dependencies. All of these are provided by the node;
  // the consensus engine is otherwise self-contained.
  //
  // Every function is called from the consensus thread, under the
  // consensus mutex. The node is responsible for making them safe
  // to call re-entrantly (in particular, `simulate_block` runs
  // while the mutex is held and may not re-enter consensus).
  struct Dependencies
  {
    // Our own validator id, or INVALID_ID if we're not a validator.
    // A non-validator node never proposes or votes; it only
    // applies committed blocks.
    std::function<Id()> my_validator_id;

    // Sign a hash with our consensus key. Returns a null signature
    // if the key is not available; every caller treats a null
    // signature as "we can't vote this round."
    std::function<Crypto::Signature(const Crypto::Hash &)> sign;

    // Our current chain height. Used as the base for the next
    // height's proposal and as a sanity check in a few places.
    std::function<Height()> current_height;

    // The active set for a given round.
    //
    // When `force_rotation` is true, the caller has observed enough
    // consecutive timeouts at this height to conclude the committed
    // set can no longer form quorum, and the derived emergency set
    // is returned instead.
    //
    // The function must be a pure function of (state, height,
    // force_rotation): every honest node that calls it with the
    // same arguments gets the same set, or quorum never forms.
    std::function<std::vector<Id>(bool force_rotation)> active_set;

    // Look up a validator by id. Returns false if the id is not
    // registered. Used to resolve a signer id to a public key and
    // to check whether a validator is still slashable.
    std::function<bool(Id, Core::ValidatorInfo &)> state_lookup_validator;

    // Our chain id. Stamped into every proposed block's header.
    // Without this, proposals carry chain_id 0 and every receiver
    // rejects them.
    std::function<uint64_t()> chain_id;

    // Parent hash for a fresh proposal. Read fresh on each call so
    // the proposer sees the head that was just committed, not a
    // cached value from the previous round.
    std::function<Crypto::Hash()> parent_hash;

    // Dry-run a block against committed state and return the
    // resulting state root. Must not commit anything.
    //
    // Called from both propose() (to compute the root the proposer
    // will publish) and validateProposal() (to verify the root a
    // proposer published). Both uses are the same computation, so
    // they cannot drift.
    std::function<std::optional<Crypto::Hash>(const Core::Block &)> simulate_block;

    // The address that appears in the proposed block's header. For
    // v1 this is the validator's reward address, matching the
    // convention used throughout for consensus identity.
    std::function<Crypto::Address()> my_address;

    // Wall-clock milliseconds. Used to stamp a fresh proposal's
    // timestamp. The consensus engine never reads the clock
    // directly so tests can make time deterministic.
    std::function<uint64_t()> now_ms;

    // Verify a Slash transaction's payload before including it in a
    // block. Returns true if the proof is valid against the current
    // active set and state.
    //
    // The proposer includes local equivocation evidence one proof
    // per Slash transaction. Without this callback, a single
    // malformed proof poisons the entire transaction and the whole
    // block is rejected on-chain. With it, the proposer skips the
    // bad proof and includes the rest.
    //
    // Optional. When unset, the proposer includes all locally-held
    // evidence and lets on-chain verification sort it out.
    std::function<bool(const std::vector<uint8_t> &payload)>
        verify_slash_proof;

    //  Return true if the node has pending work (a non-empty
    //  mempool). Called by pollTimers when a pacing delay is in
    //  effect: if the chain is idle and a transaction has arrived,
    //  the delay is cancelled and the next block is proposed
    //  immediately.
    //
    //  Optional. When unset, the engine behaves as if the mempool
    //  is always non-empty — that is, pacing never delays a block.
    //  Non-validator nodes and tests can leave it unset.
    std::function<bool()> has_pending_work;

    // The WAL exists to prevent self-slashing on restart. A
    // validator that crashes mid-round and comes back without its
    // lock or its cast votes could re-sign a different vote for the
    // same (height, round) and produce evidence against itself. The
    // WAL records the irreversible facts (our own votes, our lock)
    // before they become irreversible.
    //
    // Only the local validator's own votes are written. Recording
    // other validators' votes would help recovery but is not needed
    // for the self-slashing property, and it would grow the WAL by
    // a factor of the active set size.

    // Record one of our own votes. Must be durable before the
    // function returns: a crash after return but before the vote is
    // broadcast must not result in the node forgetting what it
    // signed.
    //
    // Called from broadcastPrevote and broadcastPrecommit, after
    // the signature is computed and before recordVote.
    std::function<void(const Vote &vote, bool is_precommit)> wal_append_vote;

    // Record a lock adoption. Must be durable before the function
    // returns: a crash after return but before the precommit that
    // motivated the lock is broadcast must not result in the
    // validator re-entering the round without a lock and signing a
    // conflicting precommit.
    //
    // Called from enterPrecommit, before `locked_` is set.
    std::function<void(Height, Round, const Crypto::Hash &)> wal_append_lock;

    // Replay the WAL for a specific height. Called from
    // enterNewHeight, after resetForNewHeight has cleared the
    // containers, so replayed entries land in a clean slate.
    //
    // The callback is expected to invoke the vote lambda once per
    // WAL vote entry for `for_height`, and the lock lambda once per
    // WAL lock entry. Entries at other heights are the callback's
    // responsibility to filter — the consensus engine does not read
    // the WAL directly.
    std::function<void(Height for_height,
                       std::function<void(const Vote &, bool)> on_vote,
                       std::function<void(Height, Round, const Crypto::Hash &)> on_lock)>
        wal_replay;

    // Discard WAL entries at heights <= `committed_height`. Called
    // after a successful commit. Entries at the committed height
    // are no longer needed: the block is durable in the chain DB,
    // and any vote or lock at that height has served its purpose.
    // Entries at the next height survive for the next height's
    // replay.
    std::function<void(Height committed_height)> wal_truncate;
  };

  // Consensus-engine tuning. Defaults are suitable for regtest and
  // testnet; mainnet may want a larger block budget.
  struct Config
  {
    // Maximum serialized block size the proposer will produce.
    // Receivers enforce this independently via the block's own
    // well-formedness check.
    uint64_t max_block_bytes{256 * 1024};

    // Maximum number of transactions in a proposed block. A hard
    // upper bound on how much work a proposer can hand to a
    // validator in one round.
    uint64_t max_block_txs{5'000};

    // How often pollTimers() is expected to be called. The consensus
    // engine does not own a timer; the node drives it.
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

    // Begin consensus at `height`. Idempotent: a second call while
    // running is a no-op. The node calls this once enough peers are
    // Established to form a quorum; calling it earlier would make
    // the first proposer broadcast into an empty peer table.
    void start(Height height);

    // Halt consensus. Cancels the round timer and stops responding
    // to messages. Idempotent. Does not flush the WAL: entries
    // written before stop are durable, entries written during a
    // round in progress are durable as soon as the corresponding
    // wal_append_* call returns.
    void stop();

    bool isRunning() const;

    // Inbound message handlers. Each is a no-op if the message is
    // for a height or round the engine has no use for; the engine
    // buffers where buffering is safe and drops where it isn't.
    // See BftConsensus.cpp for the buffering rules.
    //
    // Each also checks `running_` first: a stopped instance must
    // not process any inbound message, or a state machine that is
    // supposed to be frozen can still advance.
    void onProposal(const Proposal &p);
    void onPrevote(const Vote &v);
    void onPrecommit(const Vote &v);
    void onTimeoutVote(const TimeoutVote &tv);

    // Drive the round timer. The node calls this on its poll
    // interval; if the timer has expired, the engine advances the
    // round. No-op if the engine is stopped.
    //
    // If a commit is pending (see pending_height_), this drains the
    // pending height transition first, regardless of whether the
    // round timer has expired. The pending transition is deferred
    // out of enterCommit to break a recursion; pollTimers is where
    // it lands.
    void pollTimers();

    // Attempt to propose a block for the current round. Called
    // internally when the proposer is chosen; exposed for tests
    // that need to drive the proposer without waiting for a timer.
    void tryPropose();

    // Force the round timer to expire on the next pollTimers().
    // Tests use this to advance the state machine without sleeping.
    void forceTimerExpiryForTest();

    // Snapshot of the engine's externally-visible state. All fields
    // are copies; nothing in this struct aliases internal storage.
    struct State
    {
      Height height{0};
      Round round{0};
      Step step{Step::NewHeight};

      // True if this validator is the proposer for the current
      // round. Recomputed from my_validator_id and the proposer
      // selection function on every call to state().
      bool is_proposer{false};

      // Lock state. `locked_round` is the round at which the lock
      // was adopted; `locked_hash` is the block hash the lock
      // references. A validator with a lock prevotes the locked
      // block in preference to the current proposal.
      bool locked{false};
      Crypto::Hash locked_hash{};
      Round locked_round{0};

      // How many votes for the current (height, round) have been
      // recorded. Informational; the engine's decision to advance
      // is driven by quorumValue, not by these counts.
      size_t prevote_count{0};
      size_t precommit_count{0};
    };

    State state() const;

    // Number of equivocation evidence entries currently held. Used
    // by tests to assert that a conflict was recorded.
    size_t equivocationCount() const;

    // Rounds at the current height that ended without a commit.
    // Reset on successful commit and on entering a new height.
    Round consecutiveTimeouts() const;

    // True when consecutiveTimeouts() has reached
    // EMERGENCY_ROTATION_ROUNDS. In this state, active_set(true) is
    // used for proposer selection and quorum thresholds.
    bool emergencyRotationActive() const;

    // Verify a timeout certificate against a committed set. The
    // block carries the certificate; this checks that its
    // signatures are valid and that the height and round fields
    // agree with the block's own. Called from validateProposal and
    // from BlockProcessor on the on-chain path.
    bool verifyTimeoutCertificate(const Core::Block &block,
                                  const std::vector<Id> &committed_set,
                                  Height height) const;

    // The current round's proposal, if any. Used by tests and by the
    // node's restart path to redeliver a proposal to a node that
    // just came back online.
    std::optional<Proposal> currentProposalForTest() const;

    // Return a block at `height` for which we hold a precommit
    // quorum, if any. Used by the node to prefer a committed block
    // over a conflicting emergency proposal: a block that already
    // has quorum beats an emergency proposal, which is only a claim
    // that the normal path is stuck.
    //
    // Returns nullopt if `height` is not our current height or if
    // no block at this height has a precommit quorum yet.
    std::optional<Core::Block> heldQuorumBlock(Height height) const;

  private:
    // Each `enter*` function sets the corresponding step and performs
    // the step's local action (propose a block, broadcast a vote,
    // advance to commit). Transitions are the only place where the
    // step_ field changes.
    //
    // All of them are re-entrant: an action they perform (a
    // broadcast, a recordVote call) can synchronously drive the
    // engine into another transition. Callers guard by re-checking
    // height_ and round_ after any call that can re-enter.

    void enterNewHeight(Height height);
    void enterPropose(Height height, Round round);
    void enterPrevote(Height height, Round round);
    void enterPrecommit(Height height, Round round);
    void enterCommit(Height height, Round round);

    // Each handler applies the buffering and dispatch rules for its
    // message type. The rules are documented at the definition site
    // in BftConsensus.cpp; the header only names the entry points.

    void handleProposal(const Proposal &p);
    void handlePrevote(const Vote &v);
    void handlePrecommit(const Vote &v);

    // Timeout attestations. These accumulate locally until enough
    // exist to assemble a certificate for the emergency proposal.
    void handleTimeoutVote(const TimeoutVote &tv);

    // Called by pollTimers when the round timer expires and the
    // engine is in the corresponding step. Each broadcasts a timeout
    // attestation and advances the state machine.

    void onProposeTimeout();
    void onPrevoteTimeout();
    void onPrecommitTimeout();

    // Propose a block for the current round. Returns false if
    // proposal construction failed (simulation error, no certificate
    // for an emergency round). A false return does not advance the
    // round; the round timer will fire and the next proposer will
    // try.
    bool propose();

    // Build a fresh block with a fresh transaction set. Called only
    // when no lock or valid value is available to re-propose.
    Core::Block buildFreshBlock() const;

    // Verify a proposal's signature, certificate, and state root.
    // Returns false on any failure; the caller logs the specific
    // reason.
    bool validateProposal(const Proposal &p, const Core::Block &block);

    // Verify a proposal's signature against the set the block's
    // emergency flag selects. Used to filter a proposal before it
    // is buffered or installed.
    bool verifyProposalSignature(const Proposal &p) const;

    // Compute a block's state root by dry-running it. Returns
    // nullopt if simulation failed. The block is not mutated and
    // nothing is committed.
    std::optional<Crypto::Hash> simulateBlock(const Core::Block &block);

    // Record a vote from a peer or from ourselves. Returns true if
    // the vote was accepted (either as a first vote from that
    // signer, or as evidence of equivocation against a previous
    // vote from the same signer). Returns false if the vote was
    // rejected for any reason.
    //
    // Keyed by signer_id, not signer_index. The index means
    // different things in the committed and emergency sets; the
    // id is stable across a set transition.
    //
    // A precommit quorum fires enterCommit regardless of the current
    // step. The block referenced by the quorum is known (that is a
    // precondition of quorumValue returning a hash), so committing
    // early is safe and is what makes round-crossing recovery work:
    // a validator that reaches Prevote in a new round but observes a
    // precommit quorum for the previous round's block must commit
    // that block, not wait for its own Precommit step.
    bool recordVote(const Vote &v, bool is_precommit);

    // Buffer a vote for a future round. Returns true if it was
    // buffered, false if it was rejected (wrong round, cap reached,
    // signature invalid, or a vote from the same signer is already
    // buffered). Verification happens before buffering, so a peer
    // cannot squat a validator's slot with junk.
    bool bufferFutureVote(const Vote &v, bool is_precommit);

    // Return the block hash with a quorum of non-nil votes, if any.
    // The threshold is computed per block hash, from that block's
    // own emergency flag — not from a single threshold applied
    // across the whole container.
    std::optional<Crypto::Hash> quorumValue(bool is_precommit) const;

    // Count non-nil votes for a specific block hash. Informational.
    size_t countVotesFor(bool is_precommit, const Crypto::Hash &block_hash) const;

    // Count nil votes. Informational.
    size_t countNilVotes(bool is_precommit) const;

    // The quorum threshold for a set. bftQuorum(n) = 2n/3 + 1.
    // Computed from the set size the caller specifies, not from a
    // cached count.
    size_t quorumThreshold(bool emergency) const;

    // Our own position in the set the current round is using, or
    // INVALID_INDEX if we're not a member. Recomputed on every call,
    // so it tracks set changes at rotation boundaries.
    Index mySignerIndex() const;

    // Resolve a vote's signer against the set the vote was cast
    // against. `signer_id` is authoritative; `signer_index` is a
    // pre-upgrade fallback. Returns INVALID_ID if the vote cannot be
    // resolved.
    Id resolveVoteSigner(const Vote &v, bool &out_emergency) const;

    // Verify a vote's signature against the resolved signer's
    // effective consensus key. Separate from resolveVoteSigner so
    // callers can check resolution and verification independently.
    bool verifyVoteSignature(const Vote &v, Id signer_id) const;

    // Full verifiability check for a vote: resolve the signer,
    // verify the signature, and confirm the vote references a block
    // or round we can reason about. Used by every buffering path.
    bool voteIsVerifiable(const Vote &v, Id *out_signer = nullptr) const;

    // The block we would prevote in the current round, or nullptr
    // for nil. Shared by propose() and enterPrevote so the proposer
    // and the voters cannot disagree about what the round's
    // candidate block is.
    const Core::Block *selectPrevoteBlock() const;

    // Outbound message construction

    void broadcastProposal(const Proposal &p);
    void broadcastPrevote(bool is_nil, const Crypto::Hash &block_hash);
    void broadcastPrecommit(bool is_nil, const Crypto::Hash &block_hash);
    void broadcastTimeoutVote(Round round);

    // Assemble a timeout certificate from accumulated attestations.
    // Returns false if there aren't enough distinct signers at any
    // round to meet the f+1 threshold.
    bool assembleTimeoutCertificate(Round &out_round,
                                    TimeoutCertificate &out) const;

    // Reset all per-height state. Called at the start of a new
    // height, before any messages for that height can be processed.
    // Clears locks, valid values, proposals, and vote containers.
    // Preserves equivocation evidence, which survives height
    // transitions.
    void resetForNewHeight(Height height);

    // Reset all per-round state. Called at the start of each round
    // within a height. Preserves locks and valid values, which
    // persist across rounds so the prevote rule can compare them.
    void resetForNewRound(Round round);

    // Each drain function moves messages from a future-scoped buffer
    // into the current round's processing path. Called at the point
    // where the buffer's key becomes current: enterPropose for
    // future proposals and votes, enterPrevote/enterPrecommit for
    // pending votes at the current round.
    //
    // Drained messages are re-run through the message handler, not
    // installed directly, so the handler's verification and buffering
    // rules apply.

    void drainFutureProposal();
    void drainFutureRoundVotes();
    void drainPendingVotes(bool is_precommit);
    void drainFutureHeightVotes();
    void drainFutureHeightProposal();

    // Which set applies to a (height, round) or to a specific vote.
    // Determined by the block's emergency flag for a non-nil vote,
    // or by the round's proposal for a nil vote. If neither is
    // known, falls back to the local consecutive_timeouts_ counter.
    bool roundUsesEmergencySet(Height height, Round round) const;
    bool roundUsesEmergencySetForVote(const Vote &v) const;

    // Whether this node is currently in emergency mode. True when
    // consecutive_timeouts_ has reached the threshold. Reads the
    // counter directly; not a function of the WAL or the set.
    bool useEmergencySet() const noexcept;

    // Replay the WAL for `height` into local state. Called from
    // enterNewHeight after resetForNewHeight has cleared the
    // containers, so the replayed votes land in a clean slate.
    void replayWalForHeight(Height height);

    bool storeTimeoutVote(const TimeoutVote &tv);
    void retryEmergencyPropose();

    std::optional<Crypto::PublicKey> resolveConsensusKey(Index idx, bool emergency) const;

    Dependencies deps_;
    Callbacks callbacks_;
    Config config_;
    Logging::LoggerRef log_;

    // Guards every public method and every private method that
    // mutates state. Held across callbacks into the node — see the
    // re-entrancy contract on Dependencies.
    mutable std::mutex mutex_;

    // Current round

    Height height_{0};
    Round round_{0};
    Step step_{Step::NewHeight};
    bool running_{false};

    // The proposer for the current round. Recomputed on every
    // enterPropose. INVALID_ID if the set is empty or the proposer
    // selection failed.
    Id proposer_{INVALID_ID};

    // The lock is the block this validator has committed to
    // precommitting in preference to any other. The valid value is
    // the most recent block that saw a prevote quorum. Both are
    // preserved across rounds within a height and cleared on a
    // height transition.
    //
    // The prevote rule (Tendermint): prevote validValue if
    // validRound > lockedRound, else lockedValue if locked, else
    // the current proposal, else nil.

    bool locked_{false};
    Crypto::Hash locked_hash_{};
    Round locked_round_{0};

    bool valid_set_{false};
    Crypto::Hash valid_hash_{};
    Round valid_round_{0};

    // The current round's proposal, as received or as proposed by
    // us. Nullopt until a valid proposal arrives.
    std::optional<Proposal> proposal_;

    // Blocks we've seen, keyed by hash. Populated when a proposal
    // is accepted, and kept for the lifetime of the height so that
    // re-proposals can reference them.
    std::unordered_map<Crypto::Hash, Core::Block> proposals_by_hash_;

    // Votes for the current (height, round), keyed by signer id.
    // Keyed by id, not index, because the index is not stable
    // across a set transition.
    std::unordered_map<Id, Vote> prevotes_;
    std::unordered_map<Id, Vote> precommits_;

    // Round timer. The consensus engine does not own a thread; the
    // node polls pollTimers() on its own schedule, and pollTimers
    // checks this timer's expiry.
    std::unique_ptr<Common::RoundTimer> round_timer_;

    // A peer must not be able to grow any buffer without limit.
    // These caps are per-buffer, and for the vote buffers they are
    // per-signer: a single signer can fill at most one slot per
    // (height, round).

    static constexpr Round MAX_FUTURE_ROUNDS = 64;
    static constexpr size_t MAX_FUTURE_VOTES_PER_ROUND = 512;
    static constexpr size_t MAX_PENDING_VOTES = 4096;
    static constexpr size_t MAX_TIMEOUT_VOTES = 4096;

    // Proposals received for a round we haven't reached yet.
    std::unordered_map<Round, Proposal> future_proposals_;

    // Votes received at the current (height, round) before we
    // entered the corresponding step. Moved into the vote containers
    // by drainPendingVotes.
    std::vector<Vote> pending_prevotes_;
    std::vector<Vote> pending_precommits_;

    // Height to enter after the current commit completes. Set by
    // enterCommit, drained by pollTimers.
    //
    // Deferring the transition breaks the recursion
    // recordVote -> enterCommit -> enterNewHeight -> enterPropose ->
    // propose -> broadcastPrecommit -> recordVote, which is unbounded
    // at n=1 where every vote is a quorum.
    //
    // The drain in pollTimers runs *after* the running_ check, so a
    // stopped instance does not enter a pending height. That is what
    // makes stop() mean "inert": a stopped instance cannot advance
    // even if it had a commit in flight when it was stopped.
    std::optional<Height> pending_height_;

    //  Wall-clock timestamp at which the next proposal is allowed.
    //  Zero means "no delay in effect". Set by enterCommit; checked
    //  and cleared by pollTimers.
    uint64_t next_propose_not_before_ms_{0};

    // Votes received for rounds ahead of the local round, keyed by
    // round and then by signer id.
    std::unordered_map<Round, std::unordered_map<Id, Vote>>
        future_round_prevotes_;
    std::unordered_map<Round, std::unordered_map<Id, Vote>>
        future_round_precommits_;

    // Votes received for height_ + 1 while we are still finishing
    // height_. Keyed by height and then by signer id. Drained by
    // enterNewHeight into the pending buffers, which are in turn
    // drained once the step for the new height is set.
    std::unordered_map<Height, std::unordered_map<Id, Vote>>
        future_height_prevotes_;
    std::unordered_map<Height, std::unordered_map<Id, Vote>>
        future_height_precommits_;
    std::unordered_map<Height, Proposal> future_height_proposals_;

    // For each (height, round) we've accepted a proposal for, the
    // block hash of that proposal. Used to answer "which block did
    // this round propose?" without holding the full block.
    std::unordered_map<RoundKey, Crypto::Hash, RoundKeyHash> proposal_for_round_;

    // Evidence of equivocation seen at this height. Survives height
    // transitions so a proposer at H+1 can still include a conflict
    // it observed at H. Cleared for a specific (signer, height,
    // round) when a block containing that evidence is committed.
    std::vector<EquivocationEvidence> equivocations_;

    // Timeout attestations seen at the current height, at rounds
    // >= EMERGENCY_ROTATION_ROUNDS. Accumulated until enough exist
    // to assemble a certificate; then carried in the emergency
    // proposal's header.
    std::vector<TimeoutVote> timeout_votes_;

    // Consecutive rounds at the current height that ended without a
    // commit. Reset to zero on commit and on entering a new height.
    // When it reaches EMERGENCY_ROTATION_ROUNDS, the engine enters
    // emergency mode and uses the derived emergency set for
    // proposer selection and quorum.
    Round consecutive_timeouts_{0};
  };

} // namespace Consensus