// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BftConsensus.h"
#include "Core/EquivocationProof.h"

#include "Core/BlockProcessor.h"
#include "Core/RewardTypes.h"
#include "Crypto/Ed25519.h"

#include <algorithm>
#include <chrono>
#include <functional>
#include <map>
#include <set>

namespace Consensus
{
  //  Construction

  BftConsensus::BftConsensus(Dependencies deps,
                             Callbacks callbacks,
                             Config config,
                             Logging::LoggerRef log)
      : deps_(std::move(deps)), callbacks_(std::move(callbacks)),
        config_(config), log_(log)
  {
    round_timer_ = std::make_unique<Common::RoundTimer>([this]()
                                                        {
                                                          // Timeout handled by pollTimers().
                                                        });
  }

  BftConsensus::~BftConsensus()
  {
    stop();
  }

  //  Lifecycle

  void BftConsensus::start(Height height)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (running_)
      return;

    pending_height_.reset();
    commit_block_.reset();
    commit_attempts_ = 0;
    next_commit_attempt_ms_ = 0;
    external_next_height_.store(0);
    halted_ = false;

    //  Entries below the start height belong to commits that already
    //  succeeded; replaying them would be wrong.
    if (deps_.wal_truncate && height > 0)
      deps_.wal_truncate(height - 1);

    running_ = true;
    enterNewHeight(height);

    log_(Logging::INFO) << "Consensus started at height " << height;
  }

  void BftConsensus::stop()
  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!running_)
      return;

    running_ = false;
    if (round_timer_)
      round_timer_->stop();

    log_(Logging::INFO) << "Consensus stopped at height " << height_
                        << " round " << round_;
  }

  bool BftConsensus::isRunning() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return running_;
  }

  bool BftConsensus::halted() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return halted_;
  }

  void BftConsensus::noteChainHead(Height applied_height)
  {
    //  Lock-free on purpose: the apply path inside code it calls
    //  may report a head advance while the consensus
    //  mutex is held by this very thread.
    const Height next = applied_height + 1;
    Height cur = external_next_height_.load();
    while (next > cur &&
           !external_next_height_.compare_exchange_weak(cur, next))
    {
    }
  }

  void BftConsensus::haltConsensus(const std::string &reason)
  {
    running_ = false;
    halted_ = true;
    commit_block_.reset();
    if (round_timer_)
      round_timer_->stop();

    log_(Logging::WARNING) << "FATAL: consensus halted at height " << height_
                           << ": " << reason;

    if (callbacks_.on_consensus_halt)
      callbacks_.on_consensus_halt(reason);
  }

  //  WAL

  Round BftConsensus::replayWalForHeight(Height height)
  {
    if (!deps_.wal_replay)
      return 0;

    const Id my_id = deps_.my_validator_id();
    if (my_id == INVALID_ID)
      return 0;

    size_t locks_replayed = 0;

    //  Votes go into the signed-vote registry, not into the vote
    //  containers: the registry survives resetForNewRound and is what
    //  prevents us from ever signing a second value for one
    //  (height, round, type). emplace keeps the FIRST entry; the first
    //  signed value is the binding one.
    //
    //  Locks keep the highest round, not whichever entry came last.
    deps_.wal_replay(
        height,
        [&](const Vote &v, bool is_precommit)
        {
          if (v.height != height || v.signer_id != my_id)
            return;
          signed_votes_.emplace(
              SignedKey{v.height, v.round, is_precommit}, v);
        },
        [&](Height h, Round r, const Crypto::Hash &hash)
        {
          if (h != height)
            return;
          if (!locked_ || r >= locked_round_)
          {
            locked_ = true;
            locked_hash_ = hash;
            locked_round_ = r;
          }
          ++locks_replayed;
        });

    Round resume = 0;

    if (locked_)
    {
      //  A lock implies we saw a polka for this block at that round.
      valid_set_ = true;
      valid_hash_ = locked_hash_;
      valid_round_ = locked_round_;
      resume = std::max(resume, locked_round_);

      if (deps_.wal_load_locked_block)
      {
        auto blk = deps_.wal_load_locked_block(height);
        if (blk.has_value() && blk->hash() == locked_hash_)
        {
          proposals_by_hash_[locked_hash_] = *blk;
          proposal_for_round_[{height, locked_round_}] = locked_hash_;
        }
      }
    }

    //  Re-broadcast every vote we signed: a crash between the WAL
    //  append and the broadcast leaves a durable vote no peer saw.
    //  Messages are passed through verbatim.
    for (const auto &[key, v] : signed_votes_)
    {
      resume = std::max(resume, std::get<1>(key));
      const bool is_precommit = std::get<2>(key);
      if (is_precommit)
      {
        if (callbacks_.broadcast_precommit)
          callbacks_.broadcast_precommit(v);
      }
      else
      {
        if (callbacks_.broadcast_prevote)
          callbacks_.broadcast_prevote(v);
      }
    }

    if (!signed_votes_.empty() || locks_replayed > 0)
    {
      log_(Logging::INFO)
          << "WAL replayed for height " << height << ": "
          << signed_votes_.size() << " votes, "
          << locks_replayed << " locks, resuming at round " << resume;
    }

    return resume;
  }

  void BftConsensus::restoreOwnVotes(Round round)
  {
    const Id me = deps_.my_validator_id();
    if (me == INVALID_ID)
      return;

    auto pv = signed_votes_.find(SignedKey{height_, round, false});
    if (pv != signed_votes_.end())
      prevotes_[me] = pv->second;

    auto pc = signed_votes_.find(SignedKey{height_, round, true});
    if (pc != signed_votes_.end())
      precommits_[me] = pc->second;
  }

  //  Set resolution

  bool BftConsensus::roundUsesEmergencySet(Height height, Round round) const
  {
    auto it = proposal_for_round_.find({height, round});
    if (it == proposal_for_round_.end())
      return false;

    auto block_it = proposals_by_hash_.find(it->second);
    if (block_it == proposals_by_hash_.end())
      return false;

    return block_it->second.header.emergency_rotation > 0;
  }

  bool BftConsensus::roundUsesEmergencySetForVote(const Vote &v) const
  {
    if (!v.is_nil && !v.block_hash.isNull())
    {
      auto it = proposals_by_hash_.find(v.block_hash);
      if (it != proposals_by_hash_.end())
        return it->second.header.emergency_rotation > 0;
    }

    return roundUsesEmergencySet(v.height, v.round);
  }

  bool BftConsensus::useEmergencySet() const noexcept
  {
    return consecutive_timeouts_ >= Core::EMERGENCY_ROTATION_ROUNDS;
  }

  bool BftConsensus::stepAtLeastPrevote() const noexcept
  {
    return step_ == Step::Prevote || step_ == Step::Precommit ||
           step_ == Step::Commit;
  }

  Index BftConsensus::indexInSet(Id id, bool emergency) const
  {
    if (id == INVALID_ID)
      return INVALID_INDEX;

    auto active = deps_.active_set(emergency);
    for (size_t i = 0; i < active.size(); ++i)
    {
      if (active[i] == id)
        return static_cast<Index>(i);
    }
    return INVALID_INDEX;
  }

  std::optional<Crypto::PublicKey>
  BftConsensus::resolveConsensusKey(Index idx, bool emergency) const
  {
    auto active = deps_.active_set(emergency);
    if (idx >= active.size())
      return std::nullopt;

    Core::ValidatorInfo vinfo;
    if (!deps_.state_lookup_validator ||
        !deps_.state_lookup_validator(active[idx], vinfo))
    {
      return std::nullopt;
    }

    return vinfo.effectiveConsensusKey();
  }

  //  State machine

  void BftConsensus::enterNewHeight(Height height)
  {
    resetForNewHeight(height);

    //  Replay after the reset so replayed state is not cleared, and
    //  before enterPropose so a replayed lock is visible to the first
    //  prevote. Resume at the highest round we have signed anything in.
    const Round resume = replayWalForHeight(height);

    //  enterPropose adds one for any round > 0; we want the counter to
    //  equal the resumed round (rounds elapsed at this height).
    if (resume > 0)
      consecutive_timeouts_ = resume - 1;

    enterPropose(height, resume);
  }

  void BftConsensus::enterPropose(Height height, Round round)
  {
    resetForNewRound(round);
    step_ = Step::Propose;

    if (round > 0)
      consecutive_timeouts_++;

    //  Put our own already-signed votes for this round back into the
    //  containers (they were cleared by resetForNewRound).
    restoreOwnVotes(round);

    auto active = deps_.active_set(useEmergencySet());
    proposer_ = proposerFor(height, round, active);

    auto my_id = deps_.my_validator_id();
    bool is_proposer = (my_id == proposer_ && my_id != INVALID_ID);

    log_(Logging::DEBUGGING) << "Entering propose: h=" << height
                             << " r=" << round
                             << " proposer=" << proposer_
                             << " self=" << (is_proposer ? "yes" : "no");

    if (round_timer_)
      round_timer_->start(round);

    //  step_ is Propose now, so drained messages are routed correctly.
    //  Proposal first: it populates proposal_for_round_ and
    //  proposals_by_hash_, which the votes consult.
    drainFutureHeightProposal();
    drainFutureProposal();
    drainFutureHeightVotes();
    drainFutureRoundVotes();

    if (height_ != height || round_ != round || step_ != Step::Propose)
      return;

    if (is_proposer)
      tryPropose();
  }

  void BftConsensus::enterPrevote(Height height, Round round)
  {
    if (step_ == Step::Prevote && round_ == round)
      return;

    if (height_ != height || round_ != round)
      return;

    step_ = Step::Prevote;

    log_(Logging::DEBUGGING) << "Entering prevote: h=" << height
                             << " r=" << round;

    const auto hash = selectPrevoteHash();
    broadcastVote(/*is_precommit=*/false,
                  !hash.has_value(),
                  hash.value_or(Crypto::Hash{}));

    //  broadcastVote -> recordVote can advance the machine.
    if (height_ != height || round_ != round || step_ != Step::Prevote)
      return;

    if (round_timer_)
      round_timer_->start(round);

    drainPendingVotes();

    if (height_ != height || round_ != round || step_ != Step::Prevote)
      return;

    //  Prevotes that arrived while we were still in Propose may
    //  already form a polka (our own vote may have been a duplicate of
    //  a restored one and so triggered nothing).
    checkPrevoteQuorum();
  }

  void BftConsensus::enterPrecommit(Height height, Round round)
  {
    if (step_ == Step::Precommit && round_ == round)
      return;

    if (height_ != height || round_ != round)
      return;

    step_ = Step::Precommit;

    log_(Logging::DEBUGGING) << "Entering precommit: h=" << height
                             << " r=" << round;

    auto polka = quorumValue(/*is_precommit=*/false);

    bool precommit_nil = true;
    Crypto::Hash precommit_hash{};

    if (polka.has_value())
    {
      valid_set_ = true;
      valid_hash_ = *polka;
      valid_round_ = round;

      //  Persist the locked block first, then the lock: a block
      //  without a lock is harmless, a lock without its block is not.
      if (deps_.wal_append_locked_block)
      {
        auto it = proposals_by_hash_.find(*polka);
        if (it != proposals_by_hash_.end())
          deps_.wal_append_locked_block(height, it->second);
      }
      if (deps_.wal_append_lock)
        deps_.wal_append_lock(height, round, *polka);

      locked_ = true;
      locked_hash_ = *polka;
      locked_round_ = round;

      precommit_nil = false;
      precommit_hash = *polka;
    }
    else if (locked_)
    {
      //  Retained from the previous implementation (and documented in
      //  the README): with no polka this round, re-precommit the lock.
      //  Standard Tendermint precommits nil here. Model-check this, or
      //  switch to nil.
      precommit_nil = false;
      precommit_hash = locked_hash_;
    }

    broadcastVote(/*is_precommit=*/true, precommit_nil, precommit_hash);

    if (height_ != height || round_ != round || step_ != Step::Precommit)
      return;

    if (round_timer_)
      round_timer_->start(round);

    drainPendingVotes();

    if (height_ != height || round_ != round || step_ != Step::Precommit)
      return;

    checkPrecommitQuorum();
  }

  void BftConsensus::enterCommit(Height height, Round round)
  {
    //  Idempotent: a commit is already in flight or done for this
    //  height. Every further precommit re-observes the same quorum.
    if (pending_height_.has_value() || commit_block_.has_value())
      return;

    if (height != height_)
      return;

    //  The quorum may be in the current round or in an earlier round
    //  of this height (round-crossing).
    const VoteMap *container = nullptr;
    if (round == round_)
    {
      container = &precommits_;
    }
    else
    {
      auto pit = past_precommits_.find(round);
      if (pit == past_precommits_.end())
        return;
      container = &pit->second;
    }

    auto quorum_block = quorumValueIn(*container);
    if (!quorum_block.has_value())
      return;

    auto it = proposals_by_hash_.find(*quorum_block);
    if (it == proposals_by_hash_.end())
    {
      log_(Logging::WARNING)
          << "Precommit quorum for unknown block "
          << quorum_block->toString().substr(0, 16);
      return;
    }

    Core::Block block = it->second;

    //  The set the quorum ran on is the set the block names.
    const bool emergency = (block.header.emergency_rotation > 0);

    //  Mutating commit_round does not change the block hash
    //  (BlockHeader::hash() excludes it); it is what checkQuorum uses
    //  to recompute the signing hash.
    block.header.commit_round = round;

    auto active = deps_.active_set(emergency);
    std::unordered_map<Id, Index> id_to_index;
    for (size_t i = 0; i < active.size(); ++i)
      id_to_index[active[i]] = static_cast<Index>(i);

    block.quorum_signatures.clear();
    block.quorum_signatures.reserve(container->size());

    for (const auto &[vid, vote] : *container)
    {
      if (vote.is_nil)
        continue;
      if (vote.block_hash != *quorum_block)
        continue;

      auto idx_it = id_to_index.find(vid);
      if (idx_it == id_to_index.end())
        continue;

      Crypto::ValidatorSignature vs;
      vs.signer_index = idx_it->second;
      vs.signature = vote.signature;
      block.quorum_signatures.push_back(vs);
    }

    std::sort(block.quorum_signatures.begin(),
              block.quorum_signatures.end(),
              [](const Crypto::ValidatorSignature &a,
                 const Crypto::ValidatorSignature &b)
              {
                return a.signer_index < b.signer_index;
              });

    if (block.quorum_signatures.size() < quorumThreshold(emergency))
    {
      log_(Logging::WARNING)
          << "Precommit quorum reported but signature set is short ("
          << block.quorum_signatures.size() << " < "
          << quorumThreshold(emergency) << ")";
      return;
    }

    step_ = Step::Commit;
    commit_block_ = std::move(block);
    commit_attempts_ = 0;
    next_commit_attempt_ms_ = 0;

    log_(Logging::DEBUGGING) << "Entering commit: h=" << height
                             << " r=" << round;

    tryApplyCommit();
  }

  void BftConsensus::tryApplyCommit()
  {
    if (!commit_block_.has_value())
      return;

    const Height height = height_;
    const Core::Block &block = *commit_block_;

    log_(Logging::DEBUGGING)
        << "Committing block: h=" << height
        << " hash=" << block.hash().toString().substr(0, 16)
        << " quorum_sigs=" << block.quorum_signatures.size()
        << " participants=" << block.participants.size();

    const bool applied =
        callbacks_.on_block_committed
            ? callbacks_.on_block_committed(block)
            : true;

    if (!applied)
    {
      //  The block is decided: 2f+1 precommitted it. Advancing the
      //  round cannot help (everyone is locked on it) and would push
      //  a node with a sick disk toward emergency rotation. Retry in
      //  place; if it still will not apply, halt loudly. If the block
      //  was applied by relay/sync meanwhile, noteChainHead() makes
      //  pollTimers abandon this.
      ++commit_attempts_;

      if (commit_attempts_ > config_.max_commit_retries)
      {
        haltConsensus("committed block at height " + std::to_string(height) +
                      " could not be applied after " +
                      std::to_string(config_.max_commit_retries) + " retries");
        return;
      }

      next_commit_attempt_ms_ =
          deps_.now_ms
              ? deps_.now_ms() +
                    config_.commit_retry_backoff_ms * commit_attempts_
              : 0;

      log_(Logging::WARNING)
          << "Commit callback rejected block at h=" << height
          << " (attempt " << commit_attempts_ << "/"
          << config_.max_commit_retries << "); will retry";
      return;
    }

    //  Success path. Everything that must not happen on a failed apply
    //  happens here.
    consecutive_timeouts_ = 0;

    //  Erase evidence that this block includes. Every node does this,
    //  not just the proposer; the committed block is the source of
    //  truth. One offense per (signer, height, round).
    for (const auto &tx : block.transactions)
    {
      if (tx.tx_type != Core::TxType::Slash)
        continue;

      auto decoded = Core::decodeSlashEvidence(tx.payload);
      if (!decoded.has_value())
        continue;

      const Id target_signer = decoded->vote_a.signer_id;
      const uint64_t target_height = decoded->vote_a.height;
      const uint64_t target_round = decoded->vote_a.round;

      equivocations_.erase(
          std::remove_if(equivocations_.begin(), equivocations_.end(),
                         [&](const EquivocationEvidence &e)
                         {
                           return e.vote_a.signer_id == target_signer &&
                                  e.vote_a.height == target_height &&
                                  e.vote_a.round == target_round;
                         }),
          equivocations_.end());
    }

    if (callbacks_.on_height_advanced)
      callbacks_.on_height_advanced(height + 1);

    if (deps_.wal_truncate)
      deps_.wal_truncate(height);

    commit_block_.reset();
    commit_attempts_ = 0;

    //  Deferred: breaks recordVote -> enterCommit -> enterNewHeight ->
    //  propose -> recordVote recursion (unbounded at n=1).
    pending_height_ = height + 1;

    if (deps_.now_ms)
      next_propose_not_before_ms_ = deps_.now_ms() + MIN_BLOCK_INTERVAL_MS;
  }

  //  Inbound entry points

  void BftConsensus::onProposal(const Proposal &p)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_)
      return;
    handleProposal(p);
  }

  void BftConsensus::onPrevote(const Vote &v)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_)
      return;
    handleVote(v, /*is_precommit=*/false);
  }

  void BftConsensus::onPrecommit(const Vote &v)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_)
      return;
    handleVote(v, /*is_precommit=*/true);
  }

  void BftConsensus::onTimeoutVote(const TimeoutVote &tv)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_)
      return;
    handleTimeoutVote(tv);
  }

  std::optional<Core::Block> BftConsensus::heldQuorumBlock(Height height) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (height != height_)
      return std::nullopt;

    if (commit_block_.has_value())
      return *commit_block_;

    auto find_block = [this](const VoteMap &c) -> std::optional<Core::Block>
    {
      auto h = quorumValueIn(c);
      if (!h.has_value())
        return std::nullopt;
      auto it = proposals_by_hash_.find(*h);
      if (it == proposals_by_hash_.end())
        return std::nullopt;
      return it->second;
    };

    if (auto b = find_block(precommits_))
      return b;

    for (const auto &[round, votes] : past_precommits_)
    {
      (void)round;
      if (auto b = find_block(votes))
        return b;
    }

    return std::nullopt;
  }

  //  Proposal verification

  bool BftConsensus::verifyProposalSignatureIn(const Proposal &p,
                                               bool emergency) const
  {
    auto active = deps_.active_set(emergency);
    if (active.empty())
      return false;

    const Id expected = proposerFor(p.height, p.round, active);
    if (expected == INVALID_ID)
      return false;

    if (p.signer_id != INVALID_ID && p.signer_id != expected)
      return false;

    Index idx = INVALID_INDEX;
    for (size_t i = 0; i < active.size(); ++i)
    {
      if (active[i] == expected)
      {
        idx = static_cast<Index>(i);
        break;
      }
    }
    if (idx == INVALID_INDEX)
      return false;

    //  signer_index is a hint; when present it must agree.
    if (p.signer_id == INVALID_ID)
    {
      if (p.signer_index != idx)
        return false;
    }
    else if (p.signer_index != INVALID_INDEX && p.signer_index != idx)
    {
      return false;
    }

    auto pk = resolveConsensusKey(idx, emergency);
    if (!pk.has_value())
      return false;

    const Crypto::Hash signing_hash =
        proposalSigningHash(p.height, p.round, p.block_hash);
    return Crypto::verify(signing_hash, *pk, p.signature);
  }

  bool BftConsensus::verifyProposalSignature(const Proposal &p) const
  {
    return verifyProposalSignatureIn(p, false) ||
           verifyProposalSignatureIn(p, true);
  }

  bool BftConsensus::proposerSetAllowed(const Proposal &p,
                                        bool block_emergency) const
  {
    if (block_emergency)
      return verifyProposalSignatureIn(p, true);

    if (verifyProposalSignatureIn(p, false))
      return true;

    //  A locked validator in the emergency set may need to re-propose
    //  its (non-emergency) locked block in an emergency round.
    return p.round >= Core::EMERGENCY_ROTATION_ROUNDS &&
           verifyProposalSignatureIn(p, true);
  }

  std::optional<bool> BftConsensus::proposerSetFor(Id me, Round round,
                                                   bool block_emergency) const
  {
    auto is_proposer_in = [&](bool em)
    {
      auto a = deps_.active_set(em);
      return !a.empty() && proposerFor(height_, round, a) == me;
    };

    if (block_emergency)
    {
      if (is_proposer_in(true))
        return std::optional<bool>(true);
      return std::nullopt;
    }

    if (is_proposer_in(false))
      return std::optional<bool>(false);

    if (round >= Core::EMERGENCY_ROTATION_ROUNDS && is_proposer_in(true))
      return std::optional<bool>(true);

    return std::nullopt;
  }

  void BftConsensus::handleProposal(const Proposal &p)
  {
    //  Cheapest check first.
    if (p.block_bytes.size() > config_.max_block_bytes + MAX_PROPOSAL_SLACK_BYTES)
    {
      log_(Logging::WARNING) << "handleProposal REJECT oversize: "
                             << p.block_bytes.size();
      return;
    }

    if (p.height != height_)
    {
      //  Buffer exactly one height ahead, authenticated, first writer
      //  wins.
      if (p.height == height_ + 1 && verifyProposalSignature(p))
        future_height_proposals_.emplace(p.height, p);
      return;
    }

    if (p.round > round_)
    {
      if (p.round - round_ > MAX_FUTURE_ROUNDS)
      {
        log_(Logging::WARNING)
            << "handleProposal REJECT round-too-far: p=" << p.round
            << " local=" << round_;
        return;
      }

      if (!verifyProposalSignature(p))
        return;

      future_proposals_.emplace(p.round, p);
      noteRoundHint(p.signer_id, p.round);
      return;
    }

    if (p.round < round_)
      return;

    if (proposal_.has_value())
      return;

    //  Signature before deserialization, certificate verification and
    //  simulation: the expected proposer's id is public, so anything
    //  not signed by them must cost us almost nothing.
    if (!verifyProposalSignature(p))
    {
      log_(Logging::DEBUGGING) << "handleProposal: bad signature/proposer";
      return;
    }

    Core::Block block;
    if (!Core::Block::deserialize(p.block_bytes.data(),
                                  p.block_bytes.size(),
                                  block))
    {
      log_(Logging::WARNING) << "handleProposal: deserialize failed";
      return;
    }

    const bool block_emergency = (block.header.emergency_rotation > 0);

    if (!proposerSetAllowed(p, block_emergency))
    {
      log_(Logging::WARNING)
          << "Proposal signer not allowed for this block's set (emergency="
          << (block_emergency ? "yes" : "no") << ")";
      return;
    }

    if (!validateProposal(p, block))
    {
      log_(Logging::DEBUGGING) << "Invalid proposal";
      return;
    }

    proposal_ = p;
    proposals_by_hash_[p.block_hash] = block;
    proposal_for_round_[{p.height, p.round}] = p.block_hash;

    log_(Logging::DEBUGGING) << "Accepted proposal for h=" << height_
                             << " r=" << round_
                             << " hash=" << p.block_hash.toString().substr(0, 16);

    //  Votes that were waiting for this block can be counted now.
    drainPendingVotes();

    if (step_ == Step::Propose && height_ == p.height && round_ == p.round)
      enterPrevote(height_, round_);
  }

  bool BftConsensus::validateProposal(const Proposal &p, const Core::Block &block)
  {
    const Crypto::Hash block_hash = block.hash();
    if (block_hash != p.block_hash)
    {
      log_(Logging::WARNING) << "validateProposal: block hash mismatch";
      return false;
    }

    if (block.header.height != p.height)
    {
      log_(Logging::WARNING) << "validateProposal: height mismatch";
      return false;
    }

    //  A block we already validated this height (a re-proposal of a
    //  lock / valid value) needs no second certificate check or
    //  simulation. Its hash covers the emergency flag and certificate.
    if (proposals_by_hash_.count(block_hash) > 0)
      return true;

    const bool emergency = (block.header.emergency_rotation > 0);

    if (emergency)
    {
      if (block.header.timeout_certificate.votes.empty())
      {
        log_(Logging::WARNING)
            << "validateProposal: emergency block carries empty certificate";
        return false;
      }

      const Crypto::Hash computed =
          Core::computeTimeoutCertificateHash(block.header.timeout_certificate);
      if (computed != block.header.timeout_certificate_hash)
      {
        log_(Logging::WARNING) << "validateProposal: certificate hash mismatch";
        return false;
      }

      if (block.header.emergency_rotation > p.round)
      {
        log_(Logging::WARNING) << "validateProposal: emergency round "
                               << block.header.emergency_rotation
                               << " > proposal round " << p.round;
        return false;
      }
      if (block.header.emergency_rotation < Core::EMERGENCY_ROTATION_ROUNDS)
      {
        log_(Logging::WARNING) << "validateProposal: emergency round below threshold";
        return false;
      }

      auto committed = deps_.active_set(/*force_rotation=*/false);
      if (!verifyTimeoutCertificate(block, committed, height_))
      {
        log_(Logging::WARNING) << "validateProposal: bad timeout certificate";
        return false;
      }
    }
    else
    {
      if (!block.header.timeout_certificate.votes.empty() ||
          !block.header.timeout_certificate_hash.isNull())
      {
        log_(Logging::WARNING)
            << "validateProposal: non-emergency block carries certificate";
        return false;
      }
    }

    auto computed_root = simulateBlock(block);
    if (!computed_root.has_value())
    {
      log_(Logging::WARNING) << "validateProposal: simulateBlock returned nullopt";
      return false;
    }

    if (*computed_root != block.header.state_root)
    {
      log_(Logging::WARNING) << "validateProposal: state root mismatch";
      return false;
    }

    return true;
  }

  std::optional<Crypto::Hash> BftConsensus::simulateBlock(const Core::Block &block)
  {
    if (!deps_.simulate_block)
      return std::nullopt;
    return deps_.simulate_block(block);
  }

  //  Vote routing

  void BftConsensus::handleVote(const Vote &v, bool is_precommit)
  {
    if (v.height != height_)
    {
      if (v.height == height_ + 1)
      {
        //  Signature-checked (not block-checked: the block belongs to
        //  a height we have not reached), one slot per signer.
        Id signer = INVALID_ID;
        if (!voteSignatureOk(v, &signer))
          return;

        auto &store = is_precommit ? future_height_precommits_
                                   : future_height_prevotes_;
        auto &bucket = store[v.height];
        if (bucket.size() < MAX_FUTURE_VOTES_PER_ROUND)
          bucket.emplace(signer, v);
      }
      return;
    }

    //  Junk is dropped here. A valid signature with an unknown block is
    //  buffered below, never dropped.
    Id signer = INVALID_ID;
    if (!voteSignatureOk(v, &signer))
      return;

    if (v.round > round_)
    {
      noteRoundHint(signer, v.round); // may skip rounds
      if (v.round > round_)
      {
        bufferFutureVote(v, is_precommit, signer);
        return;
      }
      //  We skipped to this round; fall through and process it.
    }

    if (v.round < round_)
    {
      //  A precommit quorum in any round of this height commits.
      if (is_precommit)
        recordPastPrecommit(v);
      return;
    }

    if (step_ == Step::NewHeight || !voteReady(v))
    {
      pushPending(is_precommit, v);
      return;
    }

    //  No step gating: votes are recorded whenever they arrive. Only
    //  the *transitions* they trigger are step-gated.
    recordVote(v, is_precommit);
  }

  bool BftConsensus::voteReady(const Vote &v) const
  {
    return v.is_nil || proposals_by_hash_.count(v.block_hash) > 0;
  }

  void BftConsensus::pushPending(bool is_precommit, const Vote &v)
  {
    auto &buf = is_precommit ? pending_precommits_ : pending_prevotes_;
    if (buf.size() >= MAX_PENDING_VOTES)
      return;

    size_t same_signer = 0;
    for (const auto &e : buf)
    {
      if (e.signer_id != v.signer_id || e.signer_index != v.signer_index)
        continue;
      if (e.is_nil == v.is_nil && e.block_hash == v.block_hash)
        return; // exact duplicate
      ++same_signer;
    }
    if (same_signer >= MAX_PENDING_PER_SIGNER)
      return;

    buf.push_back(v);
  }

  bool BftConsensus::bufferFutureVote(const Vote &v, bool is_precommit, Id signer)
  {
    if (v.round <= round_)
      return false;
    if (v.round - round_ > MAX_FUTURE_ROUNDS)
      return false;

    auto &store = is_precommit ? future_round_precommits_
                               : future_round_prevotes_;

    auto &bucket = store[v.round];
    if (bucket.size() >= MAX_FUTURE_VOTES_PER_ROUND)
      return false;

    return bucket.emplace(signer, v).second;
  }

  void BftConsensus::drainPendingVotes()
  {
    //  Move the buffers into locals first. Handlers can re-enter the
    //  state machine (commit, round change), which clears or refills
    //  the members; iterating the members would be iterator
    //  invalidation. Handlers re-push anything still not ready.
    std::vector<Vote> pre = std::move(pending_prevotes_);
    std::vector<Vote> com = std::move(pending_precommits_);
    pending_prevotes_.clear();
    pending_precommits_.clear();

    for (const auto &v : pre)
      handleVote(v, /*is_precommit=*/false);
    for (const auto &v : com)
      handleVote(v, /*is_precommit=*/true);
  }

  void BftConsensus::drainFutureProposal()
  {
    auto it = future_proposals_.find(round_);
    if (it == future_proposals_.end())
      return;

    Proposal p = std::move(it->second);
    future_proposals_.erase(it);

    handleProposal(p);
  }

  void BftConsensus::drainFutureHeightProposal()
  {
    for (auto i = future_height_proposals_.begin();
         i != future_height_proposals_.end();)
    {
      if (i->first < height_ || i->first > height_ + 1)
        i = future_height_proposals_.erase(i);
      else
        ++i;
    }

    auto it = future_height_proposals_.find(height_);
    if (it == future_height_proposals_.end())
      return;

    Proposal p = std::move(it->second);
    future_height_proposals_.erase(it);

    handleProposal(p);
  }

  void BftConsensus::drainFutureRoundVotes()
  {
    VoteMap pre, com;

    {
      auto it = future_round_prevotes_.find(round_);
      if (it != future_round_prevotes_.end())
      {
        pre = std::move(it->second);
        future_round_prevotes_.erase(it);
      }
    }
    {
      auto it = future_round_precommits_.find(round_);
      if (it != future_round_precommits_.end())
      {
        com = std::move(it->second);
        future_round_precommits_.erase(it);
      }
    }

    auto prune = [&](auto &store)
    {
      for (auto i = store.begin(); i != store.end();)
      {
        if (i->first <= round_ || i->first > round_ + MAX_FUTURE_ROUNDS)
          i = store.erase(i);
        else
          ++i;
      }
    };
    prune(future_round_prevotes_);
    prune(future_round_precommits_);

    for (const auto &[id, v] : pre)
    {
      (void)id;
      handleVote(v, /*is_precommit=*/false);
    }
    for (const auto &[id, v] : com)
    {
      (void)id;
      handleVote(v, /*is_precommit=*/true);
    }
  }

  void BftConsensus::drainFutureHeightVotes()
  {
    VoteMap pre, com;

    {
      auto it = future_height_prevotes_.find(height_);
      if (it != future_height_prevotes_.end())
      {
        pre = std::move(it->second);
        future_height_prevotes_.erase(it);
      }
    }
    {
      auto it = future_height_precommits_.find(height_);
      if (it != future_height_precommits_.end())
      {
        com = std::move(it->second);
        future_height_precommits_.erase(it);
      }
    }

    auto prune = [&](auto &store)
    {
      for (auto i = store.begin(); i != store.end();)
      {
        if (i->first <= height_ || i->first > height_ + 1)
          i = store.erase(i);
        else
          ++i;
      }
    };
    prune(future_height_prevotes_);
    prune(future_height_precommits_);

    for (const auto &[id, v] : pre)
    {
      (void)id;
      handleVote(v, /*is_precommit=*/false);
    }
    for (const auto &[id, v] : com)
    {
      (void)id;
      handleVote(v, /*is_precommit=*/true);
    }
  }

  //  Signer resolution and vote verification

  Id BftConsensus::resolveVoteSigner(const Vote &v, bool &out_emergency) const
  {
    if (v.signer_id != INVALID_ID)
    {
      bool set_known = false;

      if (!v.is_nil && !v.block_hash.isNull())
      {
        auto it = proposals_by_hash_.find(v.block_hash);
        if (it != proposals_by_hash_.end())
        {
          out_emergency = it->second.header.emergency_rotation > 0;
          set_known = true;
        }
      }

      if (!set_known)
      {
        auto it = proposal_for_round_.find({v.height, v.round});
        if (it != proposal_for_round_.end())
        {
          auto block_it = proposals_by_hash_.find(it->second);
          if (block_it != proposals_by_hash_.end())
          {
            out_emergency = block_it->second.header.emergency_rotation > 0;
            set_known = true;
          }
        }
      }

      if (!set_known)
      {
        //  Genuinely ambiguous: accept membership in either set. The
        //  signature check still binds the vote to the signer's key.
        for (bool emergency : {false, true})
        {
          auto active = deps_.active_set(emergency);
          if (std::find(active.begin(), active.end(), v.signer_id) != active.end())
          {
            out_emergency = emergency;
            return v.signer_id;
          }
        }
        return INVALID_ID;
      }

      auto active = deps_.active_set(out_emergency);
      if (std::find(active.begin(), active.end(), v.signer_id) == active.end())
        return INVALID_ID;
      return v.signer_id;
    }

    //  Pre-upgrade fallback (no signer_id).
    out_emergency = roundUsesEmergencySetForVote(v);
    auto active = deps_.active_set(out_emergency);
    if (v.signer_index >= active.size())
      return INVALID_ID;
    return active[v.signer_index];
  }

  bool BftConsensus::verifyVoteSignature(const Vote &v, Id signer_id) const
  {
    Core::ValidatorInfo vinfo;
    if (!deps_.state_lookup_validator ||
        !deps_.state_lookup_validator(signer_id, vinfo))
      return false;

    const Crypto::PublicKey pk = vinfo.effectiveConsensusKey();
    const Crypto::Hash signing_hash =
        voteSigningHash(v.height, v.round, v.is_nil, v.block_hash);
    return Crypto::verify(signing_hash, pk, v.signature);
  }

  bool BftConsensus::voteSignatureOk(const Vote &v, Id *out_signer) const
  {
    bool emergency = false;
    const Id signer = resolveVoteSigner(v, emergency);
    if (signer == INVALID_ID)
      return false;

    if (!verifyVoteSignature(v, signer))
      return false;

    if (out_signer)
      *out_signer = signer;
    return true;
  }

  //  Recording votes

  BftConsensus::InsertResult
  BftConsensus::insertVote(VoteMap &container, const Vote &v, Id voter_id)
  {
    auto existing = container.find(voter_id);
    if (existing == container.end())
    {
      container.emplace(voter_id, v);
      return InsertResult::Inserted;
    }

    const Vote &first = existing->second;
    if (first.block_hash == v.block_hash && first.is_nil == v.is_nil)
      return InsertResult::Duplicate;

    //  Conflict. Record evidence only if BOTH signatures verify: a
    //  forged conflict must never poison the proposer's buffer.
    Core::ValidatorInfo vinfo;
    if (!deps_.state_lookup_validator ||
        !deps_.state_lookup_validator(voter_id, vinfo))
      return InsertResult::Conflict;

    const Crypto::PublicKey pk = vinfo.effectiveConsensusKey();

    const Crypto::Hash first_hash = voteSigningHash(
        first.height, first.round, first.is_nil, first.block_hash);
    const Crypto::Hash second_hash = voteSigningHash(
        v.height, v.round, v.is_nil, v.block_hash);

    if (!Crypto::verify(first_hash, pk, first.signature) ||
        !Crypto::verify(second_hash, pk, v.signature))
    {
      log_(Logging::WARNING)
          << "Conflicting vote with bad signature, not recording: vid="
          << voter_id << " h=" << v.height << " r=" << v.round;
      return InsertResult::Conflict;
    }

    const bool already_have = std::any_of(
        equivocations_.begin(), equivocations_.end(),
        [&](const EquivocationEvidence &e)
        {
          return e.vote_a.signer_id == voter_id &&
                 e.vote_a.height == first.height &&
                 e.vote_a.round == first.round;
        });

    if (!already_have)
    {
      EquivocationEvidence ev;
      ev.vote_a = first;
      ev.vote_b = v;
      ev.signer_id = voter_id;
      if (ev.isValid())
      {
        equivocations_.push_back(ev);
        if (equivocations_.size() > MAX_EQUIVOCATION_EVIDENCE)
          equivocations_.erase(equivocations_.begin());

        log_(Logging::WARNING)
            << "Equivocation evidence recorded: vid=" << voter_id
            << " h=" << v.height << " r=" << v.round;
      }
    }

    return InsertResult::Conflict;
  }

  bool BftConsensus::recordVote(const Vote &v, bool is_precommit)
  {
    if (v.height != height_ || v.round != round_)
      return false;

    bool emergency = false;
    const Id voter_id = resolveVoteSigner(v, emergency);
    if (voter_id == INVALID_ID)
      return false;

    if (!verifyVoteSignature(v, voter_id))
      return false;

    auto &container = is_precommit ? precommits_ : prevotes_;
    if (insertVote(container, v, voter_id) != InsertResult::Inserted)
      return false;

    log_(Logging::DEBUGGING) << (is_precommit ? "Precommit" : "Prevote")
                             << " received: h=" << v.height
                             << " r=" << v.round
                             << " vid=" << voter_id
                             << " nil=" << v.is_nil
                             << " em=" << (emergency ? "yes" : "no");

    if (is_precommit)
      checkPrecommitQuorum();
    else
      checkPrevoteQuorum();

    return true;
  }

  void BftConsensus::recordPastPrecommit(const Vote &v)
  {
    if (v.round + MAX_PAST_ROUNDS < round_)
      return;

    //  A past-round precommit can only be counted against a block we
    //  hold; without it there is nothing to commit.
    if (!voteReady(v))
      return;

    bool emergency = false;
    const Id voter_id = resolveVoteSigner(v, emergency);
    if (voter_id == INVALID_ID || !verifyVoteSignature(v, voter_id))
      return;

    auto &bucket = past_precommits_[v.round];
    if (insertVote(bucket, v, voter_id) != InsertResult::Inserted)
      return;

    while (past_precommits_.size() > MAX_PAST_ROUNDS)
      past_precommits_.erase(past_precommits_.begin());

    if (quorumValueIn(bucket).has_value())
      enterCommit(height_, v.round);
  }

  void BftConsensus::checkPrevoteQuorum()
  {
    auto polka = quorumValue(/*is_precommit=*/false);
    if (!polka.has_value())
      return;

    //  Record the valid value whenever a polka is seen at step >=
    //  Prevote, not only inside enterPrecommit.
    if (stepAtLeastPrevote() && (!valid_set_ || valid_round_ < round_))
    {
      valid_set_ = true;
      valid_hash_ = *polka;
      valid_round_ = round_;
    }

    if (step_ == Step::Prevote)
      enterPrecommit(height_, round_);
  }

  void BftConsensus::checkPrecommitQuorum()
  {
    //  A precommit quorum commits regardless of the current step: the
    //  block is known (a precondition of quorumValue). This is what
    //  makes late/round-crossing recovery work.
    if (quorumValue(/*is_precommit=*/true).has_value())
      enterCommit(height_, round_);
  }

  std::optional<Crypto::Hash> BftConsensus::quorumValue(bool is_precommit) const
  {
    return quorumValueIn(is_precommit ? precommits_ : prevotes_);
  }

  std::optional<Crypto::Hash>
  BftConsensus::quorumValueIn(const VoteMap &container) const
  {
    std::unordered_map<Crypto::Hash, size_t> count_by_hash;

    for (const auto &[vid, v] : container)
    {
      (void)vid;
      if (v.is_nil)
        continue;
      if (proposals_by_hash_.find(v.block_hash) == proposals_by_hash_.end())
        continue;
      count_by_hash[v.block_hash]++;
    }

    //  Threshold per hash, from that block's own set. A single
    //  threshold taken from an arbitrary vote could conjure a polka.
    for (const auto &[hash, count] : count_by_hash)
    {
      auto it = proposals_by_hash_.find(hash);
      if (it == proposals_by_hash_.end())
        continue;

      const bool emergency = (it->second.header.emergency_rotation > 0);
      if (count >= quorumThreshold(emergency))
        return hash;
    }

    return std::nullopt;
  }

  size_t BftConsensus::quorumThreshold(bool emergency) const
  {
    auto active = deps_.active_set(emergency);
    return Core::bftQuorum(active.size());
  }

  //  Own votes

  std::optional<Crypto::Hash> BftConsensus::selectPrevoteHash() const
  {
    //  By hash, not by block: after a restart the locked block may be
    //  missing, and a lock must still be honoured.
    if (locked_)
    {
      if (valid_set_ && valid_round_ > locked_round_)
        return valid_hash_;
      return locked_hash_;
    }

    if (valid_set_)
      return valid_hash_;

    if (proposal_.has_value() &&
        proposal_->height == height_ &&
        proposal_->round == round_)
      return proposal_->block_hash;

    return std::nullopt;
  }

  bool BftConsensus::ownVoteSet(bool is_nil, const Crypto::Hash &block_hash) const
  {
    //  A vote belongs to the set of the block it references (so a
    //  validator locked on a normal block can keep voting it in an
    //  emergency round even if it is not in the emergency set).
    if (!is_nil)
    {
      auto it = proposals_by_hash_.find(block_hash);
      if (it != proposals_by_hash_.end())
        return it->second.header.emergency_rotation > 0;

      //  Block unknown (e.g. restored lock without block bytes):
      //  committed set if we are in it, else emergency.
      const Id me = deps_.my_validator_id();
      return indexInSet(me, false) == INVALID_INDEX;
    }

    if (proposal_for_round_.count({height_, round_}) > 0)
      return roundUsesEmergencySet(height_, round_);

    return useEmergencySet();
  }

  void BftConsensus::broadcastVote(bool is_precommit, bool is_nil,
                                   const Crypto::Hash &block_hash)
  {
    //  Capture before any re-entrant call: recordVote can advance the
    //  height/round.
    const Height v_height = height_;
    const Round v_round = round_;
    const Id me = deps_.my_validator_id();
    if (me == INVALID_ID)
      return;

    const SignedKey key{v_height, v_round, is_precommit};

    //  Never sign a second value for one (height, round, type). If we
    //  already signed (before a restart, or earlier this round), send
    //  exactly that vote again.
    auto prior = signed_votes_.find(key);
    if (prior != signed_votes_.end())
    {
      const Vote pv = prior->second;
      recordVote(pv, is_precommit);
      if (is_precommit)
      {
        if (callbacks_.broadcast_precommit)
          callbacks_.broadcast_precommit(pv);
      }
      else
      {
        if (callbacks_.broadcast_prevote)
          callbacks_.broadcast_prevote(pv);
      }
      return;
    }

    const bool emergency_set = ownVoteSet(is_nil, block_hash);
    const Index idx = indexInSet(me, emergency_set);
    if (idx == INVALID_INDEX)
      return;

    Vote v;
    v.height = v_height;
    v.round = v_round;
    v.signer_id = me;
    v.signer_index = idx;
    v.is_nil = is_nil;
    v.block_hash = block_hash;

    const Crypto::Hash signing_hash =
        voteSigningHash(v_height, v_round, is_nil, block_hash);
    if (deps_.sign)
      v.signature = deps_.sign(signing_hash);

    //  Durable before anything else can observe or send it.
    if (deps_.wal_append_vote)
      deps_.wal_append_vote(v, is_precommit);

    signed_votes_.emplace(key, v);

    recordVote(v, is_precommit);

    if (is_precommit)
    {
      if (callbacks_.broadcast_precommit)
        callbacks_.broadcast_precommit(v);
    }
    else
    {
      if (callbacks_.broadcast_prevote)
        callbacks_.broadcast_prevote(v);
    }
  }

  void BftConsensus::broadcastProposal(const Proposal &p)
  {
    if (callbacks_.broadcast_proposal)
      callbacks_.broadcast_proposal(p);
  }

  //  Proposing

  void BftConsensus::tryPropose()
  {
    if (step_ != Step::Propose)
      return;

    if (proposal_.has_value())
      return;

    auto my_id = deps_.my_validator_id();
    if (my_id == INVALID_ID)
      return;
    if (my_id != proposer_)
      return;

    //  If we already signed a prevote this round we already proposed
    //  (and then crashed, or are being retried). A second, different
    //  proposal for the same (height, round) would be an equivocation.
    if (signed_votes_.count(SignedKey{height_, round_, false}) > 0)
      return;

    propose();
  }

  Core::Block BftConsensus::buildFreshBlock() const
  {
    Core::Block block;
    const bool emergency = useEmergencySet();
    auto active = deps_.active_set(emergency);

    block.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
    block.header.chain_id = deps_.chain_id ? deps_.chain_id() : 0;
    block.header.height = height_;
    block.header.timestamp_ms =
        deps_.now_ms
            ? deps_.now_ms()
            : static_cast<uint64_t>(
                  std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count());
    block.header.parent_hash =
        deps_.parent_hash ? deps_.parent_hash() : Crypto::Hash{};

    if (callbacks_.select_transactions)
    {
      constexpr uint64_t MAX_HEADER_RESERVE = 4 * 1024;
      block.transactions = callbacks_.select_transactions(
          config_.max_block_bytes > MAX_HEADER_RESERVE
              ? config_.max_block_bytes - MAX_HEADER_RESERVE
              : 0,
          config_.max_block_txs);
    }

    uint64_t total_fees = 0;
    for (const auto &tx : block.transactions)
      total_fees += tx.fee;
    block.header.total_fees = total_fees;

    block.header.tx_root = Core::computeTxRoot(block.transactions);
    block.header.tx_count = static_cast<uint32_t>(block.transactions.size());
    block.header.validator_set_root = Core::computeValidatorSetRoot(active);
    block.header.active_validator_count = static_cast<uint32_t>(active.size());
    block.header.commit_round = round_;
    block.participants = active;
    block.header.proposer =
        deps_.my_address ? deps_.my_address() : Crypto::Address{};

    return block;
  }

  bool BftConsensus::propose()
  {
    const Height propose_height = height_;
    const Round propose_round = round_;

    const Id me = deps_.my_validator_id();
    if (me == INVALID_ID)
      return false;

    //  Re-propose the lock / valid value if we hold its block. If we
    //  hold the hash but not the block (restart without a stored
    //  block), we propose fresh: locked validators will still prevote
    //  their lock, and a locked proposer may legally propose anything.
    Core::Block block;
    bool re_proposing = false;

    if (const auto want = selectPrevoteHash())
    {
      auto it = proposals_by_hash_.find(*want);
      if (it != proposals_by_hash_.end())
      {
        block = it->second;
        block.header.commit_round = round_;
        block.quorum_signatures.clear();
        re_proposing = true;
        log_(Logging::INFO) << "Re-proposing block for h=" << height_
                            << " r=" << round_
                            << " hash=" << want->toString().substr(0, 16);
      }
      else
      {
        log_(Logging::WARNING)
            << "Holding a lock/valid value whose block is unknown; "
            << "proposing a fresh block";
      }
    }

    if (!re_proposing)
    {
      block = buildFreshBlock();

      if (!equivocations_.empty())
      {
        std::set<Id> already_slashed;

        for (const auto &ev : equivocations_)
        {
          if (!ev.isValid())
            continue;
          const Id target = ev.vote_a.signer_id;
          if (target == INVALID_ID)
            continue;
          if (already_slashed.count(target) > 0)
            continue;
          if (block.transactions.size() >= config_.max_block_txs)
            break;

          auto payload = Core::encodeSlashPayload(
              encodeVote(ev.vote_a), encodeVote(ev.vote_b));

          //  Not "target is in the active set": a validator inside its
          //  unbonding window has left the active set but must stay
          //  slashable.
          if (deps_.verify_slash_proof)
          {
            if (!deps_.verify_slash_proof(payload))
            {
              log_(Logging::WARNING)
                  << "Skipping unverifiable equivocation evidence: signer="
                  << target << " h=" << ev.vote_a.height
                  << " r=" << ev.vote_a.round;
              continue;
            }
          }
          else
          {
            Core::ValidatorInfo vi;
            if (!deps_.state_lookup_validator ||
                !deps_.state_lookup_validator(target, vi))
              continue;
          }

          Core::Transaction slash_tx{};
          slash_tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
          slash_tx.chain_id = block.header.chain_id;
          slash_tx.tx_type = Core::TxType::Slash;
          slash_tx.payload = std::move(payload);

          block.transactions.push_back(std::move(slash_tx));
          already_slashed.insert(target);
        }

        if (!block.transactions.empty())
        {
          block.header.tx_root = Core::computeTxRoot(block.transactions);
          block.header.tx_count =
              static_cast<uint32_t>(block.transactions.size());
        }
      }

      if (useEmergencySet())
      {
        Round cert_round = 0;
        if (!assembleTimeoutCertificate(cert_round,
                                        block.header.timeout_certificate))
        {
          log_(Logging::WARNING)
              << "Emergency rotation triggered locally but no certificate "
              << "available; refusing to propose";
          return false;
        }
        block.header.emergency_rotation = cert_round;
        block.header.timeout_certificate_hash =
            Core::computeTimeoutCertificateHash(block.header.timeout_certificate);
      }
    }

    //  Which set do we sign this proposal as? The block's flag decides,
    //  not the local counter, so verifiers (which key off the block)
    //  agree with us.
    const bool block_emergency = (block.header.emergency_rotation > 0);
    const std::optional<bool> signer_set =
        proposerSetFor(me, propose_round, block_emergency);
    if (!signer_set.has_value())
    {
      log_(Logging::WARNING)
          << "Not the entitled proposer for this block at r=" << propose_round
          << " (block emergency=" << (block_emergency ? "yes" : "no") << ")";
      return false;
    }

    auto sim_root = simulateBlock(block);
    if (!sim_root.has_value() && !re_proposing && !block.transactions.empty())
    {
      //  Never strip a re-proposal: that would change its hash.
      const size_t txs_before = block.transactions.size();
      block.transactions.erase(
          std::remove_if(block.transactions.begin(),
                         block.transactions.end(),
                         [](const Core::Transaction &tx)
                         {
                           return tx.tx_type == Core::TxType::Slash;
                         }),
          block.transactions.end());

      if (block.transactions.size() != txs_before)
      {
        log_(Logging::WARNING)
            << "Proposal simulation failed with Slash txs; retrying without";
        block.header.tx_count =
            static_cast<uint32_t>(block.transactions.size());
        block.header.tx_root = Core::computeTxRoot(block.transactions);
        sim_root = simulateBlock(block);
      }
    }

    if (!sim_root.has_value())
    {
      log_(Logging::WARNING) << "Proposed block failed simulation"
                             << (re_proposing ? " (re-proposal)" : "");
      return false;
    }
    block.header.state_root = *sim_root;

    const Crypto::Hash block_hash = block.hash();
    Proposal p;
    p.height = propose_height;
    p.round = propose_round;
    p.signer_id = me;
    p.signer_index = indexInSet(me, *signer_set);
    p.block_hash = block_hash;
    p.block_bytes = block.serialize();

    const Crypto::Hash signing_hash =
        proposalSigningHash(propose_height, propose_round, block_hash);
    if (deps_.sign)
      p.signature = deps_.sign(signing_hash);

    broadcastProposal(p);

    proposal_ = p;
    proposals_by_hash_[block_hash] = block;
    proposal_for_round_[{propose_height, propose_round}] = block_hash;

    log_(Logging::DEBUGGING) << (re_proposing ? "Re-proposed" : "Proposed")
                             << " block for h=" << propose_height
                             << " r=" << propose_round
                             << " em=" << (block_emergency ? "yes" : "no")
                             << " txs=" << block.transactions.size()
                             << " hash=" << block_hash.toString().substr(0, 16);

    if (step_ == Step::Propose &&
        height_ == propose_height &&
        round_ == propose_round)
    {
      enterPrevote(height_, round_);
    }

    return true;
  }

  //  Timeouts

  void BftConsensus::pollTimers()
  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!running_)
      return;

    //  The chain advanced outside consensus (relay/sync). Follow it,
    //  abandoning any in-flight commit retry and bypassing pacing.
    {
      const Height ext = external_next_height_.load();
      const Height target = pending_height_.value_or(height_);
      if (ext != 0 && ext > target)
      {
        log_(Logging::INFO) << "Chain advanced externally; jumping from h="
                            << height_ << " to h=" << ext;

        commit_block_.reset();
        commit_attempts_ = 0;
        pending_height_.reset();
        next_propose_not_before_ms_ = 0;

        if (deps_.wal_truncate)
          deps_.wal_truncate(ext - 1);

        enterNewHeight(ext);
        return;
      }
    }

    //  Retry an in-flight commit apply.
    if (commit_block_.has_value())
    {
      if (!deps_.now_ms || deps_.now_ms() >= next_commit_attempt_ms_)
        tryApplyCommit();
      return;
    }

    if (pending_height_.has_value())
    {
      //  Pacing: wait out MIN_BLOCK_INTERVAL_MS unless there is work.
      //  With has_pending_work unset the engine behaves as if there
      //  is always work (no pacing).
      if (next_propose_not_before_ms_ != 0)
      {
        const uint64_t now = deps_.now_ms ? deps_.now_ms() : 0;

        if (now < next_propose_not_before_ms_)
        {
          const bool pending =
              !deps_.has_pending_work || deps_.has_pending_work();
          if (!pending)
            return;
        }

        next_propose_not_before_ms_ = 0;
      }

      const Height next = *pending_height_;
      pending_height_.reset();
      enterNewHeight(next);
      return;
    }

    if (!round_timer_)
      return;

    if (!round_timer_->isExpired())
      return;

    round_timer_->stop();

    switch (step_)
    {
    case Step::Propose:
      onProposeTimeout();
      break;
    case Step::Prevote:
      onPrevoteTimeout();
      break;
    case Step::Precommit:
      onPrecommitTimeout();
      break;
    default:
      break;
    }
  }

  void BftConsensus::onProposeTimeout()
  {
    log_(Logging::DEBUGGING) << "Propose timeout: h=" << height_
                             << " r=" << round_;

    broadcastTimeoutVote(round_);
    enterPrevote(height_, round_);
  }

  void BftConsensus::onPrevoteTimeout()
  {
    log_(Logging::DEBUGGING) << "Prevote timeout: h=" << height_
                             << " r=" << round_;

    broadcastTimeoutVote(round_);
    enterPrecommit(height_, round_);
  }

  void BftConsensus::onPrecommitTimeout()
  {
    auto quorum_block = quorumValue(/*is_precommit=*/true);

    log_(Logging::DEBUGGING) << "onPrecommitTimeout: h=" << height_
                             << " r=" << round_
                             << " precommits=" << precommits_.size()
                             << " quorum=" << (quorum_block ? "yes" : "no");

    broadcastTimeoutVote(round_);

    if (quorum_block.has_value() &&
        proposals_by_hash_.count(*quorum_block) > 0)
    {
      enterCommit(height_, round_);

      //  If a commit is in flight (or the engine halted), do NOT
      //  advance the round.
      if (commit_block_.has_value() || pending_height_.has_value() ||
          !running_)
        return;
    }

    enterPropose(height_, round_ + 1);
  }

  //  Timeout certificate

  void BftConsensus::broadcastTimeoutVote(Round round)
  {
    //  Receivers ignore anything below the emergency threshold, so do
    //  not sign or send it.
    if (round < Core::EMERGENCY_ROTATION_ROUNDS)
      return;

    const Id my_id = deps_.my_validator_id();
    const Index idx = indexInSet(my_id, /*emergency=*/false);
    if (idx == INVALID_INDEX)
      return;

    TimeoutVote tv;
    tv.height = height_;
    tv.round = round;
    tv.signer_id = my_id;
    tv.signer_index = idx;

    const Crypto::Hash signing_hash =
        timeoutVoteSigningHash(tv.height, tv.round);
    if (deps_.sign)
      tv.signature = deps_.sign(signing_hash);

    //  Count our own vote: fan-out (harness and real P2P) skips the
    //  sender. If we already stored ours for this round, we have
    //  already sent it; do not repeat it for each step timeout.
    if (!storeTimeoutVote(tv))
      return;

    if (callbacks_.broadcast_timeout_vote)
      callbacks_.broadcast_timeout_vote(tv);
  }

  bool BftConsensus::storeTimeoutVote(const TimeoutVote &tv)
  {
    size_t per_signer = 0;
    for (const auto &existing : timeout_votes_)
    {
      if (existing.signer_id != tv.signer_id)
        continue;
      if (existing.round == tv.round)
        return false;
      ++per_signer;
    }

    if (per_signer >= MAX_TIMEOUT_VOTES_PER_SIGNER)
      return false;
    if (timeout_votes_.size() >= MAX_TIMEOUT_VOTES)
      return false;

    timeout_votes_.push_back(tv);
    return true;
  }

  void BftConsensus::handleTimeoutVote(const TimeoutVote &tv)
  {
    if (tv.height != height_)
      return;

    if (tv.round < Core::EMERGENCY_ROTATION_ROUNDS)
      return;

    if (tv.round > round_ + MAX_FUTURE_ROUNDS)
      return;

    auto committed = deps_.active_set(/*force_rotation=*/false);

    Id voter_id = tv.signer_id;
    if (voter_id == INVALID_ID)
    {
      if (tv.signer_index >= committed.size())
        return;
      voter_id = committed[tv.signer_index];
    }
    else
    {
      if (std::find(committed.begin(), committed.end(), voter_id) ==
          committed.end())
        return;

      if (tv.signer_index != INVALID_INDEX)
      {
        if (tv.signer_index >= committed.size() ||
            committed[tv.signer_index] != voter_id)
          return;
      }
    }

    Core::ValidatorInfo vinfo;
    if (!deps_.state_lookup_validator ||
        !deps_.state_lookup_validator(voter_id, vinfo))
      return;

    const Crypto::Hash signing_hash =
        timeoutVoteSigningHash(tv.height, tv.round);
    if (!Crypto::verify(signing_hash, vinfo.effectiveConsensusKey(),
                        tv.signature))
      return;

    TimeoutVote stored = tv;
    stored.signer_id = voter_id;

    if (!storeTimeoutVote(stored))
      return;

    retryEmergencyPropose();
  }

  void BftConsensus::retryEmergencyPropose()
  {
    if (step_ != Step::Propose)
      return;
    if (proposal_.has_value())
      return;
    if (!useEmergencySet())
      return;

    const Id my_id = deps_.my_validator_id();
    if (my_id == INVALID_ID || my_id != proposer_)
      return;

    //  The certificate may be for an earlier round than round_; that is
    //  legal (validateProposal only rejects emergency_rotation > round).
    tryPropose();
  }

  bool BftConsensus::assembleTimeoutCertificate(Round &out_round,
                                                TimeoutCertificate &out) const
  {
    auto committed = deps_.active_set(/*force_rotation=*/false);
    if (committed.size() < 4)
      return false;

    const size_t f = (committed.size() - 1) / 3;
    const size_t required = f + 1;

    std::map<Round, std::vector<const TimeoutVote *>> by_round;
    for (const auto &tv : timeout_votes_)
    {
      if (tv.round < Core::EMERGENCY_ROTATION_ROUNDS)
        continue;
      by_round[tv.round].push_back(&tv);
    }

    for (auto &[round, votes] : by_round)
    {
      std::set<Id> seen;
      std::vector<TimeoutVote> picked;
      picked.reserve(required);

      for (const TimeoutVote *tv : votes)
      {
        if (tv->signer_id == INVALID_ID)
          continue;
        if (std::find(committed.begin(), committed.end(), tv->signer_id) ==
            committed.end())
          continue;
        if (seen.count(tv->signer_id) > 0)
          continue;
        seen.insert(tv->signer_id);
        picked.push_back(*tv);
        if (picked.size() >= required)
          break;
      }

      if (picked.size() >= required)
      {
        out.votes = std::move(picked);
        out_round = round;
        return true;
      }
    }

    return false;
  }

  bool BftConsensus::verifyTimeoutCertificate(
      const Core::Block &block,
      const std::vector<Id> &committed_set,
      Height height) const
  {
    auto lookup = [this](Id vid, Core::ValidatorInfo &out) -> bool
    {
      return deps_.state_lookup_validator &&
             deps_.state_lookup_validator(vid, out);
    };

    std::string error;
    const bool ok = Consensus::verifyTimeoutCertificate(
        block.header.timeout_certificate,
        committed_set,
        /*cert_height=*/height,
        /*cert_round=*/block.header.emergency_rotation,
        lookup,
        error);

    if (!ok)
      log_(Logging::WARNING) << "Timeout certificate invalid: " << error;

    return ok;
  }

  //  f+1 round skip

  void BftConsensus::noteRoundHint(Id signer, Round round)
  {
    if (signer == INVALID_ID || round <= round_)
      return;

    auto &r = round_hints_[signer];
    if (round > r)
      r = round;

    maybeSkipRound();
  }

  void BftConsensus::maybeSkipRound()
  {
    if (!running_ || step_ == Step::Commit ||
        pending_height_.has_value() || commit_block_.has_value())
      return;

    auto committed = deps_.active_set(/*force_rotation=*/false);
    if (committed.empty())
      return;

    const size_t required = (committed.size() - 1) / 3 + 1;

    std::vector<Round> rounds;
    for (const auto &[id, r] : round_hints_)
    {
      if (r <= round_)
        continue;
      if (std::find(committed.begin(), committed.end(), id) == committed.end())
        continue;
      rounds.push_back(r);
    }

    if (rounds.size() < required)
      return;

    //  (f+1)-th highest: at least f+1 validators, so at least one
    //  honest one, are at round >= target.
    std::sort(rounds.begin(), rounds.end(), std::greater<Round>());
    const Round target = rounds[required - 1];
    if (target <= round_)
      return;

    log_(Logging::INFO) << "Round skip: h=" << height_ << " r=" << round_
                        << " -> r=" << target;

    for (auto it = round_hints_.begin(); it != round_hints_.end();)
    {
      if (it->second <= target)
        it = round_hints_.erase(it);
      else
        ++it;
    }

    //  enterPropose adds one for any round > 0.
    consecutive_timeouts_ = target - 1;
    enterPropose(height_, target);
  }

  //  Reset

  void BftConsensus::resetForNewHeight(Height height)
  {
    height_ = height;
    round_ = 0;
    step_ = Step::NewHeight;

    consecutive_timeouts_ = 0;

    locked_ = false;
    locked_hash_ = Crypto::Hash{};
    locked_round_ = 0;

    valid_set_ = false;
    valid_hash_ = Crypto::Hash{};
    valid_round_ = 0;

    proposal_.reset();
    proposals_by_hash_.clear();
    prevotes_.clear();
    precommits_.clear();
    past_precommits_.clear();
    signed_votes_.clear();

    pending_prevotes_.clear();
    pending_precommits_.clear();

    future_proposals_.clear();
    future_round_prevotes_.clear();
    future_round_precommits_.clear();
    proposal_for_round_.clear();

    timeout_votes_.clear();
    round_hints_.clear();

    commit_block_.reset();
    commit_attempts_ = 0;
    next_commit_attempt_ms_ = 0;
    next_propose_not_before_ms_ = 0;

    //  future_height_* are pruned by their drains, not cleared: they
    //  hold the messages for THIS height that arrived early.
    //  equivocations_ deliberately survives height changes.
  }

  void BftConsensus::resetForNewRound(Round round)
  {
    //  Keep the precommits of the round we are leaving: a precommit
    //  quorum in any round of this height commits.
    if (!precommits_.empty())
    {
      auto &bucket = past_precommits_[round_];
      for (const auto &kv : precommits_)
        bucket.emplace(kv.first, kv.second);

      while (past_precommits_.size() > MAX_PAST_ROUNDS)
        past_precommits_.erase(past_precommits_.begin());
    }

    round_ = round;

    proposal_.reset();
    prevotes_.clear();
    precommits_.clear();

    pending_prevotes_.clear();
    pending_precommits_.clear();

    //  Prune (do not clear) the future-scoped buffers; the new
    //  round's entries are drained by enterPropose after step_ is set.
    auto prune_by_round = [this](auto &store)
    {
      for (auto it = store.begin(); it != store.end();)
      {
        if (it->first < round_)
          it = store.erase(it);
        else
          ++it;
      }
    };

    prune_by_round(future_proposals_);
    prune_by_round(future_round_prevotes_);
    prune_by_round(future_round_precommits_);

    //  locked_* and valid_* persist across rounds; cleared only by
    //  resetForNewHeight.
  }

  //  Introspection

  BftConsensus::State BftConsensus::state() const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    State s;
    s.height = height_;
    s.round = round_;
    s.step = step_;
    s.is_proposer = (deps_.my_validator_id() == proposer_);
    s.locked = locked_;
    s.locked_hash = locked_hash_;
    s.locked_round = locked_round_;
    s.prevote_count = prevotes_.size();
    s.precommit_count = precommits_.size();
    s.halted = halted_;
    return s;
  }

  void BftConsensus::forceTimerExpiryForTest()
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (round_timer_)
      round_timer_->forceExpire();
  }

  size_t BftConsensus::equivocationCount() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return equivocations_.size();
  }

  Round BftConsensus::consecutiveTimeouts() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return consecutive_timeouts_;
  }

  bool BftConsensus::emergencyRotationActive() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return useEmergencySet();
  }

  std::optional<Proposal> BftConsensus::currentProposalForTest() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return proposal_;
  }
} // namespace Consensus