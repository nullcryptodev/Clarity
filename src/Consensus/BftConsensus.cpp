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

    //  Discard any pending height transition from a previous run.
    //  A stopped instance may have had a commit in flight when stop()
    //  was called; the pending transition it left behind refers to a
    //  height that has since been superseded. Draining it after start
    //  would make the instance skip ahead to a height the rest of the
    //  network has already passed, and it would never catch up.
    pending_height_.reset();

    //  Discard WAL entries at heights strictly below the start height.
    //  Those correspond to commits that succeeded before the crash, so
    //  the corresponding votes and locks are already on-chain and
    //  replaying them would be wrong. wal_truncate(height - 1) removes
    //  entries at heights <= height - 1, keeping entries at the start
    //  height untouched for replay below.
    //
    //  Without this, the WAL would accumulate stale entries across
    //  restarts: wal_truncate is otherwise only called from enterCommit,
    //  and a restart that never reaches enterCommit for a height keeps
    //  that height's entries forever.
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

  void BftConsensus::replayWalForHeight(Height height)
  {
    if (!deps_.wal_replay)
      return;

    const Id my_id = deps_.my_validator_id();
    if (my_id == INVALID_ID)
      return;

    size_t votes_replayed = 0;
    size_t locks_replayed = 0;

    //  The caller (enterNewHeight) has already called resetForNewHeight,
    //  so prevotes_, precommits_, locked_*, and valid_* are clean.
    //  Replay only entries for `height`; entries at other heights are
    //  filtered by the callback.
    //
    //  Each replayed vote is also re-broadcast. The WAL records what
    //  we signed, but a crash between wal_append_vote and
    //  broadcast_prevote leaves a durable vote that no peer ever saw.
    //  Without the re-broadcast, that vote sits in prevotes_ on this
    //  node and nowhere else, and the round can't reach quorum.
    //
    //  The re-broadcast goes directly through the callbacks rather than
    //  through broadcastPrevote/broadcastPrecommit, because those
    //  functions take height_ and round_ from the members, and at
    //  this point in the lifecycle (inside enterNewHeight, before
    //  enterPropose sets step_ = Propose) those members are not the
    //  height/round the replayed vote is for. The vote we're
    //  re-broadcasting is a fully-formed, fully-signed message; we
    //  pass it through verbatim.
    deps_.wal_replay(
        height,
        [this, my_id, height, &votes_replayed](const Vote &v, bool is_precommit)
        {
          if (v.height != height)
            return;
          if (v.signer_id != my_id)
            return; // only our own votes should be in the WAL

          if (is_precommit)
            precommits_[my_id] = v;
          else
            prevotes_[my_id] = v;
          ++votes_replayed;

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
        },
        [this, height, &locks_replayed](Height h, Round r,
                                        const Crypto::Hash &hash)
        {
          if (h != height)
            return;

          locked_ = true;
          locked_hash_ = hash;
          locked_round_ = r;
          ++locks_replayed;
        });

    if (votes_replayed > 0 || locks_replayed > 0)
    {
      log_(Logging::INFO)
          << "WAL replayed for height " << height << ": "
          << votes_replayed << " votes, "
          << locks_replayed << " locks";
    }
  }

  //  Active set resolution

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

  //  Lifecycle (continued)

  void BftConsensus::enterNewHeight(Height height)
  {
    resetForNewHeight(height);

    //  Replay the WAL for this height now that the containers are
    //  clean. Doing this *after* resetForNewHeight is essential: a
    //  replayed vote must not be cleared by the reset that follows.
    //  Doing this *before* enterPropose means a replayed lock is
    //  visible when enterPrevote compares valid_round_ to
    //  locked_round_, and a replayed vote is re-broadcast before the
    //  propose timer starts.
    replayWalForHeight(height);

    enterPropose(height, 0);
  }

  void BftConsensus::enterPropose(Height height, Round round)
  {
    resetForNewRound(round);
    step_ = Step::Propose;

    if (round > 0)
      consecutive_timeouts_++;

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

    drainFutureHeightProposal();
    drainFutureProposal();
    drainFutureRoundVotes();

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

    bool prevote_nil = true;
    Crypto::Hash prevote_hash{};

    if (const Core::Block *b = selectPrevoteBlock())
    {
      prevote_nil = false;
      prevote_hash = b->hash();
    }

    broadcastPrevote(prevote_nil, prevote_hash);

    if (height_ != height || round_ != round)
      return;

    if (round_timer_)
      round_timer_->start(round);

    drainPendingVotes(/*is_precommit=*/false);
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

      //  Adopt the lock and record it in the WAL *before* broadcasting
      //  the precommit. A crash between here and the broadcast must
      //  not lose the lock: the validator would re-enter this round
      //  without a lock and might sign a conflicting precommit.
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
      precommit_nil = false;
      precommit_hash = locked_hash_;
    }

    broadcastPrecommit(precommit_nil, precommit_hash);

    if (height_ != height || round_ != round)
      return;

    if (round_timer_)
      round_timer_->start(round);

    drainPendingVotes(/*is_precommit=*/true);
  }

  void BftConsensus::enterCommit(Height height, Round round)
  {
    //  Idempotency: if a commit is already in flight for this height,
    //  do not commit again. A second quorum observation from
    //  recordVote would otherwise push a duplicate block onto the
    //  chain — the same (height, block) counted twice.
    //
    //  This can happen when a precommit quorum is already recorded
    //  and another precommit for the same block arrives before
    //  pollTimers drains the pending height transition. The
    //  precommits_ container has not been cleared yet (that happens
    //  in resetForNewHeight), so quorumValue returns the same block,
    //  and without this guard enterCommit would fire again.
    if (pending_height_.has_value())
      return;

    step_ = Step::Commit;

    log_(Logging::INFO) << "Entering commit: h=" << height
                        << " r=" << round;

    auto quorum_block = quorumValue(/*is_precommit=*/true);

    if (!quorum_block.has_value())
    {
      log_(Logging::DEBUGGING) << "No precommit quorum, advancing round";
      enterPropose(height, round + 1);
      return;
    }

    auto it = proposals_by_hash_.find(*quorum_block);
    if (it == proposals_by_hash_.end())
    {
      log_(Logging::WARNING)
          << "Precommit quorum for unknown block "
          << quorum_block->toString().substr(0, 16)
          << ", advancing round";
      enterPropose(height, round + 1);
      return;
    }

    Core::Block block = it->second;

    const bool emergency = (block.header.emergency_rotation > 0);

    block.header.commit_round = round;

    auto active = deps_.active_set(emergency);

    std::unordered_map<Id, Index> id_to_index;
    for (size_t i = 0; i < active.size(); ++i)
      id_to_index[active[i]] = static_cast<Index>(i);

    block.quorum_signatures.clear();
    block.quorum_signatures.reserve(precommits_.size());

    for (const auto &[vid, vote] : precommits_)
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
          << quorumThreshold(emergency) << "), advancing round";
      enterPropose(height, round + 1);
      return;
    }

    consecutive_timeouts_ = 0;

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

    log_(Logging::INFO)
        << "Committing block: h=" << height
        << " hash=" << block.hash().toString().substr(0, 16)
        << " quorum_sigs=" << block.quorum_signatures.size()
        << " participants=" << block.participants.size();

    if (callbacks_.on_block_committed)
      callbacks_.on_block_committed(block);

    if (callbacks_.on_height_advanced)
      callbacks_.on_height_advanced(height + 1);

    //  WAL truncation. Entries at heights <= `height` are no longer
    //  needed: the committed block is durable in the chain DB, and
    //  any lock or vote at this or an earlier height has served its
    //  purpose. Entries at height + 1 survive for the next height.
    if (deps_.wal_truncate)
      deps_.wal_truncate(height);

    //  Entering the next height is deferred. See pending_height_ in
    //  the header for why.
    pending_height_ = height + 1;

    //  Pacing. Record the wall-clock time at which the next proposal
    //  is allowed. pollTimers will honour this unless the node has
    //  pending work, in which case the delay is cancelled.
    //
    //  The time is set here (at commit) rather than at enterPropose
    //  because the pacing rule is "wait after the parent block was
    //  produced", and the parent's production time is now.
    if (deps_.now_ms)
    {
      next_propose_not_before_ms_ =
          deps_.now_ms() + MIN_BLOCK_INTERVAL_MS;
    }
  }

  //  Inbound message handlers.
  //
  //  Each checks `running_` before doing any work. Without that check,
  //  a stopped instance still processes inbound messages — the
  //  state machine can advance, commit blocks, and fire the
  //  on_block_committed callback even though stop() has been called.
  //  The fixture exposes this: after stopValidator(i), votes that were
  //  still in flight for i reach its onPrevote/onPrecommit handlers,
  //  record a quorum, and drive instance i through commit.
  //
  //  stop() sets running_ = false and cancels the round timer. Both
  //  are necessary: the timer is a wake-up source, and the guards
  //  here close the message-driven path.

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
    handlePrevote(v);
  }

  void BftConsensus::onPrecommit(const Vote &v)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!running_)
      return;
    handlePrecommit(v);
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

    auto quorum_hash = quorumValue(/*is_precommit=*/true);
    if (!quorum_hash.has_value())
      return std::nullopt;

    auto it = proposals_by_hash_.find(*quorum_hash);
    if (it == proposals_by_hash_.end())
      return std::nullopt;

    return it->second;
  }

  bool BftConsensus::verifyProposalSignature(const Proposal &p) const
  {
    for (bool emergency : {false, true})
    {
      auto active = deps_.active_set(emergency);
      const Id expected = proposerFor(p.height, p.round, active);

      if (p.signer_id != INVALID_ID && p.signer_id != expected)
        continue;

      Index signer_index = INVALID_INDEX;
      if (p.signer_id != INVALID_ID)
      {
        for (size_t i = 0; i < active.size(); ++i)
        {
          if (active[i] == p.signer_id)
          {
            signer_index = static_cast<Index>(i);
            break;
          }
        }
      }
      else if (p.signer_index < active.size())
      {
        signer_index = p.signer_index;
        if (active[signer_index] != expected)
          continue;
      }

      if (signer_index == INVALID_INDEX)
        continue;
      if (p.signer_index != INVALID_INDEX &&
          p.signer_index != signer_index)
        continue;

      auto pk = resolveConsensusKey(signer_index, emergency);
      if (!pk.has_value())
        continue;

      Crypto::Hash signing_hash =
          proposalSigningHash(p.height, p.round, p.block_hash);
      if (Crypto::verify(signing_hash, *pk, p.signature))
        return true;
    }
    return false;
  }

  void BftConsensus::handleProposal(const Proposal &p)
  {
    if (p.height != height_)
    {
      if (p.height == height_ + 1)
      {
        if (verifyProposalSignature(p))
          future_height_proposals_[p.height] = p;
      }
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
      {
        log_(Logging::WARNING)
            << "handleProposal: bad signature on future-round proposal, "
            << "dropped (round=" << p.round << ")";
        return;
      }

      future_proposals_[p.round] = p;
      log_(Logging::DEBUGGING)
          << "handleProposal QUEUED future round: p=" << p.round
          << " local=" << round_
          << " hash=" << p.block_hash.toString().substr(0, 16);
      return;
    }

    if (p.round < round_)
    {
      log_(Logging::WARNING)
          << "handleProposal REJECT round-stale: p=" << p.round
          << " local=" << round_;
      return;
    }

    if (proposal_.has_value())
    {
      log_(Logging::WARNING) << "handleProposal REJECT already-have";
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

    log_(Logging::DEBUGGING)
        << "[handleProposal] h=" << block.header.height
        << " hdr_root=" << block.header.state_root.toString().substr(0, 16)
        << " block_hash=" << block.hash().toString().substr(0, 16)
        << " p_hash=" << p.block_hash.toString().substr(0, 16);

    const bool emergency = (block.header.emergency_rotation > 0);
    auto active = deps_.active_set(emergency);

    Id expected_proposer = proposerFor(height_, round_, active);

    Id proposal_signer = p.signer_id;
    if (proposal_signer == INVALID_ID && p.signer_index < active.size())
      proposal_signer = active[p.signer_index];

    if (proposal_signer != expected_proposer)
    {
      log_(Logging::WARNING) << "Proposal from wrong signer";
      return;
    }

    if (p.signer_index != INVALID_INDEX)
    {
      Index derived_index = INVALID_INDEX;
      for (size_t i = 0; i < active.size(); ++i)
      {
        if (active[i] == proposal_signer)
        {
          derived_index = static_cast<Index>(i);
          break;
        }
      }
      if (derived_index != INVALID_INDEX && p.signer_index != derived_index)
      {
        log_(Logging::WARNING)
            << "Proposal signer_index disagrees with signer_id";
        return;
      }
    }

    if (!validateProposal(p, block))
    {
      log_(Logging::DEBUGGING) << "Invalid proposal";
      return;
    }

    proposal_ = p;

    log_(Logging::DEBUGGING) << "handleProposal SET: h=" << height_
                             << " r=" << round_
                             << " hash=" << p.block_hash.toString().substr(0, 16);

    proposals_by_hash_[p.block_hash] = block;
    proposal_for_round_[{p.height, p.round}] = p.block_hash;

    drainPendingVotes(/*is_precommit=*/false);
    drainPendingVotes(/*is_precommit=*/true);

    log_(Logging::DEBUGGING) << "Accepted proposal for h=" << height_
                             << " r=" << round_
                             << " hash=" << p.block_hash.toString().substr(0, 16);

    if (step_ == Step::Propose && height_ == p.height && round_ == p.round)
      enterPrevote(height_, round_);
  }

  void BftConsensus::drainFutureHeightProposal()
  {
    auto it = future_height_proposals_.find(height_);
    if (it == future_height_proposals_.end())
      return;

    Proposal p = std::move(it->second);
    future_height_proposals_.erase(it);

    log_(Logging::DEBUGGING)
        << "Draining queued proposal for height " << height_
        << " hash=" << p.block_hash.toString().substr(0, 16);

    handleProposal(p);

    for (auto i = future_height_proposals_.begin();
         i != future_height_proposals_.end();)
    {
      if (i->first <= height_ || i->first > height_ + 1)
        i = future_height_proposals_.erase(i);
      else
        ++i;
    }
  }

  void BftConsensus::drainFutureHeightVotes()
  {
    auto pv = future_height_prevotes_.find(height_);
    if (pv != future_height_prevotes_.end())
    {
      for (auto &[id, v] : pv->second)
      {
        if (pending_prevotes_.size() >= MAX_PENDING_VOTES)
          break;
        pending_prevotes_.push_back(std::move(v));
      }
      future_height_prevotes_.erase(pv);
    }

    auto pc = future_height_precommits_.find(height_);
    if (pc != future_height_precommits_.end())
    {
      for (auto &[id, v] : pc->second)
      {
        if (pending_precommits_.size() >= MAX_PENDING_VOTES)
          break;
        pending_precommits_.push_back(std::move(v));
      }
      future_height_precommits_.erase(pc);
    }

    for (auto it = future_height_prevotes_.begin();
         it != future_height_prevotes_.end();)
    {
      if (it->first <= height_ || it->first > height_ + 1)
        it = future_height_prevotes_.erase(it);
      else
        ++it;
    }
    for (auto it = future_height_precommits_.begin();
         it != future_height_precommits_.end();)
    {
      if (it->first <= height_ || it->first > height_ + 1)
        it = future_height_precommits_.erase(it);
      else
        ++it;
    }
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
      if (tv.signer_index != INVALID_INDEX)
      {
        if (tv.signer_index >= committed.size())
          return;
        if (committed[tv.signer_index] != voter_id)
          return;
      }
    }

    Core::ValidatorInfo vinfo;
    if (!deps_.state_lookup_validator ||
        !deps_.state_lookup_validator(voter_id, vinfo))
    {
      return;
    }

    const Crypto::Hash signing_hash =
        timeoutVoteSigningHash(tv.height, tv.round);
    if (!Crypto::verify(signing_hash,
                        vinfo.effectiveConsensusKey(), tv.signature))
      return;

    for (const auto &existing : timeout_votes_)
    {
      if (existing.round == tv.round &&
          existing.signer_id == voter_id)
      {
        return;
      }
    }

    if (timeout_votes_.size() >= MAX_TIMEOUT_VOTES)
      return;

    TimeoutVote stored = tv;
    stored.signer_id = voter_id;

    if (!storeTimeoutVote(stored))
      return;

    retryEmergencyPropose();
  }

  void BftConsensus::drainFutureProposal()
  {
    auto it = future_proposals_.find(round_);
    if (it == future_proposals_.end())
      return;

    Proposal p = std::move(it->second);
    future_proposals_.erase(it);

    log_(Logging::DEBUGGING)
        << "Draining queued proposal for round " << round_
        << " hash=" << p.block_hash.toString().substr(0, 16);

    handleProposal(p);
  }

  void BftConsensus::drainFutureRoundVotes()
  {
    {
      auto it = future_round_prevotes_.find(round_);
      if (it != future_round_prevotes_.end())
      {
        for (auto &[id, v] : it->second)
        {
          (void)id;
          handlePrevote(v);
        }
        future_round_prevotes_.erase(it);
      }
    }
    {
      auto it = future_round_precommits_.find(round_);
      if (it != future_round_precommits_.end())
      {
        for (auto &[id, v] : it->second)
        {
          (void)id;
          handlePrecommit(v);
        }
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
  }

  void BftConsensus::drainPendingVotes(bool is_precommit)
  {
    auto &buffer = is_precommit ? pending_precommits_ : pending_prevotes_;
    if (buffer.empty())
      return;

    std::vector<Vote> still_pending;
    still_pending.reserve(buffer.size());

    for (const auto &v : buffer)
    {
      if (v.height != height_ || v.round != round_)
        continue;

      if (is_precommit && step_ != Step::Precommit &&
          !(locked_ && !v.is_nil && v.block_hash == locked_hash_))
      {
        still_pending.push_back(v);
        continue;
      }
      if (!is_precommit && step_ != Step::Prevote)
      {
        still_pending.push_back(v);
        continue;
      }

      Id signer_id = INVALID_ID;
      if (!voteIsVerifiable(v, &signer_id))
      {
        still_pending.push_back(v);
        continue;
      }

      if (is_precommit)
        handlePrecommit(v);
      else
        recordVote(v, false);
    }

    buffer = std::move(still_pending);
  }

  bool BftConsensus::voteIsVerifiable(const Vote &v, Id *out_signer) const
  {
    bool emergency = false;
    const Id signer = resolveVoteSigner(v, emergency);
    if (signer == INVALID_ID)
      return false;

    if (!verifyVoteSignature(v, signer))
      return false;

    if (out_signer)
      *out_signer = signer;

    if (!v.is_nil)
      return proposals_by_hash_.count(v.block_hash) > 0;

    return proposal_for_round_.count({v.height, v.round}) > 0;
  }

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
        //  The set is genuinely ambiguous. Try both before rejecting.
        //  A vote that later resolves against the wrong set will be
        //  re-verified when its block arrives and rejected then.
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

      //  Set is unambiguous. Require membership in *that* set.
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

  void BftConsensus::handlePrevote(const Vote &v)
  {
    if (v.height != height_)
    {
      if (v.height == height_ + 1)
      {
        Id signer_id = INVALID_ID;
        if (!voteIsVerifiable(v, &signer_id))
          return;

        auto &bucket = future_height_prevotes_[v.height];
        if (bucket.size() < MAX_FUTURE_VOTES_PER_ROUND)
          bucket[signer_id] = v;
      }
      return;
    }

    if (v.round > round_)
    {
      bufferFutureVote(v, /*is_precommit=*/false);
      return;
    }

    if (v.round < round_)
      return;

    Id signer_id = INVALID_ID;
    if (!voteIsVerifiable(v, &signer_id))
    {
      if (pending_prevotes_.size() < MAX_PENDING_VOTES)
        pending_prevotes_.push_back(v);
      return;
    }

    if (step_ == Step::Propose || step_ == Step::NewHeight)
    {
      if (pending_prevotes_.size() < MAX_PENDING_VOTES)
        pending_prevotes_.push_back(v);
      return;
    }
    if (step_ != Step::Prevote)
      return;

    recordVote(v, false);
  }

  void BftConsensus::handlePrecommit(const Vote &v)
  {
    if (v.height != height_)
    {
      if (v.height == height_ + 1)
      {
        Id signer_id = INVALID_ID;
        if (!voteIsVerifiable(v, &signer_id))
          return;

        auto &bucket = future_height_precommits_[v.height];
        if (bucket.size() < MAX_FUTURE_VOTES_PER_ROUND)
          bucket[signer_id] = v;
      }
      return;
    }

    if (v.round > round_)
    {
      bufferFutureVote(v, /*is_precommit=*/true);
      return;
    }

    if (v.round < round_)
      return;

    const bool for_locked_block = locked_ && !v.is_nil &&
                                  v.block_hash == locked_hash_;

    Id signer_id = INVALID_ID;
    const bool verifiable = voteIsVerifiable(v, &signer_id);

    if (!for_locked_block &&
        (step_ == Step::Propose || step_ == Step::Prevote ||
         step_ == Step::NewHeight))
    {
      if (pending_precommits_.size() < MAX_PENDING_VOTES)
        pending_precommits_.push_back(v);
      return;
    }

    if (!for_locked_block && step_ != Step::Precommit)
      return;

    if (!verifiable)
    {
      if (pending_precommits_.size() < MAX_PENDING_VOTES)
        pending_precommits_.push_back(v);
      return;
    }

    if (!v.is_nil && v.block_hash != locked_hash_ &&
        !(valid_set_ && v.block_hash == valid_hash_))
    {
      log_(Logging::DEBUGGING)
          << "Rejecting precommit for block not locked or valid: h=" << v.height
          << " r=" << v.round
          << " signer=" << v.signer_id
          << " hash=" << v.block_hash.toString().substr(0, 16);
      return;
    }

    recordVote(v, /*is_precommit=*/true);
  }

  bool BftConsensus::bufferFutureVote(const Vote &v, bool is_precommit)
  {
    if (v.round <= round_)
      return false;
    if (v.round - round_ > MAX_FUTURE_ROUNDS)
      return false;

    Id signer_id = INVALID_ID;
    if (!voteIsVerifiable(v, &signer_id))
      return false;

    auto &store = is_precommit ? future_round_precommits_
                               : future_round_prevotes_;

    auto &bucket = store[v.round];
    if (bucket.size() >= MAX_FUTURE_VOTES_PER_ROUND)
      return false;

    if (bucket.count(signer_id) > 0)
      return false;

    bucket[signer_id] = v;
    return true;
  }

  //  Timers

  void BftConsensus::pollTimers()
  {
    std::lock_guard<std::mutex> lock(mutex_);

    //  The running_ check must come first. A stopped instance must
    //  not enter a pending height, or stop() would not mean "inert":
    //  a commit that was in flight when stop() was called would
    //  still drive the state machine forward on the next poll.
    if (!running_)
      return;

    if (pending_height_.has_value())
    {
      //  Pacing check. If a delay is in effect and we haven't
      //  reached the target time, decide whether to keep waiting.
      //
      //  The wait is cancelled the moment the node has pending
      //  work (a non-empty mempool). The whole point of the pacing
      //  rule is to avoid empty blocks, not to delay real
      //  transactions.
      //
      //  When has_pending_work is unset (as in tests and on
      //  non-validator nodes), the engine behaves as if there is
      //  always work — so pacing is a no-op and blocks commit as
      //  fast as they can, matching the pre-pacing behaviour.
      if (next_propose_not_before_ms_ != 0)
      {
        const uint64_t now = deps_.now_ms ? deps_.now_ms() : 0;

        if (now < next_propose_not_before_ms_)
        {
          const bool pending =
              !deps_.has_pending_work || deps_.has_pending_work();
          if (!pending)
          {
            //  Idle and still inside the delay window. Wait.
            return;
          }
          //  Otherwise fall through: pending work cancels the wait.
        }

        next_propose_not_before_ms_ = 0;
      }

      Height next = *pending_height_;
      pending_height_.reset();
      next_propose_not_before_ms_ = 0;
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
                             << " quorum=" << (quorum_block ? "yes" : "no")
                             << " prop_known="
                             << (quorum_block &&
                                         proposals_by_hash_.count(*quorum_block) > 0
                                     ? "yes"
                                     : "no");

    broadcastTimeoutVote(round_);

    if (quorum_block.has_value() &&
        proposals_by_hash_.count(*quorum_block) > 0)
    {
      enterCommit(height_, round_);
      return;
    }
    enterPropose(height_, round_ + 1);
  }

  //  Proposing

  void BftConsensus::tryPropose()
  {
    if (step_ != Step::Propose)
      return;

    auto my_id = deps_.my_validator_id();
    if (my_id == INVALID_ID)
      return;
    if (my_id != proposer_)
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

  const Core::Block *BftConsensus::selectPrevoteBlock() const
  {
    if (locked_)
    {
      if (valid_set_ && valid_round_ > locked_round_)
      {
        auto it = proposals_by_hash_.find(valid_hash_);
        if (it != proposals_by_hash_.end())
          return &it->second;
      }
      auto it = proposals_by_hash_.find(locked_hash_);
      if (it != proposals_by_hash_.end())
        return &it->second;
    }

    if (valid_set_)
    {
      auto it = proposals_by_hash_.find(valid_hash_);
      if (it != proposals_by_hash_.end())
        return &it->second;
    }

    if (proposal_.has_value() &&
        proposal_->height == height_ &&
        proposal_->round == round_)
    {
      auto it = proposals_by_hash_.find(proposal_->block_hash);
      if (it != proposals_by_hash_.end())
        return &it->second;
    }

    return nullptr;
  }

  bool BftConsensus::propose()
  {
    const Height propose_height = height_;
    const Round propose_round = round_;

    const Core::Block *selected = selectPrevoteBlock();
    bool re_proposing = (selected != nullptr);

    Core::Block block;
    if (re_proposing)
    {
      block = *selected;
      block.header.commit_round = round_;
      block.quorum_signatures.clear();
    }
    else
    {
      block = buildFreshBlock();

      if (!equivocations_.empty())
      {
        auto active = deps_.active_set(useEmergencySet());
        std::set<Id> already_slashed;

        for (const auto &ev : equivocations_)
        {
          if (!ev.isValid())
            continue;
          const Id target = ev.vote_a.signer_id;
          if (target == INVALID_ID)
            continue;
          if (std::find(active.begin(), active.end(), target) == active.end())
            continue;
          if (already_slashed.count(target) > 0)
            continue;
          if (block.transactions.size() >= config_.max_block_txs)
            break;

          auto payload = Core::encodeSlashPayload(
              encodeVote(ev.vote_a), encodeVote(ev.vote_b));

          if (deps_.verify_slash_proof && !deps_.verify_slash_proof(payload))
          {
            log_(Logging::WARNING)
                << "Skipping unverifiable equivocation evidence: signer="
                << target << " h=" << ev.vote_a.height
                << " r=" << ev.vote_a.round;
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

    auto sim_root = simulateBlock(block);
    if (!sim_root.has_value() && !re_proposing && !block.transactions.empty())
    {
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

    Crypto::Hash block_hash = block.hash();
    Proposal p;
    p.height = propose_height;
    p.round = propose_round;
    p.signer_id = deps_.my_validator_id();
    p.signer_index = mySignerIndex();
    p.block_hash = block_hash;
    p.block_bytes = block.serialize();

    Crypto::Hash signing_hash = proposalSigningHash(height_, round_, block_hash);
    if (deps_.sign)
      p.signature = deps_.sign(signing_hash);

    broadcastProposal(p);

    proposal_ = p;
    proposals_by_hash_[block_hash] = block;
    proposal_for_round_[{height_, round_}] = block_hash;

    log_(Logging::INFO) << (re_proposing ? "Re-proposed" : "Proposed")
                        << " block for h=" << height_
                        << " r=" << round_
                        << " em=" << (useEmergencySet() ? "yes" : "no")
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

  //  Timeout certificate assembly and verification

  void BftConsensus::broadcastTimeoutVote(Round round)
  {
    if (!callbacks_.broadcast_timeout_vote)
      return;

    auto committed = deps_.active_set(/*force_rotation=*/false);

    const Id my_id = deps_.my_validator_id();
    Index idx = INVALID_INDEX;
    for (size_t i = 0; i < committed.size(); ++i)
    {
      if (committed[i] == my_id)
      {
        idx = static_cast<Index>(i);
        break;
      }
    }
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

    // Count our own vote. The broadcast fan-out skips the sender (both
    // in the test harness and in real P2P), so without this our own
    // vote never enters timeout_votes_ and a 4-validator set needs 2
    // remote votes instead of 1 remote + ourselves.
    storeTimeoutVote(tv);

    callbacks_.broadcast_timeout_vote(tv);
  }

  bool BftConsensus::storeTimeoutVote(const TimeoutVote &tv)
  {
    for (const auto &existing : timeout_votes_)
    {
      if (existing.round == tv.round &&
          existing.signer_id == tv.signer_id)
      {
        return false;
      }
    }

    if (timeout_votes_.size() >= MAX_TIMEOUT_VOTES)
      return false;

    timeout_votes_.push_back(tv);
    return true;
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

    //  The certificate may be for an earlier round than round_. That is
    //  legal: validateProposal only rejects emergency_rotation > p.round.
    tryPropose();
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
    {
      log_(Logging::WARNING) << "Timeout certificate invalid: " << error;
    }
    return ok;
  }

  //  Validation

  bool BftConsensus::validateProposal(const Proposal &p, const Core::Block &block)
  {
    Crypto::Hash block_hash = block.hash();
    if (block_hash != p.block_hash)
    {
      log_(Logging::WARNING) << "validateProposal: block hash mismatch: "
                             << "computed="
                             << block_hash.toString().substr(0, 16)
                             << " proposal="
                             << p.block_hash.toString().substr(0, 16);
      return false;
    }

    if (block.header.height != p.height)
    {
      log_(Logging::WARNING) << "validateProposal: height mismatch: "
                             << "header=" << block.header.height
                             << " proposal=" << p.height;
      return false;
    }

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
        log_(Logging::WARNING)
            << "validateProposal: certificate hash mismatch: header="
            << block.header.timeout_certificate_hash.toString().substr(0, 16)
            << " computed=" << computed.toString().substr(0, 16);
        return false;
      }

      if (block.header.emergency_rotation > p.round)
      {
        log_(Logging::WARNING)
            << "validateProposal: emergency round "
            << block.header.emergency_rotation
            << " > proposal round " << p.round;
        return false;
      }
      if (block.header.emergency_rotation < Core::EMERGENCY_ROTATION_ROUNDS)
      {
        log_(Logging::WARNING)
            << "validateProposal: emergency round "
            << block.header.emergency_rotation
            << " below threshold";
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

    std::optional<Crypto::PublicKey> pk;
    if (p.signer_id != INVALID_ID)
    {
      Index idx = INVALID_INDEX;
      auto active = deps_.active_set(emergency);
      for (size_t i = 0; i < active.size(); ++i)
      {
        if (active[i] == p.signer_id)
        {
          idx = static_cast<Index>(i);
          break;
        }
      }
      if (idx == INVALID_INDEX)
      {
        log_(Logging::WARNING)
            << "validateProposal: signer_id " << p.signer_id
            << " not in the set (emergency=" << (emergency ? "yes" : "no")
            << ")";
        return false;
      }
      pk = resolveConsensusKey(idx, emergency);
    }
    else
    {
      pk = resolveConsensusKey(p.signer_index, emergency);
    }

    if (!pk.has_value())
    {
      log_(Logging::WARNING) << "validateProposal: no public key for signer "
                             << (p.signer_id != INVALID_ID
                                     ? std::to_string(p.signer_id)
                                     : std::to_string(p.signer_index))
                             << " (emergency=" << (emergency ? "yes" : "no")
                             << ")";
      return false;
    }

    Crypto::Hash signing_hash =
        proposalSigningHash(p.height, p.round, block_hash);
    if (!Crypto::verify(signing_hash, *pk, p.signature))
    {
      log_(Logging::DEBUGGING) << "validateProposal: signature verification failed";
      return false;
    }

    auto computed_root = simulateBlock(block);
    if (!computed_root.has_value())
    {
      log_(Logging::WARNING)
          << "validateProposal: simulateBlock returned nullopt";
      return false;
    }

    log_(Logging::DEBUGGING)
        << "[validateProposal] computed=" << computed_root->toString().substr(0, 16)
        << " header=" << block.header.state_root.toString().substr(0, 16)
        << " match=" << (*computed_root == block.header.state_root ? "yes" : "no");

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

  //  Quorum tracking

  bool BftConsensus::recordVote(const Vote &v, bool is_precommit)
  {
    auto &container = is_precommit ? precommits_ : prevotes_;

    log_(Logging::DEBUGGING) << "recordVote: precommit=" << is_precommit
                             << " signer_id=" << v.signer_id
                             << " h=" << v.height
                             << " r=" << v.round
                             << " nil=" << v.is_nil;

    bool emergency = false;
    const Id voter_id = resolveVoteSigner(v, emergency);
    if (voter_id == INVALID_ID)
      return false;

    if (!verifyVoteSignature(v, voter_id))
      return false;

    //  -------- Conflict path --------
    auto existing = container.find(voter_id);
    if (existing != container.end())
    {
      const Vote &first = existing->second;
      if (first.block_hash != v.block_hash || first.is_nil != v.is_nil)
      {
        Core::ValidatorInfo vinfo;
        if (!deps_.state_lookup_validator ||
            !deps_.state_lookup_validator(voter_id, vinfo))
        {
          return false;
        }
        const Crypto::PublicKey pk = vinfo.effectiveConsensusKey();

        const Crypto::Hash first_hash = voteSigningHash(
            first.height, first.round, first.is_nil, first.block_hash);
        const Crypto::Hash second_hash = voteSigningHash(
            v.height, v.round, v.is_nil, v.block_hash);

        if (!Crypto::verify(first_hash, pk, first.signature) ||
            !Crypto::verify(second_hash, pk, v.signature))
        {
          log_(Logging::WARNING)
              << "Conflicting vote with bad signature, not recording: "
              << "vid=" << voter_id
              << " h=" << v.height
              << " r=" << v.round;
          return false;
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
                << " h=" << v.height
                << " r=" << v.round;
          }
        }
      }
      return false;
    }

    //  -------- First-vote path --------
    container[voter_id] = v;

    log_(Logging::DEBUGGING) << (is_precommit ? "Precommit" : "Prevote")
                             << " received: h=" << v.height
                             << " r=" << v.round
                             << " vid=" << voter_id
                             << " nil=" << v.is_nil
                             << " em=" << (emergency ? "yes" : "no");

    if (!is_precommit && step_ >= Step::Prevote)
    {
      auto polka = quorumValue(/*is_precommit=*/false);
      if (polka.has_value() &&
          (!valid_set_ || valid_round_ < v.round))
      {
        valid_set_ = true;
        valid_hash_ = *polka;
        valid_round_ = v.round;
      }
    }

    //  Quorum check. A prevote quorum only fires enterPrecommit when
    //  we are actually in the Prevote step (otherwise the transition
    //  is stale and the precommit would be for the wrong round). A
    //  precommit quorum fires enterCommit regardless of the current
    //  step, because the block the quorum is for is known — that is
    //  a precondition of quorumValue returning a hash. This is what
    //  makes round-crossing recovery work: a validator that has
    //  advanced to a new round but observes a precommit quorum for
    //  the previous round's block must commit that block.
    if (quorumValue(is_precommit).has_value())
    {
      if (is_precommit)
      {
        enterCommit(height_, round_);
      }
      else if (step_ == Step::Prevote)
      {
        enterPrecommit(height_, round_);
      }
    }

    return true;
  }

  std::optional<Crypto::Hash> BftConsensus::quorumValue(bool is_precommit) const
  {
    auto &container = is_precommit ? precommits_ : prevotes_;

    std::unordered_map<Crypto::Hash, size_t> count_by_hash;

    for (const auto &[vid, v] : container)
    {
      (void)vid;
      if (v.is_nil)
        continue;

      auto it = proposals_by_hash_.find(v.block_hash);
      if (it == proposals_by_hash_.end())
        continue;

      count_by_hash[v.block_hash]++;
    }

    for (const auto &[hash, count] : count_by_hash)
    {
      auto it = proposals_by_hash_.find(hash);
      if (it == proposals_by_hash_.end())
        continue;

      const bool emergency = (it->second.header.emergency_rotation > 0);
      const size_t threshold = quorumThreshold(emergency);

      if (count >= threshold)
        return hash;
    }

    return std::nullopt;
  }

  size_t BftConsensus::countVotesFor(bool is_precommit,
                                     const Crypto::Hash &block_hash) const
  {
    auto &container = is_precommit ? precommits_ : prevotes_;
    size_t count = 0;
    for (const auto &[vid, v] : container)
    {
      (void)vid;
      if (!v.is_nil && v.block_hash == block_hash)
        count++;
    }
    return count;
  }

  size_t BftConsensus::countNilVotes(bool is_precommit) const
  {
    auto &container = is_precommit ? precommits_ : prevotes_;
    size_t count = 0;
    for (const auto &[vid, v] : container)
    {
      (void)vid;
      if (v.is_nil)
        count++;
    }
    return count;
  }

  //  Helpers

  size_t BftConsensus::quorumThreshold(bool emergency) const
  {
    auto active = deps_.active_set(emergency);
    return Core::bftQuorum(active.size());
  }

  Index BftConsensus::mySignerIndex() const
  {
    auto my_id = deps_.my_validator_id();
    if (my_id == INVALID_ID)
      return INVALID_INDEX;

    const bool have_proposal =
        proposal_for_round_.count({height_, round_}) > 0;
    const bool emergency = have_proposal
                               ? roundUsesEmergencySet(height_, round_)
                               : useEmergencySet();

    auto active = deps_.active_set(emergency);
    for (size_t i = 0; i < active.size(); ++i)
    {
      if (active[i] == my_id)
        return static_cast<Index>(i);
    }
    return INVALID_INDEX;
  }

  //  Broadcasting

  void BftConsensus::broadcastProposal(const Proposal &p)
  {
    if (callbacks_.broadcast_proposal)
      callbacks_.broadcast_proposal(p);
  }

  void BftConsensus::broadcastPrevote(bool is_nil,
                                      const Crypto::Hash &block_hash)
  {
    //  Capture height, round, and signer before any re-entrant call.
    //  recordVote below can trigger enterPrecommit -> enterCommit ->
    //  enterNewHeight, which would change height_ and round_. The
    //  WAL append and the Vote we sign must reflect the round the
    //  vote is *for*, not whatever round we've ended up in.
    const Height v_height = height_;
    const Round v_round = round_;
    const Id v_signer = deps_.my_validator_id();
    const Index v_index = mySignerIndex();

    if (v_signer == INVALID_ID || v_index == INVALID_INDEX)
      return;

    Vote v;
    v.height = v_height;
    v.round = v_round;
    v.signer_id = v_signer;
    v.signer_index = v_index;
    v.is_nil = is_nil;
    v.block_hash = block_hash;

    Crypto::Hash signing_hash =
        voteSigningHash(v_height, v_round, is_nil, block_hash);
    if (deps_.sign)
      v.signature = deps_.sign(signing_hash);

    //  WAL append before broadcast and before recordVote. If the
    //  process crashes between here and the peer receiving the vote,
    //  a restart must still remember that we signed this.
    if (deps_.wal_append_vote)
      deps_.wal_append_vote(v, /*is_precommit=*/false);

    recordVote(v, /*is_precommit=*/false);

    if (callbacks_.broadcast_prevote)
      callbacks_.broadcast_prevote(v);
  }

  void BftConsensus::broadcastPrecommit(bool is_nil,
                                        const Crypto::Hash &block_hash)
  {
    const Height v_height = height_;
    const Round v_round = round_;
    const Id v_signer = deps_.my_validator_id();
    const Index v_index = mySignerIndex();

    if (v_signer == INVALID_ID || v_index == INVALID_INDEX)
      return;

    Vote v;
    v.height = v_height;
    v.round = v_round;
    v.signer_id = v_signer;
    v.signer_index = v_index;
    v.is_nil = is_nil;
    v.block_hash = block_hash;

    Crypto::Hash signing_hash =
        voteSigningHash(v_height, v_round, is_nil, block_hash);
    if (deps_.sign)
      v.signature = deps_.sign(signing_hash);

    if (deps_.wal_append_vote)
      deps_.wal_append_vote(v, /*is_precommit=*/true);

    recordVote(v, /*is_precommit=*/true);

    if (callbacks_.broadcast_precommit)
      callbacks_.broadcast_precommit(v);
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

    pending_prevotes_.clear();
    pending_precommits_.clear();

    future_proposals_.clear();
    future_round_prevotes_.clear();
    future_round_precommits_.clear();
    proposal_for_round_.clear();

    timeout_votes_.clear();

    next_propose_not_before_ms_ = 0;

    //  equivocations_ is deliberately NOT cleared here.
  }

  void BftConsensus::resetForNewRound(Round round)
  {
    round_ = round;

    proposal_.reset();
    prevotes_.clear();
    precommits_.clear();

    pending_prevotes_.clear();
    pending_precommits_.clear();

    //  Prune future-scoped buffers by round, don't clear them. Entries
    //  for rounds strictly behind the new round are stale — the round
    //  they were queued for has passed. Entries for the new round and
    //  beyond survive; enterPropose will drain them after setting
    //  step_ = Propose.
    //
    //  Clearing everything here would wipe a queued proposal that
    //  arrives before its round is entered, and the round would
    //  proceed without it. That is exactly the bug the buffering was
    //  introduced to prevent.
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

  bool BftConsensus::useEmergencySet() const noexcept
  {
    return consecutive_timeouts_ >= Core::EMERGENCY_ROTATION_ROUNDS;
  }

  std::optional<Proposal> BftConsensus::currentProposalForTest() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return proposal_;
  }
} // namespace Consensus