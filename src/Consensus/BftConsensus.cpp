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
      : deps_(std::move(deps)), callbacks_(std::move(callbacks)), config_(config), log_(log)
  {
    round_timer_ = std::make_unique<Common::RoundTimer>([this]()
                                                        {
                                                          // Timeout is handled by pollTimers().
                                                          // The callback is a no-op.
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
    if (!v.is_nil)
    {
      auto it = proposals_by_hash_.find(v.block_hash);
      if (it == proposals_by_hash_.end())
        return false;
      return it->second.header.emergency_rotation > 0;
    }

    return roundUsesEmergencySet(v.height, v.round);
  }

  //  Lifecycle (continued)

  void BftConsensus::enterNewHeight(Height height)
  {
    resetForNewHeight(height);
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

    if (is_proposer)
      tryPropose();
  }

  void BftConsensus::enterPrevote(Height height, Round round)
  {
    if (step_ == Step::Prevote && round_ == round)
      return;

    step_ = Step::Prevote;
    prevotes_.clear();

    log_(Logging::DEBUGGING) << "Entering prevote: h=" << height << " r=" << round;

    bool prevote_nil = true;
    Crypto::Hash prevote_hash{};

    //  Tendermint prevote rule (arXiv:1807.04938 §4.1):
    //
    //    if lockedValue != nil and lockedRound >= validRound:
    //        prevote lockedValue
    //    else if validValue != nil and validRound >= lockedRound:
    //        prevote validValue
    //    else if proposal is for this round:
    //        prevote proposal
    //    else:
    //        prevote nil
    //
    //  In this implementation "lockedValue" is (locked_hash_,
    //  locked_round_), and "validValue" is (valid_hash_, valid_round_).
    //  The comparison is by round number. A lock is never released
    //  except by a newer polka at a higher round, or by a new height.
    if (locked_)
    {
      if (valid_set_ && valid_round_ > locked_round_)
      {
        prevote_nil = false;
        prevote_hash = valid_hash_;
      }
      else
      {
        prevote_nil = false;
        prevote_hash = locked_hash_;
      }
    }
    else if (proposal_.has_value() &&
             proposal_->height == height &&
             proposal_->round == round)
    {
      prevote_nil = false;
      prevote_hash = proposal_->block_hash;
    }

    broadcastPrevote(prevote_nil, prevote_hash);

    //  broadcastPrevote -> recordVote can synchronously advance the
    //  state machine (a prevote quorum can trigger enterPrecommit, and
    //  a precommit quorum can trigger enterCommit -> enterNewHeight).
    //  If the height or round moved, the timer and drain below are
    //  for a step that no longer exists. Return without touching them.
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

    step_ = Step::Precommit;
    precommits_.clear();

    log_(Logging::DEBUGGING) << "Entering precommit: h=" << height << " r=" << round;

    auto polka = quorumValue(/*is_precommit=*/false);

    bool precommit_nil = true;
    Crypto::Hash precommit_hash{};

    if (polka.has_value())
    {
      //  A polka this round is the newest information we have.
      //  Record it as the valid value and take the lock. Locking on
      //  the polka's block here — not at prevote time — is what makes
      //  the safety proof work.
      valid_set_ = true;
      valid_hash_ = *polka;
      valid_round_ = round;

      locked_ = true;
      locked_hash_ = *polka;
      locked_round_ = round;

      precommit_nil = false;
      precommit_hash = *polka;
    }
    else if (locked_)
    {
      //  No polka this round, but we hold a lock from an earlier
      //  round. Precommit the locked block. This is the "re-precommit"
      //  case that lets a block which missed its round still commit.
      precommit_nil = false;
      precommit_hash = locked_hash_;
    }

    broadcastPrecommit(precommit_nil, precommit_hash);

    //  Same reentrancy hazard as enterPrevote: broadcastPrecommit ->
    //  recordVote can trigger enterCommit -> enterNewHeight.
    if (height_ != height || round_ != round)
      return;

    if (round_timer_)
      round_timer_->start(round);

    drainPendingVotes(/*is_precommit=*/true);
  }

  void BftConsensus::enterCommit(Height height, Round round)
  {
    step_ = Step::Commit;

    log_(Logging::DEBUGGING) << "Entering commit: h=" << height << " r=" << round;

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

    //  The quorum was formed over this block, so the active set the
    //  round ran on is the set the block's header names. Use that same
    //  flag for the final threshold check.
    const bool emergency = (block.header.emergency_rotation > 0);

    block.header.commit_round = round;

    block.quorum_signatures.clear();
    block.quorum_signatures.reserve(precommits_.size());

    for (const auto &[signer_idx, vote] : precommits_)
    {
      if (vote.is_nil)
        continue;
      if (vote.block_hash != *quorum_block)
        continue;

      Crypto::ValidatorSignature vs;
      vs.signer_index = signer_idx;
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

      const Id target_signer = decoded->vote_a.signer_index;
      const uint64_t target_height = decoded->vote_a.height;
      const uint64_t target_round = decoded->vote_a.round;

      equivocations_.erase(
          std::remove_if(equivocations_.begin(), equivocations_.end(),
                         [&](const EquivocationEvidence &e)
                         {
                           return e.vote_a.signer_index == target_signer &&
                                  e.vote_a.height == target_height &&
                                  e.vote_a.round == target_round;
                         }),
          equivocations_.end());
    }

    log_(Logging::DEBUGGING)
        << "Committing block: h=" << height
        << " hash=" << block.hash().toString().substr(0, 16)
        << " quorum_sigs=" << block.quorum_signatures.size()
        << " participants=" << block.participants.size();

    if (callbacks_.on_block_committed)
      callbacks_.on_block_committed(block);

    if (callbacks_.on_height_advanced)
      callbacks_.on_height_advanced(height + 1);

    enterNewHeight(height + 1);
  }

  //  Message handlers

  void BftConsensus::onProposal(const Proposal &p)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    handleProposal(p);
  }

  void BftConsensus::onPrevote(const Vote &v)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    handlePrevote(v);
  }

  void BftConsensus::onPrecommit(const Vote &v)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    handlePrecommit(v);
  }

  void BftConsensus::onTimeoutVote(const TimeoutVote &tv)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    handleTimeoutVote(tv);
  }

  void BftConsensus::handleProposal(const Proposal &p)
  {
    if (p.height != height_)
    {
      //  Buffer exactly one height ahead. A proposal for height_ + 2
      //  can't be verified (we don't know the proposer for that
      //  height's active set, and the block's certificate — if any —
      //  references a committed set we haven't advanced to). Buffering
      //  further ahead is a memory-growth vector for a peer feeding us
      //  garbage.
      if (p.height == height_ + 1)
        future_height_proposals_[p.height] = p;
      else
        log_(Logging::WARNING) << "handleProposal REJECT height: p=" << p.height
                               << " local=" << height_;

      //  Return unconditionally: this proposal is not for the current
      //  height and must not be processed as if it were.
      return;
    }

    if (p.round > round_)
    {
      constexpr Round MAX_FUTURE_ROUNDS = 64;
      if (p.round - round_ > MAX_FUTURE_ROUNDS)
      {
        log_(Logging::WARNING)
            << "handleProposal REJECT round-too-far: p=" << p.round
            << " local=" << round_;
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

    const bool emergency = (block.header.emergency_rotation > 0);
    auto active = deps_.active_set(emergency);

    Id expected_proposer = proposerFor(height_, round_, active);
    if (p.signer_index >= active.size())
      return;
    if (active[p.signer_index] != expected_proposer)
    {
      log_(Logging::WARNING) << "Proposal from wrong signer";
      return;
    }

    if (!validateProposal(p, block))
    {
      log_(Logging::WARNING) << "Invalid proposal";
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

    //  Anything still keyed below height_ is stale; anything above
    //  height_ + 1 is unreachable. Drop both so a misbehaving peer
    //  can't grow the map without bound.
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
      for (auto &v : pv->second)
        pending_prevotes_.push_back(std::move(v));
      future_height_prevotes_.erase(pv);
    }

    auto pc = future_height_precommits_.find(height_);
    if (pc != future_height_precommits_.end())
    {
      for (auto &v : pc->second)
        pending_precommits_.push_back(std::move(v));
      future_height_precommits_.erase(pc);
    }

    //  Prune anything that's now unreachable. See the comment on
    //  future_height_prevotes_.
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

    //  Signers of a timeout vote are members of the committed set.
    auto committed = deps_.active_set(/*force_rotation=*/false);
    if (tv.signer_index >= committed.size())
      return;

    const Id vid = committed[tv.signer_index];
    Core::ValidatorInfo vinfo;
    if (!deps_.state_lookup_validator ||
        !deps_.state_lookup_validator(vid, vinfo))
    {
      return;
    }

    const Crypto::Hash signing_hash =
        timeoutVoteSigningHash(tv.height, tv.round);
    if (!Crypto::verify(signing_hash, vinfo.effectiveConsensusKey(), tv.signature))
      return;

    for (const auto &existing : timeout_votes_)
    {
      if (existing.round == tv.round &&
          existing.signer_index == tv.signer_index)
      {
        return;
      }
    }

    timeout_votes_.push_back(tv);
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

      if (is_precommit && step_ != Step::Precommit)
      {
        still_pending.push_back(v);
        continue;
      }
      if (!is_precommit && step_ != Step::Prevote)
      {
        still_pending.push_back(v);
        continue;
      }

      auto &container = is_precommit ? precommits_ : prevotes_;
      const bool have_vote = container.count(v.signer_index) > 0;

      if (!have_vote && !voteIsVerifiable(v))
      {
        still_pending.push_back(v);
        continue;
      }

      if (is_precommit)
        handlePrecommit(v);
      else
        recordVote(v, /*is_precommit=*/false);
    }

    buffer = std::move(still_pending);
  }

  bool BftConsensus::voteIsVerifiable(const Vote &v) const
  {
    if (!v.is_nil)
      return proposals_by_hash_.count(v.block_hash) > 0;

    return proposal_for_round_.count({v.height, v.round}) > 0;
  }

  void BftConsensus::handlePrevote(const Vote &v)
  {
    log_(Logging::DEBUGGING) << "handlePrevote: step=" << static_cast<int>(step_)
                             << " signer=" << v.signer_index
                             << " verifiable=" << voteIsVerifiable(v);

    if (v.height != height_)
    {
      //  Buffer exactly one height ahead. See the comment on
      //  future_height_prevotes_ for why we don't go further.
      if (v.height == height_ + 1)
        future_height_prevotes_[v.height].push_back(v);
      return;
    }
    if (v.round != round_)
      return;

    if (step_ == Step::Propose || step_ == Step::NewHeight)
    {
      pending_prevotes_.push_back(v);
      return;
    }
    if (step_ != Step::Prevote)
      return;

    const bool have_vote = prevotes_.count(v.signer_index) > 0;

    if (!have_vote && !voteIsVerifiable(v))
    {
      pending_prevotes_.push_back(v);
      return;
    }

    recordVote(v, false);
  }

  void BftConsensus::handlePrecommit(const Vote &v)
  {
    if (v.height != height_)
    {
      if (v.height == height_ + 1)
        future_height_precommits_[v.height].push_back(v);
      return;
    }

    if (v.round != round_)
      return;

    //  A precommit for the block we are locked on is meaningful at any
    //  step at or after Prevote, not only at Precommit. The lock is
    //  the one piece of round-crossing context that survives a round
    //  advance: validators locked on X in round R re-precommit X in
    //  round R+1, and those precommits must be counted in R+1 even
    //  though the local node may still be in Propose.
    //
    //  Precommits for anything else stay buffered until Precommit, so
    //  a minority cannot drive the node toward a commit on a block
    //  that was never polka'd.
    const bool for_locked_block = locked_ && !v.is_nil &&
                                  v.block_hash == locked_hash_;

    if (!for_locked_block &&
        (step_ == Step::Propose || step_ == Step::Prevote ||
         step_ == Step::NewHeight))
    {
      pending_precommits_.push_back(v);
      return;
    }

    if (!for_locked_block && step_ != Step::Precommit)
      return;

    const bool have_vote = precommits_.count(v.signer_index) > 0;

    if (!have_vote && !voteIsVerifiable(v))
    {
      pending_precommits_.push_back(v);
      return;
    }

    //  A precommit is only meaningful if it references a block the
    //  network has a reason to precommit at this round:
    //
    //    - nil: always acceptable.
    //    - the block we are locked on: acceptable.
    //    - the block for which a prevote quorum formed this round:
    //      acceptable.
    //
    //  Anything else is dropped.
    if (!v.is_nil && v.block_hash != locked_hash_ &&
        !(valid_set_ && v.block_hash == valid_hash_))
    {
      log_(Logging::DEBUGGING)
          << "Rejecting precommit for block not locked or valid: h=" << v.height
          << " r=" << v.round
          << " signer=" << v.signer_index
          << " hash=" << v.block_hash.toString().substr(0, 16);
      return;
    }

    recordVote(v, /*is_precommit=*/true);
  }

  //  Timers

  void BftConsensus::pollTimers()
  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!running_ || !round_timer_)
      return;

    log_(Logging::DEBUGGING) << "pollTimers: h=" << height_
                             << " r=" << round_
                             << " step=" << static_cast<int>(step_)
                             << " expired=" << (round_timer_->isExpired() ? "yes" : "no");

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

    log_(Logging::WARNING) << "onPrecommitTimeout: h=" << height_
                           << " r=" << round_
                           << " precommits=" << precommits_.size()
                           << " quorum=" << (quorum_block ? "yes" : "no")
                           << " prop_known=" << (quorum_block && proposals_by_hash_.count(*quorum_block) > 0 ? "yes" : "no");

    broadcastTimeoutVote(round_);

    if (quorum_block.has_value() && proposals_by_hash_.count(*quorum_block) > 0)
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

  bool BftConsensus::propose()
  {
    Core::Block block;

    const bool emergency = useEmergencySet();

    auto active = deps_.active_set(emergency);

    block.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
    block.header.chain_id = deps_.chain_id ? deps_.chain_id() : 0;
    block.header.height = height_;
    block.header.timestamp_ms = deps_.now_ms
                                    ? deps_.now_ms()
                                    : static_cast<uint64_t>(
                                          std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count());
    block.header.parent_hash = deps_.parent_hash ? deps_.parent_hash() : Crypto::Hash{};

    if (callbacks_.select_transactions)
    {
      //  Reserve space for the header, including a worst-case certificate,
      //  since one may be attached below when the emergency path fires.
      //  The exact size depends on the certificate, which we don't have
      //  yet at this point.
      constexpr uint64_t MAX_HEADER_RESERVE = 4 * 1024;
      block.transactions = callbacks_.select_transactions(
          config_.max_block_bytes > MAX_HEADER_RESERVE
              ? config_.max_block_bytes - MAX_HEADER_RESERVE
              : 0,
          config_.max_block_txs);
    }

    if (!equivocations_.empty() && !active.empty())
    {
      std::set<Index> already_slashed;

      for (size_t i = 0; i < equivocations_.size(); ++i)
      {
        const auto &ev = equivocations_[i];

        if (!ev.isValid())
          continue;

        if (ev.vote_a.signer_index >= active.size())
          continue;

        if (already_slashed.count(ev.vote_a.signer_index) > 0)
          continue;

        if (block.transactions.size() >= config_.max_block_txs)
          break;

        Core::Transaction slash_tx{};
        slash_tx.version = GlobalConfig::CURRENT_TRANSACTION_VERSION;
        slash_tx.chain_id = block.header.chain_id;
        slash_tx.tx_type = Core::TxType::Slash;
        slash_tx.payload = Core::encodeSlashPayload(
            encodeVote(ev.vote_a),
            encodeVote(ev.vote_b));

        block.transactions.push_back(std::move(slash_tx));
        already_slashed.insert(ev.vote_a.signer_index);
      }
    }

    block.header.tx_root = Core::computeTxRoot(block.transactions);
    block.header.tx_count = static_cast<uint32_t>(block.transactions.size());

    block.header.validator_set_root = Core::computeValidatorSetRoot(active);
    block.header.active_validator_count = static_cast<uint32_t>(active.size());

    block.header.commit_round = round_;

    block.participants = active;

    block.header.proposer = deps_.my_address ? deps_.my_address() : Crypto::Address{};

    //  Stamp the flag, and attach the certificate that justifies it.
    //  Without f+1 attestations the emergency block is not legal; we
    //  decline to propose rather than emit a block every verifier
    //  will reject.
    if (emergency)
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

      //  The certificate attests to a specific round (the smallest
      //  round >= EMERGENCY_ROTATION_ROUNDS with enough signers).
      //  The verifier checks each vote's round against this header
      //  field, so they must match. Using round_ here would fail
      //  verification whenever the certificate came from an earlier
      //  round than the one we're now proposing in.
      block.header.emergency_rotation = cert_round;
    }

    auto sim_root = simulateBlock(block);
    if (!sim_root.has_value())
    {
      log_(Logging::WARNING) << "Proposed block failed simulation";
      return false;
    }
    block.header.state_root = *sim_root;

    Crypto::Hash block_hash = block.hash();
    Proposal p;
    p.height = height_;
    p.round = round_;
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

    log_(Logging::DEBUGGING) << "Proposed block for h=" << height_
                             << " r=" << round_
                             << " em=" << (emergency ? "yes" : "no")
                             << " txs=" << block.transactions.size()
                             << " hash=" << block_hash.toString().substr(0, 16);

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
    tv.signer_index = idx;

    const Crypto::Hash signing_hash =
        timeoutVoteSigningHash(tv.height, tv.round);
    if (deps_.sign)
      tv.signature = deps_.sign(signing_hash);

    callbacks_.broadcast_timeout_vote(tv);
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
      std::vector<bool> seen(committed.size(), false);
      std::vector<TimeoutVote> picked;
      picked.reserve(required);

      for (const TimeoutVote *tv : votes)
      {
        if (tv->signer_index >= committed.size())
          continue;
        if (seen[tv->signer_index])
          continue;
        seen[tv->signer_index] = true;
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
                             << "computed=" << block_hash.toString().substr(0, 16)
                             << " proposal=" << p.block_hash.toString().substr(0, 16);
      return false;
    }

    if (block.header.height != p.height)
    {
      log_(Logging::WARNING) << "validateProposal: height mismatch: "
                             << "header=" << block.header.height
                             << " proposal=" << p.height;
      return false;
    }

    //  If the block carries the emergency flag, verify the certificate
    //  before doing anything else. The committed set is what the
    //  certificate's signers are drawn from, so resolve with
    //  force_rotation=false.
    if (block.header.emergency_rotation > 0)
    {
      auto committed = deps_.active_set(/*force_rotation=*/false);

      log_(Logging::DEBUGGING) << "validateProposal: em=" << block.header.emergency_rotation
                               << " cert_votes=" << block.header.timeout_certificate.votes.size()
                               << " committed_size=" << committed.size();

      if (!verifyTimeoutCertificate(block, committed, height_))
      {
        log_(Logging::WARNING) << "validateProposal: bad timeout certificate";
        return false;
      }
    }

    Crypto::Hash signing_hash = proposalSigningHash(p.height, p.round, block_hash);
    auto pk = deps_.signer_public_key(p.signer_index);
    if (!pk.has_value())
    {
      log_(Logging::WARNING) << "validateProposal: no public key for signer "
                             << p.signer_index;
      return false;
    }

    if (!Crypto::verify(signing_hash, *pk, p.signature))
    {
      log_(Logging::WARNING) << "validateProposal: signature verification failed";
      return false;
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

  //  Quorum tracking

  bool BftConsensus::recordVote(const Vote &v, bool is_precommit)
  {
    auto &container = is_precommit ? precommits_ : prevotes_;

    log_(Logging::DEBUGGING) << "recordVote: precommit=" << is_precommit
                             << " signer=" << v.signer_index
                             << " h=" << v.height
                             << " r=" << v.round
                             << " nil=" << v.is_nil
                             << " have=" << (container.count(v.signer_index) > 0);

    //  -------- Conflict path --------
    //
    //  A second vote from a signer we already hold a vote from is a
    //  potential equivocation. Record it ONLY if both votes' signatures
    //  verify. A forged conflict must not be able to poison the
    //  proposer's evidence buffer — that's a cheap network-wide
    //  liveness attack, since the poisoned evidence can't be committed
    //  (the block carrying it fails validation) and never gets erased.
    //
    //  The set to verify against is the one the round ran on. For a
    //  non-nil vote we can read the flag from the block, if we have it.
    //  For a nil vote we read the proposal for the round. If neither is
    //  known, we cannot verify and therefore cannot record — the
    //  conflict stays unrecorded until the block arrives, at which point
    //  the vote will be re-delivered and the evidence produced then.
    if (container.count(v.signer_index) > 0)
    {
      const Vote &first = container.at(v.signer_index);
      if (first.block_hash != v.block_hash || first.is_nil != v.is_nil)
      {
        //  Resolve the set once, from whichever vote gives us an
        //  answer. Prefer the incoming vote's block (it's the newer
        //  information); fall back to the first vote's block; then to
        //  the round's proposal.
        bool have_set = false;
        bool emergency = false;

        auto try_vote_set = [&](const Vote &candidate) -> bool
        {
          if (!candidate.is_nil)
          {
            auto it = proposals_by_hash_.find(candidate.block_hash);
            if (it == proposals_by_hash_.end())
              return false;
            emergency = (it->second.header.emergency_rotation > 0);
            return true;
          }
          auto round_it = proposal_for_round_.find({candidate.height, candidate.round});
          if (round_it == proposal_for_round_.end())
            return false;
          auto block_it = proposals_by_hash_.find(round_it->second);
          if (block_it == proposals_by_hash_.end())
            return false;
          emergency = (block_it->second.header.emergency_rotation > 0);
          return true;
        };

        if (try_vote_set(v))
        {
          have_set = true;
        }
        else if (try_vote_set(first))
        {
          have_set = true;
        }

        if (!have_set)
        {
          //  Cannot verify — do not record. See the comment above.
          log_(Logging::DEBUGGING)
              << "Conflicting vote for unknown block, not recording evidence: "
              << "signer=" << v.signer_index
              << " h=" << v.height
              << " r=" << v.round;
          return false;
        }

        auto active = deps_.active_set(emergency);
        if (v.signer_index >= active.size())
          return false;

        const Id vid = active[v.signer_index];
        Core::ValidatorInfo vinfo;
        if (!deps_.state_lookup_validator ||
            !deps_.state_lookup_validator(vid, vinfo))
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
              << "signer=" << v.signer_index
              << " h=" << v.height
              << " r=" << v.round;
          return false;
        }

        EquivocationEvidence ev;
        ev.vote_a = first;
        ev.vote_b = v;
        if (ev.isValid())
        {
          equivocations_.push_back(ev);

          if (equivocations_.size() > MAX_EQUIVOCATION_EVIDENCE)
          {
            equivocations_.erase(equivocations_.begin());
          }

          log_(Logging::WARNING)
              << "Equivocation evidence recorded: signer=" << v.signer_index
              << " h=" << v.height
              << " r=" << v.round
              << " hash_a=" << first.block_hash.toString().substr(0, 16)
              << " hash_b=" << v.block_hash.toString().substr(0, 16)
              << " nil_a=" << first.is_nil
              << " nil_b=" << v.is_nil;
        }
      }
      return false;
    }

    //  -------- First-vote path (unchanged) --------

    const bool emergency = roundUsesEmergencySetForVote(v);
    auto active = deps_.active_set(emergency);

    if (v.signer_index >= active.size())
      return false;

    Crypto::Hash signing_hash = voteSigningHash(v.height, v.round,
                                                v.is_nil, v.block_hash);

    const Id vid = active[v.signer_index];
    Core::ValidatorInfo vinfo;
    if (!deps_.state_lookup_validator ||
        !deps_.state_lookup_validator(vid, vinfo))
    {
      return false;
    }
    const Crypto::PublicKey pk = vinfo.effectiveConsensusKey();

    if (!Crypto::verify(signing_hash, pk, v.signature))
      return false;

    container[v.signer_index] = v;

    log_(Logging::DEBUGGING) << (is_precommit ? "Precommit" : "Prevote")
                             << " received: h=" << v.height
                             << " r=" << v.round
                             << " signer=" << v.signer_index
                             << " nil=" << v.is_nil
                             << " em=" << (emergency ? "yes" : "no");

    //  Fire the state transition only when a *value quorum* has formed
    //  — that is, `threshold` votes for the same non-nil block hash.
    //  A round where everyone votes nil has no value quorum and is
    //  advanced by the round timer instead.
    //
    //  enterCommit is reachable from Step::Propose as well as
    //  Step::Precommit: in the round-crossing case, precommits for a
    //  locked block can arrive while we're still in Propose, and if
    //  they form a quorum they should commit immediately rather than
    //  waiting for the round timer to advance us.
    if (quorumValue(is_precommit).has_value())
    {
      if (is_precommit &&
          (step_ == Step::Precommit || step_ == Step::Propose))
      {
        enterCommit(height_, round_);
      }
      else if (!is_precommit && step_ == Step::Prevote)
      {
        enterPrecommit(height_, round_);
      }
    }

    return true;
  }

  std::optional<Crypto::Hash> BftConsensus::quorumValue(bool is_precommit) const
  {
    auto &container = is_precommit ? precommits_ : prevotes_;

    //  Resolve the emergency flag from the votes themselves. If any
    //  non-nil vote references a block we know, use that block's header
    //  flag. This is the set the round actually ran on. If all votes are
    //  nil, fall back to the current round's proposal, then to the local
    //  counter — same fallbacks the old code used, but only for nil-only
    //  rounds, which don't carry a block reference to resolve against.
    //
    //  This matters for round-crossing: a validator locked on an
    //  emergency block in round R re-precommits it in round R+1. If the
    //  local node has no proposal for round R+1 yet, the old code used
    //  the non-emergency set and computed a different quorum threshold
    //  than the one the round actually ran on. That could let the node
    //  commit with a sub-threshold set, or refuse to commit at threshold.
    bool emergency = false;
    bool resolved = false;

    for (const auto &[idx, v] : container)
    {
      if (v.is_nil)
        continue;

      auto it = proposals_by_hash_.find(v.block_hash);
      if (it == proposals_by_hash_.end())
        continue;

      emergency = (it->second.header.emergency_rotation > 0);
      resolved = true;
      break;
    }

    if (!resolved)
      emergency = roundUsesEmergencySet(height_, round_);

    const size_t threshold = quorumThreshold(emergency);

    if (container.size() < threshold)
      return std::nullopt;

    std::unordered_map<std::string, size_t> counts;
    std::unordered_map<std::string, Crypto::Hash> hashes;

    for (const auto &[idx, v] : container)
    {
      if (v.is_nil)
        continue;

      std::string key(reinterpret_cast<const char *>(v.block_hash.data.data()), 32);
      counts[key]++;
      hashes[key] = v.block_hash;
    }

    for (const auto &[key, count] : counts)
    {
      if (count >= threshold)
        return hashes[key];
    }

    return std::nullopt;
  }

  size_t BftConsensus::countVotesFor(bool is_precommit,
                                     const Crypto::Hash &block_hash) const
  {
    auto &container = is_precommit ? precommits_ : prevotes_;
    size_t count = 0;
    for (const auto &[idx, v] : container)
    {
      if (!v.is_nil && v.block_hash == block_hash)
        count++;
    }
    return count;
  }

  size_t BftConsensus::countNilVotes(bool is_precommit) const
  {
    auto &container = is_precommit ? precommits_ : prevotes_;
    size_t count = 0;
    for (const auto &[idx, v] : container)
    {
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

    //  Prefer the round's proposal's flag. Fall back to the local
    //  counter only if no proposal has arrived yet — in that window a
    //  nil vote is the only thing we can cast, and it references no
    //  block, so the local counter is the best information available.
    const bool have_proposal = proposal_for_round_.count({height_, round_}) > 0;
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

  void BftConsensus::broadcastPrevote(bool is_nil, const Crypto::Hash &block_hash)
  {
    Vote v;
    v.height = height_;
    v.round = round_;
    v.signer_index = mySignerIndex();
    v.is_nil = is_nil;
    v.block_hash = block_hash;

    if (v.signer_index == INVALID_INDEX)
      return;

    Crypto::Hash signing_hash = voteSigningHash(height_, round_, is_nil, block_hash);
    if (deps_.sign)
      v.signature = deps_.sign(signing_hash);

    recordVote(v, /*is_precommit=*/false);

    if (callbacks_.broadcast_prevote)
      callbacks_.broadcast_prevote(v);
  }

  void BftConsensus::broadcastPrecommit(bool is_nil, const Crypto::Hash &block_hash)
  {
    Vote v;
    v.height = height_;
    v.round = round_;
    v.signer_index = mySignerIndex();
    v.is_nil = is_nil;
    v.block_hash = block_hash;

    if (v.signer_index == INVALID_INDEX)
      return;

    Crypto::Hash signing_hash = voteSigningHash(height_, round_, is_nil, block_hash);
    if (deps_.sign)
      v.signature = deps_.sign(signing_hash);

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
    proposal_for_round_.clear();

    timeout_votes_.clear();

    //  Move anything we buffered while finishing the *previous*
    //  height into the buffers for this height. Done after the
    //  clears above so the drained entries aren't wiped.
    //
    //  The proposal goes first: it populates proposal_for_round_,
    //  which voteIsVerifiable consults for nil votes, so draining the
    //  votes second lets them verify on the first pass through
    //  drainPendingVotes rather than waiting for a re-delivery.
    drainFutureHeightProposal();
    drainFutureHeightVotes();

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

    //  NOTE: valid_set_/valid_hash_/valid_round_ are NOT cleared here.
    //  Their whole purpose is to persist across rounds so enterPrevote
    //  can compare valid_round_ to locked_round_. They are cleared
    //  only on a new height.

    drainFutureProposal();
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
    return proposal_; // for the current height/round
  }
} // namespace Consensus