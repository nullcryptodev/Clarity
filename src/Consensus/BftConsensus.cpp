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
#include <set>

namespace Consensus
{
  namespace
  {
    constexpr uint64_t PROPOSE_TIMEOUT_MS = 5'000;
  } // anonymous namespace

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
  //
  //  The set a round runs on is determined by the proposal for that
  //  round, not by the local timeout counter. The proposal's block
  //  header carries `emergency_rotation`; every node reads the flag
  //  from there and derives the same set. The local counter is only
  //  consulted by the proposer, to decide whether to set the flag on
  //  the block it is about to build.
  //
  //  There is exactly one case where the local counter drives the set
  //  choice: `propose()`, before the block exists. Every verifier
  //  reads the flag from the block.

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

    if (proposal_.has_value() &&
        proposal_->height == height &&
        proposal_->round == round)
    {
      Crypto::Hash block_hash = proposal_->block_hash;
      prevote_nil = false;
      prevote_hash = block_hash;

      if (!locked_)
      {
        locked_ = true;
        locked_hash_ = block_hash;
        locked_round_ = round;
      }
    }

    broadcastPrevote(prevote_nil, prevote_hash);

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

    auto quorum_block = quorumValue(/*is_precommit=*/false);

    if (quorum_block.has_value())
    {
      valid_set_ = true;
      valid_hash_ = *quorum_block;
      valid_round_ = round;
    }

    bool precommit_nil = true;
    Crypto::Hash precommit_hash{};

    if (quorum_block.has_value())
    {
      if (!locked_ || locked_hash_ == *quorum_block)
      {
        precommit_nil = false;
        precommit_hash = *quorum_block;
      }
    }

    broadcastPrecommit(precommit_nil, precommit_hash);

    if (round_timer_)
      round_timer_->start(round);

    drainPendingVotes(/*is_precommit=*/true);
  }

  void BftConsensus::enterCommit(Height height, Round round)
  {
    step_ = Step::Commit;

    log_(Logging::INFO) << "Entering commit: h=" << height << " r=" << round;

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

    // Record the round the precommit quorum formed in. This is the
    // round the validators signed in when they precommitted, and it's
    // what BlockProcessor::checkQuorum uses to recompute the signing
    // hash.
    //
    // This may differ from the round recorded in the proposal (which
    // was set by the proposer to the round the block was proposed in).
    // In the common case they're equal. In the round-crossing case —
    // validators locked on X in round R, round advances, they
    // re-precommit X in round R+1 — commit_round becomes R+1 while
    // the proposal's commit_round was R.
    //
    // Mutating commit_round here does NOT change the block's hash,
    // because BlockHeader::hash() excludes commit_round. The
    // signatures are over the hash, and the hash is unchanged. The
    // mutated commit_round is what checkQuorum will use.
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

    if (block.quorum_signatures.size() < quorumThreshold())
    {
      log_(Logging::WARNING)
          << "Precommit quorum reported but signature set is short ("
          << block.quorum_signatures.size() << " < "
          << quorumThreshold() << "), advancing round";
      enterPropose(height, round + 1);
      return;
    }

    //  The commit is real. Reset the timeout counter now — not at
    //  the top of the function, because a failed enterCommit (no
    //  quorum, unknown block, short signature set) is exactly the
    //  stall case the counter is meant to detect. Resetting there
    //  would keep the counter at 0 or 1 forever on a stalled chain,
    //  and the emergency path would never fire.
    consecutive_timeouts_ = 0;

    //  Erase evidence that this block includes. Every node runs this,
    //  not just the proposer. The block's Slash txs are the source of
    //  truth: if a Slash tx is in the committed block, the evidence it
    //  carries is on-chain and permanent, and no node should
    //  re-include it.
    //
    //  A node that wasn't the proposer has no idea what the proposer
    //  intended to include. It only sees the block. Scanning the
    //  block's transactions is the only way for it to know what
    //  evidence was committed.
    //
    //  The block's Slash txs were already verified on-chain when the
    //  block was applied by every node's BlockProcessor. Re-verifying
    //  here would be redundant, so we use the decode-only helper.
    for (const auto &tx : block.transactions)
    {
      if (tx.tx_type != Core::TxType::Slash)
        continue;

      auto decoded = Core::decodeSlashEvidence(tx.payload);
      if (!decoded.has_value())
        continue;

      //  Erase every evidence entry against the same signer at the same
      //  (height, round). The block's Slash tx proves one offense at
      //  that (H, R); any other conflicting pair a validator produced
      //  at the same (H, R) describes the same offense. Including them
      //  in a second Slash tx would double-slash for one infraction,
      //  which is neither correct nor intended.
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

    log_(Logging::INFO)
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

  void BftConsensus::handleProposal(const Proposal &p)
  {
    if (p.height != height_)
    {
      log_(Logging::WARNING) << "handleProposal REJECT height: p=" << p.height << " local=" << height_;
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

    //  Deserialize first. The block header carries the
    //  emergency_rotation flag, which determines which active set
    //  this round ran on. Every check below must use that set, not
    //  the local counter — otherwise two honest nodes whose counters
    //  disagree by one will compute different proposers and reject
    //  each other's proposals.
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

    log_(Logging::WARNING) << "handleProposal SET: h=" << height_
                           << " r=" << round_
                           << " hash=" << p.block_hash.toString().substr(0, 16);

    proposals_by_hash_[p.block_hash] = block;

    //  Record the block for this (height, round). Later votes at the
    //  same round will look up the flag through this map.
    proposal_for_round_[{p.height, p.round}] = p.block_hash;

    //  A proposal just arrived for the current round. Votes that were
    //  buffered because their block was unknown can now be verified.
    drainPendingVotes(/*is_precommit=*/false);
    drainPendingVotes(/*is_precommit=*/true);

    log_(Logging::DEBUGGING) << "Accepted proposal for h=" << height_
                             << " r=" << round_
                             << " hash=" << p.block_hash.toString().substr(0, 16);
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

      //  A vote from a signer we already have a vote from is a
      //  potential equivocation — deliver it to recordVote so the
      //  conflict check can run, even if the block is unknown.
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
    if (v.height != height_)
      return;
    if (v.round != round_)
      return;

    if (step_ == Step::Propose || step_ == Step::NewHeight)
    {
      pending_prevotes_.push_back(v);
      return;
    }
    if (step_ != Step::Prevote)
      return;

    //  If we already hold a vote from this signer at this round, the
    //  incoming vote is either a duplicate or an equivocation. Route
    //  it to recordVote so the conflict check runs — it doesn't need
    //  the block to detect the conflict, only to verify the signature,
    //  and a conflicting vote is evidence regardless.
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
      return;

    if (v.round != round_)
      return;

    if (step_ == Step::Propose || step_ == Step::Prevote ||
        step_ == Step::NewHeight)
    {
      pending_precommits_.push_back(v);
      return;
    }

    if (step_ != Step::Precommit)
      return;

    const bool have_vote = precommits_.count(v.signer_index) > 0;

    if (!have_vote && !voteIsVerifiable(v))
    {
      pending_precommits_.push_back(v);
      return;
    }

    // A precommit is only meaningful if it references a block the
    // network has a reason to precommit at this round:
    //
    //   - nil: always acceptable.
    //   - the block we are locked on: acceptable.
    //   - the block for which a prevote quorum formed this round:
    //     acceptable.
    //
    // Anything else is dropped.
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

    log_(Logging::WARNING) << "pollTimers: h=" << height_
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

    enterPrevote(height_, round_);
  }

  void BftConsensus::onPrevoteTimeout()
  {
    log_(Logging::DEBUGGING) << "Prevote timeout: h=" << height_
                             << " r=" << round_;

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

    //  The proposer's decision: is the local counter high enough to
    //  warrant the emergency set? This is the only place the local
    //  counter drives the set choice. Once the block is built, the
    //  flag is authoritative for every verifier.
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
      block.transactions = callbacks_.select_transactions(
          config_.max_block_bytes - 258,
          config_.max_block_txs);
    }

    //  Append one Slash system transaction per equivocation we hold
    //  evidence for, subject to two filters:
    //
    //    1. The evidence must be internally valid (two non-null
    //       signatures, same height/round/signer, different value).
    //    2. signer_index must be in range for the current active set.
    //
    //  Evidence that fails a filter is left in equivocations_ for a
    //  future proposer — a validator not yet in the active set may
    //  join next epoch, and a proof that's stale now may become valid
    //  later. Erasing on skip would lose it permanently.
    //
    //  Erasure of included evidence happens at commit time, not
    //  propose time, and is driven by scanning the committed block's
    //  Slash txs. That way every node erases evidence that a block
    //  contains, not just the node that proposed it.
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

    //  Stamp the flag. This is what every verifier reads.
    if (emergency)
      block.header.emergency_rotation = round_;

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

    log_(Logging::INFO) << "Proposed block for h=" << height_
                        << " r=" << round_
                        << " em=" << (emergency ? "yes" : "no")
                        << " txs=" << block.transactions.size()
                        << " hash=" << block_hash.toString().substr(0, 16);

    return true;
  }

  //  Validation
  //
  //  Takes the already-deserialized block. handleProposal deserializes
  //  first so it can read the emergency flag before choosing the set.

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

    //  Conflict check runs first, before signature verification and
    //  before any dependency on the active set. Two votes from the
    //  same signer at the same (height, round) with different
    //  (block_hash, is_nil) is an equivocation regardless of which
    //  set the round ran on — the conflict is a property of the two
    //  votes, not of any particular chain state. Detecting it here
    //  means evidence is recorded even when the block is unknown,
    //  which is the case an adversary can exploit by equivocating
    //  against a block no honest node has seen.
    //
    //  The votes' signatures are NOT verified here. On-chain
    //  verification (Core::verifyEquivocationProof, called from
    //  BlockProcessor::applySlash) re-verifies both signatures before
    //  any slash is applied, so a forged conflict cannot cause a
    //  slash — it can only produce a block that gets rejected, which
    //  is a liveness cost, not a safety one.
    if (container.count(v.signer_index) > 0)
    {
      const Vote &first = container.at(v.signer_index);
      if (first.block_hash != v.block_hash || first.is_nil != v.is_nil)
      {
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

    //  No conflict — this is the first vote from this signer at this
    //  (height, round). Verify and record.
    const bool emergency = roundUsesEmergencySetForVote(v);
    auto active = deps_.active_set(emergency);

    if (v.signer_index >= active.size())
      return false;

    Crypto::Hash signing_hash = voteSigningHash(v.height, v.round,
                                                v.is_nil, v.block_hash);

    //  Resolve the signer through the active set: index -> validator ID
    //  -> validator record. This is the same path BlockProcessor::checkQuorum
    //  uses. Using the raw signer index against a flat key table would
    //  make the same vote resolve to different validators depending on
    //  which set the round ran on.
    const Id vid = active[v.signer_index];
    Core::ValidatorInfo vinfo;
    if (!deps_.state_lookup_validator ||
        !deps_.state_lookup_validator(vid, vinfo))
    {
      return false;
    }
    const Crypto::PublicKey pk = vinfo.reward_address;

    if (!Crypto::verify(signing_hash, pk, v.signature))
      return false;

    container[v.signer_index] = v;

    log_(Logging::DEBUGGING) << (is_precommit ? "Precommit" : "Prevote")
                             << " received: h=" << v.height
                             << " r=" << v.round
                             << " signer=" << v.signer_index
                             << " nil=" << v.is_nil
                             << " em=" << (emergency ? "yes" : "no");

    // Fire the state transition only when a *value quorum* has formed
    // — that is, `threshold` votes for the same non-nil block hash.
    // A round where everyone votes nil has no value quorum and is
    // advanced by the round timer instead.
    if (quorumValue(is_precommit).has_value())
    {
      if (is_precommit && step_ == Step::Precommit)
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
    size_t threshold = quorumThreshold();

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

  size_t BftConsensus::quorumThreshold() const
  {
    //  Threshold depends on which set the current round runs on. If
    //  a proposal for this round is known, use its flag. Otherwise,
    //  no quorum can have formed yet (we haven't even proposed), so
    //  return the committed-set threshold as a safe default.
    const bool emergency = roundUsesEmergencySet(height_, round_);
    auto active = deps_.active_set(emergency);
    return Core::bftQuorum(active.size());
  }

  Index BftConsensus::mySignerIndex() const
  {
    auto my_id = deps_.my_validator_id();
    if (my_id == INVALID_ID)
      return INVALID_INDEX;

    //  If we're the proposer of this round and haven't proposed yet,
    //  use the local counter — we're about to make the decision
    //  ourselves. Otherwise, read the flag from the block.
    const bool emergency =
        proposal_for_round_.count({height_, round_}) > 0
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

    //  equivocations_ is deliberately NOT cleared here. Evidence
    //  observed at height H must remain available to the proposer at
    //  height H+1, H+2, ... until a block containing it commits.
    //  Erasure happens in enterCommit, driven by the committed block.
  }

  void BftConsensus::resetForNewRound(Round round)
  {
    round_ = round;

    // proposal_ is cleared because a stale-round proposal must not be
    // prevoted. proposals_by_hash_ is NOT cleared: a block proposed in
    // an earlier round at this height may still reach precommit quorum
    // if validators locked on it before the round changed.
    proposal_.reset();
    prevotes_.clear();
    precommits_.clear();

    // Votes for the previous round are stale. Clear the buffers.
    pending_prevotes_.clear();
    pending_precommits_.clear();

    // The valid values from a previous round are stale: precommits in
    // this round can only reference a block that reached a prevote
    // quorum in *this* round, or the block we're locked on.
    valid_set_ = false;
    valid_hash_ = Crypto::Hash{};
    valid_round_ = 0;

    // Deliver any proposal we queued for this round before the round
    // timer starts. If there is one, we now have a chance to prevote
    // it in this round instead of timing out and advancing again.
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
} // namespace Consensus