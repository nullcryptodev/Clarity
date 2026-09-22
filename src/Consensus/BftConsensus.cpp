// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BftConsensus.h"

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

  //  State transitions

  void BftConsensus::enterNewHeight(Height height)
  {
    resetForNewHeight(height);
    enterPropose(height, 0);
  }

  void BftConsensus::enterPropose(Height height, Round round)
  {
    resetForNewRound(round);
    step_ = Step::Propose;

    auto active = deps_.active_set();
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
  }

  void BftConsensus::enterPrecommit(Height height, Round round)
  {
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
      return;

    if (p.round != round_)
      return;

    if (proposal_.has_value())
      return;

    auto active = deps_.active_set();
    Id expected_proposer = proposerFor(height_, round_, active);
    if (p.signer_index >= active.size())
      return;
    if (active[p.signer_index] != expected_proposer)
    {
      log_(Logging::WARNING) << "Proposal from wrong signer";
      return;
    }

    Core::Block block;
    if (!validateProposal(p, block))
    {
      log_(Logging::WARNING) << "Invalid proposal";
      return;
    }

    proposal_ = p;
    proposals_by_hash_[p.block_hash] = block;

    log_(Logging::DEBUGGING) << "Accepted proposal for h=" << height_
                             << " r=" << round_
                             << " hash=" << p.block_hash.toString().substr(0, 16);
  }

  void BftConsensus::handlePrevote(const Vote &v)
  {
    if (v.height != height_)
      return;

    if (v.round != round_)
      return;

    if (step_ != Step::Prevote)
      return;

    recordVote(v, /*is_precommit=*/false);
  }

  void BftConsensus::handlePrecommit(const Vote &v)
  {
    if (v.height != height_)
      return;

    if (v.round != round_)
      return;

    if (step_ != Step::Precommit)
      return;

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
    log_(Logging::DEBUGGING) << "Precommit timeout: h=" << height_
                             << " r=" << round_;

    auto quorum_block = quorumValue(/*is_precommit=*/true);

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

  bool BftConsensus::propose()
  {
    Core::Block block;

    // Header setup using deps.
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

    // Select transactions from the mempool.
    if (callbacks_.select_transactions)
    {
      block.transactions = callbacks_.select_transactions(
          config_.max_block_bytes - 258,
          config_.max_block_txs);
    }

    block.header.tx_root = Core::computeTxRoot(block.transactions);
    block.header.tx_count = static_cast<uint32_t>(block.transactions.size());

    // Validator set root.
    auto active = deps_.active_set();
    block.header.validator_set_root = Core::computeValidatorSetRoot(active);
    block.header.active_validator_count = static_cast<uint32_t>(active.size());

    // Record the round this block is being proposed in. This is the
    // round the block's hash will commit to, and it's the round that
    // the validators will sign over when they prevote and precommit.
    //
    // This must be set *before* `block.hash()` is first computed,
    // because `commit_round` is part of the header serialization and
    // therefore part of the block's hash. If it were set later — e.g.
    // in `enterCommit` — the block's hash would change between proposal
    // and commit, the validators' signatures would be over the old
    // hash, and every signature verification would fail.
    block.header.commit_round = round_;

    // Populate participants with the full active set.
    //
    // This is a state-affecting field: BlockProcessor::applyBlock updates
    // each listed validator's last_seen_height, which mutates state and
    // therefore changes the post-block state root. The proposer must
    // therefore include the same participant set that the committer will
    // apply — and the only set the proposer can know at proposal time is
    // the active set. Whether a validator actually voted is not part of
    // the state transition and is tracked separately.
    //
    // Setting this to the empty vector (as the code did previously) makes
    // the simulation root diverge from the commit root, which fails the
    // state root check inside applyBlock at commit time.
    block.participants = active;

    // Proposer.
    block.header.proposer = deps_.my_address ? deps_.my_address() : Crypto::Address{};

    // Simulate the block to get the resulting state root and receipts root.
    auto sim_root = simulateBlock(block);
    if (!sim_root.has_value())
    {
      log_(Logging::WARNING) << "Proposed block failed simulation";
      return false;
    }
    block.header.state_root = *sim_root;

    // Sign the proposal.
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

    log_(Logging::INFO) << "Proposed block for h=" << height_
                        << " r=" << round_
                        << " txs=" << block.transactions.size()
                        << " hash=" << block_hash.toString().substr(0, 16);

    return true;
  }

  //  Validation

  bool BftConsensus::validateProposal(const Proposal &p, Core::Block &out_block)
  {
    if (!Core::Block::deserialize(p.block_bytes.data(),
                                  p.block_bytes.size(),
                                  out_block))
    {
      log_(Logging::WARNING) << "validateProposal: deserialize failed";
      return false;
    }

    Crypto::Hash block_hash = out_block.hash();
    if (block_hash != p.block_hash)
    {
      log_(Logging::WARNING) << "validateProposal: block hash mismatch: "
                             << "computed=" << block_hash.toString().substr(0, 16)
                             << " proposal=" << p.block_hash.toString().substr(0, 16);
      return false;
    }

    if (out_block.header.height != p.height)
    {
      log_(Logging::WARNING) << "validateProposal: height mismatch: "
                             << "header=" << out_block.header.height
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

    auto computed_root = simulateBlock(out_block);
    if (!computed_root.has_value())
    {
      log_(Logging::WARNING) << "validateProposal: simulateBlock returned nullopt";
      return false;
    }

    if (*computed_root != out_block.header.state_root)
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
    auto active = deps_.active_set();
    if (v.signer_index >= active.size())
      return false;

    auto &container = is_precommit ? precommits_ : prevotes_;

    if (container.count(v.signer_index) > 0)
      return false;

    Crypto::Hash signing_hash = voteSigningHash(v.height, v.round,
                                                v.is_nil, v.block_hash);
    auto pk = deps_.signer_public_key(v.signer_index);
    if (!pk.has_value())
      return false;

    if (!Crypto::verify(signing_hash, *pk, v.signature))
      return false;

    container[v.signer_index] = v;

    log_(Logging::DEBUGGING) << (is_precommit ? "Precommit" : "Prevote")
                             << " received: h=" << v.height
                             << " r=" << v.round
                             << " signer=" << v.signer_index
                             << " nil=" << v.is_nil;

    // Fire the state transition only when a *value quorum* has formed
    // — that is, `threshold` votes for the same non-nil block hash.
    // A round where everyone votes nil has no value quorum and is
    // advanced by the round timer instead. Firing on container size
    // (as the code did previously) would let a set of votes that
    // doesn't actually agree on a value advance the round, missing
    // the moment the value quorum would have formed.
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
    auto active = deps_.active_set();
    return Core::bftQuorum(active.size());
  }

  Index BftConsensus::mySignerIndex() const
  {
    auto my_id = deps_.my_validator_id();
    if (my_id == INVALID_ID)
      return INVALID_INDEX;

    auto active = deps_.active_set();
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

    // The valid values from a previous round are stale: precommits in
    // this round can only reference a block that reached a prevote
    // quorum in *this* round, or the block we're locked on.
    valid_set_ = false;
    valid_hash_ = Crypto::Hash{};
    valid_round_ = 0;
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
} // namespace Consensus