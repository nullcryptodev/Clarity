#pragma once

#include <gtest/gtest.h>
#include <random>

#include "Tests/ConsensusHelpers.h"
#include "Tests/Logger.h"

#include "Consensus/Types.h"

namespace Tests
{

  //  ConsensusNetwork
  //
  //  Owns N BftConsensus instances and a shared message queue. Each
  //  instance's broadcast callbacks push envelopes into the queue
  //  instead of delivering directly. deliverAll() drains the queue
  //  until it's empty, which settles a full round deterministically.
  //
  //  The network never advances time on its own. Tests drive timers
  //  explicitly via advanceAllTimers().
  //
  //  Two modes:
  //    - Deterministic (default, random_seed_ == 0): FIFO delivery,
  //      every message reaches every online peer, no partitions.
  //      This is what every existing test relies on.
  //    - Randomized (random_seed_ != 0): deliverAll() picks a random
  //      subset of the queue to deliver each iteration, then
  //      re-queues the rest. Used by adversarial tests to explore
  //      message orderings.
  //
  //  Partitions are orthogonal to the mode. A partition drops any
  //  message whose (from, to) pair crosses the partition. Cleared
  //  partitions re-deliver held messages.
  //
  //  Validator set, Dependencies, and the various per-instance test
  //  helpers come from a ConsensusTestEnv. The network owns the
  //  network-specific state: the queue, the offline flags, the
  //  partition table, and the RNG.
  class ConsensusNetwork
  {
  public:
    explicit ConsensusNetwork(size_t n, Logging::ILogger &logger)
        : logger_(logger),
          log_ref_(std::make_unique<Logging::LoggerRef>(logger, "net"))
    {
      env_.makeValidators(n);

      instances_.reserve(n);
      committed_.resize(n);
      offline_.assign(n, false);
      height_advances_.resize(n);

      //  Partition state. side_[i] == 0 means "not in a partition".
      //  Non-zero side ids partition the set into two groups;
      //  messages from one group to the other are dropped.
      partition_side_.assign(n, 0);

      for (size_t i = 0; i < n; ++i)
        instances_.push_back(makeInstance(i));
    }

    // ---- Lifecycle ----

    void startAll(Height height)
    {
      for (size_t i = 0; i < instances_.size(); ++i)
      {
        if (!offline_[i])
          instances_[i]->start(height);
      }
      //  Deliberately do NOT deliverAll() here. The network's initial
      //  proposal and votes are queued and delivered by the first
      //  advanceAllTimers() call. This keeps the contract
      //  "startAll(h) puts every instance at height h with the round's
      //  messages in flight" — it does not commit anything. Tests that
      //  want a commit call advanceAllTimers() or advanceUntil().
      //
      //  Before the pending-height fix in BftConsensus, deliverAll()
      //  here was harmless because enterCommit recursed through
      //  heights; the recursion is now deferred, so a deliverAll()
      //  here would commit exactly one height and skew every test's
      //  commit count.
    }

    void stopAll()
    {
      for (auto &inst : instances_)
        inst->stop();
    }

    // Deliver every queued message, including any messages those
    // deliveries generate, until the queue is empty. Order of
    // delivery depends on the current mode.
    void deliverAll()
    {
      constexpr size_t MAX_ROUNDS = 10'000;
      size_t iterations = 0;

      while (!queue_.empty())
      {
        if (++iterations > MAX_ROUNDS)
          throw std::runtime_error(
              "ConsensusNetwork::deliverAll: message loop did not settle");

        Envelope env;
        if (random_seed_ == 0)
        {
          env = std::move(queue_.front());
          queue_.erase(queue_.begin());
        }
        else
        {
          std::uniform_int_distribution<size_t> dist(0, queue_.size() - 1);
          size_t idx = dist(random_engine_);
          std::swap(queue_[idx], queue_[0]);
          env = std::move(queue_.front());
          queue_.erase(queue_.begin());
        }

        if (offline_[env.to])
          continue;
        if (env.from != env.to && crossesPartition(env.from, env.to))
          continue;

        switch (env.kind)
        {
        case Envelope::Proposal:
          //  Suppression models a network that persistently rejects
          //  ordinary proposals. Emergency proposals are the recovery
          //  path and must get through, otherwise the test would be
          //  modeling a permanent partition, not a proposal-suppression
          //  fault.
          if (proposal_suppressed_ && !env.is_emergency)
            continue;
          instances_[env.to]->onProposal(env.proposal);
          break;
        case Envelope::Prevote:
          instances_[env.to]->onPrevote(env.vote);
          break;
        case Envelope::Precommit:
          instances_[env.to]->onPrecommit(env.vote);
          break;
        case Envelope::TimeoutVote:
          instances_[env.to]->onTimeoutVote(env.timeout_vote);
          break;
        case Envelope::Restart:
          instances_[env.to]->start(env.restart_height);
          break;
        }
      }
    }

    size_t totalCommitted() const
    {
      size_t n = 0;
      for (const auto &v : committed_)
        n += v.size();
      return n;
    }

    void advanceAllTimers()
    {
      //  Snapshot heights before delivering, so we can tell whether
      //  any validator advanced a height during (A).
      std::vector<Height> heights_before(instances_.size());
      for (size_t i = 0; i < instances_.size(); ++i)
        heights_before[i] = offline_[i] ? 0 : heightOf(i);

      deliverAll();

      //  Only force-expire timers on validators that did NOT advance a
      //  height during the delivery pass. A validator that just
      //  entered a new height needs a real chance to receive that
      //  height's proposal before its round timer fires; otherwise it
      //  prevotes nil, advances a round, and — under randomized
      //  delivery — drifts to a round where no live proposer exists.
      for (size_t i = 0; i < instances_.size(); ++i)
      {
        if (offline_[i])
          continue;
        if (heightOf(i) != heights_before[i])
          continue;
        instances_[i]->forceTimerExpiryForTest();
      }

      for (size_t i = 0; i < instances_.size(); ++i)
        if (!offline_[i])
          instances_[i]->pollTimers();

      deliverAll();
    }

    // advance until a specific condition is met, or fail.
    bool advanceUntil(std::function<bool()> predicate, int max_passes = 16)
    {
      for (int i = 0; i < max_passes; ++i)
      {
        if (predicate())
          return true;
        advanceAllTimers();
      }
      return predicate();
    }

    // ---- Introspection ----

    Consensus::BftConsensus &instance(size_t i) { return *instances_[i]; }

    const std::vector<Core::Block> &committed(size_t i) const
    {
      return committed_[i];
    }

    const std::vector<Height> &heightAdvances(size_t i) const
    {
      return height_advances_[i];
    }

    const TestValidator &validator(size_t i) const
    {
      return env_.validator(i);
    }

    const ConsensusTestEnv &env() const { return env_; }
    ConsensusTestEnv &env() { return env_; }

    size_t size() const { return instances_.size(); }

    // ---- Offline control ----

    void setOffline(size_t i, bool offline)
    {
      offline_[i] = offline;
    }

    bool isOffline(size_t i) const { return offline_[i]; }

    // ---- Crash / restart ----
    //
    //  stopValidator(i) marks i as offline AND stops its consensus
    //  instance: it doesn't send, doesn't receive, doesn't fire
    //  timers, and its run loop is halted. Any messages already
    //  queued for it are dropped when delivered.
    //
    //  restartValidator(i) stops the instance (in case it was only
    //  setOffline'd, not stopValidator'd), brings it back at the
    //  current height, and backfills its committed chain from a live
    //  peer. Tests that care about the restored node's committed
    //  history should assert on future commits, not past ones.
    //
    //  setOffline(i, true) is a *network* control only: the instance
    //  keeps running and keeps its state, but messages to and from it
    //  are dropped. Use it to simulate a partition-like isolation
    //  without a lifecycle change.

    void stopValidator(size_t i)
    {
      if (i >= offline_.size())
        return;
      offline_[i] = true;
      instances_[i]->stop();
    }

    void restartValidator(size_t i, Height /*at_height*/)
    {
      if (i >= offline_.size())
        return;

      //  A validator may have been taken offline either via
      //  stopValidator (which calls stop()) or via setOffline (which
      //  only flips the network flag). In the latter case the instance
      //  is still running and start() would be a no-op, leaving it
      //  stuck at its old height forever. Stop it unconditionally so
      //  start() below actually takes effect.
      instances_[i]->stop();

      offline_[i] = false;

      Height target = 0;
      size_t peer = SIZE_MAX;
      for (size_t p = 0; p < instances_.size(); ++p)
      {
        if (p == i || offline_[p])
          continue;
        if (!committed_[p].empty())
        {
          committed_[i] = committed_[p];
          target = committed_[p].back().header.height + 1;
          peer = p;
          break;
        }
      }

      instances_[i]->start(target);

      //  Re-deliver the peer's current-round proposal to the restarted
      //  validator. Without this, the restarted node can never commit:
      //  it has no proposal for its entry height, and no other node
      //  will re-propose for that height.
      if (peer != SIZE_MAX)
      {
        auto proposal = instances_[peer]->currentProposalForTest();
        if (proposal.has_value())
          instances_[i]->onProposal(*proposal);
      }
    }

    Height heightOf(size_t i) const
    {
      //  BftConsensus::state() is const-safe but locks the mutex; the
      //  harness drives these serially so there's no contention.
      return instances_[i]->state().height;
    }

    // ---- Proposal suppression ----
    //
    //  When enabled, proposals are dropped on the *receiving* side in
    //  deliverAll, but proposers still generate them and the network
    //  still carries them. Timeout-vote gossip is unaffected. This
    //  models a fault where proposals are persistently rejected
    //  (malformed, failing validation, censored by the network layer)
    //  while the rest of the protocol keeps running, which is exactly
    //  the condition that drives consecutive_timeouts_ up to
    //  EMERGENCY_ROTATION_ROUNDS.
    //
    //  Note: restartValidator re-delivers a peer's proposal via a
    //  direct onProposal call, bypassing deliverAll. A test that
    //  enables suppression and then restarts a validator will see
    //  that one proposal get through. Don't mix the two unless you
    //  mean to.
    void setProposalSuppressed(bool suppressed)
    {
      proposal_suppressed_ = suppressed;
    }

    bool isProposalSuppressed() const { return proposal_suppressed_; }

    // ---- Partition control ----
    //
    //  setPartition({0, 1}, {2, 3}) puts validators 0 and 1 on side 1
    //  and validators 2 and 3 on side 2. Messages from a validator on
    //  side 1 to a validator on side 2 (or vice versa) are dropped
    //  until clearPartition() is called.
    //
    //  Pass overlapping or incomplete groups at your own risk — the
    //  fixture doesn't validate the partition, it just tags each
    //  validator with a side and compares tags.

    void setPartition(const std::vector<size_t> &side_a,
                      const std::vector<size_t> &side_b)
    {
      partition_side_.assign(instances_.size(), 0);
      for (size_t i : side_a)
        if (i < partition_side_.size())
          partition_side_[i] = 1;
      for (size_t i : side_b)
        if (i < partition_side_.size())
          partition_side_[i] = 2;
    }

    void clearPartition()
    {
      partition_side_.assign(instances_.size(), 0);
    }

    // ---- Randomized delivery ----

    //  0 (default): deterministic FIFO.
    //  Non-zero: seed for the internal RNG. Same seed + same starting
    //  conditions produces the same sequence of delivery decisions, so
    //  a failing case is reproducible.
    void setRandomSeed(uint64_t seed)
    {
      random_seed_ = seed;
      random_engine_.seed(seed);
    }

  private:
    bool crossesPartition(size_t from, size_t to) const
    {
      const uint8_t a = partition_side_[from];
      const uint8_t b = partition_side_[to];
      if (a == 0 || b == 0)
        return false; // not in a partition
      return a != b;
    }

    //  Per-instance callbacks. The env's makeCallbacks() returns a
    //  single set of callbacks built from the env's slots; that's
    //  fine for a fixture that owns a single BftConsensus, but the
    //  network needs per-instance callbacks because the broadcast must
    //  fan out to the sender's peers, not to a shared queue with no
    //  sender tag.
    //
    //  The Dependencies come from the env (single source of truth for
    //  what a consensus instance sees). The Callbacks are built here,
    //  per instance, because they close over `index`.
    Consensus::Callbacks makeCallbacks(size_t index)
    {
      Consensus::Callbacks cb;

      cb.broadcast_proposal =
          [this, index](const Consensus::Proposal &p)
      {
        if (offline_[index])
          return;

        //  Peek the emergency flag so deliverAll can let emergency
        //  proposals through even when proposal suppression is on.
        //  A full decode is fine here: the proposer already has the
        //  block in memory, and the tests use empty blocks.
        bool is_emergency = false;
        Core::Block b;
        if (Core::Block::deserialize(p.block_bytes.data(),
                                     p.block_bytes.size(), b))
          is_emergency = (b.header.emergency_rotation > 0);

        for (size_t to = 0; to < instances_.size(); ++to)
        {
          if (to == index || offline_[to])
            continue;
          Envelope env;
          env.kind = Envelope::Proposal;
          env.to = to;
          env.from = index;
          env.proposal = p;
          env.is_emergency = is_emergency;
          queue_.push_back(std::move(env));
        }
      };

      cb.broadcast_prevote =
          [this, index](const Consensus::Vote &v)
      {
        if (offline_[index])
          return;
        for (size_t to = 0; to < instances_.size(); ++to)
        {
          if (to == index || offline_[to])
            continue;
          Envelope env;
          env.kind = Envelope::Prevote;
          env.to = to;
          env.from = index;
          env.vote = v;
          queue_.push_back(std::move(env));
        }
      };

      cb.broadcast_precommit =
          [this, index](const Consensus::Vote &v)
      {
        if (offline_[index])
          return;
        for (size_t to = 0; to < instances_.size(); ++to)
        {
          if (to == index || offline_[to])
            continue;
          Envelope env;
          env.kind = Envelope::Precommit;
          env.to = to;
          env.from = index;
          env.vote = v;
          queue_.push_back(std::move(env));
        }
      };

      cb.broadcast_timeout_vote =
          [this, index](const Consensus::TimeoutVote &tv)
      {
        if (offline_[index])
          return;
        for (size_t to = 0; to < instances_.size(); ++to)
        {
          if (to == index || offline_[to])
            continue;
          Envelope env;
          env.kind = Envelope::TimeoutVote;
          env.to = to;
          env.from = index;
          env.timeout_vote = tv;
          queue_.push_back(std::move(env));
        }
      };

      cb.select_transactions = [](uint64_t, uint64_t)
      { return std::vector<Core::Transaction>{}; };

      cb.on_block_committed =
          [this, index](const Core::Block &b)
      {
        committed_[index].push_back(b);
        //  No Restart envelope: enterCommit already calls
        //  enterNewHeight() synchronously after this callback returns,
        //  so start() would be a no-op. Queuing it only perturbs
        //  randomized delivery order.
      };

      cb.on_height_advanced =
          [this, index](Height h)
      {
        height_advances_[index].push_back(h);
      };

      return cb;
    }

    std::unique_ptr<Consensus::BftConsensus> makeInstance(size_t index)
    {
      return std::make_unique<Consensus::BftConsensus>(
          env_.makeDeps(index),
          makeCallbacks(index),
          Consensus::Config{},
          *log_ref_);
    }

    Logging::ILogger &logger_;
    std::unique_ptr<Logging::LoggerRef> log_ref_;

    //  Single source of truth for what a consensus instance sees.
    //  Owns the validator set, the emergency set, and the network
    //  identity. Not copyable or movable; the deps lambdas capture
    //  `this`, so it must outlive every instance.
    ConsensusTestEnv env_;

    std::vector<std::unique_ptr<Consensus::BftConsensus>> instances_;
    std::vector<std::vector<Core::Block>> committed_;
    std::vector<std::vector<Height>> height_advances_;
    std::vector<bool> offline_;
    std::vector<Envelope> queue_;

    //  Partition state: 0 = unpartitioned, 1 = side A, 2 = side B.
    //  Messages between different non-zero sides are dropped.
    std::vector<uint8_t> partition_side_;

    //  When true, proposals are dropped on the receiving side in
    //  deliverAll. See setProposalSuppressed.
    bool proposal_suppressed_{false};

    //  Randomized delivery. random_seed_ == 0 means deterministic.
    uint64_t random_seed_{0};
    std::mt19937_64 random_engine_;
  };

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
      deps.active_set = [this](bool force_rotation) -> std::vector<Id>
      {
        if (force_rotation && !emergency_ids_.empty())
          return emergency_ids_;
        return activeIds();
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
      deps.state_lookup_validator =
          [this](Id id, Core::ValidatorInfo &out) -> bool
      {
        for (const auto &v : validators_)
        {
          if (v.id == id)
          {
            out.id = id;
            std::memcpy(out.reward_address.data.data(),
                        v.pubkey().data.data(), 32);
            out.owner = out.reward_address;
            out.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
            out.uptime_score = 10'000;
            out.is_active = true;
            return true;
          }
        }
        return false;
      };
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
      cb.broadcast_timeout_vote = [this](const Consensus::TimeoutVote &tv)
      { broadcast_timeout_votes.push_back(tv); };
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
      p.signer_id = validators_[proposer_index].id;
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
      v.signer_id = validators_[signer_index].id;
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

    void setEmergencyIds(std::vector<Id> ids)
    {
      emergency_ids_ = std::move(ids);
    }

    // ------------------------------------------------------------------
    //  Timeout certificate helpers
    // ------------------------------------------------------------------

    //  Sign `hash` with validator `signer_index`'s private key. The
    //  index is a position in the committed set, matching the
    //  convention used by makeSignedVote and by the consensus object
    //  when it resolves a signer through active_set[signer_index].
    Crypto::Signature signForValidator(Index signer_index,
                                       const Crypto::Hash &hash)
    {
      if (signer_index >= validators_.size())
        return Crypto::Signature{};
      return validators_[signer_index].sign(hash);
    }

    //  Build a TimeoutCertificate for (height, round) with one vote
    //  per signer index in `signers`. Signatures are produced by
    //  signForValidator, so a certificate built here verifies against
    //  the fixture's key material and against the fixture's
    //  state_lookup_validator, which exposes each validator's pubkey
    //  as its reward_address.
    Consensus::TimeoutCertificate makeTimeoutCertificate(
        Height height, Round round, const std::vector<Index> &signers)
    {
      Consensus::TimeoutCertificate cert;
      cert.votes.reserve(signers.size());

      const Crypto::Hash signing_hash =
          Consensus::timeoutVoteSigningHash(height, round);

      for (Index idx : signers)
      {
        Consensus::TimeoutVote tv;
        tv.height = height;
        tv.round = round;
        tv.signer_index = idx;
        if (idx < validators_.size())
          tv.signer_id = validators_[idx].id;
        tv.signature = signForValidator(idx, signing_hash);
        cert.votes.push_back(tv);
      }

      return cert;
    }

    //  Build a signed TimeoutVote for `signer_index` and deliver it to
    //  the consensus object via onTimeoutVote — equivalent to what a
    //  peer's P2P message would do.
    void deliverTimeoutVote(Index signer_index, Height height, Round round)
    {
      const Crypto::Hash signing_hash =
          Consensus::timeoutVoteSigningHash(height, round);

      Consensus::TimeoutVote tv;
      tv.height = height;
      tv.round = round;
      tv.signer_index = signer_index;
      if (signer_index < validators_.size())
        tv.signer_id = validators_[signer_index].id;
      tv.signature = signForValidator(signer_index, signing_hash);

      consensus_->onTimeoutVote(tv);
    }

    NoopLogger logger_;
    std::unique_ptr<Logging::LoggerRef> log_ref_;
    std::vector<TestValidator> validators_;
    Height current_height_{0};
    std::unique_ptr<Consensus::BftConsensus> consensus_;

    std::vector<Consensus::Proposal> broadcast_proposals;
    std::vector<Consensus::Vote> broadcast_prevotes;
    std::vector<Consensus::Vote> broadcast_precommits;
    std::vector<Consensus::TimeoutVote> broadcast_timeout_votes;
    std::vector<Core::Block> committed_blocks;
    std::vector<Height> height_advances;

    //  Optional distinct emergency set. When empty (default), the
    //  fixture returns activeIds() regardless of force_rotation, which
    //  preserves the behavior every existing test relies on. When
    //  populated, force_rotation=true returns emergency_ids_ — that
    //  lets a test exercise the case where the emergency set differs
    //  from the committed set.
    std::vector<Id> emergency_ids_;
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