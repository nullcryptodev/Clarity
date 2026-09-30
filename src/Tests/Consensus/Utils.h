#pragma once

#include "Tests/Logger.h"
#include "Tests/Utils.h"

#include <random>

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

  class ConsensusNetwork
  {
  public:
    explicit ConsensusNetwork(size_t n, Logging::ILogger &logger)
        : logger_(logger), log_ref_(std::make_unique<Logging::LoggerRef>(logger, "net"))
    {
      validators_.reserve(n);
      for (size_t i = 0; i < n; ++i)
        validators_.push_back(TestValidator::make(static_cast<Id>(i + 1)));

      instances_.reserve(n);
      committed_.resize(n);
      offline_.assign(n, false);
      height_advances_.resize(n);

      // Partition state. side_[i] == 0 means "not in a partition".
      // Non-zero side ids partition the set into two groups; messages
      // from one group to the other are dropped.
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
      deliverAll();
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
          throw std::runtime_error("ConsensusNetwork::deliverAll: message loop did not settle");

        Envelope env;
        if (random_seed_ == 0)
        {
          env = queue_.front();
          queue_.erase(queue_.begin());
        }
        else
        {
          std::uniform_int_distribution<size_t> dist(0, queue_.size() - 1);
          size_t idx = dist(random_engine_);
          std::swap(queue_[idx], queue_[0]);
          env = queue_.front();
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
      // Snapshot heights before delivering, so we can tell whether any
      // validator advanced a height during (A).
      std::vector<Height> heights_before(instances_.size());
      for (size_t i = 0; i < instances_.size(); ++i)
        heights_before[i] = offline_[i] ? 0 : heightOf(i);

      deliverAll();

      // Only force-expire timers on validators that did NOT advance a
      // height during the delivery pass. A validator that just entered
      // a new height needs a real chance to receive that height's
      // proposal before its round timer fires; otherwise it prevotes
      // nil, advances a round, and — under randomized delivery —
      // drifts to a round where no live proposer exists.
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
      return validators_[i];
    }

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

      // Re-deliver the peer's current-round proposal to the restarted
      // validator. Without this, the restarted node can never commit:
      // it has no proposal for its entry height, and no other node will
      // re-propose for that height.
      if (peer != SIZE_MAX)
      {
        auto proposal = instances_[peer]->currentProposalForTest();
        if (proposal.has_value())
          instances_[i]->onProposal(*proposal);
      }
    }

    Height heightOf(size_t i) const
    {
      // BftConsensus::state() is const-safe but locks the mutex; the
      // harness drives these serially so there's no contention.
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

    Consensus::Dependencies makeDeps(size_t index)
    {
      Consensus::Dependencies deps;
      deps.my_validator_id = [this, index]() -> Id
      { return validators_[index].id; };
      deps.sign = [this, index](const Crypto::Hash &h) -> Crypto::Signature
      { return validators_[index].sign(h); };
      deps.current_height = []() -> Height
      { return 0; };
      deps.active_set = [this](bool /*force_rotation*/) -> std::vector<Id>
      {
        std::vector<Id> ids;
        ids.reserve(validators_.size());
        for (const auto &v : validators_)
          ids.push_back(v.id);
        return ids;
      };
      deps.signer_public_key =
          [this](Index idx) -> std::optional<Crypto::PublicKey>
      {
        if (idx >= validators_.size())
          return std::nullopt;
        return validators_[idx].pubkey();
      };
      deps.chain_id = []() -> uint64_t
      { return 0x434C5247; };
      deps.parent_hash = []() -> Crypto::Hash
      { return Crypto::Hash{}; };
      deps.simulate_block =
          [](const Core::Block &b) -> std::optional<Crypto::Hash>
      { return b.header.state_root; };
      deps.my_address = [this, index]() -> Crypto::Address
      { return validators_[index].address; };
      deps.now_ms = [this]() -> uint64_t
      {
        return 1'700'000'000'000ULL + proposed_count_++;
      };
      deps.state_lookup_validator =
          [this](Id id, Core::ValidatorInfo &out) -> bool
      {
        for (const auto &v : validators_)
        {
          if (v.id == id)
          {
            std::memcpy(out.reward_address.data.data(),
                        v.pubkey().data.data(), 32);
            out.id = id;
            return true;
          }
        }
        return false;
      };
      return deps;
    }

    Consensus::Callbacks makeCallbacks(size_t index)
    {
      Consensus::Callbacks cb;

      cb.broadcast_proposal = [this, index](const Consensus::Proposal &p)
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

      cb.broadcast_prevote = [this, index](const Consensus::Vote &v)
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

      cb.broadcast_precommit = [this, index](const Consensus::Vote &v)
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

      cb.broadcast_timeout_vote = [this, index](const Consensus::TimeoutVote &tv)
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

      cb.on_block_committed = [this, index](const Core::Block &b)
      {
        committed_[index].push_back(b);
        // No Restart envelope: enterCommit already calls enterNewHeight()
        // synchronously after this callback returns, so start() would be
        // a no-op. Queuing it only perturbs randomized delivery order.
      };

      cb.on_height_advanced = [this, index](Height h)
      { height_advances_[index].push_back(h); };

      return cb;
    }

    std::unique_ptr<Consensus::BftConsensus> makeInstance(size_t index)
    {
      return std::make_unique<Consensus::BftConsensus>(
          makeDeps(index),
          makeCallbacks(index),
          Consensus::Config{},
          *log_ref_);
    }

    Logging::ILogger &logger_;
    std::unique_ptr<Logging::LoggerRef> log_ref_;
    std::vector<TestValidator> validators_;
    std::vector<std::unique_ptr<Consensus::BftConsensus>> instances_;
    std::vector<std::vector<Core::Block>> committed_;
    std::vector<std::vector<Height>> height_advances_;
    uint64_t proposed_count_{0};
    std::vector<bool> offline_;
    std::vector<Envelope> queue_;

    // Partition state: 0 = unpartitioned, 1 = side A, 2 = side B.
    // Messages between different non-zero sides are dropped.
    std::vector<uint8_t> partition_side_;

    //  When true, proposals are dropped on the receiving side in
    //  deliverAll. See setProposalSuppressed.
    bool proposal_suppressed_{false};

    // Randomized delivery. random_seed_ == 0 means deterministic.
    uint64_t random_seed_{0};
    std::mt19937_64 random_engine_;

  };
}