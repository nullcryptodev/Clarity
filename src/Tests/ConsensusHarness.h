#pragma once

#include <algorithm>
#include <functional>
#include <memory>
#include <queue>
#include <random>
#include <stdexcept>
#include <vector>

#include "Consensus/BftConsensus.h"
#include "Tests/ConsensusHelpers.h"

namespace Tests
{
  //  ConsensusHarness
  //
  //  Owns a set of BftConsensus instances and the message queue they
  //  exchange through. Provides the delivery loop, the timer driving,
  //  the offline flags, the partition table, and the RNG. The env
  //  supplies Dependencies; the harness supplies per-instance
  //  Callbacks that route through the queue.
  //
  //  Two consumers today: ConsensusNetwork (where every instance is
  //  a real BftConsensus driven only by the harness), and
  //  Node_EndToEndFixture (where instances exist in parallel with
  //  real Node objects, and the committed-block callback routes
  //  through NodeTestAccess::applyBlock instead of a local vector).
  //
  //  Not copyable or movable. The deps captured by the instances'
  //  Dependencies hold a pointer to the env; moving the env or the
  //  harness would dangle those pointers.
  class ConsensusHarness
  {
  public:
    using InstanceVec =
        std::vector<std::unique_ptr<Consensus::BftConsensus>>;

    ConsensusHarness(ConsensusTestEnv &env, size_t n, Logging::ILogger &logger)
        : env_(env), logger_(logger),
          log_ref_(std::make_unique<Logging::LoggerRef>(logger, "harness"))
    {
      instances_.reserve(n);
      committed_.resize(n);
      height_advances_.resize(n);
      offline_.assign(n, false);
      partition_side_.assign(n, 0);

      for (size_t i = 0; i < n; ++i)
        instances_.push_back(makeInstance(i));
    }

    //  ---- Lifecycle ----

    void startAll(Height height)
    {
      for (size_t i = 0; i < instances_.size(); ++i)
        if (!offline_[i])
          instances_[i]->start(height);
      //  Deliberately no deliverAll(). The first advanceAllTimers()
      //  call delivers whatever the start broadcast.
    }

    void stopAll()
    {
      for (auto &inst : instances_)
        inst->stop();
    }

    //  ---- Enqueue helpers ----
    //
    //  Fixtures call these from their per-instance broadcast
    //  callbacks to push envelopes into the queue. The harness owns
    //  the queue; the fixture supplies the fan-out policy (which
    //  peers are eligible, whether suppression applies, etc.) and
    //  calls back here to enqueue a single envelope per peer.
    //
    //  These do not consult offline_ or the partition table — the
    //  caller is responsible for having already filtered. The
    //  delivery loop consults offline_ and the partition table again
    //  at pop time; enqueuing for a peer that later goes offline is
    //  fine, the envelope is dropped at delivery.

    void enqueueProposal(size_t from,
                         size_t to,
                         const Consensus::Proposal &p,
                         bool is_emergency)
    {
      Envelope env;
      env.kind = Envelope::Proposal;
      env.from = from;
      env.to = to;
      env.proposal = p;
      env.is_emergency = is_emergency;
      queue_.push(std::move(env));
    }

    void enqueueVote(size_t from,
                     size_t to,
                     Envelope::Kind kind,
                     const Consensus::Vote &v)
    {
      Envelope env;
      env.kind = kind;
      env.from = from;
      env.to = to;
      env.vote = v;
      queue_.push(std::move(env));
    }

    void enqueueTimeoutVote(size_t from,
                            size_t to,
                            const Consensus::TimeoutVote &tv)
    {
      Envelope env;
      env.kind = Envelope::TimeoutVote;
      env.from = from;
      env.to = to;
      env.timeout_vote = tv;
      queue_.push(std::move(env));
    }

    //  ---- Delivery ----

    void deliverAll()
    {
      constexpr size_t MAX_ROUNDS = 10'000;
      size_t iterations = 0;

      while (!queue_.empty())
      {
        if (++iterations > MAX_ROUNDS)
          throw std::runtime_error(
              "ConsensusHarness::deliverAll: message loop did not settle");

        Envelope env;
        if (random_seed_ == 0)
        {
          env = std::move(queue_.front());
          queue_.pop();
        }
        else
        {
          std::vector<Envelope> tmp;
          tmp.reserve(queue_.size());
          while (!queue_.empty())
          {
            tmp.push_back(std::move(queue_.front()));
            queue_.pop();
          }
          std::uniform_int_distribution<size_t> dist(0, tmp.size() - 1);
          const size_t idx = dist(random_engine_);
          env = std::move(tmp[idx]);
          tmp.erase(tmp.begin() + static_cast<std::ptrdiff_t>(idx));
          for (auto &e : tmp)
            queue_.push(std::move(e));
        }

        if (offline_[env.to])
          continue;
        if (env.from != env.to && crossesPartition(env.from, env.to))
          continue;

        switch (env.kind)
        {
        case Envelope::Proposal:
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

    void advanceAllTimers()
    {
      std::vector<Height> heights_before(instances_.size());
      for (size_t i = 0; i < instances_.size(); ++i)
        heights_before[i] = offline_[i] ? 0 : heightOf(i);

      deliverAll();

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

    //  ---- Callback installation ----

    void setOnProposal(
        std::function<void(size_t index, const Consensus::Proposal &)> f)
    {
      on_proposal_ = std::move(f);
    }

    void setOnPrevote(
        std::function<void(size_t index, const Consensus::Vote &)> f)
    {
      on_prevote_ = std::move(f);
    }

    void setOnPrecommit(
        std::function<void(size_t index, const Consensus::Vote &)> f)
    {
      on_precommit_ = std::move(f);
    }

    void setOnTimeoutVote(
        std::function<void(size_t index, const Consensus::TimeoutVote &)> f)
    {
      on_timeout_vote_ = std::move(f);
    }

    void setOnBlockCommitted(
        std::function<void(size_t index, const Core::Block &)> f)
    {
      on_block_committed_ = std::move(f);
    }

    void setSelectTransactions(
        std::function<std::vector<Core::Transaction>(size_t index,
                                                     uint64_t max_bytes,
                                                     uint64_t max_txs)>
            f)
    {
      select_transactions_ = std::move(f);
    }

    //  ---- Introspection ----

    Consensus::BftConsensus &instance(size_t i) { return *instances_[i]; }
    size_t size() const { return instances_.size(); }

    const std::vector<Core::Block> &committed(size_t i) const
    {
      return committed_[i];
    }

    const std::vector<Height> &heightAdvances(size_t i) const
    {
      return height_advances_[i];
    }

    Height heightOf(size_t i) const
    {
      return instances_[i]->state().height;
    }

    //  ---- Offline control ----

    void setOffline(size_t i, bool offline) { offline_[i] = offline; }
    bool isOffline(size_t i) const { return offline_[i]; }

    //  ---- Crash / restart ----

    void stopValidator(size_t i)
    {
      if (i >= offline_.size())
        return;
      offline_[i] = true;
      instances_[i]->stop();
    }

    void restartValidator(size_t i, Height target)
    {
      if (i >= offline_.size())
        return;

      instances_[i]->stop();
      offline_[i] = false;

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

      if (peer != SIZE_MAX)
      {
        auto proposal = instances_[peer]->currentProposalForTest();
        if (proposal.has_value())
          instances_[i]->onProposal(*proposal);
      }
    }

    //  ---- Proposal suppression ----

    void setProposalSuppressed(bool suppressed)
    {
      proposal_suppressed_ = suppressed;
    }
    bool isProposalSuppressed() const { return proposal_suppressed_; }

    //  ---- Partition control ----

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

    //  ---- Randomized delivery ----

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
        return false;
      return a != b;
    }

    Consensus::Callbacks makeCallbacks(size_t index)
    {
      Consensus::Callbacks cb;

      cb.broadcast_proposal =
          [this, index](const Consensus::Proposal &p)
      {
        if (on_proposal_)
          on_proposal_(index, p);
      };

      cb.broadcast_prevote =
          [this, index](const Consensus::Vote &v)
      {
        if (on_prevote_)
          on_prevote_(index, v);
      };

      cb.broadcast_precommit =
          [this, index](const Consensus::Vote &v)
      {
        if (on_precommit_)
          on_precommit_(index, v);
      };

      cb.broadcast_timeout_vote =
          [this, index](const Consensus::TimeoutVote &tv)
      {
        if (on_timeout_vote_)
          on_timeout_vote_(index, tv);
      };

      cb.select_transactions =
          [this, index](uint64_t max_bytes, uint64_t max_txs)
      {
        if (select_transactions_)
          return select_transactions_(index, max_bytes, max_txs);
        return std::vector<Core::Transaction>{};
      };

      cb.on_block_committed =
          [this, index](const Core::Block &b)
      {
        committed_[index].push_back(b);
        if (on_block_committed_)
          on_block_committed_(index, b);
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

    ConsensusTestEnv &env_;
    Logging::ILogger &logger_;
    std::unique_ptr<Logging::LoggerRef> log_ref_;

    InstanceVec instances_;
    std::vector<std::vector<Core::Block>> committed_;
    std::vector<std::vector<Height>> height_advances_;
    std::vector<bool> offline_;
    std::queue<Envelope> queue_;
    std::vector<uint8_t> partition_side_;

    std::function<void(size_t, const Consensus::Proposal &)> on_proposal_;
    std::function<void(size_t, const Consensus::Vote &)> on_prevote_;
    std::function<void(size_t, const Consensus::Vote &)> on_precommit_;
    std::function<void(size_t, const Consensus::TimeoutVote &)>
        on_timeout_vote_;
    std::function<std::vector<Core::Transaction>(size_t, uint64_t, uint64_t)>
        select_transactions_;
    std::function<void(size_t, const Core::Block &)> on_block_committed_;

    bool proposal_suppressed_{false};
    uint64_t random_seed_{0};
    std::mt19937_64 random_engine_;
  };
}