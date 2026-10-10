#pragma once

#include <gtest/gtest.h>
#include <memory>

#include "Tests/ConsensusHarness.h"
#include "Tests/ConsensusHelpers.h"
#include "Tests/Logger.h"

#include "Consensus/Types.h"

namespace Tests
{

  //  =================================================================
  //  Consensus_BftFixture
  //
  //  Single-instance fixture. Owns one BftConsensus plus its own
  //  validator set, its own deps, its own callbacks, and a pile of
  //  helpers for constructing blocks, proposals, votes, and timeout
  //  certificates.
  //
  //  This class does NOT use ConsensusHarness or ConsensusTestEnv —
  //  it predates both and re-implements what ConsensusTestEnv
  //  provides. That duplication is scheduled for removal in a
  //  follow-up commit; for now the fixture is unchanged so that the
  //  single-instance tests (BftConsensus.cpp, BftEdgeCases.cpp, etc.)
  //  keep working without modification.
  //  =================================================================

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
      deps.now_ms = [this]() -> uint64_t
      { return now_ms_; };
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
      //  WAL plumbing. All six callbacks are optional in the real
      //  engine; the fixture installs all of them so the restart
      //  tests can exercise the full path.
      deps.wal_append_vote =
          [this](const Consensus::Vote &v, bool is_precommit)
      {
        TestWal::VoteKey k{v.height, v.round, is_precommit};
        wal_.votes.emplace(k, v); // first write wins, matching the
                                  // engine's "sign once" invariant
      };

      deps.wal_append_lock =
          [this](Height h, Round r, const Crypto::Hash &hash)
      {
        auto it = wal_.locks.find(h);
        if (it == wal_.locks.end() || r >= it->second.first)
          wal_.locks[h] = {r, hash};
      };

      deps.wal_append_locked_block =
          [this](Height h, const Core::Block &b)
      {
        wal_.locked_blocks[h] = b;
      };

      deps.wal_load_locked_block =
          [this](Height h) -> std::optional<Core::Block>
      {
        auto it = wal_.locked_blocks.find(h);
        if (it == wal_.locked_blocks.end())
          return std::nullopt;
        return it->second;
      };

      deps.wal_replay =
          [this](Height for_height,
                 std::function<void(const Consensus::Vote &, bool)> on_vote,
                 std::function<void(Height, Round, const Crypto::Hash &)> on_lock)
      {
        //  On restart the engine expects to see what survived the
        //  crash. The fixture's WAL is either the live one (no
        //  restart) or the snapshot's (after a restart); the replay
        //  callback reads whichever is current.
        const TestWal &w = restarting_ ? restart_wal_ : wal_;

        for (const auto &[k, v] : w.votes)
        {
          if (k.height != for_height)
            continue;
          if (on_vote)
            on_vote(v, k.is_precommit);
        }

        auto it = w.locks.find(for_height);
        if (it != w.locks.end() && on_lock)
          on_lock(for_height, it->second.first, it->second.second);
      };

      deps.wal_truncate =
          [this](Height up_to)
      {
        //  Entries at heights <= up_to are no longer needed.
        for (auto it = wal_.votes.begin(); it != wal_.votes.end();)
        {
          if (it->first.height <= up_to)
            it = wal_.votes.erase(it);
          else
            ++it;
        }
        for (auto it = wal_.locks.begin(); it != wal_.locks.end();)
        {
          if (it->first <= up_to)
            it = wal_.locks.erase(it);
          else
            ++it;
        }
        for (auto it = wal_.locked_blocks.begin();
             it != wal_.locked_blocks.end();)
        {
          if (it->first <= up_to)
            it = wal_.locked_blocks.erase(it);
          else
            ++it;
        }
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
      cb.on_block_committed = [this](const Core::Block &b) -> bool
      {
        committed_blocks.push_back(b);

        if (block_commit_fail_remaining_ > 0)
        {
          --block_commit_fail_remaining_;
          return false;
        }
        return true;
      };
      cb.on_consensus_halt = [this](const std::string &reason)
      {
        last_halt_reason_ = reason;
        halt_count_++;
      };
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
      local_index_ = local_index;
      if (!restarting_)
      {
        //  Fresh instance: start with an empty WAL.
        wal_ = TestWal{};
      }
      restarting_ = false;

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

    Crypto::Signature signForValidator(Index signer_index,
                                       const Crypto::Hash &hash)
    {
      if (signer_index >= validators_.size())
        return Crypto::Signature{};
      return validators_[signer_index].sign(hash);
    }

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

    // ------------------------------------------------------------------
    //  Restart / WAL test support
    // ------------------------------------------------------------------

    //  Minimal in-memory write-ahead log. The real Node wires the
    //  engine's WAL callbacks to MDBX; the fixture keeps them in
    //  memory so a test can snapshot, destroy the instance, and
    //  rebuild it — that is the crash/restart the WAL is designed to
    //  survive.
    struct TestWal
    {
      struct VoteKey
      {
        Height height{0};
        Round round{0};
        bool is_precommit{false};

        bool operator<(const VoteKey &o) const noexcept
        {
          if (height != o.height)
            return height < o.height;
          if (round != o.round)
            return round < o.round;
          return is_precommit < o.is_precommit;
        }
      };

      // Signed votes, keyed by (height, round, type). The engine
      // writes one entry per vote it signs and never overwrites;
      // replay restores them into the signed-vote registry.
      std::map<VoteKey, Consensus::Vote> votes;

      // Highest-round lock per height. The engine writes one entry
      // per lock adoption; replay keeps the highest round.
      std::map<Height, std::pair<Round, Crypto::Hash>> locks;

      // Locked block per height, so a restarted validator can
      // re-propose without fetching it from peers.
      std::map<Height, Core::Block> locked_blocks;
    };

    //  What a restart preserves. Everything the instance learned
    //  during its first life is captured here; the second life sees
    //  exactly these and nothing else.
    struct RestartSnapshot
    {
      Height height{0};
      TestWal wal;
    };

    //  Force the next `attempts` apply attempts to fail, then
    //  succeed. Zero means "never fail".
    void setBlockCommitFailsFor(size_t attempts)
    {
      block_commit_fail_remaining_ = attempts;
    }

    //  Snapshot everything the fixture needs to rebuild the instance
    //  after a simulated crash.
    RestartSnapshot snapshotForRestart() const
    {
      RestartSnapshot s;
      s.height = consensus_ ? consensus_->state().height : 0;
      s.wal = wal_;
      return s;
    }

    //  Destroy the current instance and build a fresh one at
    //  `snap.height`, replaying the snapshot's WAL. The validator
    //  key set and the fixture's other members are preserved; only
    //  the BftConsensus instance's in-memory state is reset.
    void restartFromSnapshot(const RestartSnapshot &snap)
    {
      consensus_.reset();

      //  Clear anything that would leak state across the restart.
      broadcast_proposals.clear();
      broadcast_prevotes.clear();
      broadcast_precommits.clear();
      broadcast_timeout_votes.clear();
      // committed_blocks and height_advances survive: they are the
      // fixture's observations, not the engine's state.

      restart_wal_ = snap.wal;
      restart_at_height_ = snap.height;
      restarting_ = true;

      makeConsensus(local_index_);
      consensus_->start(snap.height);
    }

    bool consensusHalted() const
    {
      return consensus_ && consensus_->halted();
    }

    const std::string &lastHaltReason() const
    {
      return last_halt_reason_;
    }

    //  Poll the engine `max_polls` times, advancing the clock by
    //  `advance_ms` before each poll. Returns as soon as `predicate`
    //  is true. Used by the retry / halt tests, where the engine's
    //  retry gate compares deps_.now_ms() against next_commit_attempt_ms_.
    bool pollWithTimeAdvance(std::function<bool()> predicate,
                             uint64_t advance_ms = 5000,
                             int max_polls = 200)
    {
      for (int i = 0; i < max_polls; ++i)
      {
        if (predicate())
          return true;
        advanceTimeMs(advance_ms);
        consensus_->pollTimers();
      }
      return predicate();
    }

    void advanceTimeMs(uint64_t ms) { now_ms_ += ms; }
    uint64_t nowMs() const { return now_ms_; }

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

    //  Restart / WAL test support.
    TestWal wal_;
    TestWal restart_wal_;
    Height restart_at_height_{0};
    bool restarting_{false};
    size_t local_index_{SIZE_MAX};

    size_t block_commit_fail_remaining_{0};
    size_t halt_count_{0};
    std::string last_halt_reason_;

    uint64_t now_ms_{1'700'000'000'000ULL};

    // When true, on_block_committed returns false. Used by tests that
    // exercise the commit-retry / halt path.
    bool block_commit_fails_{false};

    //  Optional distinct emergency set. When empty (default), the
    //  fixture returns activeIds() regardless of force_rotation, which
    //  preserves the behavior every existing test relies on. When
    //  populated, force_rotation=true returns emergency_ids_ — that
    //  lets a test exercise the case where the emergency set differs
    //  from the committed set.
    std::vector<Id> emergency_ids_;
  };

  //  =================================================================
  //  Consensus_NetworkFixture
  //
  //  Wraps ConsensusHarness. Owns the env and the harness, and wires
  //  the harness's broadcast callbacks to fan out into the queue.
  //
  //  Replaces the retired ConsensusNetwork class. All existing network
  //  tests keep their semantics unchanged: every broadcast from
  //  instance i becomes one envelope per peer, offline and partition
  //  filtering happen at delivery time, and proposal suppression is
  //  honored at delivery time using the emergency flag peeked from
  //  the serialized block.
  //  =================================================================

  class Consensus_NetworkFixture : public testing::Test
  {
  protected:
    void TearDown() override
    {
      if (harness_)
      {
        harness_->stopAll();
        harness_.reset();
      }
      env_.reset();
    }

    //  Build a fresh env and harness for N validators, and install
    //  the fan-out callbacks. Any previous harness is destroyed
    //  first, so calling makeNetwork(n) twice in a test is safe and
    //  produces a genuinely fresh env (validator keys, emergency
    //  set, backends, all reset).
    void makeNetwork(size_t n)
    {
      harness_.reset();
      env_ = std::make_unique<ConsensusTestEnv>();
      env_->makeValidators(n);
      harness_ = std::make_unique<ConsensusHarness>(*env_, n, logger_);
      wireFanOut();
    }

    ConsensusHarness &net() { return *harness_; }

    //  Install harness callbacks that reproduce the old
    //  ConsensusNetwork fan-out: every broadcast from instance i is
    //  enqueued as one envelope per peer.
    //
    //  Offline and partition filtering is NOT done here — the
    //  harness's deliverAll() consults those at pop time, and the
    //  enqueue helpers deliberately don't filter. This matches how
    //  ConsensusNetwork behaved: it pushed envelopes for every peer
    //  and let the delivery loop drop the ones that had gone offline
    //  or were separated by a partition.
    void wireFanOut()
    {
      auto &h = *harness_;
      const size_t n = h.size();

      //  Proposal fan-out. The emergency flag is read from the
      //  serialized block so the harness can honor proposal
      //  suppression correctly.
      h.setOnProposal([&h, n](size_t from, const Consensus::Proposal &p)
                      {
        bool is_emergency = false;
        Core::Block b;
        if (Core::Block::deserialize(p.block_bytes.data(),
                                     p.block_bytes.size(), b))
          is_emergency = (b.header.emergency_rotation > 0);

        for (size_t to = 0; to < n; ++to)
        {
          if (to == from)
            continue;
          h.enqueueProposal(from, to, p, is_emergency);
        } });

      h.setOnPrevote([&h, n](size_t from, const Consensus::Vote &v)
                     {
        for (size_t to = 0; to < n; ++to)
        {
          if (to == from)
            continue;
          h.enqueueVote(from, to, Envelope::Prevote, v);
        } });

      h.setOnPrecommit([&h, n](size_t from, const Consensus::Vote &v)
                       {
        for (size_t to = 0; to < n; ++to)
        {
          if (to == from)
            continue;
          h.enqueueVote(from, to, Envelope::Precommit, v);
        } });

      h.setOnTimeoutVote(
          [&h, n](size_t from, const Consensus::TimeoutVote &tv)
          {
            for (size_t to = 0; to < n; ++to)
            {
              if (to == from)
                continue;
              h.enqueueTimeoutVote(from, to, tv);
            }
          });
    }

    NoopLogger logger_;
    std::unique_ptr<ConsensusTestEnv> env_;
    std::unique_ptr<ConsensusHarness> harness_;
  };
}