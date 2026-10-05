#pragma once

#include "Tests/Utils.h"

namespace Tests
{

  // MockStateView - In-memory StateView for testing. Callers
  // set account balances and nonces, then pass it to
  // Mempool::add() or selectForBlock().

  class MockStateView : public Core::StateView
  {
  public:
    MockStateView() = default;

    Core::Account getAccount(const Crypto::Address &address) const override
    {
      auto it = accounts_.find(address.toString());
      if (it != accounts_.end())
        return it->second;
      return Core::Account{};
    }

    uint64_t getTokenBalance(const Crypto::Address & /*address*/,
                             Id /*token_id*/) const override
    {
      return 0;
    }

    uint64_t currentHeight() const override { return height_; }
    uint64_t chainId() const override { return chain_id_; }
    bool getValidator(Id /*validator_id*/, Core::ValidatorInfo & /*out*/) const override
    {
      return false;
    }

    // ---- Test helpers ----

    void setBalance(const Crypto::Address &addr, uint64_t balance)
    {
      auto &a = accounts_[addr.toString()];
      a.balance = balance;
      a.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    }

    void setNonce(const Crypto::Address &addr, uint64_t nonce)
    {
      accounts_[addr.toString()].nonce = nonce;
    }

    void setHeight(uint64_t h) { height_ = h; }
    void setChainId(uint64_t id) { chain_id_ = id; }

  private:
    std::unordered_map<std::string, Core::Account> accounts_;
    uint64_t height_ = 0;
    uint64_t chain_id_ = 0x434C5247; // regtest
  };

  //  Registry builder for rotation tests.
  //  Validators are numbered 1..N. Active set starts as the first M
  //  validators. Uptime scores default to 10'000 (perfect). Callers can
  //  override per-validator state via the helpers below.

  struct RotationBuilder
  {
    Core::ValidatorRegistry reg;

    explicit RotationBuilder(size_t total_validators = 0,
                             size_t active_count = 0)
    {
      // Index 0 sentinel.
      reg.validators.push_back(Core::ValidatorInfo{});
      reg.next_id = 1;

      for (size_t i = 0; i < total_validators; ++i)
      {
        Core::ValidatorInfo v;
        v.id = static_cast<Id>(i + 1);
        v.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
        v.uptime_score = 10'000;
        v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
        v.is_active = false;
        v.registered_at_height = 1;
        v.last_active_at = 1;
        v.became_active_at = 0;
        reg.validators.push_back(v);
        reg.next_id = v.id + 1;
      }

      for (size_t i = 0; i < active_count && i < total_validators; ++i)
      {
        Id vid = static_cast<Id>(i + 1);
        auto *v = reg.find(vid);
        if (v)
        {
          v->is_active = true;
          v->became_active_at = 1;
          reg.active_set.push_back(vid);
        }
      }
    }

    // Set an arbitrary uptime for a validator.
    void setUptime(Id id, uint16_t uptime)
    {
      if (auto *v = reg.find(id))
        v->uptime_score = uptime;
    }

    // Set last_active_at (for rotation fairness tie-breaking).
    void setLastActive(Id id, uint64_t h)
    {
      if (auto *v = reg.find(id))
        v->last_active_at = h;
    }

    // Set became_active_at (for removal priority tie-breaking).
    void setBecameActive(Id id, uint64_t h)
    {
      if (auto *v = reg.find(id))
        v->became_active_at = h;
    }

    // Mark a validator as a seed.
    void setSeed(Id id, bool seed = true)
    {
      if (auto *v = reg.find(id))
        v->is_seed = seed;
    }

    // Set last_seen_height for offline detection.
    void setLastSeen(Id id, uint64_t h)
    {
      if (auto *v = reg.find(id))
        v->last_seen_height = h;
    }

    // Mark a validator as pending-unbond with the given expiry
    // height. Used by the unbonding tests to construct a validator
    // that has requested unregistration but whose record has not
    // yet been released.
    void setPendingUnbond(Id id, uint64_t pending_unbond_height)
    {
      if (auto *v = reg.find(id))
        v->pending_unbond_height = pending_unbond_height;
    }

    // Set current target_size in the registry.
    void setTargetSize(uint64_t t) { reg.target_size = t; }
  };
}