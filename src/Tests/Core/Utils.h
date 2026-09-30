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
}