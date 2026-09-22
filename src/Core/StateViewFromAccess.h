// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>

#include "StateView.h"

namespace State
{
  class StateAccess;
}

namespace Core
{
  //  StateViewFromAccess
  //
  //  Adapts a State::StateAccess into a StateView. Used by the node when
  //  it needs to add transactions to the mempool.
  //
  //  Ownership: the StateView takes ownership of the StateAccess via
  //  unique_ptr. The reference-based version this replaces had a lifetime
  //  hazard — the node kept the StateAccess alive in a thread_local slot,
  //  which meant a second call to makeStateView on the same thread would
  //  invalidate any StateView still holding a reference to the first.
  //  Owning eliminates the hazard entirely.

  class StateViewFromAccess : public StateView
  {
  public:
    StateViewFromAccess(std::unique_ptr<State::StateAccess> access,
                        uint64_t current_height,
                        uint64_t chain_id);

    Account getAccount(const Crypto::Address &address) const override;
    uint64_t getTokenBalance(const Crypto::Address &address, Id token_id) const override;
    uint64_t currentHeight() const override { return current_height_; }
    uint64_t chainId() const override { return chain_id_; }

  private:
    std::unique_ptr<State::StateAccess> access_;
    uint64_t current_height_;
    uint64_t chain_id_;
  };

} // namespace Core