// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StateViewFromAccess.h"

#include "State/StateAccess.h"

namespace Core
{

  StateViewFromAccess::StateViewFromAccess(
      std::unique_ptr<State::StateAccess> access,
      uint64_t current_height,
      uint64_t chain_id)
      : access_(std::move(access)),
        current_height_(current_height),
        chain_id_(chain_id)
  {
  }

  Account StateViewFromAccess::getAccount(const Crypto::Address &address) const
  {
    return access_->getAccount(address);
  }

  uint64_t StateViewFromAccess::getTokenBalance(const Crypto::Address &address, Id token_id) const
  {
    return access_->getTokenBalance(address, token_id);
  }

} // namespace Core