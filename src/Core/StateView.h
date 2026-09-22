// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>

#include "Account.h"
#include "Crypto/Types.h"

namespace Core
{
  //  StateView
  //
  //  A read-only view of chain state. The mempool uses this to validate
  //  incoming transactions (nonce, balance, signature) without needing
  //  the full StateAccess machinery.
  //
  //  Implementations:
  //    - StateViewFromAccess: wraps a State::StateAccess (production)
  //    - StateViewSnapshot:   in-memory snapshot (testing)
  //
  //  All methods are pure reads. Implementations must be thread-safe if
  //  the mempool is accessed from multiple threads.

  class StateView
  {
  public:
    virtual ~StateView() = default;

    // Get the account for an address. Returns a zero-initialized account
    // if not present.
    virtual Account getAccount(const Crypto::Address &address) const = 0;

    // Get the balance of a token for an address.
    // Returns 0 if no balance exists.
    virtual uint64_t getTokenBalance(const Crypto::Address &address, Id token_id) const = 0;

    // Get the current chain height.
    virtual uint64_t currentHeight() const = 0;

    // Get the chain ID.
    virtual uint64_t chainId() const = 0;
  };

} // namespace Core