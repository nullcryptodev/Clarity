// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>

#include "Account.h"
#include "ValidatorTypes.h"
#include "TokenTypes.h"
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

    //  Fetch a token's metadata. Returns false if the token does not
    //  exist. Used by the mempool to reject transactions that target
    //  a nonexistent token before they occupy a block slot.
    virtual bool getToken(Id token_id, TokenInfo &out) const = 0;

    //  Current supply of a token. Returns 0 for a token that does not
    //  exist and for a token whose supply is genuinely zero. Callers
    //  that need to distinguish must call getToken first.
    virtual uint64_t getTokenSupply(Id token_id) const = 0;

    // Get the current chain height.
    virtual uint64_t currentHeight() const = 0;

    // Get the chain ID.
    virtual uint64_t chainId() const = 0;

    virtual bool getValidator(Id validator_id, ValidatorInfo &out) const = 0;

    //  Release any read txn the underlying access is holding, so that
    //  a caller can immediately perform a write without MDBX refusing
    //  to open a write txn while a read txn is open on the same thread.
    //  The next read after the write will reopen a fresh read txn
    //  transparently.
    //
    //  Default implementation is a no-op, so a StateView backed by
    //  something other than a StateAccess (a test mock, a pure
    //  in-memory view) doesn't need to implement it.
    virtual void releaseReadTxnIfHeld() const {}
  };

} // namespace Core