// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>

#include "Account.h"
#include "Receipt.h"
#include "Transaction.h"
#include "TransactionTypes.h"
#include "GlobalConfig.h"

namespace State
{
  class StateAccess;
}

namespace Core
{
  //  TransactionExecutor
  //
  //  Applies a single transaction to state. Pure function of (state, tx,
  //  current_height) → Receipt.
  //
  //  Semantics:
  //    - On success: all state changes applied, status = Success,
  //      nonce bumped, fee charged.
  //    - On failure: status = Failure, nonce NOT bumped, but the fee IS
  //      still charged. This discourages spam.
  //
  //  Handlers are written to be atomic w.r.t. everything EXCEPT the fee:
  //    - They validate all preconditions before modifying state.
  //    - If any precondition fails, they return without touching state.
  //    - The fee is charged by the dispatcher before dispatch, so it is
  //      always taken.
  //
  //  The caller (BlockProcessor) can rely on this: a failed tx leaves
  //  state unchanged except for the fee deduction on `from`.

  struct TxExecutionContext
  {
    uint64_t current_height;
    uint64_t chain_id;
    uint64_t tx_index_in_block; // 0-based
  };

  class TransactionExecutor
  {
  public:
    // Execute a transaction, mutating state.
    //
    // Returns the receipt. See file-level comment above for exact
    // success/failure semantics.
    static Receipt execute(State::StateAccess &state,
                           const Transaction &tx,
                           const TxExecutionContext &ctx);

  private:
    // Per-type handlers. Each returns Success on success, and reports
    // failure by returning a Failure receipt (without exception).
    //
    // All handlers are static and take the same parameters.
    static Receipt executeTransfer(State::StateAccess &state,
                                   const Transaction &tx,
                                   const TxExecutionContext &ctx);

    static Receipt executeOptInStaking(State::StateAccess &state,
                                       const Transaction &tx,
                                       const TxExecutionContext &ctx);

    static Receipt executeOptOutStaking(State::StateAccess &state,
                                        const Transaction &tx,
                                        const TxExecutionContext &ctx);

    static Receipt executeClaimRewards(State::StateAccess &state,
                                       const Transaction &tx,
                                       const TxExecutionContext &ctx);

    static Receipt executeRegisterValidator(State::StateAccess &state,
                                            const Transaction &tx,
                                            const TxExecutionContext &ctx);

    static Receipt executeUnregisterValidator(State::StateAccess &state,
                                              const Transaction &tx,
                                              const TxExecutionContext &ctx);

    static Receipt executeUpdateRewardAddress(State::StateAccess &state,
                                              const Transaction &tx,
                                              const TxExecutionContext &ctx);

    static Receipt executeCreateToken(State::StateAccess &state,
                                      const Transaction &tx,
                                      const TxExecutionContext &ctx);

    static Receipt executeMintToken(State::StateAccess &state,
                                    const Transaction &tx,
                                    const TxExecutionContext &ctx);

    static Receipt executeBurnToken(State::StateAccess &state,
                                    const Transaction &tx,
                                    const TxExecutionContext &ctx);

    static Receipt executeUpdateTokenMeta(State::StateAccess &state,
                                          const Transaction &tx,
                                          const TxExecutionContext &ctx);

    static Receipt executeCreatePool(State::StateAccess &state,
                                     const Transaction &tx,
                                     const TxExecutionContext &ctx);

    static Receipt executeAddLiquidity(State::StateAccess &state,
                                       const Transaction &tx,
                                       const TxExecutionContext &ctx);

    static Receipt executeRemoveLiquidity(State::StateAccess &state,
                                          const Transaction &tx,
                                          const TxExecutionContext &ctx);

    static Receipt executeSwap(State::StateAccess &state,
                               const Transaction &tx,
                               const TxExecutionContext &ctx);

    static Receipt executeCreateOrder(State::StateAccess &state,
                                      const Transaction &tx,
                                      const TxExecutionContext &ctx);

    static Receipt executeCancelOrder(State::StateAccess &state,
                                      const Transaction &tx,
                                      const TxExecutionContext &ctx);

    // ---- Common helpers ----

    // Charge the fee from `tx.from`. Returns true if the fee was charged.
    // Called before dispatch, so every transaction pays regardless of outcome.
    static bool chargeFee(State::StateAccess &state, const Transaction &tx);

    // Refund the fee on execution failure (optional; unused in v1).
    static void refundFee(State::StateAccess &state, const Transaction &tx);

    // Verify the transaction's signature against tx.from. Returns true if valid.
    static bool verifySignature(const Transaction &tx);

    // Verify the nonce matches the sender's expected nonce.
    static bool verifyNonce(State::StateAccess &state, const Transaction &tx);

    // Verify the transaction has not expired.
    static bool checkExpiry(const Transaction &tx, const TxExecutionContext &ctx);

    // Increment the nonce of `tx.from` after a successful execution.
    static void bumpNonce(State::StateAccess &state, const Transaction &tx);

    // Load the active set from global state. Returns an empty vector if
    // unset. Shared by RegisterValidator, UnregisterValidator, and
    // UpdateRewardAddress.
    static std::vector<Id> loadActiveSet(State::StateAccess &state);

    // Persist the active set to global state.
    static void saveActiveSet(State::StateAccess &state, const std::vector<Id> &active_set);
  };

} // namespace Core