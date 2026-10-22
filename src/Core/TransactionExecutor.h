// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "Account.h"
#include "BridgeTypes.h"
#include "Receipt.h"
#include "Transaction.h"
#include "TransactionTypes.h"
#include "GlobalConfig.h"
#include "OrderBook.h"
#include "MatchingEngine.h"

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
  //
  //  Bridge signer set
  //  -----------------
  //
  //  The bridge's operational signer set is the active validator set.
  //  A validator IS a bridge watcher: there is no separate watcher
  //  record, no separate stake, no per-chain registration. Attestation
  //  quorums are computed with bftQuorum(active_validators) at the
  //  height of the operation. See Core/BridgeTypes.h for the full
  //  rationale.

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

    // Applies a consensus-generated slash. Bypasses the user-tx prechecks
    // (signature, nonce, fee) because the proof has already been verified
    // by the consensus layer that produced it.
    //
    // Returns Success if the slash was applied, Failure if the target
    // was ineligible (unregistered, seed, nothing left to slash).
    static Receipt executeSystemSlash(State::StateAccess &state,
                                      uint64_t validator_id,
                                      uint64_t slash_height,
                                      const TxExecutionContext &ctx);

    // Load the active set from global state. Returns an empty vector if
    // unset.
    static std::vector<Id> loadActiveSet(State::StateAccess &state);

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

    static Receipt executeRotateConsensusKey(State::StateAccess &state,
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

    static Receipt executeCreateNftCollection(State::StateAccess &state,
                                              const Transaction &tx,
                                              const TxExecutionContext &ctx);

    static Receipt executeMintNft(State::StateAccess &state,
                                  const Transaction &tx,
                                  const TxExecutionContext &ctx);

    static Receipt executeWrapNft(State::StateAccess &state,
                                  const Transaction &tx,
                                  const TxExecutionContext &ctx);

    static Receipt executeTransferNft(State::StateAccess &state,
                                      const Transaction &tx,
                                      const TxExecutionContext &ctx);

    static Receipt executeBurnNft(State::StateAccess &state,
                                  const Transaction &tx,
                                  const TxExecutionContext &ctx);

    static Receipt executeUpdateNftMetadata(State::StateAccess &state,
                                            const Transaction &tx,
                                            const TxExecutionContext &ctx);

    static Receipt executeTopUpNft(State::StateAccess &state,
                                   const Transaction &tx,
                                   const TxExecutionContext &ctx);

    static Receipt executeClaimNftReward(State::StateAccess &state,
                                         const Transaction &tx,
                                         const TxExecutionContext &ctx);

    static Receipt executeRefillCollectionReward(State::StateAccess &state,
                                                 const Transaction &tx,
                                                 const TxExecutionContext &ctx);

    //  ---- Bridge ----
    //
    //  There is no executeRegisterBridgeWatcher or
    //  executeUnregisterBridgeWatcher. A validator is a watcher by
    //  virtue of being in the active set; there is no separate
    //  registration or unbonding. If those tx types ever arrive in
    //  a block (a peer on an older protocol version, or a malicious
    //  block producer), the dispatch default in execute() rejects
    //  them.

    static Receipt executeBridgeMint(State::StateAccess &state,
                                     const Transaction &tx,
                                     const TxExecutionContext &ctx);
    static Receipt executeBridgeBurn(State::StateAccess &state,
                                     const Transaction &tx,
                                     const TxExecutionContext &ctx);
    static Receipt executeBridgePause(State::StateAccess &state,
                                      const Transaction &tx,
                                      const TxExecutionContext &ctx);
    static Receipt executeBridgeUnpause(State::StateAccess &state,
                                        const Transaction &tx,
                                        const TxExecutionContext &ctx);
    static Receipt executeBridgeAckWithdrawal(State::StateAccess &state,
                                              const Transaction &tx,
                                              const TxExecutionContext &ctx);
    static Receipt executeBridgeRegisterChain(State::StateAccess &state,
                                              const Transaction &tx,
                                              const TxExecutionContext &ctx);
    static Receipt executeBridgeAttest(State::StateAccess &state,
                                       const Transaction &tx,
                                       const TxExecutionContext &ctx);
    //  per-validator attestation over a withdrawal. Mirrors
    //  executeBridgeAttest but carries only (withdrawal_id,
    //  signer_index, signature): the destination and amount live
    //  in the BridgeWithdrawal record created at burn time.
    static Receipt executeBridgeAckAttest(State::StateAccess &state,
                                          const Transaction &tx,
                                          const TxExecutionContext &ctx);

    //  Verify M-of-N attestations for a bridge operation. The signer
    //  set is the active validator set at `ctx.current_height`; the
    //  threshold is bftQuorum(active_count).
    //
    //  `signatures` is the same `[2] count || N*66` block used before;
    //  the `signer_index` in each entry is a position in the sorted
    //  active validator id list.
    //
    //  `source_chain_id` is used only for logging/attribution; the
    //  set itself is chain-agnostic. `domain` selects the signed-
    //  message construction: "bmin" for a mint attestation, "back"
    //  for a withdrawal-ack attestation.
    static bool verifyAttestationSignatures(
        State::StateAccess &state,
        uint64_t source_chain_id,
        std::string_view domain,
        const uint8_t *message, size_t message_len,
        const uint8_t *signatures, size_t signatures_len,
        const TxExecutionContext &ctx);

    //  Verify M-of-N validator-set attestations for a governance
    //  operation (pause, unpause, register-chain). Same set, same
    //  threshold, same signature-block shape as
    //  verifyAttestationSignatures; the two names are kept for
    //  call-site readability and because governance operations
    //  don't carry a `source_chain_id`.
    static bool verifyGovernanceSignatures(
        State::StateAccess &state,
        std::string_view domain,
        const uint8_t *message, size_t message_len,
        const uint8_t *signatures, size_t signatures_len,
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

    // Persist the active set to global state.
    static void saveActiveSet(State::StateAccess &state, const std::vector<Id> &active_set);

    //  Pre-lock validation for a CreateOrder transaction.
    static bool validateCreateOrderStructure(const Transaction &tx);

    //  Adopt-or-create the wrapped token for a bridge chain
    //  registration.
    static bool adoptOrCreateWrappedToken(
        State::StateAccess &state,
        Core::BridgeChainRegistration &reg);
  }; // class TransactionExecutor

} // namespace Core