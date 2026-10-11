// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Block.h"
#include "Order.h"
#include "Receipt.h"
#include "ValidatorTypes.h"

namespace State
{
  class StateAccess;
}

namespace Core
{
  //  BlockProcessor
  //
  //  Stateless validator that applies a block to state and verifies the
  //  resulting commitments. Given the same block and state, it always
  //  produces the same result on every node.

  struct BlockContext
  {
    uint64_t chain_id{0};
    uint64_t current_height{0}; // height of this block

    // Test-only / simulation flag.
    //
    // When true, applyBlock still applies every state mutation but
    // SKIPS the three commitment checks (state_root, receipts_root,
    // validator_set_root). This lets a caller compute what the
    // post-state root *would* be without having to first know it.
    //
    // Production code paths always leave this false. The value is
    // ignored when the block's state_root is the null hash — see
    // applyBlock for the "compute-only" convention.
    bool dry_run{false};
  };

  // Result of applying or validating a block.
  struct BlockResult
  {
    bool valid{false};
    std::string error; // populated on failure

    // Populated on success:
    Crypto::Hash new_state_root;
    Crypto::Hash new_receipts_root;
    std::vector<Receipt> receipts;
    std::vector<Crypto::Hash> tx_hashes;
    Crypto::Hash block_hash;
  };

  class BlockProcessor
  {
  public:
    static BlockResult applyBlock(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx);

    static BlockResult validateBlock(State::StateAccess &state,
                                     const Block &block,
                                     const BlockContext &ctx);

    static ValidatorRegistry loadValidatorRegistry(State::StateAccess &state);

    static std::vector<Id> resolveActiveSet(
        State::StateAccess &state,
        const std::vector<Id> &committed_set,
        uint64_t current_height,
        bool force_rotation);

    //  Evaluate every outstanding order's conditions. Called once
    //  per epoch, at the same boundary as processEpochBoundary and
    //  processRotation. Orders whose conditions have failed are
    //  cancelled and refunded, in the same way as a manual
    //  CancelOrder (fee deducted from the refund, order removed
    //  from all indexes).
    //
    //  See Order.h for the full semantics of each condition type.
    static void evaluateOrderConditions(State::StateAccess &state,
                                        const BlockContext &ctx);

  private:
    // ---- Pre-checks (before any state mutation) ----

    static bool checkHeader(const Block &block, const BlockContext &ctx,
                            std::string &error);

    static bool checkTxRoot(const Block &block, std::string &error);

    static bool checkQuorum(State::StateAccess &state,
                            const Block &block,
                            const std::vector<Id> &active_set,
                            std::string &error);

    static bool checkValidatorSetRoot(const Block &block,
                                      const std::vector<Id> &active_set,
                                      std::string &error);

    //  Verify that the certificate carried in the header matches the
    //  hash committed to in timeout_certificate_hash. Called from
    //  checkHeader (via checkTimeoutCertificateHash) and from
    //  checkTimeoutCertificate (which additionally verifies the
    //  signatures in the certificate).
    //
    //  These are two separate checks: the hash binding is a wire
    //  integrity check (the certificate bytes we received match what
    //  the header committed to), and the signature check is a
    //  consensus check (the certificate's votes are valid and come
    //  from the right set). A block must pass both.
    static bool checkTimeoutCertificateHash(const Block &block,
                                            std::string &error);

    // ---- Application steps ----

    static bool applyTransactions(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx,
                                  const std::vector<Id> &active_set,
                                  std::vector<Receipt> &receipts,
                                  std::vector<Crypto::Hash> &tx_hashes,
                                  std::string &error);

    static void processOrderExpiries(State::StateAccess &state,
                                     uint64_t current_height);

    //  Return the spot price of the pool, expressed as
    //  (amount of buy_token per unit of sell_token) * PRICE_SCALE.
    //
    //  Returns std::nullopt if:
    //    - the pool does not exist,
    //    - the pool's reserves do not contain both sell_token and
    //      buy_token, or
    //    - either reserve is zero.
    //
    //  A caller that gets nullopt treats the condition as
    //  unevaluable: the condition holds, the order is not cancelled.
    static std::optional<uint64_t> poolSpotPrice(
        State::StateAccess &state,
        uint32_t pool_id,
        uint32_t sell_token,
        uint32_t buy_token);

    //  True if every condition on `order` holds. Called by the
    //  evaluator.
    static bool conditionsAllHold(State::StateAccess &state,
                                  const Core::Order &order,
                                  uint64_t current_height);

    //  Cancel an order whose conditions have failed. Refunds the
    //  remaining sell amount minus ORDER_CANCEL_FEE_ATOMIC, removes
    //  the expiry-index entry if any, and deletes the order record
    //  (which also removes it from the pool index, owner index, and
    //  pair index via StateAccess::deleteOrder).
    static void cancelOrderByCondition(State::StateAccess &state,
                                       Id order_id,
                                       uint64_t current_height);

    static void processUnbondExpiries(State::StateAccess &state,
                                      uint64_t current_height);

    static void distributeRewards(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx);

    static void updateGlobalState(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx);

    static void processEpochBoundary(State::StateAccess &state,
                                     const Block &block,
                                     const BlockContext &ctx);

    static void processRotation(State::StateAccess &state,
                                const Block &block,
                                const BlockContext &ctx);

    // ---- Verification ----

    static bool verifyStateRoot(const Crypto::Hash &computed,
                                const Crypto::Hash &expected,
                                std::string &error);

    static bool verifyReceiptsRoot(State::StateAccess &state,
                                   const std::vector<Crypto::Hash> &tx_hashes,
                                   const std::vector<Receipt> &receipts,
                                   const Crypto::Hash &expected,
                                   std::string &error);

    // ---- Helpers ----

    static std::vector<Id> loadActiveSet(State::StateAccess &state);

    static uint64_t epochOf(uint64_t height) noexcept;

    static uint64_t rotationIndexOf(uint64_t height) noexcept;

    static void runOfflineCheck(State::StateAccess &state,
                                const BlockContext &ctx);

    static bool applySlash(State::StateAccess &state,
                           const Transaction &tx,
                           const std::vector<Id> &active_set,
                           const BlockContext &ctx,
                           std::string &error);

    static bool checkTimeoutCertificate(State::StateAccess &state,
                                        const Block &block,
                                        const std::vector<Id> &committed_set,
                                        uint64_t current_height,
                                        std::string &error);

    //  Write the block's per-block index rows: the producer index
    //  (one row per block) and the transaction indexes (one row per
    //  address, token, and type per transaction).
    //
    //  Called from applyBlock after every state mutation has
    //  succeeded, so the indexes only record blocks that actually
    //  applied. Skipped during dry-run.
    //
    //  These are pure index writes — they don't affect the state
    //  root, and a node that never wrote them would still agree
    //  with a node that did. They exist so the RPC layer can answer
    //  queries like "which blocks did this validator produce" and
    //  "what's the transaction history for this address" without
    //  walking the chain.
    static void indexBlockProducer(State::StateAccess &state,
                                   const Block &block);

    static void indexTransactions(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx);
  };

} // namespace Core