// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_set>

#include "Block.h"
#include "Order.h"
#include "Receipt.h"
#include "ValidatorTypes.h"
#include "Fill.h"

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

    //  Fills produced at the epoch boundary by the Active-order
    //  router. These are not attached to any transaction — there
    //  is no transaction at the epoch boundary — so they cannot
    //  go into the per-transaction receipts. They are committed
    //  to separately via the header's epoch_fills_root.
    //
    //  Populated on both the dry-run and apply paths. The
    //  commitment check for the root is skipped on dry_run, same
    //  rule as every other commitment.
    std::vector<Fill> epoch_fills;
  };

  //  Outcome of attempting to route an Active order against its
  //  AMM pool. The caller switches on this to decide whether to
  //  leave the order in state for a retry, or cancel it.
  //
  //  Distinguishing Rested from Unroutable is load-bearing: a pool
  //  whose current price is unfavorable should not cause the order
  //  to be cancelled, but a pool that is gone should.
  enum class ActiveRouteOutcome
  {
    //  One or more fills were produced. The order may be fully
    //  filled (record deleted) or have a remainder (record
    //  updated and still resting). Check order.isFullyFilled()
    //  to distinguish.
    Filled,

    //  The order is still valid and still resting, but the pool's
    //  current price does not permit a fill at the order's limit.
    //  The caller should leave the order in state and retry at
    //  the next epoch.
    Rested,

    //  The order can never fill against this pool:
    //    - the pool does not exist,
    //    - the pool is inactive,
    //    - the pool's reserves do not contain the order's pair,
    //    - the pool has zero reserves on one side, or
    //    - the order's canonical price overflows.
    //  The caller should cancel the order. executeActiveOrder has
    //  NOT cancelled it; it has only reported the condition. The
    //  caller decides whether to charge the cancel fee and what
    //  policy applies.
    Unroutable,
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
    //  Active orders whose conditions hold are routed against
    //  their AMM pool. The fills produced by that routing are
    //  appended to `epoch_fills_out` in execution order. A
    //  partial fill leaves the order in state for a retry at the
    //  next epoch; an unroutable order (pool gone, pair mismatch,
    //  empty reserves) is cancelled.
    //
    //  See Order.h for the full semantics of each condition type.
    static void evaluateOrderConditions(State::StateAccess &state,
                                        const BlockContext &ctx,
                                        std::vector<Fill> &epoch_fills_out);

    //  Route an Active order against its AMM pool.
    //
    //  Preconditions:
    //    - order.mode == Active
    //    - order.pool_id != 0
    //    - the caller has already taken the sell-token lock at order
    //      creation
    //
    //  Postconditions on Filled:
    //    - One Fill is appended to `fills_out`. Its source is
    //      FillSource::Amm, its maker_order_id is 0, its pool_id
    //      is order.pool_id.
    //    - The order's filled_amount is updated. If it is now fully
    //      filled, its record is deleted; otherwise it is
    //      rewritten.
    //    - The pool's reserves are updated, the counterparty
    //      balance is credited, and the fill is written to
    //      TBL_FILL_HISTORY.
    //
    //  Postconditions on Rested:
    //    - Nothing was written to state. The caller leaves the
    //      order in place and retries next epoch.
    //
    //  Postconditions on Unroutable:
    //    - Nothing was written to state. The caller cancels the
    //      order.
    static ActiveRouteOutcome executeActiveOrder(
        State::StateAccess &state,
        Order &order,
        uint64_t height,
        uint32_t tx_index_in_block,
        std::vector<Fill> &fills_out);

    //  Compute the Merkle root over a list of fills. Used both for
    //  the block header's epoch_fills_root and by tests.
    //
    //  Leaf layout: Blake2b("efil" || Fill::serializeState()).
    //  Empty vector yields the null hash, matching receipts_root's
    //  treatment of an empty receipt list.
    static Crypto::Hash computeEpochFillsRoot(
        const std::vector<Fill> &fills);

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

    static std::optional<uint64_t> poolSpotPrice(
        State::StateAccess &state,
        uint32_t pool_id,
        uint32_t sell_token,
        uint32_t buy_token);

    static bool conditionsAllHold(State::StateAccess &state,
                                  const Core::Order &order,
                                  uint64_t current_height);

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

    static bool verifyEpochFillsRoot(const std::vector<Fill> &epoch_fills,
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

    static void indexBlockProducer(State::StateAccess &state,
                                   const Block &block);

    static void indexTransactions(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx);

    static void updateFeeWindow(State::StateAccess &state,
                                uint64_t block_fees);
  };

} // namespace Core