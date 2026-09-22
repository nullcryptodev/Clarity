// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Block.h"
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
  //
  //  Two entry points:
  //
  //    applyBlock — the mutating path. Applies all transactions, distributes
  //                 rewards, processes order expiries, and updates state.
  //                 Called by the chain when a block is added.
  //
  //    validateBlock — the read-only path. Given a block and the pre-state,
  //                    simulates the application and returns whether the
  //                    block is valid. Called by the consensus engine before
  //                    voting on a proposed block.
  //
  //  Both paths share the same logic. validateBlock can be implemented by
  //  cloning the state, applying, and discarding.

  struct BlockContext
  {
    uint64_t chain_id{0};
    uint64_t current_height{0}; // height of this block

    // Test-only / simulation flag.
    //
    // When true, applyBlock still applies every state mutation but
    // SKIPS the three commitment checks (state_root, receipts_root,
    // validator_set_root). This lets a caller compute what the post-state
    // root *would* be without having to first know it.
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
    // Apply a block to state. Mutates state on success.
    //
    // The caller is expected to be inside a transaction. On failure, the
    // caller should discard the state changes (e.g., by using a fresh
    // StateAccess or by aborting the underlying DB txn).
    //
    // `state` is expected to represent the state *after* the block's parent
    // (i.e., the pre-state). We apply the block's transactions in order.
    static BlockResult applyBlock(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx);

    // Validate a block without mutating state. Since StateAccess is not
    // copyable and SMT updates are not trivially reversible, this method
    // is implemented by applying to a *throwaway* view.
    //
    // For v1, we simply call applyBlock and discard — the caller is
    // responsible for providing a state that won't be persisted.
    static BlockResult validateBlock(State::StateAccess &state,
                                     const Block &block,
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

    // ---- Application steps ----

    // Apply all transactions, generating receipts.
    static bool applyTransactions(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx,
                                  std::vector<Receipt> &receipts,
                                  std::vector<Crypto::Hash> &tx_hashes,
                                  std::string &error);

    // Process order expiry for this block height.
    static void processOrderExpiries(State::StateAccess &state,
                                     uint64_t current_height);

    // Distribute block rewards to active validators and staker pot.
    static void distributeRewards(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx);

    // Update global counters that change per block (epoch tracking, etc.)
    static void updateGlobalState(State::StateAccess &state,
                                  const Block &block,
                                  const BlockContext &ctx);

    // Process epoch boundary if this block is the last of an epoch.
    static void processEpochBoundary(State::StateAccess &state,
                                     const Block &block,
                                     const BlockContext &ctx);

    // Process validator rotation if due.
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

    // Load the current active validator set from state.
    static std::vector<Id> loadActiveSet(State::StateAccess &state);

    // Compute the epoch number for a given block height.
    static uint64_t epochOf(uint64_t height) noexcept;

    // Compute the rotation index for a given block height.
    static uint64_t rotationIndexOf(uint64_t height) noexcept;

    static void runOfflineCheck(State::StateAccess &state,
                                const BlockContext &ctx);
  };

} // namespace Core