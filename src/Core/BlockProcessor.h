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
  };

} // namespace Core