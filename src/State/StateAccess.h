// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "Core/Account.h"
#include "Core/AmmPool.h"
#include "Core/AmmPosition.h"
#include "Core/BridgeTypes.h"
#include "Core/Order.h"
#include "Core/Receipt.h"
#include "Core/TokenTypes.h"
#include "Core/ValidatorTypes.h"
#include "Core/KeyRotation.h"
#include "Core/NftTypes.h"
#include "Crypto/Types.h"
#include "SparseMerkleTree.h"
#include "StateDB.h"
#include "SmtProof.h"

namespace State
{
  //  =========================================================================
  //  ProofResult
  //
  //  The result of a proof request. Replaces the older
  //  std::optional<SmtProof> so callers can distinguish:
  //
  //    Ok                 — a proof was produced
  //    VersionUnavailable — the requested version has no saved root
  //                         (outside the retention window, or never
  //                         written)
  //    KeyNotFound        — the version has a root, but the key is
  //                         not represented in it (a pruned or
  //                         inconsistent DB)
  //    InternalError      — a malformed node was encountered on the
  //                         walk (a corrupt DB)
  //
  //  Only Ok carries a proof. Every other status carries no proof
  //  and should be reported to the caller as-is.
  //  =========================================================================

  enum class ProofResultStatus : uint8_t
  {
    Ok = 0,
    VersionUnavailable = 1,
    KeyNotFound = 2,
    InternalError = 3,
  };

  struct ProofResult
  {
    ProofResultStatus status{ProofResultStatus::InternalError};
    std::optional<SmtProof> proof;
  };

  //  =========================================================================
  //  StateAccess
  //
  //  A typed façade over StateDB and SparseMerkleTree. Every read
  //  and write of state goes through one of:
  //
  //    - A bound write txn (txn_ non-null): used by the block
  //      processor and consensus paths. Reads and writes see each
  //      other's uncommitted effects.
  //
  //    - A held read txn (read_txn_ non-null): used by the RPC
  //      layer and various Node helpers. A single MDBX reader slot
  //      is held for the lifetime of the StateAccess, so a 256-level
  //      SMT walk is one reader, not 256.
  //
  //  A write method called on a StateAccess holding a read txn
  //  releases it before opening its own write txn. This is what
  //  makes interleaved reads and writes work.
  //
  //  Historical reads (getXAtVersion) are enforced against the
  //  retention window. A version outside the window returns
  //  std::nullopt without touching the DB, and a proof request
  //  returns VersionUnavailable.
  //
  //  Bridge watcher model
  //  --------------------
  //
  //  There is no `BridgeWatcherInfo` record. Every active validator
  //  is a bridge watcher: their stake is the validator's stake, their
  //  signing key is the validator's consensus key, and their attestation
  //  quorum is `bftQuorum(active_validators)`. This module provides
  //  `forEachActiveValidator` and `countActiveValidators` for the
  //  bridge executor's attestation and verification paths.
  //  =========================================================================

  class StateAccess
  {
  public:
    //  Autocommit mode: each operation opens its own txn internally,
    //  and a single read txn is held for the lifetime of this object.
    StateAccess(StateDB &db, uint64_t version);

    using EntryVisitor = StateDB::EntryVisitor;

    //  Txn-bound mode: all writes go through the given txn.
    //  The txn is NOT owned by StateAccess. Caller commits or aborts.
    StateAccess(StateDB &db, StateDB::Txn &txn, uint64_t version);

    //  =====================================================================
    //  Meta
    //  =====================================================================

    bool getMeta(const std::string &key, std::vector<uint8_t> &out) const;
    void putMeta(const std::string &key, const std::vector<uint8_t> &value);

    //  =====================================================================
    //  Callback return-value convention
    //
    //  The forEach* methods fall into two categories:
    //
    //    (a) Exhaustive walks. The callback returns void. The
    //        implementation visits every entry; there is no way for
    //        the caller to stop early.
    //
    //    (b) Early-exit walks. The callback returns bool. Return
    //        false to stop iteration; return true to continue. The
    //        early-exit walks also carry a max_results bound in
    //        some cases.
    //
    //  forEachBookLevel and the "recent" iterators are category (b).
    //  Everything else is category (a).
    //  =====================================================================

    //  =====================================================================
    //  Accounts
    //  =====================================================================

    Core::Account getAccount(const Crypto::Address &address) const;
    bool accountExists(const Crypto::Address &address) const;
    void putAccount(const Crypto::Address &address,
                    const Core::Account &account);
    void deleteAccount(const Crypto::Address &address);

    void forEachAccount(
        const std::function<void(const Crypto::Address &, const Core::Account &)> &fn) const;

    //  =====================================================================
    //  Token balances
    //  =====================================================================

    uint64_t getTokenBalance(const Crypto::Address &address, Id token_id) const;
    void putTokenBalance(const Crypto::Address &address, Id token_id, uint64_t balance);
    void deleteTokenBalance(const Crypto::Address &address, Id token_id);

    void forEachTokenBalanceForOwner(
        const Crypto::Address &owner,
        const std::function<void(Id token_id, uint64_t balance)> &fn) const;

    void forEachHolderOfToken(
        Id token_id,
        const std::function<bool(const Crypto::Address &, uint64_t balance)> &fn) const;

    //  =====================================================================
    //  Token metadata
    //  =====================================================================

    bool getToken(Id token_id, Core::TokenInfo &out) const;
    void putToken(const Core::TokenInfo &token);

    void forEachToken(
        const std::function<void(const Core::TokenInfo &)> &fn) const;

    //  =====================================================================
    //  Token supply
    //  =====================================================================

    uint64_t getTokenSupply(Id token_id) const;
    void putTokenSupply(Id token_id, uint64_t supply);

    //  =====================================================================
    //  Validators
    //  =====================================================================

    bool getValidator(uint64_t validator_id, Core::ValidatorInfo &out) const;
    void putValidator(const Core::ValidatorInfo &validator);
    void deleteValidator(uint64_t validator_id);

    void forEachValidator(
        const std::function<void(const Core::ValidatorInfo &)> &fn) const;

    //  Iterate the validators that are currently active at `height`.
    //  Under the "validator is watcher" model, this is also the
    //  bridge's operational signer set for every registered source
    //  chain. The bridge executor calls this from
    //  executeBridgeAttest, executeBridgeMint, executeBridgeAckAttest,
    //  and executeBridgeAckWithdrawal.
    //
    //  "Active at `height`" means the validator is in the `active_set`
    //  global AND, if the set is height-dependent via rotation, the
    //  caller has resolved the rotation at `height` first (the
    //  executor does this via resolveActiveSet before reading the
    //  set). The iterator here is the plain "read the current
    //  active_set global" view; it does not re-run rotation.
    void forEachActiveValidator(
        const std::function<void(const Core::ValidatorInfo &)> &fn) const;

    //  Count of active validators. Cheaper than materializing the
    //  full records when the caller only needs the threshold check.
    size_t countActiveValidators() const;

    //  =====================================================================
    //  Validator lookup by reward address
    //  =====================================================================

    bool getValidatorByAddress(const Crypto::Address &address,
                               uint64_t &validator_id_out) const;
    void putValidatorByAddress(const Crypto::Address &address,
                               uint64_t validator_id);
    void deleteValidatorByAddress(const Crypto::Address &address);

    //  =====================================================================
    //  Validator consensus-key history
    //  =====================================================================

    bool getValidatorKeyHistory(uint64_t validator_id,
                                std::vector<Core::KeyRotation> &out) const;

    void putValidatorKeyHistory(uint64_t validator_id,
                                const std::vector<Core::KeyRotation> &history);

    std::optional<Crypto::PublicKey> validatorKeyAtHeight(
        uint64_t validator_id, uint64_t height) const;

    //  =====================================================================
    //  NFTs
    //  =====================================================================

    bool getNft(uint64_t nft_id, Core::NftInfo &out) const;
    void putNft(const Core::NftInfo &nft);
    void deleteNft(uint64_t nft_id);

    void unindexNft(const Core::NftInfo &old);

    bool getNftCollection(uint64_t collection_id,
                          Core::NftCollection &out) const;
    void putNftCollection(const Core::NftCollection &collection);
    void deleteNftCollection(uint64_t collection_id);

    void forEachNft(
        const std::function<void(const Core::NftInfo &)> &fn) const;

    void forEachNftForOwner(
        const Crypto::Address &owner,
        const std::function<void(const Core::NftInfo &)> &fn) const;

    void forEachNftForCollection(
        uint64_t collection_id,
        const std::function<void(const Core::NftInfo &)> &fn) const;

    void forEachNftCollection(
        const std::function<void(const Core::NftCollection &)> &fn) const;

    //  =====================================================================
    //  Orders
    //  =====================================================================

    bool getOrder(Id order_id, Core::Order &out) const;
    void putOrder(const Core::Order &order);
    void deleteOrder(Id order_id);

    void forEachOrder(
        const std::function<void(const Core::Order &)> &fn) const;

    void forEachOrderForOwner(
        const Crypto::Address &owner,
        const std::function<void(const Core::Order &)> &fn) const;

    void forEachOrderForPair(
        Id sell_token, Id buy_token,
        const std::function<void(const Core::Order &)> &fn) const;

    //  =====================================================================
    //  Order book
    //  =====================================================================

    void addToOrderBook(const Core::Order &order, uint64_t sequence);
    void removeFromOrderBook(const Core::Order &order);

    void forEachBookLevel(
        Id sell_token, Id buy_token, uint8_t side,
        const std::function<bool(Id order_id,
                                 uint64_t canonical_price,
                                 uint64_t sequence)> &fn) const;

    uint64_t nextOrderSequence();

    void refundOrder(const Core::Order &order, bool charge_fee);

    void deleteRestingOrder(const Core::Order &order);

    void indexFill(const Core::Fill &fill,
                   uint64_t height,
                   uint32_t tx_index_in_block,
                   uint16_t fill_index);

    void forEachRecentFillForPair(
        uint32_t base_token,
        uint32_t quote_token,
        size_t max_results,
        const std::function<bool(const Core::Fill &,
                                 uint64_t height,
                                 uint32_t tx_index_in_block)> &fn) const;

    void forEachRecentFillForOrder(
        uint64_t order_id,
        size_t max_results,
        const std::function<bool(const Core::Fill &,
                                 uint64_t height,
                                 uint32_t tx_index_in_block)> &fn) const;

    void snapshotBookSide(
        Id sell_token,
        Id buy_token,
        uint8_t side,
        size_t depth,
        const std::function<void(uint64_t price,
                                 uint64_t total_base,
                                 size_t order_count)> &fn) const;

    void forEachOrderForPool(
        Id pool_id,
        const std::function<void(const Core::Order &)> &fn) const;

    //  =====================================================================
    //  Order expiry index
    //  =====================================================================

    std::vector<uint64_t> getOrdersExpiringAt(uint64_t height) const;
    void addOrderExpiry(uint64_t height, uint64_t order_id);
    void removeOrderExpiry(uint64_t height, uint64_t order_id);
    void clearOrderExpiry(uint64_t height);

    //  =====================================================================
    //  AMM Pools
    //  =====================================================================

    bool getAmmPool(Id pool_id, Core::AmmPool &out) const;
    void putAmmPool(const Core::AmmPool &pool);
    void deleteAmmPool(Id pool_id);

    void forEachAmmPool(
        const std::function<void(const Core::AmmPool &)> &fn) const;

    void forEachPoolForToken(
        Id token_id,
        const std::function<void(const Core::AmmPool &)> &fn) const;

    //  =====================================================================
    //  AMM Positions
    //  =====================================================================

    bool getAmmPosition(Id pos_id, Core::AmmPosition &out) const;
    void putAmmPosition(const Core::AmmPosition &pos);
    void deleteAmmPosition(Id pos_id);

    void forEachAmmPosition(
        const std::function<void(const Core::AmmPosition &)> &fn) const;

    void forEachPositionForOwner(
        const Crypto::Address &owner,
        const std::function<void(const Core::AmmPosition &)> &fn) const;

    //  =====================================================================
    //  LP position index
    //  =====================================================================

    bool getPositionIndex(const Crypto::Address &owner,
                          uint64_t pool_id,
                          uint64_t &position_id_out) const;
    void putPositionIndex(const Crypto::Address &owner,
                          uint64_t pool_id,
                          uint64_t position_id);
    void deletePositionIndex(const Crypto::Address &owner,
                             uint64_t pool_id);

    //  =====================================================================
    //  Transaction history indexes
    //  =====================================================================

    void indexTransaction(const Crypto::Hash &txid,
                          uint64_t block_height,
                          uint32_t tx_index_in_block,
                          const std::vector<Crypto::Address> &addresses,
                          const std::vector<Id> &token_ids,
                          uint8_t tx_type);

    void forEachRecentTxForAddress(
        const Crypto::Address &address,
        size_t max_results,
        const std::function<bool(const Crypto::Hash &txid,
                                 uint64_t block_height,
                                 uint32_t tx_index)> &fn) const;

    void forEachRecentTxForToken(
        Id token_id,
        size_t max_results,
        const std::function<bool(const Crypto::Hash &txid,
                                 uint64_t block_height,
                                 uint32_t tx_index)> &fn) const;

    void forEachRecentTxOfType(
        uint8_t tx_type,
        size_t max_results,
        const std::function<bool(const Crypto::Hash &txid,
                                 uint64_t block_height,
                                 uint32_t tx_index)> &fn) const;

    //  =====================================================================
    //  Block-by-producer index
    //  =====================================================================

    void indexBlockProducer(const Crypto::Address &proposer,
                            uint64_t block_height,
                            const Crypto::Hash &block_hash);

    void forEachBlockByProducer(
        const Crypto::Address &proposer,
        size_t max_results,
        const std::function<bool(uint64_t block_height,
                                 const Crypto::Hash &block_hash)> &fn) const;

    //  =====================================================================
    //  Receipts
    //  =====================================================================

    bool getReceipt(const Crypto::Hash &tx_hash, Core::Receipt &out) const;
    void putReceipt(const Crypto::Hash &tx_hash, const Core::Receipt &receipt);

    //  =====================================================================
    //  Bridge
    //  =====================================================================
    //
    //  Consumed-deposit records, withdrawal records, per-chain
    //  registrations, and per-validator deposit attestations.
    //
    //  The operational signer set for a source chain is the active
    //  validator set (see forEachActiveValidator above). There is no
    //  watcher role, no watcher record, and no per-chain registration
    //  of a watcher.
    //
    //  Attestations are recorded on-chain by BridgeAttest
    //  transactions. Each active validator submits exactly one per
    //  deposit; the submission assembler reads them back and
    //  assembles a BridgeMint signature block once a quorum has
    //  agreed on the same (destination, amount) pair.

    //  ---- Consumed deposits ----

    bool getBridgeConsumed(uint64_t source_chain_id,
                           const Crypto::Hash &source_tx_hash,
                           uint32_t source_output_index,
                           uint64_t &mint_height_out) const;

    void putBridgeConsumed(uint64_t source_chain_id,
                           const Crypto::Hash &source_tx_hash,
                           uint32_t source_output_index,
                           uint64_t mint_height);

    //  ---- Withdrawals ----

    bool getBridgeWithdrawal(uint64_t withdrawal_id,
                             Core::BridgeWithdrawal &out) const;

    void putBridgeWithdrawal(const Core::BridgeWithdrawal &w);

    void deleteBridgeWithdrawal(uint64_t withdrawal_id);

    void forEachPendingBridgeWithdrawal(
        uint64_t from_height,
        size_t max_results,
        const std::function<bool(const Core::BridgeWithdrawal &)> &fn) const;

    //  ---- bridge event log (non-SMT, chronological) ----

    void putBridgeEvent(const Core::BridgeEvent &evt);

    void forEachBridgeEvent(
        uint64_t source_chain_id,
        uint64_t from_height,
        const std::function<bool(const Core::BridgeEvent &)> &fn) const;

    void forEachBridgeEventForWithdrawal(
        uint64_t withdrawal_id,
        const std::function<bool(const Core::BridgeEvent &)> &fn) const;

    //  ---- Chain registry ----

    bool getBridgeChainRegistration(uint64_t source_chain_id,
                                    Core::BridgeChainRegistration &out) const;

    void putBridgeChainRegistration(
        const Core::BridgeChainRegistration &reg);

    void deleteBridgeChainRegistration(uint64_t source_chain_id);

    //  ---- Attestations ----
    //
    //  A BridgeAttestation is keyed by
    //  (source_chain_id, source_tx_hash, source_output_index,
    //   validator_id). The composite key is used because:
    //
    //    - A deposit is identified by (chain, tx_hash, output_index);
    //    - Each active validator submits exactly one attestation per
    //      deposit (enforced by the executor's AlreadyAttested
    //      check);
    //    - A future fetch for "all attestations on a deposit" wants
    //      the tx_hash-prefixed range.
    //
    //  Key layout (52 bytes):
    //    [8]  source_chain_id (LE)
    //    [32] source_tx_hash
    //    [4]  source_output_index (LE)
    //    [8]  validator_id (LE)

    void putBridgeAttestation(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index,
        uint64_t validator_id,
        const Core::BridgeAttestation &attestation);

    bool getBridgeAttestation(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index,
        uint64_t validator_id,
        Core::BridgeAttestation &out) const;

    void forEachBridgeAttestationForDeposit(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index,
        const std::function<bool(uint64_t validator_id,
                                 const Core::BridgeAttestation &)> &fn) const;

    size_t countBridgeAttestationsForDeposit(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index) const;

    void forEachBridgeAttestation(
        const std::function<bool(uint64_t source_chain_id,
                                 const Crypto::Hash &source_tx_hash,
                                 uint32_t source_output_index,
                                 uint64_t validator_id,
                                 const Core::BridgeAttestation &)> &fn) const;

    static std::array<uint8_t, 52> bridgeAttestationKey(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index,
        uint64_t validator_id);

    //  ---- Withdrawal attestations ----
    //
    //  Key layout (16 bytes):
    //    [8]  withdrawal_id (LE)
    //    [8]  validator_id (LE)

    void putBridgeAckAttestation(
        uint64_t withdrawal_id,
        uint64_t validator_id,
        const Core::BridgeAckAttestation &attestation);

    bool getBridgeAckAttestation(
        uint64_t withdrawal_id,
        uint64_t validator_id,
        Core::BridgeAckAttestation &out) const;

    void forEachBridgeAckAttestationForWithdrawal(
        uint64_t withdrawal_id,
        const std::function<bool(uint64_t validator_id,
                                 const Core::BridgeAckAttestation &)> &fn) const;

    size_t countBridgeAckAttestationsForWithdrawal(
        uint64_t withdrawal_id) const;

    void forEachBridgeAckAttestation(
        const std::function<bool(uint64_t withdrawal_id,
                                 uint64_t validator_id,
                                 const Core::BridgeAckAttestation &)> &fn) const;

    static std::array<uint8_t, 16> bridgeAckAttestationKey(
        uint64_t withdrawal_id,
        uint64_t validator_id);

    //  ---- Withdrawals awaiting release ----

    void forEachUnreleasedBridgeWithdrawal(
        uint64_t from_height,
        size_t max_results,
        const std::function<bool(const Core::BridgeWithdrawal &)> &fn) const;

    //  ---- Bridge stats ----

    bool getBridgeStats(uint64_t source_chain_id,
                        Core::BridgeStats &out) const;

    void putBridgeStats(const Core::BridgeStats &stats);

    //  =====================================================================
    //  Global state
    //  =====================================================================

    bool getGlobal(const std::string &name, std::vector<uint8_t> &out) const;
    void putGlobal(const std::string &name, const std::vector<uint8_t> &value);

    uint64_t getMetaU64(const std::string &key) const;
    void putMetaU64(const std::string &key, uint64_t value);

    uint64_t getGlobalU64(const std::string &name) const;
    void putGlobalU64(const std::string &name, uint64_t value);

    //  =====================================================================
    //  Raw SMT access
    //  =====================================================================

    std::optional<std::vector<uint8_t>> getRaw(const Crypto::Hash &smt_key) const;
    void putRaw(const Crypto::Hash &smt_key, const std::vector<uint8_t> &value);
    void deleteRaw(const Crypto::Hash &smt_key);

    //  =====================================================================
    //  Commit
    //  =====================================================================

    void commit(uint64_t version);
    Crypto::Hash stateRoot() const { return smt_.root(); }

    //  =====================================================================
    //  Indexes (node-local)
    //  =====================================================================

    void indexStaker(const Crypto::Address &address);
    void unindexStaker(const Crypto::Address &address);

    void forEachStaker(const std::function<void(const Crypto::Address &)> &fn) const;

    //  =====================================================================
    //  Versioned reads
    //  =====================================================================

    std::optional<Crypto::Hash> smtRootAtVersion(uint64_t version) const;

    std::optional<std::vector<uint8_t>> getRawAtVersion(
        const Crypto::Hash &smt_key, uint64_t version) const;

    Core::Account getAccountAtVersion(const Crypto::Address &address,
                                      uint64_t version) const;

    bool getValidatorAtVersion(uint64_t validator_id,
                               uint64_t version,
                               Core::ValidatorInfo &out) const;

    bool getGlobalAtVersion(const std::string &name,
                            uint64_t version,
                            std::vector<uint8_t> &out) const;

    //  =====================================================================
    //  Proofs
    //  =====================================================================

    ProofResult proveAtVersion(const Crypto::Hash &key,
                               uint64_t version) const;

    //  =====================================================================
    //  Retention window
    //  =====================================================================

    void setHistoryWindow(uint64_t window_blocks) noexcept
    {
      history_window_ = window_blocks;
    }

    uint64_t historyWindow() const noexcept { return history_window_; }

    uint64_t oldestAvailableVersion() const noexcept;

    //  =====================================================================
    //  Stats
    //  =====================================================================

    size_t tableEntryCount(uint32_t table_id) const;

    StateDB::TableStats tableStats(uint32_t table_id) const;

    const SparseMerkleTree::Stats &smtStats() const noexcept
    {
      return smt_.stats();
    }

    //  =====================================================================
    //  Read txn release
    //  =====================================================================

    void releaseReadTxnIfHeld();

    //  The version (chain height) this StateAccess was constructed
    //  with. For an autocommit access, this is the height passed to
    //  the constructor; for a txn-bound access, the height of the
    //  block being applied. The mempool's bridge verifiers use it
    //  so their key-history lookups happen at the same height the
    //  executor will use, rather than a sentinel.
    uint64_t version() const noexcept { return version_; }

private:
    //  Txn-aware storage helpers.
    void putMetaImpl(const std::string &key,
                     const std::vector<uint8_t> &value);
    bool getMetaImpl(const std::string &key,
                     std::vector<uint8_t> &out) const;

    //  =====================================================================
    //  Index write helpers. Each picks the right table and key layout
    //  for one index row. They are called from the corresponding
    //  putX/deleteX method and share its txn context (txn_ if
    //  bound, autocommit otherwise).
    //  =====================================================================

    void indexAccountRow(const Crypto::Address &address);
    void unindexAccountRow(const Crypto::Address &address);

    void indexTokenRow(Id token_id);
    void unindexTokenRow(Id token_id);

    void indexTokenBalanceRow(const Crypto::Address &address, Id token_id, uint64_t balance);
    void unindexTokenBalanceRow(const Crypto::Address &address, Id token_id);

    void indexAmmPoolRow(Id pool_id, Id token_a, Id token_b);
    void unindexAmmPoolRow(Id pool_id, Id token_a, Id token_b);

    void indexAmmPositionRow(Id position_id, const Crypto::Address &owner);
    void unindexAmmPositionRow(Id position_id, const Crypto::Address &owner);

    void indexOrderRow(Id order_id, const Crypto::Address &owner, Id sell_token, Id buy_token);
    void unindexOrderRow(Id order_id, const Crypto::Address &owner, Id sell_token, Id buy_token);

    void indexOrderPoolRows(const Core::Order &order);
    void unindexOrderPoolRows(const Core::Order &order);

    void indexBridgeWithdrawalRow(const Core::BridgeWithdrawal &w);
    void unindexBridgeWithdrawalRow(const Core::BridgeWithdrawal &w);

    //  Low-level row writers.
    void putSentinel(uint32_t table_id, const void *key, size_t key_len);
    void putU64Row(uint32_t table_id, const void *key, size_t key_len, uint64_t value);
    void putBlobRow(uint32_t table_id, const void *key, size_t key_len,
                    const void *value, size_t value_len);
    void deleteRow(uint32_t table_id, const void *key, size_t key_len);

    //  Dispatch a single-key lookup through whichever txn context is
    //  active: write txn first, then read txn, then the DB's
    //  autocommit path (which itself reuses the thread-local read
    //  txn if one is open — this branch is a safety net).
    bool readRow(uint32_t table_id,
                 const void *key, size_t key_len,
                 std::vector<uint8_t> &out) const;

    void readForEach(uint32_t table_id,
                     const EntryVisitor &visitor) const;

    void readForEachWithPrefix(uint32_t table_id,
                               const std::vector<uint8_t> &prefix,
                               const EntryVisitor &visitor) const;

    void readForEachReverse(uint32_t table_id,
                            const EntryVisitor &visitor) const;

    void readForEachWithPrefixReverse(uint32_t table_id,
                                      const std::vector<uint8_t> &prefix,
                                      const EntryVisitor &visitor) const;

    void readForEachFromKey(uint32_t table_id,
                            const std::vector<uint8_t> &seek_key,
                            const StateDB::EntryVisitor &visitor) const;

    size_t readTableCount(uint32_t table_id) const;

    bool versionIsAvailable(uint64_t version) const noexcept;

    StateDB &db_;
    StateDB::Txn *txn_{nullptr};

    std::unique_ptr<StateDB::ReadTxn> read_txn_;

    uint64_t version_;
    uint64_t history_window_{UINT64_MAX};
    SparseMerkleTree smt_;
  };

} // namespace State