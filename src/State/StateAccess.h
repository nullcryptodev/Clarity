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
#include "Core/BridgeWatcherTypes.h"
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
    //
    //  A companion to the validator record that describes which
    //  signing key was authoritative at each height the validator
    //  was registered. Not part of ValidatorInfo's wire format;
    //  stored under Keys::validatorKeyHistory.
    //
    //  Invariants:
    //    - The list is ordered by valid_from_height ascending.
    //    - The last entry's valid_until_height is 0 (current).
    //    - Every other entry's valid_until_height equals the next
    //      entry's valid_from_height (gapless, non-overlapping).
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
    //  Order book (placement index)
    //
    //  The book index is pair-symmetric and price-sorted. Write
    //  discipline:
    //
    //    addToOrderBook      once, when an order first rests
    //    removeFromOrderBook once, when an order leaves the book
    //
    //  A partial fill does not call either. Both methods are
    //  idempotent against the txn.
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
    //  registrations, and registered-watcher records. The
    //  operational signer set for a source chain is the active
    //  watcher set for that chain, resolved from the watcher
    //  records on each verification; there is no separately-stored
    //  signer set.

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

    //  Iterate pending withdrawals in creation order, starting from
    //  `from_height` (inclusive), yielding at most `max_results`.
    //
    //  The callback returns true to continue, false to stop. The
    //  iteration uses the (height, id) index so a caller can persist
    //  the last-seen height and resume without scanning the whole
    //  set.
    //
    //  `from_height == 0` means "from genesis", which is what a
    //  fresh watcher uses on its first run. After that, the watcher
    //  passes its last-processed height to avoid re-processing.
    void forEachPendingBridgeWithdrawal(
        uint64_t from_height,
        size_t max_results,
        const std::function<bool(const Core::BridgeWithdrawal &)> &fn) const;

    //  ---- Chain registry ----

    bool getBridgeChainRegistration(uint64_t source_chain_id,
                                    Core::BridgeChainRegistration &out) const;

    void putBridgeChainRegistration(
        const Core::BridgeChainRegistration &reg);

    void deleteBridgeChainRegistration(uint64_t source_chain_id);

    //  ---- Watchers ----

    bool getBridgeWatcher(uint64_t watcher_id,
                          Core::BridgeWatcherInfo &out) const;

    void putBridgeWatcher(const Core::BridgeWatcherInfo &w);

    void deleteBridgeWatcher(uint64_t watcher_id);

    bool getBridgeWatcherIdByAddress(const Crypto::Address &addr,
                                     uint64_t &watcher_id_out) const;

    void forEachBridgeWatcher(
        const std::function<void(const Core::BridgeWatcherInfo &)> &fn) const;

    //  Iterate the active watchers for a specific source chain at
    //  the given height. Uses isInActiveSet to filter. Used by the
    //  executor and the RPC.
    void forEachActiveBridgeWatcherForChain(
        uint64_t source_chain_id,
        uint64_t current_height,
        const std::function<void(const Core::BridgeWatcherInfo &)> &fn) const;

    //  Count the active watchers for a source chain at a height.
    //  Cheap when the caller only needs the threshold; the executor
    //  uses it to decide whether the active set is large enough to
    //  verify a watcher attestation.
    size_t countActiveBridgeWatchersForChain(
        uint64_t source_chain_id,
        uint64_t current_height) const;

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
    //
    //  Each of these returns std::nullopt if the requested version
    //  is outside the retention window, without touching the DB.
    //  The window is the range of versions for which the historical
    //  SMT tables retain rows. It is set at startup from
    //  NodeConfig::smt_history_blocks and is a property of the DB,
    //  not of the StateAccess.
    //
    //  A caller that wants to distinguish "outside the window" from
    //  "key not present in this version" should call
    //  smtRootAtVersion first: if that returns nullopt, the version
    //  is unavailable; if it returns a root, the version is
    //  available and a subsequent key lookup that returns nullopt
    //  means the key wasn't in the tree at that version.
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
    //
    //  proveAtVersion returns a ProofResult. The status distinguishes
    //  the four outcomes; only Ok carries a proof.
    //  =====================================================================

    ProofResult proveAtVersion(const Crypto::Hash &key,
                               uint64_t version) const;

    //  =====================================================================
    //  Retention window
    //
    //  The window is (current_height - smt_history_blocks, current_height].
    //  A version in this range has its historical rows present; a
    //  version outside it has been pruned (or never existed).
    //
    //  setHistoryWindow is called once at startup by Node after it
    //  reads NodeConfig. The default window (before setHistoryWindow
    //  is called) is UINT64_MAX, which means "everything is in the
    //  window" — the safe default for tests and genesis.
    //  =====================================================================

    void setHistoryWindow(uint64_t window_blocks) noexcept
    {
      history_window_ = window_blocks;
    }

    uint64_t historyWindow() const noexcept { return history_window_; }

    //  Compute the oldest version that is still available, given the
    //  current height and the configured window. Returns 0 if the
    //  window is larger than the current height, meaning every
    //  version from genesis is available.
    uint64_t oldestAvailableVersion() const noexcept;

    //  =====================================================================
    //  Stats
    //  =====================================================================

    //  Number of entries in a table. O(1) via MDBX's dbi stat.
    size_t tableEntryCount(uint32_t table_id) const;

    //  Per-table stats including a byte estimate.
    StateDB::TableStats tableStats(uint32_t table_id) const;

    //  Snapshot of the SMT's cumulative counters.
    const SparseMerkleTree::Stats &smtStats() const noexcept
    {
      return smt_.stats();
    }

    //  =====================================================================
    //  Read txn release
    //
    //  Destroy the autocommit read txn (if any). Called at the top
    //  of every write method. MDBX refuses to open a write txn on a
    //  thread that already has a read txn open; the next read after
    //  this method returns will transparently acquire a fresh one.
    //  =====================================================================

    void releaseReadTxnIfHeld();

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

    //  Iterate every row whose key is >= seek_key, in ascending key
    //  order. Same three-layer dispatch as the other readForEach
    //  helpers: bound txn wins, then held read txn, then DB
    //  autocommit.
    void readForEachFromKey(uint32_t table_id,
                            const std::vector<uint8_t> &seek_key,
                            const StateDB::EntryVisitor &visitor) const;

    size_t readTableCount(uint32_t table_id) const;

    //  Guard: enforce the retention window on a historical read.
    //  Returns true if the version is available (either within the
    //  window or the window is unbounded), false otherwise.
    bool versionIsAvailable(uint64_t version) const noexcept;

    StateDB &db_;
    StateDB::Txn *txn_{nullptr};

    //  Autocommit-mode read transaction. Owns a single MDBX read
    //  txn for the lifetime of this StateAccess. Null when the
    //  StateAccess is bound to a write txn.
    std::unique_ptr<StateDB::ReadTxn> read_txn_;

    uint64_t version_;
    uint64_t history_window_{UINT64_MAX};
    SparseMerkleTree smt_;
  };

} // namespace State