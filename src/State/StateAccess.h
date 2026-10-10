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
#include "Core/Order.h"
#include "Core/Receipt.h"
#include "Core/TokenTypes.h"
#include "Core/ValidatorTypes.h"
#include "Crypto/Types.h"
#include "SparseMerkleTree.h"
#include "StateDB.h"
#include "SmtProof.h"

namespace State
{
  class StateAccess
  {
  public:
    // Autocommit mode: each operation opens its own txn internally.
    StateAccess(StateDB &db, uint64_t version);

    using EntryVisitor = StateDB::EntryVisitor;

    // Txn-bound mode: all writes go through the given txn.
    // The txn is NOT owned by StateAccess. Caller commits or aborts.
    StateAccess(StateDB &db, StateDB::Txn &txn, uint64_t version);

    // =================================================================
    //  Accounts
    // =================================================================

    Core::Account getAccount(const Crypto::Address &address) const;
    bool accountExists(const Crypto::Address &address) const;
    void putAccount(const Crypto::Address &address,
                    const Core::Account &account);
    void deleteAccount(const Crypto::Address &address);

    // Enumerate every account. Order is by address (byte-lexicographic).
    // The Account passed to the callback is a full deserialized record,
    // not just the key. Reads through the txn-aware path so in txn-bound
    // mode it sees the txn's own writes.
    //
    // Iteration cost is O(entries). The MDBX table only stores a
    // sentinel value per address (the authoritative record lives in
    // the SMT); each callback invocation therefore does one SMT read
    // per account. For a large account set this is expensive — use
    // for pagination, not for full scans on every poll.
    void forEachAccount(
        const std::function<void(const Crypto::Address &, const Core::Account &)> &fn) const;

    // =================================================================
    //  Token balances
    // =================================================================

    uint64_t getTokenBalance(const Crypto::Address &address, Id token_id) const;
    void putTokenBalance(const Crypto::Address &address, Id token_id, uint64_t balance);
    void deleteTokenBalance(const Crypto::Address &address, Id token_id);

    // Every (token_id, balance) pair held by an address. Order is by
    // token_id ascending. Uses TBL_TOKEN_BALANCES with an address
    // prefix scan; each entry's balance is read directly from the
    // table, not the SMT.
    void forEachTokenBalanceForOwner(
        const Crypto::Address &owner,
        const std::function<void(Id token_id, uint64_t balance)> &fn) const;

    // Every (address, balance) pair for a token. Order is by address.
    // Uses TBL_INDEX_BALANCES_BY_TOKEN.
    //
    // This is the query behind "top holders of a token". Callers that
    // want the top N by balance should collect all pairs and sort,
    // because MDBX has no native ordering by value.
    void forEachHolderOfToken(
        Id token_id,
        const std::function<void(const Crypto::Address &, uint64_t balance)> &fn) const;

    // =================================================================
    //  Token metadata
    // =================================================================

    bool getToken(Id token_id, Core::TokenInfo &out) const;
    void putToken(const Core::TokenInfo &token);

    // Enumerate every registered token, ordered by token_id.
    void forEachToken(
        const std::function<void(const Core::TokenInfo &)> &fn) const;

    // =================================================================
    //  Token supply
    // =================================================================

    uint64_t getTokenSupply(Id token_id) const;
    void putTokenSupply(Id token_id, uint64_t supply);

    // =================================================================
    //  Validators
    // =================================================================

    bool getValidator(uint64_t validator_id, Core::ValidatorInfo &out) const;
    void putValidator(const Core::ValidatorInfo &validator);
    void deleteValidator(uint64_t validator_id);

    // Already present — iterates TBL_INDEX_VALIDATORS.
    void forEachValidator(
        const std::function<void(const Core::ValidatorInfo &)> &fn) const;

    // =================================================================
    //  Validator lookup by reward address
    // =================================================================

    bool getValidatorByAddress(const Crypto::Address &address,
                               uint64_t &validator_id_out) const;
    void putValidatorByAddress(const Crypto::Address &address,
                               uint64_t validator_id);
    void deleteValidatorByAddress(const Crypto::Address &address);

    // =================================================================
    //  Orders
    // =================================================================

    bool getOrder(Id order_id, Core::Order &out) const;
    void putOrder(const Core::Order &order);
    void deleteOrder(Id order_id);

    // Enumerate every order, ordered by order_id.
    void forEachOrder(
        const std::function<void(const Core::Order &)> &fn) const;

    // Every order owned by a given address, ordered by order_id.
    // Uses TBL_INDEX_ORDERS_BY_OWNER.
    void forEachOrderForOwner(
        const Crypto::Address &owner,
        const std::function<void(const Core::Order &)> &fn) const;

    // Every order for a specific (sell_token, buy_token) pair, ordered
    // by order_id. Uses TBL_INDEX_ORDERS_BY_PAIR.
    void forEachOrderForPair(
        Id sell_token, Id buy_token,
        const std::function<void(const Core::Order &)> &fn) const;

    // =================================================================
    //  Order expiry index
    // =================================================================

    std::vector<uint64_t> getOrdersExpiringAt(uint64_t height) const;
    void addOrderExpiry(uint64_t height, uint64_t order_id);
    void removeOrderExpiry(uint64_t height, uint64_t order_id);
    void clearOrderExpiry(uint64_t height);

    // =================================================================
    //  AMM Pools
    // =================================================================

    bool getAmmPool(Id pool_id, Core::AmmPool &out) const;
    void putAmmPool(const Core::AmmPool &pool);
    void deleteAmmPool(Id pool_id);

    // Enumerate every pool, ordered by pool_id.
    void forEachAmmPool(
        const std::function<void(const Core::AmmPool &)> &fn) const;

    // Every pool containing a given token (as either token_a or
    // token_b), ordered by pool_id. Uses TBL_INDEX_POOLS_BY_TOKEN.
    void forEachPoolForToken(
        Id token_id,
        const std::function<void(const Core::AmmPool &)> &fn) const;

    // =================================================================
    //  AMM Positions
    // =================================================================

    bool getAmmPosition(Id pos_id, Core::AmmPosition &out) const;
    void putAmmPosition(const Core::AmmPosition &pos);
    void deleteAmmPosition(Id pos_id);

    // Enumerate every position, ordered by position_id.
    void forEachAmmPosition(
        const std::function<void(const Core::AmmPosition &)> &fn) const;

    // Every position owned by a given address, ordered by position_id.
    // Uses TBL_INDEX_POSITIONS_BY_OWNER.
    void forEachPositionForOwner(
        const Crypto::Address &owner,
        const std::function<void(const Core::AmmPosition &)> &fn) const;

    // =================================================================
    //  LP position index
    // =================================================================

    bool getPositionIndex(const Crypto::Address &owner,
                          uint64_t pool_id,
                          uint64_t &position_id_out) const;
    void putPositionIndex(const Crypto::Address &owner,
                          uint64_t pool_id,
                          uint64_t position_id);
    void deletePositionIndex(const Crypto::Address &owner,
                             uint64_t pool_id);

    // =================================================================
    //  Transaction history indexes
    // =================================================================

    // Record a transaction's participation in a block. Called once per
    // transaction from BlockProcessor after the block's transactions
    // have been applied.
    //
    // `addresses` is the set of addresses the transaction touched (from,
    // to, and any others the type implies). Each is indexed separately.
    //
    // `token_ids` is the set of tokens the transaction involved. For a
    // native transfer, this is {NATIVE_TOKEN_ID}. For a swap, it's both
    // tokens of the pair. For a CreatePool, both tokens.
    //
    // The `tx_type` is the transaction's type as it appears on the wire
    // (TxType enum value). Used by TBL_INDEX_TX_BY_TYPE.
    //
    // All four indexes (by-address, by-token, by-type, and the
    // optional multi-address expansion) are written in the same call,
    // so a single failure mode covers all of them.
    void indexTransaction(const Crypto::Hash &txid,
                          uint64_t block_height,
                          uint32_t tx_index_in_block,
                          const std::vector<Crypto::Address> &addresses,
                          const std::vector<Id> &token_ids,
                          uint8_t tx_type);

    // Recent transactions touching a given address, newest first.
    // Walks TBL_INDEX_TX_BY_ADDRESS in reverse with the address prefix,
    // resolving each txid to the full transaction by looking it up in
    // its block. Stops after `max_results` or when the scan is
    // exhausted, whichever comes first.
    //
    // The `txid` in the callback is the transaction's hash; the block
    // height and index are passed alongside so the caller can locate
    // the transaction without a second index lookup.
    void forEachRecentTxForAddress(
        const Crypto::Address &address,
        size_t max_results,
        const std::function<void(const Crypto::Hash &txid,
                                 uint64_t block_height,
                                 uint32_t tx_index)> &fn) const;

    // Recent transactions touching a given token, newest first.
    void forEachRecentTxForToken(
        Id token_id,
        size_t max_results,
        const std::function<void(const Crypto::Hash &txid,
                                 uint64_t block_height,
                                 uint32_t tx_index)> &fn) const;

    // Recent transactions of a given type, newest first.
    void forEachRecentTxOfType(
        uint8_t tx_type,
        size_t max_results,
        const std::function<void(const Crypto::Hash &txid,
                                 uint64_t block_height,
                                 uint32_t tx_index)> &fn) const;

    // =================================================================
    //  Block-by-producer index
    // =================================================================

    // Record that a validator produced a block. Called once per block
    // from BlockProcessor after the block's header has been finalized
    // and its proposer is known.
    void indexBlockProducer(const Crypto::Address &proposer,
                            uint64_t block_height,
                            const Crypto::Hash &block_hash);

    // Recent blocks produced by a given proposer address, newest first.
    void forEachBlockByProducer(
        const Crypto::Address &proposer,
        size_t max_results,
        const std::function<void(uint64_t block_height,
                                 const Crypto::Hash &block_hash)> &fn) const;

    // =================================================================
    //  Receipts
    // =================================================================

    bool getReceipt(const Crypto::Hash &tx_hash, Core::Receipt &out) const;
    void putReceipt(const Crypto::Hash &tx_hash, const Core::Receipt &receipt);

    // =================================================================
    //  Global state
    // =================================================================

    bool getGlobal(const std::string &name, std::vector<uint8_t> &out) const;
    void putGlobal(const std::string &name, const std::vector<uint8_t> &value);

    //  Convenience for reading and writing a uint64 in the meta
    //  table. Txn-aware: in txn-bound mode these route through the
    //  bound txn, so writes are atomic with the block-apply commit.
    uint64_t getMetaU64(const std::string &key) const;
    void putMetaU64(const std::string &key, uint64_t value);

    // Convenience for reading and writing a uint64 global as a
    // little-endian 8-byte value. Both write 0 as an 8-byte zero
    // vector, not a missing entry — this keeps the "has this global
    // been initialized" check as a presence check rather than a
    // value check.
    uint64_t getGlobalU64(const std::string &name) const;
    void putGlobalU64(const std::string &name, uint64_t value);

    // =================================================================
    //  Raw SMT access
    // =================================================================

    std::optional<std::vector<uint8_t>> getRaw(const Crypto::Hash &smt_key) const;
    void putRaw(const Crypto::Hash &smt_key, const std::vector<uint8_t> &value);
    void deleteRaw(const Crypto::Hash &smt_key);

    // =================================================================
    //  Commit
    // =================================================================

    void commit(uint64_t version);
    Crypto::Hash stateRoot() const { return smt_.root(); }

    // =================================================================
    //  Indexes (node-local)
    // =================================================================

    void indexStaker(const Crypto::Address &address);
    void unindexStaker(const Crypto::Address &address);
    void forEachStaker(const std::function<void(const Crypto::Address &)> &fn) const;

    // =================================================================
    //  Versioned reads
    // =================================================================

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

    std::optional<State::SmtProof> proveAtVersion(
        const Crypto::Hash &key, uint64_t version) const;

    // =================================================================
    //  Table stats (for RPC diagnostics and chain aggregates)
    // =================================================================

    // Number of entries in a table. O(1) via MDBX's dbi stat.
    // Used by getChainStats for unique-count fields.
    size_t tableEntryCount(uint32_t table_id) const;

  private:
    // Txn-aware storage helpers.
    void putMetaImpl(const std::string &key,
                     const std::vector<uint8_t> &value);
    bool getMetaImpl(const std::string &key,
                     std::vector<uint8_t> &out) const;

    // Release the autocommit read txn if one is held. Called at the
    // top of every write method. MDBX refuses to open a write txn on
    // a thread that already has a read txn open; the next read after
    // this method returns will transparently acquire a fresh one.
    void releaseReadTxnIfHeld();

    // =================================================================
    //  Index write helpers. Each is a small wrapper that picks the
    //  right table and key layout for one index row. They are called
    //  from the corresponding putX/deleteX method and share its txn
    //  context (txn_ if bound, autocommit otherwise).
    // =================================================================

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

    // Low-level: put a row with a sentinel value.
    void putSentinel(uint32_t table_id, const void *key, size_t key_len);

    // Low-level: put a row with an 8-byte LE uint64 value.
    void putU64Row(uint32_t table_id, const void *key, size_t key_len, uint64_t value);

    // Low-level: put a row with a byte-blob value.
    void putBlobRow(uint32_t table_id, const void *key, size_t key_len,
                    const void *value, size_t value_len);

    // Low-level: delete a row.
    void deleteRow(uint32_t table_id, const void *key, size_t key_len);

    //  Dispatch a single-key lookup through whichever txn context
    //  is active: write txn first, then read txn, then the DB's
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

    size_t readTableCount(uint32_t table_id) const;

    StateDB &db_;
    StateDB::Txn *txn_{nullptr};

    //  Autocommit-mode read transaction. Owns a single MDBX read
    //  txn for the lifetime of this StateAccess. Null when the
    //  StateAccess is bound to a write txn.
    std::unique_ptr<StateDB::ReadTxn> read_txn_;

    uint64_t version_;
    SparseMerkleTree smt_;
  };

} // namespace State