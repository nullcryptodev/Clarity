// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <mdbx.h>

#include "Crypto/Types.h"

namespace State
{
  class StateDBError : public std::runtime_error
  {
  public:
    explicit StateDBError(const std::string &what)
        : std::runtime_error("StateDB: " + what) {}
  };

  class StateDB
  {
  public:
    enum TableId : uint32_t
    {
      TBL_SMT_NODES = 0,
      TBL_SMT_LEAVES = 1,
      TBL_META = 2,
      TBL_ACCOUNTS = 3,
      TBL_TOKEN_BALANCES = 4,
      TBL_TOKENS = 5,
      TBL_VALIDATORS = 6,
      TBL_ORDERS = 7,
      TBL_INDEX_STAKERS = 8,
      TBL_INDEX_VALIDATORS = 9,
      TBL_INDEX_ORDERS_EXPIRY = 10,
      TBL_RECEIPTS = 11,
      TBL_TX_INDEX = 12,
      TBL_BLOCKS_BY_HASH = 13,
      TBL_BLOCKS_BY_HEIGHT = 14,
      TBL_MEMPOOL = 15,
      TBL_CONSENSUS_WAL = 16,

      // Historical SMT. Two index tables and two value tables.
      //
      //   TBL_SMT_NODES_HIST:      (hash || version_be) -> children
      //   TBL_SMT_LEAVES_HIST:     (hash || version_be) -> leaf value
      //   TBL_SMT_NODES_BY_VER:    (version_be || hash) -> empty
      //   TBL_SMT_LEAVES_BY_VER:   (version_be || hash) -> empty
      //
      // The historical tables are keyed by (hash, version) for O(1)
      // historical reads. The by-version tables are keyed by
      // (version, hash) for O(entries-pruned) historical pruning.
      //
      // Version is big-endian in the by-version index so that
      // lexicographic order matches numeric order, which lets
      // pruneHistory stop at the first version >= keepFrom instead of
      // scanning the whole index.
      TBL_SMT_NODES_HIST = 17,
      TBL_SMT_LEAVES_HIST = 18,
      TBL_SMT_NODES_BY_VER = 19,
      TBL_SMT_LEAVES_BY_VER = 20,

      // ---- Application index tables ----
      //
      // These mirror data that lives authoritatively in the SMT, but
      // keyed for enumeration and scoped queries. The SMT is the
      // commitment; these tables are the query layer.
      //
      // Every write that touches the SMT also updates the
      // corresponding index rows in the same txn, so the two can
      // never drift.
      //
      // Key layouts (all integers little-endian unless noted):
      //
      //   TBL_AMM_POOLS
      //     pool_id(8) -> serialized AmmPool
      //
      //   TBL_AMM_POSITIONS
      //     position_id(8) -> serialized AmmPosition
      //
      //   TBL_INDEX_POSITIONS_BY_OWNER
      //     owner(32) || position_id(8) -> pool_id(8)
      //     Prefix-scan on owner enumerates that owner's positions.
      //
      //   TBL_INDEX_ORDERS_BY_OWNER
      //     owner(32) || order_id(8) -> empty
      //     Prefix-scan on owner enumerates that owner's orders.
      //
      //   TBL_INDEX_BALANCES_BY_TOKEN
      //     token_id(4) || owner(32) -> balance(8)
      //     Prefix-scan on token_id enumerates that token's holders.
      //     Balance is duplicated here (also in the SMT) so a holder
      //     listing is one range scan, not N SMT lookups.
      //
      //   TBL_INDEX_POOLS_BY_TOKEN
      //     token_id(4) || pool_id(8) -> empty
      //     Prefix-scan on token_id enumerates pools containing it.
      //
      //   TBL_INDEX_TX_BY_ADDRESS
      //     address(32) || height(8 BE) || tx_index(4 BE) -> txid(32)
      //     Big-endian height so a reverse cursor scan visits newest
      //     first — the natural order for "recent transactions for
      //     an address".
      //
      //   TBL_INDEX_TX_BY_TOKEN
      //     token_id(4) || height(8 BE) || tx_index(4 BE) -> txid(32)
      //     Same idea, keyed by the token the transaction touched.
      //
      //   TBL_INDEX_TX_BY_TYPE
      //     type(1) || height(8 BE) || tx_index(4 BE) -> txid(32)
      //     Type is the TxType enum value, one byte.
      //
      //   TBL_INDEX_BLOCKS_BY_PRODUCER
      //     proposer(32) || height(8 BE) -> block_hash(32)
      //     Enumerates the blocks a validator produced.
      //
      //   TBL_INDEX_ORDERS_BY_PAIR
      //     sell_token(4) || buy_token(4) || order_id(8) -> empty
      //     Enumerates the order book for a specific pair.
      TBL_AMM_POOLS = 21,
      TBL_AMM_POSITIONS = 22,
      TBL_INDEX_POSITIONS_BY_OWNER = 23,
      TBL_INDEX_ORDERS_BY_OWNER = 24,
      TBL_INDEX_BALANCES_BY_TOKEN = 25,
      TBL_INDEX_POOLS_BY_TOKEN = 26,
      TBL_INDEX_TX_BY_ADDRESS = 27,
      TBL_INDEX_TX_BY_TOKEN = 28,
      TBL_INDEX_TX_BY_TYPE = 29,
      TBL_INDEX_BLOCKS_BY_PRODUCER = 30,
      TBL_INDEX_ORDERS_BY_PAIR = 31,

      TBL_COUNT = 32,
    };

    using EntryVisitor = std::function<bool(const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &value)>;

    // =================================================================
    //  Write transaction
    // =================================================================

    class Txn
    {
    public:
      Txn() noexcept = default;
      Txn(Txn &&other) noexcept;
      Txn &operator=(Txn &&other) noexcept;
      ~Txn();

      Txn(const Txn &) = delete;
      Txn &operator=(const Txn &) = delete;

      void put(uint32_t tableId,
               const void *key, size_t keyLen,
               const void *value, size_t valueLen);

      bool get(uint32_t tableId,
               const void *key, size_t keyLen,
               std::vector<uint8_t> &out) const;

      void del(uint32_t tableId, const void *key, size_t keyLen);

      bool has(uint32_t tableId, const void *key, size_t keyLen) const;

      // Iterate all entries in the given table via the txn's view.
      // The visitor is called for each (key, value) pair in key order.
      // If the visitor returns false, iteration stops.
      //
      // NOTE: unlike StateDB::forEachEntry, this uses the write txn's
      // own cursor, so it *does* see uncommitted writes made via this
      // same txn.
      void forEach(uint32_t tableId, const EntryVisitor &visitor) const;

      // Iterate entries whose key begins with `prefix`. Same semantics
      // as StateDB::forEachEntryWithPrefix, but through the txn's own
      // view (sees uncommitted writes).
      void forEachWithPrefix(uint32_t tableId,
                             const std::vector<uint8_t> &prefix,
                             const EntryVisitor &visitor) const;

      // Reverse iteration: visits entries in descending key order.
      // The first call positions the cursor at the last entry in the
      // table (or, with a prefix, at the last entry whose key begins
      // with that prefix). Useful for "newest first" scans on indexes
      // whose keys embed a big-endian height.
      //
      // The visitor returns false to stop early, matching forEach.
      void forEachReverse(uint32_t tableId, const EntryVisitor &visitor) const;

      void forEachWithPrefixReverse(uint32_t tableId,
                                    const std::vector<uint8_t> &prefix,
                                    const EntryVisitor &visitor) const;

      void commit();
      void abort();

      bool isOpen() const noexcept;

    private:
      friend class StateDB;
      explicit Txn(MDBX_txn *txn, StateDB *owner) noexcept;

      MDBX_txn *txn_{nullptr};
      StateDB *owner_{nullptr};
      bool open_{false};
    };

    // =================================================================
    //  Lifecycle
    // =================================================================

    StateDB(const std::string &path, size_t mapSizeBytes);
    ~StateDB();

    StateDB(const StateDB &) = delete;
    StateDB &operator=(const StateDB &) = delete;

    void flush();
    void close();

    // =================================================================
    //  Transactions
    // =================================================================

    Txn beginWrite();

    void txnPut(Txn &txn, uint32_t tableId,
                const void *key, size_t keyLen,
                const void *value, size_t valueLen);

    bool txnGet(const Txn &txn, uint32_t tableId,
                const void *key, size_t keyLen,
                std::vector<uint8_t> &out) const;

    void txnDel(Txn &txn, uint32_t tableId,
                const void *key, size_t keyLen);

    // =================================================================
    //  Raw access (autocommit)
    // =================================================================

    void rawPut(uint32_t tableId,
                const void *key, size_t keyLen,
                const void *value, size_t valueLen);

    bool rawGet(uint32_t tableId,
                const void *key, size_t keyLen,
                std::vector<uint8_t> &out) const;

    void rawDel(uint32_t tableId, const void *key, size_t keyLen);

    bool rawHas(uint32_t tableId,
                const void *key, size_t keyLen) const;

    // =================================================================
    //  Iteration (autocommit — opens its own read-only txn)
    // =================================================================

    void forEachEntry(uint32_t tableId, const EntryVisitor &visitor) const;

    void forEachEntryWithPrefix(uint32_t tableId,
                                const std::vector<uint8_t> &prefix,
                                const EntryVisitor &visitor) const;

    // Reverse variants. See Txn::forEachReverse for semantics.
    void forEachEntryReverse(uint32_t tableId,
                             const EntryVisitor &visitor) const;

    void forEachEntryWithPrefixReverse(uint32_t tableId,
                                       const std::vector<uint8_t> &prefix,
                                       const EntryVisitor &visitor) const;

    // =================================================================
    //  Meta helpers
    // =================================================================

    bool getMeta(const std::string &key, std::vector<uint8_t> &out) const;
    std::optional<std::vector<uint8_t>> getMeta(const std::string &key) const;
    void putMeta(const std::string &key, const std::vector<uint8_t> &value);
    void removeMeta(const std::string &key);

    // =================================================================
    //  SMT convenience API
    // =================================================================

    void putNode(const Crypto::Hash &hash,
                 const std::vector<uint8_t> &children,
                 uint64_t version);

    bool getNode(const Crypto::Hash &hash,
                 std::vector<uint8_t> &out) const;

    std::optional<std::vector<uint8_t>> getNode(const Crypto::Hash &hash) const;

    void putLeafData(const Crypto::Hash &leaf_hash,
                     const std::vector<uint8_t> &value,
                     uint64_t version);

    bool getLeafData(const Crypto::Hash &leaf_hash,
                     std::vector<uint8_t> &out) const;

    std::optional<std::vector<uint8_t>> getLeafData(const Crypto::Hash &leaf_hash) const;

    // ---- Historical SMT access ----
    void putNodeAtVersion(const Crypto::Hash &hash,
                          uint64_t version,
                          const std::vector<uint8_t> &children);

    bool getNodeAtVersion(const Crypto::Hash &hash,
                          uint64_t version,
                          std::vector<uint8_t> &out) const;

    void putLeafDataAtVersion(const Crypto::Hash &leaf_hash,
                              uint64_t version,
                              const std::vector<uint8_t> &value);

    bool getLeafDataAtVersion(const Crypto::Hash &leaf_hash,
                              uint64_t version,
                              std::vector<uint8_t> &out) const;

    // ---- Historical pruning ----
    void pruneHistoryBefore(uint64_t keepFrom);

    void pruneHistoryBeforeTxn(Txn &txn, uint64_t keepFrom);

    // =================================================================
    //  Diagnostics
    // =================================================================

    size_t entryCount(uint32_t tableId) const;
    size_t mapSize() const noexcept;
    MDBX_env *env() const noexcept;

    MDBX_dbi tableHandlePublic(uint32_t tableId) const noexcept
    {
      return tableHandle(tableId);
    }

  private:
    void openEnv(const std::string &path, size_t mapSizeBytes);
    void openTables(MDBX_txn *txn);

    MDBX_dbi tableHandle(uint32_t tableId) const noexcept;

    static MDBX_val toVal(const void *data, size_t len);
    static MDBX_val toVal(const std::string &s);

    static const char *tableName(uint32_t id) noexcept;

    MDBX_env *env_{nullptr};
    MDBX_dbi tables_[TBL_COUNT]{};
    size_t mapSizeBytes_{0};

    mutable std::mutex mutex_;
    std::string path_;
  };

} // namespace State