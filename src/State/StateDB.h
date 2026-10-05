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

      TBL_COUNT = 21,
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
    //
    // Reads and writes the (hash, version)-keyed historical tables.
    // A historical write also writes the by-version index entry, so
    // that pruneHistory can find rows to delete without a full scan.
    //
    // Callers that write both a current and a historical row (the
    // SMT update path) use these alongside putNode/putLeafData; they
    // are not replacements.

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
    //
    // Delete every historical row whose version is strictly less than
    // keepFrom, from both the historical table and the by-version
    // index. The index is keyed by (version, hash), so a single cursor
    // scan finds every row to delete, in version order, and stops at
    // the first version >= keepFrom.
    //
    // Two entry points:
    //
    //   pruneHistoryBefore(keepFrom)
    //     Opens its own write txn. Used by callers that don't already
    //     hold one (e.g. a startup maintenance pass).
    //
    //   pruneHistoryBeforeTxn(txn, keepFrom)
    //     Uses the caller's write txn. Required when the rows to be
    //     pruned were written in that same txn — for example when a
    //     SparseMerkleTree is bound to a txn and its historical rows
    //     are still uncommitted.
    //
    // Both are safe to call from any thread that can hold the DB
    // mutex. Not called during block application.
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