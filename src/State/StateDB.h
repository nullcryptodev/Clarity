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

      TBL_SMT_NODES_HIST = 17,
      TBL_SMT_LEAVES_HIST = 18,
      TBL_SMT_NODES_BY_VER = 19,
      TBL_SMT_LEAVES_BY_VER = 20,

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

      void forEach(uint32_t tableId, const EntryVisitor &visitor) const;

      void forEachWithPrefix(uint32_t tableId,
                             const std::vector<uint8_t> &prefix,
                             const EntryVisitor &visitor) const;

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
    //  Read transaction
    //
    //  A holder of an MDBX read txn. Any number of read txns can be
    //  open at once across threads (MDBX is MVCC), but at most one
    //  per thread. StateDB tracks the per-thread handle in
    //  tls_read_txn_ so that a nested beginRead() returns a
    //  non-owning ReadTxn wrapping the outer one, and so that any
    //  legacy rawGet / forEach* call reuses the outer txn rather
    //  than trying (and failing) to open a second overlapping one.
    //
    //  MDBX also refuses to open a write txn on a thread that
    //  already has a read txn open. StateDB handles this by exposing
    //  releaseReadTxn(): any write path calls it first, which
    //  destroys the current ReadTxn on this thread and reopens it
    //  lazily on the next read. See the comment on releaseReadTxn.
    // =================================================================

    class ReadTxn
    {
    public:
      ReadTxn() noexcept = default;
      ReadTxn(ReadTxn &&other) noexcept;
      ReadTxn &operator=(ReadTxn &&other) noexcept;
      ~ReadTxn();

      ReadTxn(const ReadTxn &) = delete;
      ReadTxn &operator=(const ReadTxn &) = delete;

      bool get(uint32_t tableId,
               const void *key, size_t keyLen,
               std::vector<uint8_t> &out) const;

      void forEach(uint32_t tableId, const EntryVisitor &visitor) const;
      void forEachWithPrefix(uint32_t tableId,
                             const std::vector<uint8_t> &prefix,
                             const EntryVisitor &visitor) const;
      void forEachReverse(uint32_t tableId, const EntryVisitor &visitor) const;
      void forEachWithPrefixReverse(uint32_t tableId,
                                    const std::vector<uint8_t> &prefix,
                                    const EntryVisitor &visitor) const;

      size_t dbiStat(uint32_t tableId) const;

      void abort();

      bool isOpen() const noexcept;

      MDBX_txn *raw() const noexcept { return txn_; }

    private:
      friend class StateDB;
      explicit ReadTxn(MDBX_txn *txn, StateDB *owner,
                       bool owns, MDBX_txn *prev_tls) noexcept;

      MDBX_txn *txn_{nullptr};
      StateDB *owner_{nullptr};
      bool open_{false};
      bool owns_txn_{false};
      MDBX_txn *prev_tls_{nullptr};
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
    //
    //  Reads do NOT take write_mutex_. MDBX readers are MVCC and
    //  concurrent-safe.
    //
    //  Reads reuse the per-thread read txn if one is open; see
    //  beginRead / releaseReadTxn.
    //
    //  Writes DO take write_mutex_. MDBX allows only one write txn
    //  at a time; a second concurrent mdbx_txn_begin(READWRITE)
    //  returns MDBX_BUSY, which this code does not retry.
    //
    //  Before opening a write txn, every write method calls
    //  releaseReadTxn() to close any open read txn on this thread.
    //  MDBX refuses to open a write txn while a read txn is open
    //  on the same thread (MDBX_TXN_OVERLAPPING), so this release
    //  step is mandatory.
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
    //  Iteration (autocommit — opens its own read-only txn if none
    //  is open on this thread)
    // =================================================================

    void forEachEntry(uint32_t tableId, const EntryVisitor &visitor) const;

    void forEachEntryWithPrefix(uint32_t tableId,
                                const std::vector<uint8_t> &prefix,
                                const EntryVisitor &visitor) const;

    void forEachEntryReverse(uint32_t tableId,
                             const EntryVisitor &visitor) const;

    void forEachEntryWithPrefixReverse(uint32_t tableId,
                                       const std::vector<uint8_t> &prefix,
                                       const EntryVisitor &visitor) const;

    // =================================================================
    //  Read txn lifecycle
    //
    //  beginRead returns a ReadTxn for the current thread. If a
    //  read txn is already open, it returns a non-owning ReadTxn
    //  wrapping the outer one, so the caller can hold it in a
    //  unique_ptr alongside the outer's owner without any
    //  coordination.
    //
    //  releaseReadTxn closes the outermost read txn on this thread,
    //  if any. Write paths call this before opening a write txn,
    //  because MDBX refuses to overlap them. The next read (via
    //  rawGet, rawHas, forEach*, or beginRead) will transparently
    //  open a fresh read txn, so a caller that interleaves reads
    //  and writes simply gets a new read txn after each write.
    //
    //  This is the mechanism that makes "hold a ReadTxn for the
    //  lifetime of a StateAccess" compatible with "the same
    //  StateAccess does a write halfway through": the write closes
    //  the read txn, then the next read reopens it.
    // =================================================================

    ReadTxn beginRead();

    void releaseReadTxn() noexcept;

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

    void pruneHistoryBefore(uint64_t keepFrom);

    void pruneHistoryBeforeTxn(Txn &txn, uint64_t keepFrom);

    //  Delete every row in TBL_CONSENSUS_WAL. Called from
    //  Node::initGenesis on a fresh DB, so that stale WAL entries
    //  from a previous chain (whose votes reference blocks that no
    //  longer exist) don't get replayed by the consensus engine.
    void wipeConsensusWal();

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

    //  Per-thread handle to the outermost read txn on this thread,
    //  if one is open. Set by beginRead when it opens a fresh txn,
    //  cleared by releaseReadTxn and by the owning ReadTxn's
    //  destructor.
    //
    //  MDBX requires this: a read txn already in progress on a given
    //  thread must be reused by any nested read, because
    //  mdbx_txn_begin returns MDBX_BUSY for a second overlapping
    //  read txn on the same thread, and MDBX_TXN_OVERLAPPING for a
    //  write txn that would overlap an existing read txn.
    static thread_local MDBX_txn *tls_read_txn_;

    MDBX_env *env_{nullptr};
    MDBX_dbi tables_[TBL_COUNT]{};
    size_t mapSizeBytes_{0};

    // Guards writes only. Reads are lock-free (MVCC).
    mutable std::mutex write_mutex_;
    std::string path_;
  };

} // namespace State