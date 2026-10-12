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

      //  Orders indexed by the AMM pool their conditions reference.
      //  Key = pool_id (4 LE) || order_id (8 LE). Value = sentinel.
      //  Written when an order is created, removed on cancel or
      //  condition-triggered cancellation. Used by the condition
      //  evaluator to enumerate orders per pool without scanning the
      //  full order table.
      TBL_INDEX_ORDERS_BY_POOL = 32,

      //  Order book: resting orders keyed by
      //    pair_key(32) || side(1) || ~price(8 BE) || sequence(8 BE)
      //  and valued with a sentinel byte. The pair_key is
      //  Blake2b(min(sell,buy)(4 LE) || max(sell,buy)(4 LE)) so a
      //  buy-A-for-B order and a sell-B-for-A order share a book.
      //  The side byte is 0 if the order sells the pair's min
      //  token, 1 otherwise. The ~price byte order makes ascending
      //  MDBX iteration yield best-price-first on both sides; the
      //  sequence byte is the price-time tiebreaker. See
      //  Core/OrderBook.h for the full key derivation.
      //
      //  This table is a *placement* index, not a state mirror.
      //  It is written by MatchingEngine when an order first rests
      //  and deleted when the order leaves the book. It is NOT
      //  rewritten on every partial fill: a fill changes the
      //  order's filled_amount, not its price or its sequence, so
      //  the book row is stable across the order's resting life.
      //  See StateAccess::addToOrderBook / removeFromOrderBook.
      TBL_INDEX_ORDER_BOOK = 33,

      //  Fill history. One row per fill produced by a taker
      //  crossing a resting maker. Written by the matching engine
      //  at fill time. Two key shapes share the table, distinguished
      //  by a leading tag byte:
      //
      //    tag 0x01  pair view
      //      key = 0x01 || pair_key(32) || height(8 BE) ||
      //            tx_index(4 BE) || fill_index(2 BE)
      //      value = Fill::serializeState() (55 bytes)
      //
      //    tag 0x02  order view
      //      key = 0x02 || order_id(8 BE) || height(8 BE) ||
      //            tx_index(4 BE) || fill_index(2 BE)
      //      value = Fill::serializeState() (55 bytes)
      //
      //  The order-view rows are written twice per fill: once with
      //  the maker's id and once with the taker's. That is what
      //  makes getOrderFills(order_id) a single prefix scan.
      //
      //  The pair view is ordered by height ascending, so a
      //  reverse-prefix scan yields the newest trades first. The
      //  order view is the same shape with a different prefix.
      //
      //  Nothing removes rows from this table today. History is
      //  cheap (55 bytes + a 47/23-byte key per fill) and the table
      //  grows with fills, not with block count. A retention policy
      //  can be added later without a schema change.
      TBL_FILL_HISTORY = 34,

      TBL_NFTS = 35,
      TBL_NFT_COLLECTIONS = 36,
      TBL_INDEX_NFTS_BY_OWNER = 37,
      TBL_INDEX_NFTS_BY_COLLECTION = 38,

      TBL_COUNT = 39,
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
    //  already has a read txn open. The write paths therefore
    //  refuse to run while a read txn is open on the same thread:
    //  they call requireNoOpenReadTxn(), which throws a StateDBError
    //  naming the write method. Callers that want to write must
    //  destroy the owning ReadTxn first — usually by destroying the
    //  StateAccess that holds it, or by calling
    //  StateAccess::releaseReadTxnIfHeld().
    //
    //  Before the guard was added, the write paths called
    //  releaseReadTxn(), which aborted the txn out from under its
    //  owning ReadTxn object. When that object's destructor later
    //  ran, it aborted the same freed handle, which glibc reported
    //  as "double free or corruption (out)" and which MDBX would
    //  have crashed on regardless. The guard turns a silent
    //  use-after-free into a loud, addressable error.
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
    //  beginRead.
    //
    //  Writes DO take write_mutex_. MDBX allows only one write txn
    //  at a time; a second concurrent mdbx_txn_begin(READWRITE)
    //  returns MDBX_BUSY, which this code does not retry.
    //
    //  Before opening a write txn, every raw write method calls
    //  requireNoOpenReadTxn(), which throws if a read txn is open
    //  on the current thread. MDBX refuses to open a write txn
    //  while a read txn is open on the same thread
    //  (MDBX_TXN_OVERLAPPING), so this check is mandatory.
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
    //  The owning ReadTxn's destructor is the only place the txn is
    //  aborted. Callers that want to write must destroy the owning
    //  ReadTxn first; the raw write paths enforce this with
    //  requireNoOpenReadTxn().
    // =================================================================

    ReadTxn beginRead();

    //  Historical no-op. Kept for source compatibility with call
    //  sites written against the old behavior, where this method
    //  aborted the thread-local read txn out from under its owning
    //  ReadTxn object. That behavior caused a use-after-free when
    //  the object was later destroyed.
    //
    //  Callers that previously called this method before a write
    //  must now destroy their ReadTxn instead. StateAccess does
    //  this correctly via releaseReadTxnIfHeld().
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

    //  Throw if a read txn is open on the current thread. Called at
    //  the top of every raw write path so that a write attempted
    //  while a read txn is open fails loudly instead of aborting the
    //  read txn out from under its owning ReadTxn object (which was
    //  a use-after-free).
    static void requireNoOpenReadTxn(const char *where);

    //  Per-thread handle to the outermost read txn on this thread,
    //  if one is open. Set by beginRead when it opens a fresh txn,
    //  cleared by the owning ReadTxn's destructor.
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