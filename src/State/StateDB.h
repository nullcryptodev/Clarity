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

  //  =========================================================================
  //  StateDB
  //
  //  An MDBX-backed key-value store with 44 tables. The tables fall into
  //  four groups:
  //
  //    - Live SMT: TBL_SMT_NODES, TBL_SMT_LEAVES. Written by every tree
  //      update. Content-addressed, so a re-write of the same node
  //      upserts the same row.
  //
  //    - Historical SMT: TBL_SMT_NODES_HIST, TBL_SMT_LEAVES_HIST, and
  //      the two by-version prune indexes. Written by every tree update
  //      at version != 0. Pruned by StateAccess on block commit.
  //
  //    - Entity tables: accounts, tokens, balances, validators, orders,
  //      pools, positions, NFTs, receipts, blocks, transactions,
  //      mempool, consensus WAL, meta. Some are mirrors of state
  //      that also lives in the SMT (accounts, orders, etc.); others
  //      are the only copy (blocks, tx index, mempool, meta).
  //
  //    - Index tables: the "by owner", "by token", "by pair", "by
  //      producer", "by type" indexes that the RPC and metrics
  //      layers read. None of these participate in the state root;
  //      they are node-local and can be rebuilt from the entity
  //      tables.
  //
  //  Transactions
  //  ------------
  //
  //  MDBX permits one write txn at a time and at most one read txn per
  //  thread. StateDB exposes:
  //
  //    - Txn: an owning write-txn wrapper. Move-only.
  //    - ReadTxn: an owning-or-non-owning read-txn wrapper.
  //
  //  beginWrite() returns an owning Txn. beginRead() returns a ReadTxn
  //  that owns its txn if none was open on the current thread, or
  //  wraps the existing per-thread txn if one was. The wrapper tracks
  //  which case it is in and does the right thing in its destructor.
  //
  //  A write attempted while a read txn is open on the same thread
  //  throws. The discipline is: destroy the ReadTxn (or the
  //  StateAccess that owns it) before writing.
  //  =========================================================================

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
      //  condition-triggered cancellation.
      TBL_INDEX_ORDERS_BY_POOL = 32,

      //  Order book placement index. Key shape:
      //
      //    pair_key(32) || side(1) || ~canonical_price(8 BE)
      //                 || sequence(8 BE)
      //
      //  Value = order_id (8 LE). Written by StateAccess::addToOrderBook
      //  and removed by removeFromOrderBook. A partial fill does not
      //  move the row: the price and sequence are unchanged.
      TBL_INDEX_ORDER_BOOK = 33,

      //  Fill history. One row per fill, three rows per matched fill
      //  (pair view, maker order view, taker order view). See
      //  StateAccess::indexFill.
      TBL_FILL_HISTORY = 34,

      TBL_INDEX_BRIDGE_WITHDRAWALS_BY_HEIGHT = 35,
      TBL_INDEX_BRIDGE_WATCHERS_BY_OWNER = 36,

      TBL_NFTS = 37,
      TBL_NFT_COLLECTIONS = 38,
      TBL_INDEX_NFTS_BY_OWNER = 39,
      TBL_INDEX_NFTS_BY_COLLECTION = 40,

      //  Per-watcher attestations over bridge deposits. Key =
      //  source_chain_id (8 LE) || source_tx_hash (32) ||
      //  source_output_index (4 LE) || validator_id (8 LE). Value =
      //  serialized BridgeAttestation. Written by executeBridgeAttest;
      //  read by the submission assembler to build a BridgeMint's
      //  signature block. Not part of the state root: it is bridge
      //  federation state, not per-account state, and it does not
      //  affect any other transaction's validity.
      TBL_BRIDGE_ATTESTATIONS = 41,

      //  Per-watcher attestations over bridge withdrawals. Key =
      //  withdrawal_id (8 LE) || validator_id (8 LE). Value =
      //  serialized BridgeAckAttestation. Written by
      //  executeBridgeAckAttest; read by the submission assembler
      //  to build a BridgeAckWithdrawal's signature block. Same
      //  rationale as TBL_BRIDGE_ATTESTATIONS: federation state,
      //  not per-account state, not part of the state root.
      TBL_BRIDGE_ACK_ATTESTATIONS = 42,

      //  Aggregate bridge counters, one row per source chain. Key =
      //  source_chain_id (8 LE). Value = serialized BridgeStats.
      //  Written by executeBridgeMint, executeBridgeBurn, and
      //  executeBridgeAckWithdrawal. Read by the getBridgeStats RPC.
      TBL_BRIDGE_STATS = 43,

      //  Chronological log of successful bridge operations. Written
      //  by the executor after the operation's state changes have
      //  committed, and read by getBridgeEvents. NOT in the SMT:
      //  this is audit history, not consensus input. A node that
      //  never wrote a row would still produce the same state root
      //  as one that did.
      TBL_BRIDGE_EVENTS = 44,

      //  Per-pool farm schedule. Key = pool_id (8 LE). Value =
      //  serialized AmmFarmSchedule. Mirror of the SMT record at
      //  Keys::ammFarm(pool_id). Written by putAmmFarm and
      //  deleteAmmFarm; iterated by forEachAmmFarm for the
      //  epoch-boundary emission pass. Not part of the state root:
      //  this is a local mirror, the SMT leaf is authoritative.
      TBL_AMM_FARMS = 45,

      //  Per-position farm accrual companion. Key = position_id
      //  (8 LE). Value = serialized AmmPositionAccrual. Mirror of
      //  the SMT record at Keys::ammPositionAccrual(position_id).
      //  Written by putAmmPositionAccrual and
      //  deleteAmmPositionAccrual; read by getAmmPositionAccrual
      //  on every settle. Not part of the state root, same as
      //  TBL_AMM_FARMS.
      TBL_AMM_POSITION_ACCRUALS = 46,

      TBL_COUNT = 47,
    };

    //  Per-table diagnostic information. Reported by the metrics
    //  endpoint and by the clrty_getChainStats RPC method.
    //
    //  bytes_estimate is derived from MDBX's page counts, not from a
    //  scan of the values. It is an upper bound on the live data
    //  (MDBX allocates pages in fixed-size chunks and keeps a
    //  freelist, so an over-estimate is expected and normal). It is
    //  accurate enough for capacity planning and for detecting a
    //  runaway table.
    struct TableStats
    {
      uint64_t entries = 0;
      uint64_t bytes_estimate = 0;
    };

    using EntryVisitor = std::function<bool(const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &value)>;

    //  =====================================================================
    //  Write transaction
    //  =====================================================================

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

      void forEachFromKey(uint32_t tableId,
                          const std::vector<uint8_t> &seek_key,
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

    //  =====================================================================
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
    //  MDBX also refuses to open a write txn on a thread that already
    //  has a read txn open. The write paths therefore refuse to run
    //  while a read txn is open on the same thread: they call
    //  requireNoOpenReadTxn(), which throws a StateDBError naming
    //  the write method.
    //  =====================================================================

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
      void forEachFromKey(uint32_t tableId,
                          const std::vector<uint8_t> &seek_key,
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

    //  =====================================================================
    //  Lifecycle
    //  =====================================================================

    StateDB(const std::string &path, size_t mapSizeBytes);
    ~StateDB();

    StateDB(const StateDB &) = delete;
    StateDB &operator=(const StateDB &) = delete;

    void flush();
    void close();

    //  =====================================================================
    //  Transactions
    //  =====================================================================

    Txn beginWrite();

    void txnPut(Txn &txn, uint32_t tableId,
                const void *key, size_t keyLen,
                const void *value, size_t valueLen);

    bool txnGet(const Txn &txn, uint32_t tableId,
                const void *key, size_t keyLen,
                std::vector<uint8_t> &out) const;

    void txnDel(Txn &txn, uint32_t tableId,
                const void *key, size_t keyLen);

    //  =====================================================================
    //  Raw access (autocommit)
    //
    //  Reads do NOT take write_mutex_; MDBX readers are MVCC.
    //  Writes take write_mutex_ and refuse to run while a read txn
    //  is open on the current thread.
    //
    //  Raw reads reuse the per-thread read txn if one is open; see
    //  beginRead. This is what makes a nested read from inside a
    //  forEach visitor safe.
    //  =====================================================================

    void rawPut(uint32_t tableId,
                const void *key, size_t keyLen,
                const void *value, size_t valueLen);

    bool rawGet(uint32_t tableId,
                const void *key, size_t keyLen,
                std::vector<uint8_t> &out) const;

    void rawDel(uint32_t tableId, const void *key, size_t keyLen);

    bool rawHas(uint32_t tableId,
                const void *key, size_t keyLen) const;

    //  =====================================================================
    //  Iteration (autocommit — opens its own read-only txn if none
    //  is open on this thread)
    //  =====================================================================

    void forEachEntry(uint32_t tableId, const EntryVisitor &visitor) const;

    void forEachEntryWithPrefix(uint32_t tableId,
                                const std::vector<uint8_t> &prefix,
                                const EntryVisitor &visitor) const;

    void forEachEntryReverse(uint32_t tableId,
                             const EntryVisitor &visitor) const;

    void forEachEntryWithPrefixReverse(uint32_t tableId,
                                       const std::vector<uint8_t> &prefix,
                                       const EntryVisitor &visitor) const;

    //  Iterate every entry whose key is >= `seek_key`, in ascending
    //  key order. `seek_key` is the full key to seek to; there is no
    //  prefix match. This is the primitive for "give me all rows at
    //  or after this point" — used by the bridge's withdrawal
    //  height scan, where the key is (height BE, id BE) and seeking
    //  to (from_height, 0) yields every pending withdrawal at or
    //  after `from_height`.
    //
    //  Contrast with forEachEntryWithPrefix, which stops at the end
    //  of the prefix match. forEachEntryFromKey has no upper bound;
    //  the visitor controls termination (return false to stop) and
    //  the caller is expected to have a max_results or a natural
    //  end.
    void forEachEntryFromKey(uint32_t tableId,
                             const std::vector<uint8_t> &seek_key,
                             const EntryVisitor &visitor) const;

    //  =====================================================================
    //  Read txn lifecycle
    //
    //  beginRead returns a ReadTxn for the current thread. If a read
    //  txn is already open, it returns a non-owning ReadTxn wrapping
    //  the outer one, so the caller can hold it in a unique_ptr
    //  alongside the outer's owner without any coordination.
    //
    //  The owning ReadTxn's destructor is the only place the txn is
    //  aborted. Callers that want to write must destroy the owning
    //  ReadTxn first; the raw write paths enforce this with
    //  requireNoOpenReadTxn().
    //  =====================================================================

    ReadTxn beginRead();

    //  Historical no-op. Kept for source compatibility with call
    //  sites written against the old behavior, where this method
    //  aborted the thread-local read txn out from under its owning
    //  ReadTxn object. That behavior caused a use-after-free when
    //  the object was later destroyed.
    void releaseReadTxn() noexcept;

    //  =====================================================================
    //  Meta helpers
    //  =====================================================================

    bool getMeta(const std::string &key, std::vector<uint8_t> &out) const;
    std::optional<std::vector<uint8_t>> getMeta(const std::string &key) const;
    void putMeta(const std::string &key, const std::vector<uint8_t> &value);
    void removeMeta(const std::string &key);

    //  =====================================================================
    //  SMT convenience API
    //
    //  These methods are used by callers that write SMT rows outside
    //  of a SparseMerkleTree instance (genesis, test fixtures, and
    //  migration code). The tree itself writes through its own
    //  txn-aware helpers in SparseMerkleTree.cpp, which build the
    //  same key layouts directly against the bound txn.
    //
    //  The version argument on the "live" methods is ignored: live
    //  rows are content-addressed and versionless.
    //  =====================================================================

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

    //  =====================================================================
    //  Historical pruning
    //
    //  Both variants delete every historical row whose version is
    //  strictly less than keepFrom, from all four historical tables.
    //  The live tables and the current root are untouched.
    //
    //  pruneHistoryBefore opens its own write txn. Used by callers
    //  that want to prune outside a block-commit context (e.g. at
    //  startup with --prune-on-startup).
    //
    //  pruneHistoryBeforeTxn runs inside the caller's txn. Used by
    //  the block processor to make pruning atomic with the commit.
    //  =====================================================================

    void pruneHistoryBefore(uint64_t keepFrom);
    void pruneHistoryBeforeTxn(Txn &txn, uint64_t keepFrom);

    //  Delete every row in TBL_CONSENSUS_WAL. Called from
    //  Node::initGenesis on a fresh DB, so that stale WAL entries
    //  from a previous chain don't get replayed.
    void wipeConsensusWal();

    //  =====================================================================
    //  Diagnostics
    //  =====================================================================

    size_t entryCount(uint32_t tableId) const;
    TableStats tableStats(uint32_t tableId) const;
    size_t mapSize() const noexcept;
    MDBX_env *env() const noexcept;

    MDBX_dbi tableHandlePublic(uint32_t tableId) const noexcept
    {
      return tableHandle(tableId);
    }

    //  =====================================================================
    //  Historical key helpers
    //
    //  The historical SMT tables use a two-field key encoding:
    //
    //    TBL_SMT_*_HIST:     hash(32) || version_be64
    //    TBL_SMT_*_BY_VER:   version_be64 || hash(32)
    //
    //  The same encoding is used by:
    //
    //    - SparseMerkleTree::putNodeImpl and putLeafDataImpl when
    //      writing historical rows.
    //    - SparseMerkleTree::getNodeAtVersionImpl and
    //      getLeafDataAtVersionImpl when reading them.
    //    - pruneHistoryBefore and pruneHistoryBeforeTxn when
    //      deleting them.
    //
    //  Consolidating the encoding here means a future change to the
    //  layout only needs to touch this header and the two callers
    //  in SparseMerkleTree.cpp, not the prune path in this file.
    //  =====================================================================

    struct HistKey
    {
      uint8_t bytes[40];
    };

    static HistKey makeHistKey(const Crypto::Hash &hash,
                               uint64_t version) noexcept;

    static HistKey makeByVersionKey(uint64_t version,
                                    const Crypto::Hash &hash) noexcept;

    static uint64_t readVersionFromByVersionKey(const uint8_t *key) noexcept;

    //  Per-thread handle to the outermost read txn on this thread,
    //  if one is open. Set by beginRead when it opens a fresh txn,
    //  cleared by the owning ReadTxn's destructor.
    static thread_local MDBX_txn *tls_read_txn_;

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
    //  read txn out from under its owning ReadTxn object.
    static void requireNoOpenReadTxn(const char *where);

    MDBX_env *env_{nullptr};
    MDBX_dbi tables_[TBL_COUNT]{};
    size_t mapSizeBytes_{0};

    //  Guards writes only. Reads are lock-free (MVCC).
    mutable std::mutex write_mutex_;
    std::string path_;
  };

} // namespace State