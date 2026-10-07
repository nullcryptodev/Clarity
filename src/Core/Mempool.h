// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include "Crypto/Types.h"
#include "StateView.h"
#include "Transaction.h"

namespace State
{
  class StateDB;
}

namespace Core
{
  //  Mempool
  //
  //  Holds pending transactions awaiting inclusion in a block.
  //
  //  Fee model:
  //    - Two tiers: standard and priority
  //    - Priority txs pay a fixed surcharge on top of their base fee
  //    - Block builder drains priority txs first, then standard
  //    - Fee rate = fee / serialized_size (atomic per byte)
  //
  //  Nonce model:
  //    - Sequential per sender (Ethereum-style)
  //    - Higher nonces are held ("queued") until earlier nonces clear
  //    - Duplicate (from, nonce) is rejected unless the new one has
  //      strictly higher priority or fee rate
  //
  //  Thread safety:
  //    - Mempool is internally synchronized via a mutex
  //    - All public methods are safe to call from multiple threads
  //
  //  Persistence:
  //    - Optionally attached to a State::StateDB. When attached, every
  //      mutation writes through to TBL_MEMPOOL in the same operation.
  //      When not attached, the pool is purely in-memory.
  //    - On startup, `load(state)` rebuilds the pool from persisted
  //      rows by re-adding each through the normal validation path.
  //      Entries that fail validation (nonce too low, insufficient
  //      funds, expired) are dropped and their rows deleted. This is
  //      what filters out transactions that were mined while the node
  //      was offline.
  //    - Persistence stores the full Entry (tx + tier + fee rate +
  //      sequence + add time), not just the tx, so eviction ordering
  //      and priority status survive a restart.

  // ---- Fee policy constants ----

  inline constexpr uint64_t MIN_FEE_PER_BYTE = 1;
  inline constexpr uint64_t PRIORITY_SURCHARGE = 10'000; // 0.1 CLRTY in atomic
  inline constexpr uint64_t MAX_FEE_RATE = 1'000;
  inline constexpr uint32_t PRIORITY_BLOCK_SHARE = 50; // percent

  // ---- Mempool size limits ----

  inline constexpr size_t MAX_MEMPOOL_BYTES = 128ULL * 1024 * 1024;
  inline constexpr size_t MAX_MEMPOOL_TXS = 50'000;

  // ---- Result of adding a transaction ----

  enum class MempoolAddResult
  {
    Accepted,
    Rejected_Malformed,
    Rejected_TooLarge,
    Rejected_BadSignature,
    Rejected_WrongChain,
    Rejected_Expired,
    Rejected_NonceTooLow,       // nonce < state nonce (already used)
    Rejected_NonceConflict,     // same (from, nonce) already in pool
    Rejected_LowFee,            // fee rate below MIN_FEE_PER_BYTE
    Rejected_HighFee,           // fee rate above MAX_FEE_RATE
    Rejected_InsufficientFunds, // balance < amount + fee
    Rejected_PoolFull,
  };

  const char *mempoolAddResultName(MempoolAddResult r) noexcept;

  // ---- Fee tier ----

  enum class FeeTier : uint8_t
  {
    Standard = 0,
    Priority = 1,
  };

  //  Mempool

  class Mempool
  {
  public:
    Mempool() = default;
    ~Mempool() = default;

    // Construct attached to a DB. Equivalent to default construction
    // followed by attach().
    explicit Mempool(State::StateDB &db);

    Mempool(const Mempool &) = delete;
    Mempool &operator=(const Mempool &) = delete;

    // ---- Persistence ----

    // Attach a DB for write-through persistence. Idempotent. The DB
    // must outlive the Mempool.
    //
    // If called while the pool already holds entries, those entries
    // are NOT retroactively persisted. attach() only affects future
    // mutations. Typical usage is to attach once at construction.
    void attach(State::StateDB &db);

    // Rebuild the pool from persisted rows. Reads TBL_MEMPOOL, and for
    // each stored Entry, re-adds it through the normal `add` path with
    // the supplied StateView. Entries that fail validation (nonce too
    // low, insufficient funds, expired, already on chain) are dropped
    // and their rows deleted.
    //
    // No-op if no DB is attached. Typically called once at node startup.
    void load(const StateView &state);

    // ---- Add / Remove ----

    // Validate and add a transaction. Uses the provided StateView to check
    // nonce, balance, and current chain height.
    //
    // The `tier` indicates whether the sender paid the priority surcharge.
    // This is enforced by the caller (wallet sets the fee accordingly,
    // node verifies the surcharge was included in tx.fee).
    MempoolAddResult add(const Transaction &tx,
                         const StateView &state,
                         FeeTier tier);

    // Remove a single transaction by txid. Returns true if it was present.
    bool remove(const Crypto::Hash &txid);

    // Remove all transactions that appear in a confirmed block.
    // Called after a block is accepted.
    void removeIncluded(const std::vector<Crypto::Hash> &txids);

    // Remove transactions that have expired at the given height.
    void purgeExpired(uint64_t current_height);

    // Wipe the entire pool, in-memory and persisted.
    void clear();

    // ---- Query ----

    bool contains(const Crypto::Hash &txid) const;

    std::optional<Transaction> get(const Crypto::Hash &txid) const;

    size_t size() const;
    size_t bytes() const;
    size_t priorityCount() const;

    // ---- Block selection ----

    // Select transactions for a block proposal.
    //
    // Constraints:
    //   - Total serialized size must not exceed `max_block_bytes`
    //   - Total count must not exceed `max_block_txs`
    //   - Priority tier transactions are selected first, up to
    //     `max_block_bytes * PRIORITY_BLOCK_SHARE / 100` bytes
    //   - Standard tier fills the remainder
    //
    // Nonce ordering is respected: a transaction is only selected if
    // all earlier nonces from the same sender are already in the block
    // (or the state). Transactions with nonce gaps are skipped until
    // their predecessor arrives.
    //
    // The returned transactions are NOT removed from the mempool.
    // The caller must call removeIncluded() once a block is confirmed.
    std::vector<Transaction> selectForBlock(const StateView &state,
                                            uint64_t max_block_bytes,
                                            uint64_t max_block_txs) const;

    // ---- Introspection ----

    // Snapshot of pool statistics.
    struct Stats
    {
      size_t total_txs{0};
      size_t priority_txs{0};
      size_t standard_txs{0};
      size_t total_bytes{0};
      uint64_t min_fee_rate{0};
      uint64_t max_fee_rate{0};
      uint64_t avg_fee_rate{0};
    };

    Stats stats() const;

    // ---- Introspection ----

    // Snapshot of the pool for external consumers (RPC, diagnostics).
    //
    // Returns a copy of every entry, taken under the pool's mutex. Safe
    // to iterate after the call returns. The pool is bounded
    // (MAX_MEMPOOL_TXS), so the copy is cheap; a 50k-entry pool at a
    // few hundred bytes each is a few MB, which is fine for an RPC
    // that's called at human rates.
    //
    // The `txid` is the key the entry is stored under, which equals
    // `entry.tx.txid()`. It's duplicated into the snapshot so callers
    // don't have to recompute it.
    struct Snapshot
    {
      Crypto::Hash txid;
      Transaction tx;
      FeeTier tier{FeeTier::Standard};
      uint64_t fee_rate{0};
      uint64_t sequence{0};
      uint64_t added_at_ms{0};
      uint32_t tx_size{0};
    };

    std::vector<Snapshot> snapshot() const;

  private:
    // ---- Internal data ----

    struct Entry
    {
      Transaction tx;
      FeeTier tier{FeeTier::Standard};
      uint64_t fee_rate{0}; // fee / serialized size
      uint64_t sequence{0}; // monotonic counter, for FIFO ties
      uint64_t added_at_ms{0};
      uint32_t tx_size{0}; // cached
    };

    // Heap item. Priority txs always beat standard txs. Within a tier,
    // higher fee rate beats lower. Ties broken by lower sequence (FIFO).
    struct HeapItem
    {
      FeeTier tier;
      uint64_t fee_rate;
      uint64_t sequence;
      Crypto::Hash txid;
    };

    struct HeapCompare
    {
      // Returns true if `a` has LOWER priority than `b` (max-heap semantics).
      bool operator()(const HeapItem &a, const HeapItem &b) const noexcept
      {
        if (a.tier != b.tier)
        {
          return static_cast<uint8_t>(a.tier) < static_cast<uint8_t>(b.tier);
        }
        if (a.fee_rate != b.fee_rate)
        {
          return a.fee_rate < b.fee_rate;
        }
        return a.sequence > b.sequence;
      }
    };

    using MaxHeap = std::priority_queue<HeapItem, std::vector<HeapItem>, HeapCompare>;

    // ---- Internal helpers ----

    // Compute the fee rate for a transaction.
    static uint64_t computeFeeRate(const Transaction &tx, FeeTier tier) noexcept;

    // Validate a transaction against state. Returns a result code.
    MempoolAddResult validate(const Transaction &tx,
                              const StateView &state,
                              FeeTier tier,
                              uint64_t &out_fee_rate,
                              uint32_t &out_tx_size) const;

    // Eviction. Called when the pool is full and a new tx arrives.
    // Returns true if the new tx should be admitted (something was evicted
    // or there was room). Returns false if the new tx should be rejected.
    bool makeRoomFor(const Entry &new_entry);

    // Find the lowest-priority entry in the pool. O(n). Used for eviction.
    // Returns nullptr if the pool is empty.
    const Entry *findLowestPriorityEntry() const;

    // Build a nonce key from (address, nonce).
    static std::string nonceKey(const Crypto::Address &from, uint64_t nonce);

    // ---- Persistence helpers. No-ops when db_ is null. ----
    //
    // All of these are called from inside public methods that already
    // hold mutex_. They take the StateDB's own lock internally; there
    // is no cross-lock dependency because the Mempool never calls into
    // a StateDB method that would call back into the Mempool.

    void persistEntry(const Crypto::Hash &txid, const Entry &e);
    void unpersistEntry(const Crypto::Hash &txid);
    void unpersistBatch(const std::vector<Crypto::Hash> &txids);

    // Serialize / deserialize an Entry for storage.
    static std::vector<uint8_t> serializeEntry(const Entry &e);
    static bool deserializeEntry(const uint8_t *data, size_t len, Entry &out);

    // ---- Members ----

    mutable std::mutex mutex_;

    // Primary storage: txid → Entry.
    std::unordered_map<Crypto::Hash, Entry> entries_;

    // Nonce index: (from, nonce) → txid. For duplicate detection.
    std::unordered_map<std::string, Crypto::Hash> nonce_index_;

    // Selection heap. Lazy-deletion: stale entries are skipped when popped.
    mutable MaxHeap heap_;

    // Size accounting.
    size_t total_bytes_{0};

    // Monotonic sequence counter for FIFO tie-breaking.
    uint64_t next_sequence_{1};

    // The DB the pool persists to. Null when persistence is disabled.
    // Owned by the caller; must outlive the Mempool.
    State::StateDB *db_{nullptr};
  };

} // namespace Core