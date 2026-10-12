// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <atomic>
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
  //      funds, expired) are dropped from memory and their txids are
  //      collected for the caller to prune from disk later. This is
  //      what filters out transactions that were mined while the node
  //      was offline.
  //    - During load, `add` does NOT persist. The entries being
  //      re-added are already on disk; re-writing them would open a
  //      write txn while the caller's read txn is still open, which
  //      MDBX refuses. The load path collects the stale txids and the
  //      caller drains them with takeStaleAfterLoad() from a
  //      write-friendly context.
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

    //  Order-specific rejections. A CreateOrder or CancelOrder tx
    //  whose payload fails structural validation — wrong size,
    //  invalid conditions, a canonical price that overflows u64, or
    //  a pool_id that does not match the declared mode — is rejected
    //  here rather than at apply time. The mempool's job is to hold
    //  transactions that will apply; holding one that will fail
    //  wastes a block slot and a proposer's attempt.
    Rejected_OrderMalformed,
    Rejected_OrderPriceOverflow,
    //  The transaction is well-formed, correctly signed, has a valid
    //  nonce and enough balance for the fee, but its *type-specific*
    //  preconditions cannot be satisfied at the current chain tip.
    //  For MintToken: the token doesn't exist, the sender isn't the
    //  creator, or the mint would exceed max_supply. For BurnToken:
    //  the token doesn't exist. For UpdateTokenMeta: the token
    //  doesn't exist or the sender isn't the creator.
    //
    //  These preconditions are also enforced by the executor when the
    //  transaction is applied. The mempool checks them here so a
    //  transaction the executor will reject never occupies a block
    //  slot; without this check, a mint for a nonexistent token sits
    //  in the pool forever and every block proposal that tries to
    //  include it fails simulation.
    Rejected_TokenPrecondition,
  };

  //  Pin the counter array size to the enum. Update both if a
  //  variant is added.
  static_assert(
      static_cast<size_t>(MempoolAddResult::Rejected_TokenPrecondition) + 1 == 15,
      "MempoolAddResult grew; update Mempool::ADD_RESULT_COUNT");

  const char *mempoolAddResultName(MempoolAddResult r) noexcept;

  // ---- Fee tier ----

  enum class FeeTier : uint8_t
  {
    Standard = 0,
    Priority = 1,
  };

  //  Which tx types move value out of the sender's balance?
  //
  //  The mempool's balance check applies only to transactions that
  //  actually debit the sender. Mint-family transactions create new
  //  supply and do not need the sender to already hold the token
  //  they are minting; creation, metadata, staking, validator, and
  //  reward transactions carry no amount at all. The executor has
  //  the authoritative per-type rules; this predicate exists so the
  //  mempool does not reject those types before the executor sees
  //  them.
  //
  //  These two predicates must be kept in sync with the executor's
  //  semantics. If a new tx type is added that debits the sender,
  //  add it here.
  inline bool txMovesNativeFromSender(TxType t) noexcept
  {
    switch (t)
    {
    case TxType::Transfer:
    case TxType::TransferNft:
    case TxType::BurnNft:
    case TxType::MintNft:
    case TxType::CreateNftCollection:
    case TxType::TopUpNft:
      return true;
    default:
      return false;
    }
  }

  inline bool txMovesTokenFromSender(TxType t) noexcept
  {
    switch (t)
    {
    case TxType::Transfer:
    case TxType::BurnToken:
    case TxType::TransferNft:
    case TxType::BurnNft:
      return true;
    default:
      return false;
    }
  }

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
    // from memory and their txids are collected for later pruning.
    //
    // No-op if no DB is attached. Typically called once at node startup.
    //
    // During load, `add` does NOT persist. The entries being re-added
    // are already on disk. See takeStaleAfterLoad() for how the
    // caller drains the collected stale txids.
    void load(const StateView &state);

    // Return and clear the list of txids whose persisted rows should
    // be pruned after the most recent load(). The caller is expected
    // to delete those rows from TBL_MEMPOOL in a write-friendly
    // context — after any read txn it held during load() has been
    // destroyed — because MDBX refuses to open a write txn while a
    // read txn is open on the same thread.
    //
    // Returns an empty vector if no load has been performed since the
    // last call. Idempotent from the caller's perspective: the list
    // is drained on every call.
    std::vector<Crypto::Hash> takeStaleAfterLoad();

    // ---- Add / Remove ----

    // Validate and add a transaction. Uses the provided StateView to check
    // nonce, balance, and current chain height.
    //
    // The `tier` indicates whether the sender paid the priority surcharge.
    // This is enforced by the caller (wallet sets the fee accordingly,
    // node verifies the surcharge was included in tx.fee).
    //
    // Every call updates the per-result counters exposed by
    // addResultCounts(). The update happens inside add(), after the
    // underlying implementation returns, so the counter array is
    // always consistent with the value returned to the caller.
    MempoolAddResult add(const Transaction &tx,
                         const StateView &state,
                         FeeTier tier);

    // Counters for add() results, indexed by MempoolAddResult. The
    // i-th element is the count of add() calls that returned result i
    // since process start.
    //
    // Per-process, not persisted: a counter that resets on restart is
    // what Prometheus expects from a _total series, and nobody wants
    // a "rejected since genesis" number.
    //
    // The array has one slot per MempoolAddResult variant. The size
    // is pinned to the enum by a static_assert above.
    static constexpr size_t ADD_RESULT_COUNT = 15;
    std::array<uint64_t, ADD_RESULT_COUNT> addResultCounts() const;

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
    // The body of add(), separated so add() can count the result
    // exactly once at a single site. Callers must use add(), not
    // addImpl directly — addImpl does not update the counters.
    MempoolAddResult addImpl(const Transaction &tx,
                             const StateView &state,
                             FeeTier tier);

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

    //  Structural validation of an order-shaped transaction. Runs
    //  inside validate() when tx.tx_type is CreateOrder or
    //  CancelOrder. Returns Accepted if the payload is well-formed,
    //  or the specific rejection reason otherwise.
    //
    //  This is deliberately shallow: it does not read state (balance,
    //  nonce) — those checks are the caller's job. It only checks
    //  the payload's shape and the order-specific invariants that
    //  do not depend on state.
    static MempoolAddResult validateOrderPayload(const Transaction &tx);

    // Eviction. Called when the pool is full and a new tx arrives.
    // Returns true if the new tx should be admitted (something was evicted
    // or there was room). Returns false if the new tx should be rejected.
    //
    //  `state` is the caller's StateView. It is passed through so that
    //  eviction can release the read txn the caller is holding before
    //  calling unpersistEntry: MDBX refuses to open a write txn while
    //  a read txn is open on the same thread. The view reopens a fresh
    //  read txn on the next read, so releasing is safe.
    bool makeRoomFor(const Entry &new_entry, const StateView &state);

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
    //
    // During load(), `persistEntry` is skipped entirely (see loading_
    // below) so that load does not attempt a write while the caller's
    // read txn is still open. `unpersistEntry` and `unpersistBatch`
    // are still reachable during load only through the caller's
    // explicit drain of the stale list (see takeStaleAfterLoad), which
    // runs after the read txn is closed.

    void persistEntry(const Crypto::Hash &txid, const Entry &e);
    void unpersistEntry(const Crypto::Hash &txid);
    void unpersistBatch(const std::vector<Crypto::Hash> &txids);

    // Serialize / deserialize an Entry for storage.
    static std::vector<uint8_t> serializeEntry(const Entry &e);
    static bool deserializeEntry(const uint8_t *data, size_t len, Entry &out);

    // ---- Members ----

    //  Per-result counters for add(). Updated by add() after addImpl
    //  returns; read by addResultCounts(). Indexed by
    //  static_cast<size_t>(MempoolAddResult).
    //
    //  The atomics are relaxed because they are pure counters with no
    //  ordering requirements: a reader either sees an update or it
    //  doesn't, and every observation is a valid sample. There is no
    //  memory guarded by these values.
    std::array<std::atomic<uint64_t>, ADD_RESULT_COUNT> add_result_counts_{};

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

    //  Set while load() is running. addImpl checks this before
    //  calling persistEntry, so that the load path does not attempt
    //  a write while the caller's read txn is still open. Cleared
    //  when load() returns.
    bool loading_{false};

    //  Txids collected by load() for entries that failed
    //  re-validation. The caller drains this via
    //  takeStaleAfterLoad() from a write-friendly context, after any
    //  read txn it held during load() has been destroyed. Empty
    //  outside of the window between a load() and the next
    //  takeStaleAfterLoad().
    std::vector<Crypto::Hash> stale_after_load_;
  };

} // namespace Core