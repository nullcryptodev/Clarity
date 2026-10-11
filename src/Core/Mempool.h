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
  //  (Rest of the class documentation unchanged — see the previous
  //  version. The only new material is the two order-specific
  //  rejection reasons and the structural-validation hook.)

  // ---- Fee policy constants ----

  inline constexpr uint64_t MIN_FEE_PER_BYTE = 1;
  inline constexpr uint64_t PRIORITY_SURCHARGE = 10'000;
  inline constexpr uint64_t MAX_FEE_RATE = 1'000;
  inline constexpr uint32_t PRIORITY_BLOCK_SHARE = 50;

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
    Rejected_NonceTooLow,
    Rejected_NonceConflict,
    Rejected_LowFee,
    Rejected_HighFee,
    Rejected_InsufficientFunds,
    Rejected_PoolFull,

    //  Order-specific rejections. A CreateOrder or CancelOrder tx
    //  whose payload fails structural validation — wrong size,
    //  invalid conditions, Active mode when it is disabled, a
    //  canonical price that overflows u64 — is rejected here rather
    //  than at apply time. The mempool's job is to hold transactions
    //  that will apply; holding one that will fail wastes a block
    //  slot and a proposer's attempt.
    Rejected_OrderMalformed,
    Rejected_OrderDisabledMode,
    Rejected_OrderPriceOverflow,
  };

  //  Pin the counter array size to the enum. Update both if a
  //  variant is added.
  static_assert(
      static_cast<size_t>(MempoolAddResult::Rejected_OrderPriceOverflow) + 1 == 15,
      "MempoolAddResult grew; update Mempool::ADD_RESULT_COUNT");

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

    explicit Mempool(State::StateDB &db);

    Mempool(const Mempool &) = delete;
    Mempool &operator=(const Mempool &) = delete;

    // ---- Persistence ----

    void attach(State::StateDB &db);
    void load(const StateView &state);

    // ---- Add / Remove ----

    MempoolAddResult add(const Transaction &tx,
                         const StateView &state,
                         FeeTier tier);

    static constexpr size_t ADD_RESULT_COUNT = 15;
    std::array<uint64_t, ADD_RESULT_COUNT> addResultCounts() const;

    bool remove(const Crypto::Hash &txid);
    void removeIncluded(const std::vector<Crypto::Hash> &txids);
    void purgeExpired(uint64_t current_height);
    void clear();

    // ---- Query ----

    bool contains(const Crypto::Hash &txid) const;
    std::optional<Transaction> get(const Crypto::Hash &txid) const;

    size_t size() const;
    size_t bytes() const;
    size_t priorityCount() const;

    // ---- Block selection ----

    std::vector<Transaction> selectForBlock(const StateView &state,
                                            uint64_t max_block_bytes,
                                            uint64_t max_block_txs) const;

    // ---- Introspection ----

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
    MempoolAddResult addImpl(const Transaction &tx,
                             const StateView &state,
                             FeeTier tier);

    struct Entry
    {
      Transaction tx;
      FeeTier tier{FeeTier::Standard};
      uint64_t fee_rate{0};
      uint64_t sequence{0};
      uint64_t added_at_ms{0};
      uint32_t tx_size{0};
    };

    struct HeapItem
    {
      FeeTier tier;
      uint64_t fee_rate;
      uint64_t sequence;
      Crypto::Hash txid;
    };

    struct HeapCompare
    {
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

    static uint64_t computeFeeRate(const Transaction &tx, FeeTier tier) noexcept;

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

    bool makeRoomFor(const Entry &new_entry);
    const Entry *findLowestPriorityEntry() const;

    static std::string nonceKey(const Crypto::Address &from, uint64_t nonce);

    void persistEntry(const Crypto::Hash &txid, const Entry &e);
    void unpersistEntry(const Crypto::Hash &txid);
    void unpersistBatch(const std::vector<Crypto::Hash> &txids);

    static std::vector<uint8_t> serializeEntry(const Entry &e);
    static bool deserializeEntry(const uint8_t *data, size_t len, Entry &out);

    std::array<std::atomic<uint64_t>, ADD_RESULT_COUNT> add_result_counts_{};

    mutable std::mutex mutex_;

    std::unordered_map<Crypto::Hash, Entry> entries_;
    std::unordered_map<std::string, Crypto::Hash> nonce_index_;
    mutable MaxHeap heap_;

    size_t total_bytes_{0};
    uint64_t next_sequence_{1};

    State::StateDB *db_{nullptr};
  };

} // namespace Core