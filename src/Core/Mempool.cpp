// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Mempool.h"

#include "Crypto/Ed25519.h"
#include "RewardTypes.h"
#include "State/StateDB.h"

#include "Order.h"
#include "OrderBook.h"
#include "TransactionExecutor.h"

#include <chrono>
#include <cstring>

namespace Core
{

  //  Result name

  const char *mempoolAddResultName(MempoolAddResult r) noexcept
  {
    switch (r)
    {
    case MempoolAddResult::Accepted:
      return "accepted";
    case MempoolAddResult::Rejected_Malformed:
      return "malformed";
    case MempoolAddResult::Rejected_TooLarge:
      return "too-large";
    case MempoolAddResult::Rejected_BadSignature:
      return "bad-signature";
    case MempoolAddResult::Rejected_WrongChain:
      return "wrong-chain";
    case MempoolAddResult::Rejected_Expired:
      return "expired";
    case MempoolAddResult::Rejected_NonceTooLow:
      return "nonce-too-low";
    case MempoolAddResult::Rejected_NonceConflict:
      return "nonce-conflict";
    case MempoolAddResult::Rejected_LowFee:
      return "low-fee";
    case MempoolAddResult::Rejected_HighFee:
      return "high-fee";
    case MempoolAddResult::Rejected_InsufficientFunds:
      return "insufficient-funds";
    case MempoolAddResult::Rejected_PoolFull:
      return "pool-full";
    case MempoolAddResult::Rejected_OrderMalformed:
      return "order-malformed";
    case MempoolAddResult::Rejected_OrderDisabledMode:
      return "order-disabled-mode";
    case MempoolAddResult::Rejected_OrderPriceOverflow:
      return "order-price-overflow";
    }
    return "unknown";
  }

  //  Helpers

  namespace
  {
    uint64_t nowMs() noexcept
    {
      using namespace std::chrono;
      return duration_cast<milliseconds>(
                 system_clock::now().time_since_epoch())
          .count();
    }
  } // anonymous namespace

  //  Construction

  Mempool::Mempool(State::StateDB &db) : db_(&db) {}

  void Mempool::attach(State::StateDB &db)
  {
    std::lock_guard<std::mutex> lock(mutex_);
    db_ = &db;
  }

  std::string Mempool::nonceKey(const Crypto::Address &from, uint64_t nonce)
  {
    std::string key;
    key.resize(40);
    std::memcpy(&key[0], from.data.data(), 32);
    for (int i = 0; i < 8; ++i)
    {
      key[32 + i] = char(uint8_t(nonce >> (i * 8)));
    }
    return key;
  }

  uint64_t Mempool::computeFeeRate(const Transaction &tx, FeeTier tier) noexcept
  {
    uint32_t size = static_cast<uint32_t>(tx.serializedSize());
    if (size == 0)
      return 0;

    uint64_t effective_fee = tx.fee;
    (void)tier;

    return effective_fee / size;
  }

  //  Order payload structural validation
  //
  //  This is the mempool-side mirror of TransactionExecutor's own
  //  payload check. It exists so that a malformed CreateOrder or
  //  CancelOrder never enters the pool: the pool holds transactions
  //  that will apply, and an order whose payload fails at apply
  //  time is wasted space and a wasted proposer attempt.
  //
  //  The check is deliberately pure: it inspects only tx.payload and
  //  tx.token_id, and does not read state. That means it can run
  //  during mempool admission without acquiring a StateAccess.

  MempoolAddResult Mempool::validateOrderPayload(const Transaction &tx)
  {
    if (tx.tx_type == TxType::CreateOrder)
    {
      if (tx.payload.size() < 22)
        return MempoolAddResult::Rejected_OrderMalformed;

      size_t off = 0;
      uint32_t buy_token = uint32_t(tx.payload[off]) |
                           (uint32_t(tx.payload[off + 1]) << 8) |
                           (uint32_t(tx.payload[off + 2]) << 16) |
                           (uint32_t(tx.payload[off + 3]) << 24);
      off += 4;

      uint64_t min_buy_amount = 0;
      for (int i = 0; i < 8; ++i)
        min_buy_amount |= uint64_t(tx.payload[off + i]) << (i * 8);
      off += 8;

      uint8_t mode = tx.payload[off++];

      uint64_t expires_at_height = 0;
      for (int i = 0; i < 8; ++i)
        expires_at_height |= uint64_t(tx.payload[off + i]) << (i * 8);
      off += 8;

      uint8_t condition_count = tx.payload[off++];

      if (condition_count > ORDER_MAX_CONDITIONS)
        return MempoolAddResult::Rejected_OrderMalformed;

      if (mode != static_cast<uint8_t>(OrderExecutionMode::Passive) &&
          mode != static_cast<uint8_t>(OrderExecutionMode::Active))
      {
        return MempoolAddResult::Rejected_OrderMalformed;
      }

      //  Active mode is disabled until AMM routing ships. Reject
      //  it at admission rather than letting it reach the executor
      //  and fail there, where the fee would still be charged but
      //  the mempool slot was wasted.
      if (mode == static_cast<uint8_t>(OrderExecutionMode::Active) &&
          !TransactionExecutor::activeOrdersEnabled())
      {
        return MempoolAddResult::Rejected_OrderDisabledMode;
      }

      //  Parse conditions. Each one has a fixed 13-byte layout; the
      //  cursor advances inside deserializeState only on success.
      OrderCondition conditions[ORDER_MAX_CONDITIONS]{};
      for (uint8_t i = 0; i < condition_count; ++i)
      {
        if (!OrderCondition::deserializeState(
                tx.payload.data(), tx.payload.size(), off, conditions[i]))
        {
          return MempoolAddResult::Rejected_OrderMalformed;
        }
      }

      if (tx.token_id == buy_token)
        return MempoolAddResult::Rejected_OrderMalformed;
      if (tx.amount == 0)
        return MempoolAddResult::Rejected_OrderMalformed;
      if (min_buy_amount == 0)
        return MempoolAddResult::Rejected_OrderMalformed;

      //  Canonical-price overflow check. A Passive order whose
      //  price cannot be represented as a u64 cannot enter the
      //  book; rejecting it here keeps the caller from paying a fee
      //  for an order the matcher would refuse to hold.
      if (mode == static_cast<uint8_t>(OrderExecutionMode::Passive))
      {
        Order probe;
        probe.sell_token = tx.token_id;
        probe.buy_token = buy_token;
        probe.sell_amount = tx.amount;
        probe.min_buy_amount = min_buy_amount;
        uint64_t canonical_price = 0;
        if (!OrderBook::canonicalPrice(probe, canonical_price))
          return MempoolAddResult::Rejected_OrderPriceOverflow;
      }

      return MempoolAddResult::Accepted;
    }

    if (tx.tx_type == TxType::CancelOrder)
    {
      //  CancelOrder payload is exactly one u64: the order id.
      if (tx.payload.size() < 8)
        return MempoolAddResult::Rejected_OrderMalformed;
      return MempoolAddResult::Accepted;
    }

    return MempoolAddResult::Accepted;
  }

  //  Entry serialization

  std::vector<uint8_t> Mempool::serializeEntry(const Entry &e)
  {
    auto tx_bytes = e.tx.serialize();

    std::vector<uint8_t> out;
    out.reserve(4 + tx_bytes.size() + 1 + 8 + 8 + 8 + 4);

    uint32_t txs = static_cast<uint32_t>(tx_bytes.size());
    out.push_back(uint8_t(txs));
    out.push_back(uint8_t(txs >> 8));
    out.push_back(uint8_t(txs >> 16));
    out.push_back(uint8_t(txs >> 24));

    out.insert(out.end(), tx_bytes.begin(), tx_bytes.end());

    out.push_back(static_cast<uint8_t>(e.tier));

    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(e.fee_rate >> (i * 8)));
    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(e.sequence >> (i * 8)));
    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(e.added_at_ms >> (i * 8)));

    out.push_back(uint8_t(e.tx_size));
    out.push_back(uint8_t(e.tx_size >> 8));
    out.push_back(uint8_t(e.tx_size >> 16));
    out.push_back(uint8_t(e.tx_size >> 24));

    return out;
  }

  bool Mempool::deserializeEntry(const uint8_t *data, size_t len, Entry &out)
  {
    if (len < 4)
      return false;

    size_t off = 0;
    uint32_t txs = uint32_t(data[off]) |
                   (uint32_t(data[off + 1]) << 8) |
                   (uint32_t(data[off + 2]) << 16) |
                   (uint32_t(data[off + 3]) << 24);
    off += 4;

    if (txs == 0 || off + txs + 1 + 8 + 8 + 8 + 4 > len)
      return false;

    Transaction tx;
    if (!Transaction::deserialize(data + off, txs, tx))
      return false;
    off += txs;

    out.tx = std::move(tx);

    uint8_t tier_byte = data[off++];
    if (tier_byte > 1)
      return false;
    out.tier = static_cast<FeeTier>(tier_byte);

    auto readU64 = [&]() -> uint64_t
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(data[off + i]) << (i * 8);
      off += 8;
      return v;
    };

    out.fee_rate = readU64();
    out.sequence = readU64();
    out.added_at_ms = readU64();

    out.tx_size = uint32_t(data[off]) |
                  (uint32_t(data[off + 1]) << 8) |
                  (uint32_t(data[off + 2]) << 16) |
                  (uint32_t(data[off + 3]) << 24);

    return true;
  }

  //  Persistence helpers

  void Mempool::persistEntry(const Crypto::Hash &txid, const Entry &e)
  {
    if (!db_)
      return;

    auto bytes = serializeEntry(e);
    db_->rawPut(State::StateDB::TBL_MEMPOOL,
                txid.data.data(), txid.data.size(),
                bytes.data(), bytes.size());
  }

  void Mempool::unpersistEntry(const Crypto::Hash &txid)
  {
    if (!db_)
      return;
    db_->rawDel(State::StateDB::TBL_MEMPOOL,
                txid.data.data(), txid.data.size());
  }

  void Mempool::unpersistBatch(const std::vector<Crypto::Hash> &txids)
  {
    if (!db_)
      return;
    for (const auto &txid : txids)
    {
      db_->rawDel(State::StateDB::TBL_MEMPOOL,
                  txid.data.data(), txid.data.size());
    }
  }

  //  Load

  void Mempool::load(const StateView &state)
  {
    if (!db_)
      return;

    std::vector<Entry> persisted;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      db_->forEachEntry(
          State::StateDB::TBL_MEMPOOL,
          [&persisted](const std::vector<uint8_t> & /*key*/,
                       const std::vector<uint8_t> &value)
          {
            Entry e;
            if (deserializeEntry(value.data(), value.size(), e))
              persisted.push_back(std::move(e));
            return true;
          });
    }

    std::vector<Crypto::Hash> stale;
    for (const auto &e : persisted)
    {
      auto result = add(e.tx, state, e.tier);
      if (result != MempoolAddResult::Accepted)
      {
        stale.push_back(e.tx.txid());
      }
    }
    unpersistBatch(stale);
  }

  //  Validation

  MempoolAddResult Mempool::validate(const Transaction &tx,
                                     const StateView &state,
                                     FeeTier tier,
                                     uint64_t &out_fee_rate,
                                     uint32_t &out_tx_size) const
  {
    // ---- Structural ----
    if (!tx.isWellFormed())
    {
      return MempoolAddResult::Rejected_Malformed;
    }

    // ---- Chain ID ----
    if (tx.chain_id != state.chainId())
    {
      return MempoolAddResult::Rejected_WrongChain;
    }

    // ---- Size cap ----
    uint32_t size = static_cast<uint32_t>(tx.serializedSize());
    if (size > 1024 * 1024)
    {
      return MempoolAddResult::Rejected_TooLarge;
    }
    out_tx_size = size;

    // ---- Signature ----
    {
      Crypto::Hash signing_hash = tx.signingHash();
      if (!Crypto::verify(signing_hash, tx.from, tx.signature))
      {
        return MempoolAddResult::Rejected_BadSignature;
      }
    }

    // ---- Expiry ----
    uint64_t current_height = state.currentHeight();
    if (tx.valid_until_height != 0 && current_height > tx.valid_until_height)
    {
      return MempoolAddResult::Rejected_Expired;
    }

    // ---- Fee rate ----
    uint64_t rate = computeFeeRate(tx, tier);
    if (rate < MIN_FEE_PER_BYTE)
    {
      return MempoolAddResult::Rejected_LowFee;
    }
    if (rate > MAX_FEE_RATE)
    {
      return MempoolAddResult::Rejected_HighFee;
    }
    out_fee_rate = rate;

    // ---- Order payload structure ----
    //
    //  Placed before the state reads (nonce, balance) because a
    //  malformed payload rejects the tx on its own merits,
    //  regardless of the sender's state. This is also where
    //  Active-mode orders are rejected while the feature is
    //  disabled; see validateOrderPayload.
    if (tx.tx_type == TxType::CreateOrder ||
        tx.tx_type == TxType::CancelOrder)
    {
      MempoolAddResult payload_result = validateOrderPayload(tx);
      if (payload_result != MempoolAddResult::Accepted)
        return payload_result;
    }

    // ---- Nonce ----
    Account acct = state.getAccount(tx.from);
    if (tx.nonce < acct.nonce)
    {
      return MempoolAddResult::Rejected_NonceTooLow;
    }

    // ---- Balance (native CLRTY) ----
    if (tx.fee > 0 && acct.balance < tx.fee)
    {
      return MempoolAddResult::Rejected_InsufficientFunds;
    }

    if (tx.token_id == NATIVE_TOKEN_ID)
    {
      //  CreateOrder locks the sell amount, same as a Transfer
      //  would move it. The pool's structural check cannot see
      //  the lock, so the balance check has to cover it here.
      //  fee + amount is the full debit the sender is committing
      //  to at admission time.
      if (acct.balance < tx.amount + tx.fee)
      {
        return MempoolAddResult::Rejected_InsufficientFunds;
      }
    }
    else
    {
      uint64_t token_balance = state.getTokenBalance(tx.from, tx.token_id);
      if (token_balance < tx.amount)
      {
        return MempoolAddResult::Rejected_InsufficientFunds;
      }
    }

    return MempoolAddResult::Accepted;
  }

  //  Add

  MempoolAddResult Mempool::add(const Transaction &tx,
                                const StateView &state,
                                FeeTier tier)
  {
    const MempoolAddResult result = addImpl(tx, state, tier);

    const size_t idx = static_cast<size_t>(result);
    if (idx < add_result_counts_.size())
    {
      add_result_counts_[idx].fetch_add(1, std::memory_order_relaxed);
    }

    return result;
  }

  MempoolAddResult Mempool::addImpl(const Transaction &tx,
                                    const StateView &state,
                                    FeeTier tier)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    uint64_t fee_rate = 0;
    uint32_t tx_size = 0;
    MempoolAddResult result = validate(tx, state, tier, fee_rate, tx_size);
    if (result != MempoolAddResult::Accepted)
    {
      return result;
    }

    Crypto::Hash txid = tx.txid();

    std::string nk = nonceKey(tx.from, tx.nonce);
    {
      auto it = nonce_index_.find(nk);
      if (it != nonce_index_.end())
      {
        Crypto::Hash existing_txid = it->second;
        auto existing_it = entries_.find(existing_txid);
        if (existing_it == entries_.end())
        {
          nonce_index_.erase(it);
        }
        else
        {
          if (existing_txid == txid)
          {
            return MempoolAddResult::Accepted;
          }

          const Entry &existing = existing_it->second;

          if (tier == FeeTier::Priority && existing.tier == FeeTier::Standard)
          {
            total_bytes_ -= existing.tx_size;
            entries_.erase(existing_it);
            nonce_index_.erase(it);
            unpersistEntry(existing_txid);
          }
          else if (tier == existing.tier && fee_rate > existing.fee_rate)
          {
            total_bytes_ -= existing.tx_size;
            entries_.erase(existing_it);
            nonce_index_.erase(it);
            unpersistEntry(existing_txid);
          }
          else
          {
            return MempoolAddResult::Rejected_NonceConflict;
          }
        }
      }
    }

    Entry e;
    e.tx = tx;
    e.tier = tier;
    e.fee_rate = fee_rate;
    e.sequence = next_sequence_++;
    e.added_at_ms = nowMs();
    e.tx_size = tx_size;

    if (entries_.size() >= MAX_MEMPOOL_TXS ||
        total_bytes_ + tx_size > MAX_MEMPOOL_BYTES)
    {
      if (!makeRoomFor(e))
      {
        return MempoolAddResult::Rejected_PoolFull;
      }
    }

    uint64_t seq = e.sequence;
    entries_.emplace(txid, std::move(e));
    nonce_index_.emplace(std::move(nk), txid);
    total_bytes_ += tx_size;

    HeapItem item;
    item.tier = tier;
    item.fee_rate = fee_rate;
    item.sequence = seq;
    item.txid = txid;
    heap_.push(item);

    persistEntry(txid, entries_.at(txid));

    return MempoolAddResult::Accepted;
  }

  //  Remove

  bool Mempool::remove(const Crypto::Hash &txid)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = entries_.find(txid);
    if (it == entries_.end())
      return false;

    total_bytes_ -= it->second.tx_size;

    std::string nk = nonceKey(it->second.tx.from, it->second.tx.nonce);
    nonce_index_.erase(nk);

    entries_.erase(it);
    unpersistEntry(txid);
    return true;
  }

  void Mempool::removeIncluded(const std::vector<Crypto::Hash> &txids)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto &txid : txids)
    {
      auto it = entries_.find(txid);
      if (it == entries_.end())
        continue;

      total_bytes_ -= it->second.tx_size;

      std::string nk = nonceKey(it->second.tx.from, it->second.tx.nonce);
      nonce_index_.erase(nk);

      entries_.erase(it);
      unpersistEntry(txid);
    }
  }

  void Mempool::purgeExpired(uint64_t current_height)
  {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<Crypto::Hash> to_remove;

    for (const auto &[txid, entry] : entries_)
    {
      if (entry.tx.valid_until_height != 0 &&
          current_height > entry.tx.valid_until_height)
      {
        to_remove.push_back(txid);
      }
    }

    for (const auto &txid : to_remove)
    {
      auto it = entries_.find(txid);
      if (it == entries_.end())
        continue;

      total_bytes_ -= it->second.tx_size;

      std::string nk = nonceKey(it->second.tx.from, it->second.tx.nonce);
      nonce_index_.erase(nk);

      entries_.erase(it);
      unpersistEntry(txid);
    }
  }

  void Mempool::clear()
  {
    std::lock_guard<std::mutex> lock(mutex_);

    if (db_)
    {
      std::vector<Crypto::Hash> all;
      db_->forEachEntry(
          State::StateDB::TBL_MEMPOOL,
          [&all](const std::vector<uint8_t> &key,
                 const std::vector<uint8_t> & /*value*/)
          {
            if (key.size() == 32)
            {
              Crypto::Hash h;
              std::memcpy(h.data.data(), key.data(), 32);
              all.push_back(h);
            }
            return true;
          });
      unpersistBatch(all);
    }

    entries_.clear();
    nonce_index_.clear();
    total_bytes_ = 0;
    next_sequence_ = 1;

    heap_ = MaxHeap{};
  }

  //  Query

  bool Mempool::contains(const Crypto::Hash &txid) const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.count(txid) > 0;
  }

  std::optional<Transaction> Mempool::get(const Crypto::Hash &txid) const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(txid);
    if (it == entries_.end())
      return std::nullopt;
    return it->second.tx;
  }

  size_t Mempool::size() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
  }

  size_t Mempool::bytes() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_bytes_;
  }

  size_t Mempool::priorityCount() const
  {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto &[txid, entry] : entries_)
    {
      if (entry.tier == FeeTier::Priority)
        ++count;
    }
    return count;
  }

  //  Block selection

  std::vector<Transaction> Mempool::selectForBlock(const StateView &state,
                                                   uint64_t max_block_bytes,
                                                   uint64_t max_block_txs) const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<Transaction> result;
    result.reserve(128);

    const uint64_t priority_cap = max_block_bytes * PRIORITY_BLOCK_SHARE / 100;

    std::unordered_map<Crypto::Address, uint64_t> next_nonce;

    MaxHeap heap = heap_;

    //  Pass 1: priority txs.
    {
      uint64_t bytes_used = 0;
      bool progress = true;

      while (progress &&
             !heap.empty() &&
             result.size() < max_block_txs &&
             bytes_used < priority_cap)
      {

        progress = false;
        MaxHeap deferred;

        while (!heap.empty() &&
               result.size() < max_block_txs &&
               bytes_used < priority_cap)
        {

          if (heap.top().tier != FeeTier::Priority)
          {
            break;
          }

          HeapItem item = heap.top();
          heap.pop();

          auto it = entries_.find(item.txid);
          if (it == entries_.end())
          {
            continue;
          }

          const Entry &entry = it->second;

          if (bytes_used + entry.tx_size > priority_cap)
          {
            continue;
          }

          uint64_t &expected = next_nonce[entry.tx.from];
          if (expected == 0)
          {
            Account acct = state.getAccount(entry.tx.from);
            expected = acct.nonce;
          }

          if (entry.tx.nonce != expected)
          {
            deferred.push(item);
            continue;
          }

          result.push_back(entry.tx);
          bytes_used += entry.tx_size;
          expected = entry.tx.nonce + 1;
          progress = true;
        }

        while (!deferred.empty())
        {
          heap.push(deferred.top());
          deferred.pop();
        }

        if (!heap.empty() && heap.top().tier != FeeTier::Priority)
        {
          break;
        }
      }
    }

    //  Pass 2: standard txs.
    {
      uint64_t bytes_used = 0;
      for (const auto &tx : result)
      {
        bytes_used += tx.serializedSize();
      }

      bool progress = true;

      while (progress &&
             !heap.empty() &&
             result.size() < max_block_txs &&
             bytes_used < max_block_bytes)
      {

        progress = false;
        MaxHeap deferred;

        while (!heap.empty() &&
               result.size() < max_block_txs &&
               bytes_used < max_block_bytes)
        {

          HeapItem item = heap.top();
          heap.pop();

          auto it = entries_.find(item.txid);
          if (it == entries_.end())
          {
            continue;
          }

          const Entry &entry = it->second;

          if (bytes_used + entry.tx_size > max_block_bytes)
          {
            continue;
          }

          uint64_t &expected = next_nonce[entry.tx.from];
          if (expected == 0)
          {
            Account acct = state.getAccount(entry.tx.from);
            expected = acct.nonce;
          }

          if (entry.tx.nonce != expected)
          {
            deferred.push(item);
            continue;
          }

          result.push_back(entry.tx);
          bytes_used += entry.tx_size;
          expected = entry.tx.nonce + 1;
          progress = true;
        }

        while (!deferred.empty())
        {
          heap.push(deferred.top());
          deferred.pop();
        }
      }
    }

    return result;
  }

  //  Eviction

  const Mempool::Entry *Mempool::findLowestPriorityEntry() const
  {
    const Entry *lowest = nullptr;

    for (const auto &[txid, entry] : entries_)
    {
      if (!lowest)
      {
        lowest = &entry;
        continue;
      }

      if (entry.tier != lowest->tier)
      {
        if (entry.tier == FeeTier::Standard)
        {
          lowest = &entry;
        }
        continue;
      }

      if (entry.fee_rate < lowest->fee_rate)
      {
        lowest = &entry;
      }
      else if (entry.fee_rate == lowest->fee_rate &&
               entry.sequence > lowest->sequence)
      {
        lowest = &entry;
      }
    }

    return lowest;
  }

  bool Mempool::makeRoomFor(const Entry &new_entry)
  {
    if (total_bytes_ + new_entry.tx_size > MAX_MEMPOOL_BYTES * 2)
    {
      return false;
    }

    const Entry *victim = findLowestPriorityEntry();
    if (!victim)
    {
      return true;
    }

    bool new_beats_victim = false;
    if (new_entry.tier == FeeTier::Priority &&
        victim->tier == FeeTier::Standard)
    {
      new_beats_victim = true;
    }
    else if (new_entry.tier == victim->tier &&
             new_entry.fee_rate > victim->fee_rate)
    {
      new_beats_victim = true;
    }

    if (!new_beats_victim)
    {
      return false;
    }

    Crypto::Hash victim_txid;
    bool found = false;
    for (const auto &[txid, entry] : entries_)
    {
      if (&entry == victim)
      {
        victim_txid = txid;
        found = true;
        break;
      }
    }

    if (!found)
    {
      return false;
    }

    total_bytes_ -= entries_[victim_txid].tx_size;
    std::string nk = nonceKey(entries_[victim_txid].tx.from,
                              entries_[victim_txid].tx.nonce);
    nonce_index_.erase(nk);
    entries_.erase(victim_txid);
    unpersistEntry(victim_txid);

    return true;
  }

  //  Stats

  Mempool::Stats Mempool::stats() const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    Stats s;
    s.total_txs = entries_.size();
    s.total_bytes = total_bytes_;

    if (entries_.empty())
    {
      return s;
    }

    uint64_t sum_rate = 0;
    uint64_t min_rate = UINT64_MAX;
    uint64_t max_rate = 0;

    for (const auto &[txid, entry] : entries_)
    {
      if (entry.tier == FeeTier::Priority)
      {
        ++s.priority_txs;
      }
      else
      {
        ++s.standard_txs;
      }

      sum_rate += entry.fee_rate;
      if (entry.fee_rate < min_rate)
        min_rate = entry.fee_rate;
      if (entry.fee_rate > max_rate)
        max_rate = entry.fee_rate;
    }

    s.min_fee_rate = min_rate;
    s.max_fee_rate = max_rate;
    s.avg_fee_rate = sum_rate / entries_.size();

    return s;
  }

  //  Add-result counters

  std::array<uint64_t, Mempool::ADD_RESULT_COUNT>
  Mempool::addResultCounts() const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    std::array<uint64_t, ADD_RESULT_COUNT> out{};
    for (size_t i = 0; i < add_result_counts_.size(); ++i)
    {
      out[i] = add_result_counts_[i].load(std::memory_order_relaxed);
    }
    return out;
  }

  std::vector<Mempool::Snapshot> Mempool::snapshot() const
  {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<Snapshot> out;
    out.reserve(entries_.size());

    for (const auto &[txid, entry] : entries_)
    {
      Snapshot s;
      s.txid = txid;
      s.tx = entry.tx;
      s.tier = entry.tier;
      s.fee_rate = entry.fee_rate;
      s.sequence = entry.sequence;
      s.added_at_ms = entry.added_at_ms;
      s.tx_size = entry.tx_size;
      out.push_back(std::move(s));
    }

    return out;
  }
} // namespace Core