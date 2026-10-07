// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Mempool.h"

#include "Crypto/Ed25519.h"
#include "RewardTypes.h"
#include "State/StateDB.h"

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
    // Key = (32-byte address || 8-byte LE nonce).
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
    // Priority txs are ranked by tier, not by an inflated fee rate.
    // The surcharge is accounted for separately by the block processor.
    (void)tier;

    return effective_fee / size;
  }

  //  Entry serialization
  //
  //  Wire format (little-endian):
  //    [4]  tx_size
  //    [N]  tx serialized bytes
  //    [1]  tier
  //    [8]  fee_rate
  //    [8]  sequence
  //    [8]  added_at_ms
  //    [4]  cached tx_size
  //
  //  Total: 33 + N bytes.

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

    // Collect persisted entries under the mutex, then release it
    // before re-adding. `add` takes the mutex again, so we cannot hold
    // it across the re-add loop. This also means we must collect first
    // because the callback runs while StateDB holds its own lock.
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

    // Re-add through the normal validation path. Entries that fail
    // (nonce too low, insufficient funds, expired, already on chain)
    // are silently dropped and their persisted rows are deleted.
    //
    // `add` persists an accepted entry with a fresh sequence number,
    // so a successful re-add leaves the persisted row overwritten with
    // a current version. A failed re-add leaves the stale row, which
    // we delete here.
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
    { // hard cap: 1 MiB per tx
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
    std::lock_guard<std::mutex> lock(mutex_);

    // ---- Validate first ----
    uint64_t fee_rate = 0;
    uint32_t tx_size = 0;
    MempoolAddResult result = validate(tx, state, tier, fee_rate, tx_size);
    if (result != MempoolAddResult::Accepted)
    {
      return result;
    }

    Crypto::Hash txid = tx.txid();

    // ---- Nonce conflict check comes FIRST ----
    //
    // Even if this exact txid isn't in the pool, a different tx with the
    // same (from, nonce) might be. Replacement rules apply:
    //   - Priority tier beats Standard tier
    //   - Within same tier, strictly higher fee rate replaces
    //   - Otherwise, reject with NonceConflict
    //
    // Same txid case (rebroadcast) is treated as idempotent Accept.
    std::string nk = nonceKey(tx.from, tx.nonce);
    {
      auto it = nonce_index_.find(nk);
      if (it != nonce_index_.end())
      {
        Crypto::Hash existing_txid = it->second;
        auto existing_it = entries_.find(existing_txid);
        if (existing_it == entries_.end())
        {
          // Stale index entry — clean it up and proceed.
          nonce_index_.erase(it);
        }
        else
        {
          // Exact same tx already in pool: idempotent accept.
          if (existing_txid == txid)
          {
            return MempoolAddResult::Accepted;
          }

          const Entry &existing = existing_it->second;

          // Priority beats Standard: replace.
          if (tier == FeeTier::Priority && existing.tier == FeeTier::Standard)
          {
            total_bytes_ -= existing.tx_size;
            entries_.erase(existing_it);
            nonce_index_.erase(it);
            unpersistEntry(existing_txid);
          }
          // Same tier, strictly higher fee rate: replace.
          else if (tier == existing.tier && fee_rate > existing.fee_rate)
          {
            total_bytes_ -= existing.tx_size;
            entries_.erase(existing_it);
            nonce_index_.erase(it);
            unpersistEntry(existing_txid);
          }
          // Otherwise: reject with conflict.
          else
          {
            return MempoolAddResult::Rejected_NonceConflict;
          }
        }
      }
    }

    // ---- Build the entry ----
    Entry e;
    e.tx = tx;
    e.tier = tier;
    e.fee_rate = fee_rate;
    e.sequence = next_sequence_++;
    e.added_at_ms = nowMs();
    e.tx_size = tx_size;

    // ---- Pool size check + eviction ----
    if (entries_.size() >= MAX_MEMPOOL_TXS ||
        total_bytes_ + tx_size > MAX_MEMPOOL_BYTES)
    {
      if (!makeRoomFor(e))
      {
        return MempoolAddResult::Rejected_PoolFull;
      }
    }

    // ---- Insert ----
    uint64_t seq = e.sequence;
    entries_.emplace(txid, std::move(e));
    nonce_index_.emplace(std::move(nk), txid);
    total_bytes_ += tx_size;

    // Push onto the selection heap.
    HeapItem item;
    item.tier = tier;
    item.fee_rate = fee_rate;
    item.sequence = seq;
    item.txid = txid;
    heap_.push(item);

    // Write through to persistence.
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

    // Wipe persisted rows. Collect the txids first — the forEachEntry
    // callback runs while StateDB holds its own lock, and rawDel would
    // try to take it again.
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

    // Per-sender next expected nonce. Initialized from state on first sight.
    std::unordered_map<Crypto::Address, uint64_t> next_nonce;

    // Copy the heap so we can pop without mutating the pool.
    MaxHeap heap = heap_;

    // ---- Pass 1: priority txs, up to priority_cap bytes ----
    //
    // Within this pass, we retry skipped txs until no new progress is made.
    // This handles the case where a nonce-2 tx is at the top of the heap
    // but nonce 1 hasn't been processed yet.
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

          // Check tier BEFORE popping so we don't lose the item.
          if (heap.top().tier != FeeTier::Priority)
          {
            break;
          }

          HeapItem item = heap.top();
          heap.pop();

          auto it = entries_.find(item.txid);
          if (it == entries_.end())
          {
            continue; // stale
          }

          const Entry &entry = it->second;

          if (bytes_used + entry.tx_size > priority_cap)
          {
            continue;
          }

          // Nonce ordering.
          uint64_t &expected = next_nonce[entry.tx.from];
          if (expected == 0)
          {
            Account acct = state.getAccount(entry.tx.from);
            expected = acct.nonce;
          }

          if (entry.tx.nonce != expected)
          {
            // Nonce gap — defer to next pass.
            deferred.push(item);
            continue;
          }

          // Select.
          result.push_back(entry.tx);
          bytes_used += entry.tx_size;
          expected = entry.tx.nonce + 1;
          progress = true;
        }

        // Move deferred items back into the heap for the next pass.
        // Any remaining priority items (below the break) also need to
        // stay in the heap.
        while (!deferred.empty())
        {
          heap.push(deferred.top());
          deferred.pop();
        }

        // If we broke out because we hit a standard item, we're done with
        // Pass 1 — the standard items will be handled in Pass 2.
        if (!heap.empty() && heap.top().tier != FeeTier::Priority)
        {
          break;
        }
      }
    }

    // ---- Pass 2: standard txs, filling up to max_block_bytes ----
    //
    // Same retry-until-progress pattern. A tx may be deferred because its
    // nonce isn't the next expected, but a later pass (after the expected
    // tx is selected) will pick it up.
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

        // Move deferred items back for the next pass.
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

      // Priority beats standard.
      if (entry.tier != lowest->tier)
      {
        if (entry.tier == FeeTier::Standard)
        {
          lowest = &entry;
        }
        continue;
      }

      // Same tier: lower fee rate is lower priority.
      if (entry.fee_rate < lowest->fee_rate)
      {
        lowest = &entry;
      }
      // Tie: later sequence is lower priority (FIFO eviction).
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

    // Would the new entry beat the victim?
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

    // Find the victim's txid by scanning entries_ again.
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