// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StateAccess.h"
#include "Keys.h"

#include "Common/Wire.h"
#include "Core/GlobalState.h"
#include "Core/RewardTypes.h"
#include "Core/OrderBook.h"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace State
{

  //  =========================================================================
  //  Little-endian list encoding helpers
  //
  //  Order-expiry lists are stored as a 4-byte count followed by N
  //  8-byte LE IDs. This is specific to the order-expiry index and
  //  isn't a general-purpose format.
  //  =========================================================================

  namespace
  {
    //  Compose the 49-byte book key.
    //
    //    [0..32)  pair_key
    //    [32]     side
    //    [33..41) ~canonical_price (8 BE)
    //    [41..49) sequence (8 BE)
    //
    //  The ~price byte order makes ascending MDBX iteration yield
    //  best-price-first. The sequence byte is big-endian so
    //  lexicographic order equals numeric order.
    void encodeBookKey(const Crypto::Hash &pair_key,
                       uint8_t side,
                       uint64_t canonical_price,
                       uint64_t sequence,
                       uint8_t out[49])
    {
      std::memcpy(out, pair_key.data.data(), 32);
      out[32] = side;

      const uint64_t key_price = (side == 0) ? canonical_price
                                             : ~canonical_price;
      for (int i = 0; i < 8; ++i)
        out[33 + i] = uint8_t(key_price >> ((7 - i) * 8));

      for (int i = 0; i < 8; ++i)
        out[41 + i] = uint8_t(sequence >> ((7 - i) * 8));
    }

    void decodeBookKey(const uint8_t *key,
                       uint64_t &canonical_price_out,
                       uint64_t &sequence_out)
    {
      const uint8_t side = key[32];

      uint64_t stored = 0;
      for (int i = 0; i < 8; ++i)
        stored = (stored << 8) | key[33 + i];

      canonical_price_out = (side == 0) ? stored : ~stored;

      uint64_t seq = 0;
      for (int i = 0; i < 8; ++i)
        seq = (seq << 8) | key[41 + i];
      sequence_out = seq;
    }

    std::vector<uint8_t> encodeU64List(const std::vector<uint64_t> &ids)
    {
      std::vector<uint8_t> out;
      out.reserve(4 + ids.size() * 8);

      uint32_t count = static_cast<uint32_t>(ids.size());
      out.push_back(uint8_t(count));
      out.push_back(uint8_t(count >> 8));
      out.push_back(uint8_t(count >> 16));
      out.push_back(uint8_t(count >> 24));

      for (auto id : ids)
      {
        for (int i = 0; i < 8; ++i)
          out.push_back(uint8_t(id >> (i * 8)));
      }

      return out;
    }

    bool decodeU64List(const std::vector<uint8_t> &bytes,
                       std::vector<uint64_t> &out)
    {
      if (bytes.size() < 4)
        return false;

      uint32_t count = uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) |
                       (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);

      if (bytes.size() != 4 + static_cast<size_t>(count) * 8)
        return false;

      out.clear();
      out.reserve(count);

      for (uint32_t i = 0; i < count; ++i)
      {
        uint64_t id = 0;
        for (int j = 0; j < 8; ++j)
          id |= uint64_t(bytes[4 + i * 8 + j]) << (j * 8);
        out.push_back(id);
      }

      return true;
    }

    //  Fill-history keys. Two shapes, distinguished by a tag byte.
    //
    //    tag 0x01  pair view
    //      [1]  tag
    //      [32] pair_key
    //      [8]  height BE
    //      [4]  tx_index BE
    //      [2]  fill_index BE
    //      total 47 bytes
    //
    //    tag 0x02  order view
    //      [1]  tag
    //      [8]  order_id BE
    //      [8]  height BE
    //      [4]  tx_index BE
    //      [2]  fill_index BE
    //      total 23 bytes

    void encodePairFillKey(const Crypto::Hash &pair_key,
                           uint64_t height,
                           uint32_t tx_index,
                           uint16_t fill_index,
                           uint8_t out[47])
    {
      out[0] = 0x01;
      std::memcpy(out + 1, pair_key.data.data(), 32);
      for (int i = 0; i < 8; ++i)
        out[33 + i] = uint8_t(height >> ((7 - i) * 8));
      for (int i = 0; i < 4; ++i)
        out[41 + i] = uint8_t(tx_index >> ((3 - i) * 8));
      out[45] = uint8_t(fill_index >> 8);
      out[46] = uint8_t(fill_index);
    }

    void encodeOrderFillKey(uint64_t order_id,
                            uint64_t height,
                            uint32_t tx_index,
                            uint16_t fill_index,
                            uint8_t out[23])
    {
      out[0] = 0x02;
      for (int i = 0; i < 8; ++i)
        out[1 + i] = uint8_t(order_id >> ((7 - i) * 8));
      for (int i = 0; i < 8; ++i)
        out[9 + i] = uint8_t(height >> ((7 - i) * 8));
      for (int i = 0; i < 4; ++i)
        out[17 + i] = uint8_t(tx_index >> ((3 - i) * 8));
      out[21] = uint8_t(fill_index >> 8);
      out[22] = uint8_t(fill_index);
    }

    //  Bridge withdrawal height index. Key:
    //
    //    height(8 BE) || withdrawal_id(8 BE)
    //
    //  Big-endian so lexicographic byte order equals numeric order;
    //  this is what makes the ascending prefix scan yield creation
    //  order, and what makes a (from_height) prefix scan correct.

    void encodeBridgeWithdrawalHeightKey(uint64_t height,
                                         uint64_t withdrawal_id,
                                         uint8_t out[16])
    {
      for (int i = 0; i < 8; ++i)
        out[i] = uint8_t(height >> ((7 - i) * 8));
      for (int i = 0; i < 8; ++i)
        out[8 + i] = uint8_t(withdrawal_id >> ((7 - i) * 8));
    }

    //  Bridge-attestation key composition. The full 52-byte key is
    //
    //    [8]  source_chain_id (LE)
    //    [32] source_tx_hash
    //    [4]  source_output_index (LE)
    //    [8]  validator_id (LE)
    //
    //  and the 44-byte prefix (everything except validator_id) is
    //  what the per-deposit range scan seeks.

    std::array<uint8_t, 52> bridgeAttestationKeyImpl(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index,
        uint64_t validator_id)
    {
      std::array<uint8_t, 52> key{};
      for (int i = 0; i < 8; ++i)
        key[i] = uint8_t(source_chain_id >> (i * 8));
      std::memcpy(key.data() + 8, source_tx_hash.data.data(), 32);
      for (int i = 0; i < 4; ++i)
        key[40 + i] = uint8_t(source_output_index >> (i * 8));
      for (int i = 0; i < 8; ++i)
        key[44 + i] = uint8_t(validator_id >> (i * 8));
      return key;
    }

    std::array<uint8_t, 44> bridgeAttestationPrefixImpl(
        uint64_t source_chain_id,
        const Crypto::Hash &source_tx_hash,
        uint32_t source_output_index)
    {
      std::array<uint8_t, 44> prefix{};
      for (int i = 0; i < 8; ++i)
        prefix[i] = uint8_t(source_chain_id >> (i * 8));
      std::memcpy(prefix.data() + 8, source_tx_hash.data.data(), 32);
      for (int i = 0; i < 4; ++i)
        prefix[40 + i] = uint8_t(source_output_index >> (i * 8));
      return prefix;
    }

    //  Bridge ack-attestation key composition. The full 16-byte key is
    //
    //    [8]  withdrawal_id (LE)
    //    [8]  validator_id (LE)
    //
    //  and the 8-byte prefix (withdrawal_id) is what the
    //  per-withdrawal range scan seeks.

    std::array<uint8_t, 16> bridgeAckAttestationKeyImpl(
        uint64_t withdrawal_id,
        uint64_t validator_id)
    {
      std::array<uint8_t, 16> key{};
      for (int i = 0; i < 8; ++i)
        key[i] = uint8_t(withdrawal_id >> (i * 8));
      for (int i = 0; i < 8; ++i)
        key[8 + i] = uint8_t(validator_id >> (i * 8));
      return key;
    }

    std::array<uint8_t, 8> bridgeAckAttestationPrefixImpl(
        uint64_t withdrawal_id)
    {
      std::array<uint8_t, 8> prefix{};
      for (int i = 0; i < 8; ++i)
        prefix[i] = uint8_t(withdrawal_id >> (i * 8));
      return prefix;
    }
  } // anonymous namespace

  //  =========================================================================
  //  Construction
  //  =========================================================================

  StateAccess::StateAccess(StateDB &db, uint64_t version)
      : db_(db), txn_(nullptr), version_(version), smt_(db)
  {
    //  Autocommit mode. Hold one read txn for the lifetime of this
    //  StateAccess and bind it into the SMT. Reads below route
    //  through it, so a 256-level SMT walk is one reader slot, not
    //  256.
    //
    //  Writes below must release this read txn before opening their
    //  own write txn. See releaseReadTxnIfHeld().
    read_txn_ = std::make_unique<StateDB::ReadTxn>(db.beginRead());
    smt_.setReadTxn(read_txn_.get());
    smt_.load();
  }

  StateAccess::StateAccess(StateDB &db, StateDB::Txn &txn, uint64_t version)
      : db_(db), txn_(&txn), version_(version), smt_(db)
  {
    //  Txn-bound mode. No read txn is opened: the write txn serves
    //  both roles, and mixing a read txn with a write txn on the
    //  same thread would defeat the write txn's visibility into its
    //  own uncommitted writes.
    smt_.setTxn(txn_);
    smt_.load();
  }

  //  =========================================================================
  //  Read dispatch helpers
  //
  //  Three-layer fallback for reads:
  //    1. bound write txn  (txn_)       — sees uncommitted writes
  //    2. bound read txn   (read_txn_)  — the normal autocommit path
  //    3. raw DB access    (db_)        — safety net; db_ internally
  //                                        reuses tls_read_txn_ if
  //                                        a read txn is open on
  //                                        this thread
  //
  //  Layer 1 wins when present, because a write txn that has just
  //  written a value must see that value on the next read.
  //  =========================================================================

  bool StateAccess::readRow(uint32_t table_id,
                            const void *key, size_t key_len,
                            std::vector<uint8_t> &out) const
  {
    if (txn_)
      return txn_->get(table_id, key, key_len, out);
    if (read_txn_)
      return read_txn_->get(table_id, key, key_len, out);
    return db_.rawGet(table_id, key, key_len, out);
  }

  void StateAccess::readForEach(uint32_t table_id,
                                const StateDB::EntryVisitor &visitor) const
  {
    if (txn_)
    {
      txn_->forEach(table_id, visitor);
      return;
    }
    if (read_txn_)
    {
      read_txn_->forEach(table_id, visitor);
      return;
    }
    db_.forEachEntry(table_id, visitor);
  }

  void StateAccess::readForEachWithPrefix(
      uint32_t table_id,
      const std::vector<uint8_t> &prefix,
      const StateDB::EntryVisitor &visitor) const
  {
    if (txn_)
    {
      txn_->forEachWithPrefix(table_id, prefix, visitor);
      return;
    }
    if (read_txn_)
    {
      read_txn_->forEachWithPrefix(table_id, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefix(table_id, prefix, visitor);
  }

  void StateAccess::readForEachReverse(
      uint32_t table_id,
      const StateDB::EntryVisitor &visitor) const
  {
    if (txn_)
    {
      txn_->forEachReverse(table_id, visitor);
      return;
    }
    if (read_txn_)
    {
      read_txn_->forEachReverse(table_id, visitor);
      return;
    }
    db_.forEachEntryReverse(table_id, visitor);
  }

  void StateAccess::readForEachWithPrefixReverse(
      uint32_t table_id,
      const std::vector<uint8_t> &prefix,
      const StateDB::EntryVisitor &visitor) const
  {
    if (txn_)
    {
      txn_->forEachWithPrefixReverse(table_id, prefix, visitor);
      return;
    }
    if (read_txn_)
    {
      read_txn_->forEachWithPrefixReverse(table_id, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefixReverse(table_id, prefix, visitor);
  }

  void StateAccess::readForEachFromKey(
      uint32_t table_id,
      const std::vector<uint8_t> &seek_key,
      const StateDB::EntryVisitor &visitor) const
  {
    if (txn_)
    {
      txn_->forEachFromKey(table_id, seek_key, visitor);
      return;
    }
    if (read_txn_)
    {
      read_txn_->forEachFromKey(table_id, seek_key, visitor);
      return;
    }
    db_.forEachEntryFromKey(table_id, seek_key, visitor);
  }

  size_t StateAccess::readTableCount(uint32_t table_id) const
  {
    if (txn_)
      return 0; // write txns can't stat; callers don't use this path
    if (read_txn_)
      return read_txn_->dbiStat(table_id);
    return db_.entryCount(table_id);
  }

  //  =========================================================================
  //  Read txn release
  //  =========================================================================

  void StateAccess::releaseReadTxnIfHeld()
  {
    if (read_txn_)
    {
      smt_.setReadTxn(nullptr);
      read_txn_.reset();
    }
  }

  //  =========================================================================
  //  Low-level index primitives
  //  =========================================================================

  void StateAccess::putSentinel(uint32_t table_id,
                                const void *key, size_t key_len)
  {
    static const uint8_t SENTINEL[1] = {0x01};

    if (txn_)
    {
      txn_->put(table_id, key, key_len, SENTINEL, sizeof(SENTINEL));
      return;
    }

    releaseReadTxnIfHeld();
    db_.rawPut(table_id, key, key_len, SENTINEL, sizeof(SENTINEL));
  }

  void StateAccess::putU64Row(uint32_t table_id,
                              const void *key, size_t key_len,
                              uint64_t value)
  {
    uint8_t buf[8];
    Common::writeU64(buf, value);

    if (txn_)
    {
      txn_->put(table_id, key, key_len, buf, sizeof(buf));
      return;
    }

    releaseReadTxnIfHeld();
    db_.rawPut(table_id, key, key_len, buf, sizeof(buf));
  }

  void StateAccess::putBlobRow(uint32_t table_id,
                               const void *key, size_t key_len,
                               const void *value, size_t value_len)
  {
    if (txn_)
    {
      txn_->put(table_id, key, key_len, value, value_len);
      return;
    }

    releaseReadTxnIfHeld();
    db_.rawPut(table_id, key, key_len, value, value_len);
  }

  void StateAccess::deleteRow(uint32_t table_id,
                              const void *key, size_t key_len)
  {
    if (txn_)
    {
      txn_->del(table_id, key, key_len);
      return;
    }

    releaseReadTxnIfHeld();
    db_.rawDel(table_id, key, key_len);
  }

  //  =========================================================================
  //  Index writers — one per entity type
  //  =========================================================================

  void StateAccess::indexAccountRow(const Crypto::Address &address)
  {
    Core::Account acct = getAccount(address);
    auto bytes = acct.serializeState();
    putBlobRow(StateDB::TBL_ACCOUNTS,
               address.data.data(), address.data.size(),
               bytes.data(), bytes.size());
  }

  void StateAccess::unindexAccountRow(const Crypto::Address &address)
  {
    deleteRow(StateDB::TBL_ACCOUNTS,
              address.data.data(), address.data.size());
  }

  void StateAccess::indexTokenRow(Id token_id)
  {
    Core::TokenInfo token;
    if (!getToken(token_id, token))
      return;
    auto bytes = token.serializeState();
    uint8_t key[4];
    Common::writeU32(key, static_cast<uint32_t>(token_id));
    putBlobRow(StateDB::TBL_TOKENS, key, sizeof(key),
               bytes.data(), bytes.size());
  }

  void StateAccess::unindexTokenRow(Id token_id)
  {
    uint8_t key[4];
    Common::writeU32(key, static_cast<uint32_t>(token_id));
    deleteRow(StateDB::TBL_TOKENS, key, sizeof(key));
  }

  void StateAccess::indexTokenBalanceRow(const Crypto::Address &address,
                                         Id token_id,
                                         uint64_t balance)
  {
    uint8_t key_by_owner[36];
    std::memcpy(key_by_owner, address.data.data(), 32);
    Common::writeU32(key_by_owner + 32, static_cast<uint32_t>(token_id));
    putU64Row(StateDB::TBL_TOKEN_BALANCES,
              key_by_owner, sizeof(key_by_owner), balance);

    uint8_t key_by_token[36];
    Common::writeU32(key_by_token, static_cast<uint32_t>(token_id));
    std::memcpy(key_by_token + 4, address.data.data(), 32);
    putU64Row(StateDB::TBL_INDEX_BALANCES_BY_TOKEN,
              key_by_token, sizeof(key_by_token), balance);
  }

  void StateAccess::unindexTokenBalanceRow(const Crypto::Address &address,
                                           Id token_id)
  {
    uint8_t key_by_owner[36];
    std::memcpy(key_by_owner, address.data.data(), 32);
    Common::writeU32(key_by_owner + 32, static_cast<uint32_t>(token_id));
    deleteRow(StateDB::TBL_TOKEN_BALANCES,
              key_by_owner, sizeof(key_by_owner));

    uint8_t key_by_token[36];
    Common::writeU32(key_by_token, static_cast<uint32_t>(token_id));
    std::memcpy(key_by_token + 4, address.data.data(), 32);
    deleteRow(StateDB::TBL_INDEX_BALANCES_BY_TOKEN,
              key_by_token, sizeof(key_by_token));
  }

  void StateAccess::indexAmmPoolRow(Id pool_id, Id token_a, Id token_b)
  {
    Core::AmmPool pool;
    if (!getAmmPool(pool_id, pool))
      return;

    auto bytes = pool.serializeState();
    uint8_t key[8];
    Common::writeU64(key, pool_id);
    putBlobRow(StateDB::TBL_AMM_POOLS, key, sizeof(key),
               bytes.data(), bytes.size());

    uint8_t key_a[12];
    Common::writeU32(key_a, static_cast<uint32_t>(token_a));
    Common::writeU64(key_a + 4, pool_id);
    putSentinel(StateDB::TBL_INDEX_POOLS_BY_TOKEN, key_a, sizeof(key_a));

    uint8_t key_b[12];
    Common::writeU32(key_b, static_cast<uint32_t>(token_b));
    Common::writeU64(key_b + 4, pool_id);
    putSentinel(StateDB::TBL_INDEX_POOLS_BY_TOKEN, key_b, sizeof(key_b));
  }

  void StateAccess::unindexAmmPoolRow(Id pool_id, Id token_a, Id token_b)
  {
    uint8_t key[8];
    Common::writeU64(key, pool_id);
    deleteRow(StateDB::TBL_AMM_POOLS, key, sizeof(key));

    uint8_t key_a[12];
    Common::writeU32(key_a, static_cast<uint32_t>(token_a));
    Common::writeU64(key_a + 4, pool_id);
    deleteRow(StateDB::TBL_INDEX_POOLS_BY_TOKEN, key_a, sizeof(key_a));

    uint8_t key_b[12];
    Common::writeU32(key_b, static_cast<uint32_t>(token_b));
    Common::writeU64(key_b + 4, pool_id);
    deleteRow(StateDB::TBL_INDEX_POOLS_BY_TOKEN, key_b, sizeof(key_b));
  }

  void StateAccess::indexAmmPositionRow(Id position_id,
                                        const Crypto::Address &owner)
  {
    Core::AmmPosition pos;
    if (!getAmmPosition(position_id, pos))
      return;

    auto bytes = pos.serializeState();
    uint8_t key[8];
    Common::writeU64(key, position_id);
    putBlobRow(StateDB::TBL_AMM_POSITIONS, key, sizeof(key),
               bytes.data(), bytes.size());

    uint8_t owner_key[40];
    std::memcpy(owner_key, owner.data.data(), 32);
    Common::writeU64(owner_key + 32, position_id);
    putU64Row(StateDB::TBL_INDEX_POSITIONS_BY_OWNER,
              owner_key, sizeof(owner_key), pos.pool_id);
  }

  void StateAccess::unindexAmmPositionRow(Id position_id,
                                          const Crypto::Address &owner)
  {
    uint8_t key[8];
    Common::writeU64(key, position_id);
    deleteRow(StateDB::TBL_AMM_POSITIONS, key, sizeof(key));

    uint8_t owner_key[40];
    std::memcpy(owner_key, owner.data.data(), 32);
    Common::writeU64(owner_key + 32, position_id);
    deleteRow(StateDB::TBL_INDEX_POSITIONS_BY_OWNER,
              owner_key, sizeof(owner_key));
  }

  void StateAccess::indexOrderRow(Id order_id,
                                  const Crypto::Address &owner,
                                  Id sell_token, Id buy_token)
  {
    Core::Order order;
    if (!getOrder(order_id, order))
      return;

    auto bytes = order.serializeState();
    uint8_t key[8];
    Common::writeU64(key, order_id);
    putBlobRow(StateDB::TBL_ORDERS, key, sizeof(key),
               bytes.data(), bytes.size());

    uint8_t owner_key[40];
    std::memcpy(owner_key, owner.data.data(), 32);
    Common::writeU64(owner_key + 32, order_id);
    putSentinel(StateDB::TBL_INDEX_ORDERS_BY_OWNER,
                owner_key, sizeof(owner_key));

    uint8_t pair_key[16];
    Common::writeU32(pair_key, static_cast<uint32_t>(sell_token));
    Common::writeU32(pair_key + 4, static_cast<uint32_t>(buy_token));
    Common::writeU64(pair_key + 8, order_id);
    putSentinel(StateDB::TBL_INDEX_ORDERS_BY_PAIR,
                pair_key, sizeof(pair_key));
  }

  void StateAccess::unindexOrderRow(Id order_id,
                                    const Crypto::Address &owner,
                                    Id sell_token, Id buy_token)
  {
    uint8_t key[8];
    Common::writeU64(key, order_id);
    deleteRow(StateDB::TBL_ORDERS, key, sizeof(key));

    uint8_t owner_key[40];
    std::memcpy(owner_key, owner.data.data(), 32);
    Common::writeU64(owner_key + 32, order_id);
    deleteRow(StateDB::TBL_INDEX_ORDERS_BY_OWNER,
              owner_key, sizeof(owner_key));

    uint8_t pair_key[16];
    Common::writeU32(pair_key, static_cast<uint32_t>(sell_token));
    Common::writeU32(pair_key + 4, static_cast<uint32_t>(buy_token));
    Common::writeU64(pair_key + 8, order_id);
    deleteRow(StateDB::TBL_INDEX_ORDERS_BY_PAIR,
              pair_key, sizeof(pair_key));
  }

  void StateAccess::indexOrderPoolRows(const Core::Order &order)
  {
    std::unordered_set<uint32_t> pools;
    for (uint8_t i = 0; i < order.condition_count; ++i)
    {
      const auto &c = order.conditions[i];
      if (c.type == Core::OrderConditionType::PriceAbove ||
          c.type == Core::OrderConditionType::PriceBelow ||
          c.type == Core::OrderConditionType::VolumeBelow)
      {
        pools.insert(c.param2);
      }
    }

    for (uint32_t pool_id : pools)
    {
      uint8_t key[12];
      Common::writeU32(key, pool_id);
      Common::writeU64(key + 4, order.id);
      putSentinel(StateDB::TBL_INDEX_ORDERS_BY_POOL, key, sizeof(key));
    }
  }

  void StateAccess::unindexOrderPoolRows(const Core::Order &order)
  {
    std::unordered_set<uint32_t> pools;
    for (uint8_t i = 0; i < order.condition_count; ++i)
    {
      const auto &c = order.conditions[i];
      if (c.type == Core::OrderConditionType::PriceAbove ||
          c.type == Core::OrderConditionType::PriceBelow ||
          c.type == Core::OrderConditionType::VolumeBelow)
      {
        pools.insert(c.param2);
      }
    }

    for (uint32_t pool_id : pools)
    {
      uint8_t key[12];
      Common::writeU32(key, pool_id);
      Common::writeU64(key + 4, order.id);
      deleteRow(StateDB::TBL_INDEX_ORDERS_BY_POOL, key, sizeof(key));
    }
  }

  //  =========================================================================
  //  Transaction and block indexes
  //  =========================================================================

  void StateAccess::indexTransaction(
      const Crypto::Hash &txid,
      uint64_t block_height,
      uint32_t tx_index_in_block,
      const std::vector<Crypto::Address> &addresses,
      const std::vector<Id> &token_ids,
      uint8_t tx_type)
  {
    for (const auto &addr : addresses)
    {
      if (addr.isNull())
        continue;

      uint8_t key[44];
      std::memcpy(key, addr.data.data(), 32);
      Common::writeU64BE(key + 32, block_height);
      Common::writeU32BE(key + 40, tx_index_in_block);
      putBlobRow(StateDB::TBL_INDEX_TX_BY_ADDRESS,
                 key, sizeof(key),
                 txid.data.data(), txid.data.size());
    }

    for (Id token_id : token_ids)
    {
      uint8_t key[16];
      Common::writeU32(key, static_cast<uint32_t>(token_id));
      Common::writeU64BE(key + 4, block_height);
      Common::writeU32BE(key + 12, tx_index_in_block);
      putBlobRow(StateDB::TBL_INDEX_TX_BY_TOKEN,
                 key, sizeof(key),
                 txid.data.data(), txid.data.size());
    }

    uint8_t type_key[13];
    type_key[0] = tx_type;
    Common::writeU64BE(type_key + 1, block_height);
    Common::writeU32BE(type_key + 9, tx_index_in_block);
    putBlobRow(StateDB::TBL_INDEX_TX_BY_TYPE,
               type_key, sizeof(type_key),
               txid.data.data(), txid.data.size());
  }

  void StateAccess::indexBlockProducer(const Crypto::Address &proposer,
                                       uint64_t block_height,
                                       const Crypto::Hash &block_hash)
  {
    if (proposer.isNull())
      return;

    uint8_t key[40];
    std::memcpy(key, proposer.data.data(), 32);
    Common::writeU64BE(key + 32, block_height);
    putBlobRow(StateDB::TBL_INDEX_BLOCKS_BY_PRODUCER,
               key, sizeof(key),
               block_hash.data.data(), block_hash.data.size());
  }

  //  =========================================================================
  //  Accounts
  //  =========================================================================

  Core::Account StateAccess::getAccount(const Crypto::Address &address) const
  {
    Core::Account result;

    Crypto::Hash key = Keys::account(address);
    auto value = smt_.get(key);
    if (!value.has_value())
      return result;

    Core::Account::deserializeState(value->data(), value->size(), result);
    return result;
  }

  bool StateAccess::accountExists(const Crypto::Address &address) const
  {
    Crypto::Hash key = Keys::account(address);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;

    Core::Account acct;
    if (!Core::Account::deserializeState(value->data(), value->size(), acct))
    {
      return false;
    }
    return !acct.isEmpty();
  }

  void StateAccess::putAccount(const Crypto::Address &address,
                               const Core::Account &account)
  {
    Core::Account copy = account;
    copy.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);

    Core::Account old = getAccount(address);

    const bool was_staker = (old.staked > 0);
    const bool is_staker = (copy.staked > 0);

    //  ---- Update staker_since_height based on the transition ----
    if (is_staker && !was_staker)
    {
      copy.staker_since_height = version_;
    }
    else if (!is_staker && was_staker)
    {
      copy.staker_since_height = 0;
    }
    else if (is_staker && was_staker)
    {
      copy.staker_since_height = old.staker_since_height;
    }
    else
    {
      copy.staker_since_height = 0;
    }

    //  ---- Release read txn before any writes ----
    releaseReadTxnIfHeld();

    //  ---- Write the account record ----
    Crypto::Hash key = Keys::account(address);
    auto value = copy.serializeState();
    smt_.update(key, value, version_);

    //  ---- Write the index row ----
    {
      auto bytes = copy.serializeState();
      putBlobRow(StateDB::TBL_ACCOUNTS,
                 address.data.data(), address.data.size(),
                 bytes.data(), bytes.size());
    }

    //  ---- Native balance by-token index ----
    //
    //  The native token (id 0) lives in Account.balance, not in the
    //  SMT as a tokenBalance entry. But getTokenHolders(0) and
    //  getTokensForAddress(0) both route through
    //  TBL_INDEX_BALANCES_BY_TOKEN, so without this block the
    //  native token has no holders in the by-token index.
    if (copy.balance != old.balance)
    {
      if (copy.balance == 0)
        unindexTokenBalanceRow(address, NATIVE_TOKEN_ID);
      else
        indexTokenBalanceRow(address, NATIVE_TOKEN_ID, copy.balance);
    }

    //  Helper lambdas for globals.
    auto readGlobalU64 = [this](const char *name) -> uint64_t
    {
      std::vector<uint8_t> bytes;
      if (!getGlobal(name, bytes) || bytes.size() != 8)
        return 0;
      return Common::readU64(bytes.data());
    };

    auto writeGlobalU64 = [this](const char *name, uint64_t v)
    {
      std::vector<uint8_t> bytes(8);
      Common::writeU64(bytes.data(), v);
      putGlobal(name, bytes);
    };

    //  ---- Maintain total_staked ----
    if (copy.staked != old.staked)
    {
      uint64_t total = readGlobalU64("total_staked");

      if (copy.staked >= old.staked)
        total += copy.staked - old.staked;
      else
        total -= (old.staked - copy.staked);

      writeGlobalU64("total_staked", total);
    }

    //  ---- Maintain the staker index and staker_count ----
    if (is_staker && !was_staker)
    {
      indexStaker(address);
      writeGlobalU64("staker_count", readGlobalU64("staker_count") + 1);
    }
    else if (!is_staker && was_staker)
    {
      unindexStaker(address);
      uint64_t count = readGlobalU64("staker_count");
      if (count > 0)
        --count;
      writeGlobalU64("staker_count", count);
    }
  }

  void StateAccess::deleteAccount(const Crypto::Address &address)
  {
    Core::Account old = getAccount(address);
    const bool was_staker = (old.staked > 0);

    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::account(address);
    smt_.remove(key, version_);

    unindexAccountRow(address);
    unindexTokenBalanceRow(address, NATIVE_TOKEN_ID);

    if (!was_staker)
      return;

    auto readGlobalU64 = [this](const char *name) -> uint64_t
    {
      std::vector<uint8_t> bytes;
      if (!getGlobal(name, bytes) || bytes.size() != 8)
        return 0;
      return Common::readU64(bytes.data());
    };

    auto writeGlobalU64 = [this](const char *name, uint64_t v)
    {
      std::vector<uint8_t> bytes(8);
      Common::writeU64(bytes.data(), v);
      putGlobal(name, bytes);
    };

    unindexStaker(address);

    uint64_t total = readGlobalU64("total_staked");
    if (total >= old.staked)
      total -= old.staked;
    else
      total = 0;
    writeGlobalU64("total_staked", total);

    uint64_t count = readGlobalU64("staker_count");
    if (count > 0)
      --count;
    writeGlobalU64("staker_count", count);
  }

  void StateAccess::forEachAccount(
      const std::function<void(const Crypto::Address &, const Core::Account &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 32)
        return true;
      Crypto::Address addr;
      std::memcpy(addr.data.data(), key.data(), 32);

      Core::Account acct;
      if (!Core::Account::deserializeState(value.data(), value.size(), acct))
        return true;

      fn(addr, acct);
      return true;
    };

    readForEach(StateDB::TBL_ACCOUNTS, visitor);
  }

  //  =========================================================================
  //  Token balances
  //  =========================================================================

  uint64_t StateAccess::getTokenBalance(const Crypto::Address &address, Id token_id) const
  {
    Crypto::Hash key = Keys::tokenBalance(address, token_id);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return 0;

    return Common::readU64(value->data());
  }

  void StateAccess::putTokenBalance(const Crypto::Address &address, Id token_id, uint64_t balance)
  {
    Crypto::Hash key = Keys::tokenBalance(address, token_id);

    releaseReadTxnIfHeld();

    if (balance == 0)
    {
      smt_.remove(key, version_);
      unindexTokenBalanceRow(address, token_id);
      return;
    }

    std::vector<uint8_t> value(8);
    Common::writeU64(value.data(), balance);
    smt_.update(key, value, version_);

    indexTokenBalanceRow(address, token_id, balance);
  }

  void StateAccess::deleteTokenBalance(const Crypto::Address &address, Id token_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::tokenBalance(address, token_id);
    smt_.remove(key, version_);
    unindexTokenBalanceRow(address, token_id);
  }

  void StateAccess::forEachTokenBalanceForOwner(
      const Crypto::Address &owner,
      const std::function<void(Id token_id, uint64_t balance)> &fn) const
  {
    std::vector<uint8_t> prefix(owner.data.begin(), owner.data.end());

    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 36 || value.size() != 8)
        return true;
      Id token_id = Common::readU32(key.data() + 32);
      uint64_t balance = Common::readU64(value.data());
      fn(token_id, balance);
      return true;
    };

    readForEachWithPrefix(StateDB::TBL_TOKEN_BALANCES, prefix, visitor);
  }

  void StateAccess::forEachHolderOfToken(
      Id token_id,
      const std::function<bool(const Crypto::Address &, uint64_t balance)> &fn) const
  {
    uint8_t prefix_bytes[4];
    Common::writeU32(prefix_bytes, static_cast<uint32_t>(token_id));
    std::vector<uint8_t> prefix(prefix_bytes, prefix_bytes + 4);

    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 36 || value.size() != 8)
        return true;
      Crypto::Address addr;
      std::memcpy(addr.data.data(), key.data() + 4, 32);
      uint64_t balance = Common::readU64(value.data());
      return fn(addr, balance);
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_BALANCES_BY_TOKEN, prefix, visitor);
  }

  //  =========================================================================
  //  Token metadata
  //  =========================================================================

  bool StateAccess::getToken(Id token_id, Core::TokenInfo &out) const
  {
    Crypto::Hash key = Keys::token(token_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::TokenInfo::deserializeState(value->data(), value->size(), out);
  }

  void StateAccess::putToken(const Core::TokenInfo &token)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::token(token.id);
    auto value = token.serializeState();
    smt_.update(key, value, version_);

    indexTokenRow(token.id);
  }

  void StateAccess::forEachToken(
      const std::function<void(const Core::TokenInfo &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 4)
        return true;

      Core::TokenInfo token;
      if (!Core::TokenInfo::deserializeState(value.data(), value.size(), token))
        return true;

      fn(token);
      return true;
    };

    readForEach(StateDB::TBL_TOKENS, visitor);
  }

  //  =========================================================================
  //  Token supply
  //  =========================================================================

  uint64_t StateAccess::getTokenSupply(Id token_id) const
  {
    Crypto::Hash key = Keys::tokenSupply(token_id);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return 0;

    return Common::readU64(value->data());
  }

  void StateAccess::putTokenSupply(Id token_id, uint64_t supply)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::tokenSupply(token_id);

    if (supply == 0)
    {
      smt_.remove(key, version_);
      return;
    }

    std::vector<uint8_t> value(8);
    Common::writeU64(value.data(), supply);
    smt_.update(key, value, version_);
  }

  //  =========================================================================
  //  Validators
  //  =========================================================================

  bool StateAccess::getValidator(uint64_t validator_id, Core::ValidatorInfo &out) const
  {
    Crypto::Hash key = Keys::validator(validator_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::ValidatorInfo::deserializeState(value->data(), value->size(), out);
  }

  void StateAccess::putValidator(const Core::ValidatorInfo &validator)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::validator(validator.id);
    auto value = validator.serializeState();
    smt_.update(key, value, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, validator.id);

    putSentinel(StateDB::TBL_INDEX_VALIDATORS, id_key, sizeof(id_key));
    putBlobRow(StateDB::TBL_VALIDATORS, id_key, sizeof(id_key),
               value.data(), value.size());
  }

  void StateAccess::deleteValidator(uint64_t validator_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::validator(validator_id);
    smt_.remove(key, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, validator_id);

    deleteRow(StateDB::TBL_INDEX_VALIDATORS, id_key, sizeof(id_key));
    deleteRow(StateDB::TBL_VALIDATORS, id_key, sizeof(id_key));
  }

  void StateAccess::forEachValidator(
      const std::function<void(const Core::ValidatorInfo &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 8)
        return true;

      Core::ValidatorInfo v;
      if (!Core::ValidatorInfo::deserializeState(value.data(), value.size(), v))
        return true;

      fn(v);
      return true;
    };

    readForEach(StateDB::TBL_VALIDATORS, visitor);
  }

  //  =========================================================================
  //  Active validator set (bridge operational signer set)
  //
  //  Under the validator-is-watcher model, the bridge's operational
  //  signer set for every registered source chain is the active
  //  validator set. There is no separate watcher record, no per-chain
  //  scope, no separate stake.
  //
  //  The `active_set` global is written by the genesis writer (seed
  //  validators) and by the rotation logic in BlockProcessor. It is
  //  a packed list of little-endian uint64 validator ids, 8 bytes
  //  each.
  //
  //  forEachActiveValidator yields the ValidatorInfo record for
  //  each id in the set that is present in state and marked
  //  is_active. The two filters (present, is_active) are defensive:
  //  a record can be absent if it was deleted while still in the
  //  set (shouldn't happen on a healthy chain, but the alternative
  //  is a crash), and a record can be is_active=false if it's in
  //  the set but pending unbond (a transient state the rotation
  //  logic will correct at the next epoch).
  //
  //  countActiveValidators yields the same count, computed with the
  //  same filters, so callers can check "is the set big enough for
  //  this chain's active_validator_min" without materializing the
  //  records.
  //  =========================================================================

  void StateAccess::forEachActiveValidator(
      const std::function<void(const Core::ValidatorInfo &)> &fn) const
  {
    std::vector<uint8_t> set_bytes;
    if (!getGlobal("active_set", set_bytes))
      return;

    const size_t count = set_bytes.size() / 8;
    for (size_t i = 0; i < count; ++i)
    {
      uint64_t vid = 0;
      for (int j = 0; j < 8; ++j)
        vid |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);

      Core::ValidatorInfo v;
      if (!getValidator(vid, v))
        continue;
      if (!v.is_active)
        continue;

      fn(v);
    }
  }

  size_t StateAccess::countActiveValidators() const
  {
    std::vector<uint8_t> set_bytes;
    if (!getGlobal("active_set", set_bytes))
      return 0;

    const size_t count = set_bytes.size() / 8;
    size_t active = 0;
    for (size_t i = 0; i < count; ++i)
    {
      uint64_t vid = 0;
      for (int j = 0; j < 8; ++j)
        vid |= uint64_t(set_bytes[i * 8 + j]) << (j * 8);

      Core::ValidatorInfo v;
      if (!getValidator(vid, v))
        continue;
      if (!v.is_active)
        continue;
      ++active;
    }
    return active;
  }

  //  =========================================================================
  //  Validator by address
  //  =========================================================================

  bool StateAccess::getValidatorByAddress(const Crypto::Address &address,
                                          uint64_t &validator_id_out) const
  {
    Crypto::Hash key = Keys::validatorByAddress(address);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return false;

    validator_id_out = Common::readU64(value->data());
    return true;
  }

  void StateAccess::putValidatorByAddress(const Crypto::Address &address,
                                          uint64_t validator_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::validatorByAddress(address);
    std::vector<uint8_t> value(8);
    Common::writeU64(value.data(), validator_id);
    smt_.update(key, value, version_);
  }

  void StateAccess::deleteValidatorByAddress(const Crypto::Address &address)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::validatorByAddress(address);
    smt_.remove(key, version_);
  }

  //  =========================================================================
  //  Validator consensus-key history
  //  =========================================================================

  bool StateAccess::getValidatorKeyHistory(
      uint64_t validator_id,
      std::vector<Core::KeyRotation> &out) const
  {
    out.clear();

    Crypto::Hash key = Keys::validatorKeyHistory(validator_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;

    return Core::decodeKeyHistory(value->data(), value->size(), out);
  }

  void StateAccess::putValidatorKeyHistory(
      uint64_t validator_id,
      const std::vector<Core::KeyRotation> &history)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::validatorKeyHistory(validator_id);

    if (history.empty())
    {
      smt_.remove(key, version_);
      return;
    }

    auto value = Core::encodeKeyHistory(history);
    smt_.update(key, value, version_);
  }

  std::optional<Crypto::PublicKey> StateAccess::validatorKeyAtHeight(
      uint64_t validator_id, uint64_t height) const
  {
    std::vector<Core::KeyRotation> history;
    if (!getValidatorKeyHistory(validator_id, history))
    {
      Core::ValidatorInfo v;
      if (!getValidator(validator_id, v))
        return std::nullopt;
      return v.effectiveConsensusKey();
    }

    if (history.size() == 1 &&
        history[0].valid_until_height == 0 &&
        height >= history[0].valid_from_height)
    {
      return history[0].key;
    }

    for (const auto &entry : history)
    {
      if (height < entry.valid_from_height)
        continue;
      if (entry.valid_until_height != 0 &&
          height >= entry.valid_until_height)
        continue;
      return entry.key;
    }

    return std::nullopt;
  }

  //  =========================================================================
  //  NFTs
  //  =========================================================================

  bool StateAccess::getNft(uint64_t nft_id, Core::NftInfo &out) const
  {
    Crypto::Hash key = Keys::nft(nft_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::NftInfo::deserializeState(value->data(), value->size(), out);
  }

  void StateAccess::putNft(const Core::NftInfo &nft)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::nft(nft.id);
    auto value = nft.serializeState();
    smt_.update(key, value, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, nft.id);
    putBlobRow(StateDB::TBL_NFTS, id_key, sizeof(id_key),
               value.data(), value.size());

    uint8_t owner_key[40];
    std::memcpy(owner_key, nft.owner.data.data(), 32);
    Common::writeU64(owner_key + 32, nft.id);
    putSentinel(StateDB::TBL_INDEX_NFTS_BY_OWNER,
                owner_key, sizeof(owner_key));

    if (nft.collection_id != 0)
    {
      uint8_t coll_key[16];
      Common::writeU64(coll_key, nft.collection_id);
      Common::writeU64(coll_key + 8, nft.id);
      putSentinel(StateDB::TBL_INDEX_NFTS_BY_COLLECTION,
                  coll_key, sizeof(coll_key));
    }
  }

  void StateAccess::unindexNft(const Core::NftInfo &old)
  {
    releaseReadTxnIfHeld();

    if (!old.owner.isNull())
    {
      uint8_t owner_key[40];
      std::memcpy(owner_key, old.owner.data.data(), 32);
      Common::writeU64(owner_key + 32, old.id);
      deleteRow(StateDB::TBL_INDEX_NFTS_BY_OWNER,
                owner_key, sizeof(owner_key));
    }

    if (old.collection_id != 0)
    {
      uint8_t coll_key[16];
      Common::writeU64(coll_key, old.collection_id);
      Common::writeU64(coll_key + 8, old.id);
      deleteRow(StateDB::TBL_INDEX_NFTS_BY_COLLECTION,
                coll_key, sizeof(coll_key));
    }
  }

  void StateAccess::deleteNft(uint64_t nft_id)
  {
    Core::NftInfo nft;
    const bool have_nft = getNft(nft_id, nft);

    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::nft(nft_id);
    smt_.remove(key, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, nft_id);
    deleteRow(StateDB::TBL_NFTS, id_key, sizeof(id_key));

    if (!have_nft)
      return;

    if (!nft.owner.isNull())
    {
      uint8_t owner_key[40];
      std::memcpy(owner_key, nft.owner.data.data(), 32);
      Common::writeU64(owner_key + 32, nft_id);
      deleteRow(StateDB::TBL_INDEX_NFTS_BY_OWNER,
                owner_key, sizeof(owner_key));
    }

    if (nft.collection_id != 0)
    {
      uint8_t coll_key[16];
      Common::writeU64(coll_key, nft.collection_id);
      Common::writeU64(coll_key + 8, nft_id);
      deleteRow(StateDB::TBL_INDEX_NFTS_BY_COLLECTION,
                coll_key, sizeof(coll_key));
    }
  }

  bool StateAccess::getNftCollection(uint64_t collection_id,
                                     Core::NftCollection &out) const
  {
    Crypto::Hash key = Keys::nftCollection(collection_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::NftCollection::deserializeState(
        value->data(), value->size(), out);
  }

  void StateAccess::putNftCollection(const Core::NftCollection &collection)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::nftCollection(collection.id);
    auto value = collection.serializeState();
    smt_.update(key, value, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, collection.id);
    putBlobRow(StateDB::TBL_NFT_COLLECTIONS, id_key, sizeof(id_key),
               value.data(), value.size());
  }

  void StateAccess::deleteNftCollection(uint64_t collection_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::nftCollection(collection_id);
    smt_.remove(key, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, collection_id);
    deleteRow(StateDB::TBL_NFT_COLLECTIONS, id_key, sizeof(id_key));
  }

  void StateAccess::forEachNft(
      const std::function<void(const Core::NftInfo &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 8)
        return true;

      Core::NftInfo nft;
      if (!Core::NftInfo::deserializeState(value.data(), value.size(), nft))
        return true;

      fn(nft);
      return true;
    };

    readForEach(StateDB::TBL_NFTS, visitor);
  }

  void StateAccess::forEachNftForOwner(
      const Crypto::Address &owner,
      const std::function<void(const Core::NftInfo &)> &fn) const
  {
    std::vector<uint8_t> prefix(owner.data.begin(), owner.data.end());

    auto visitor = [this, &fn](const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 40)
        return true;
      Id nft_id = Common::readU64(key.data() + 32);
      Core::NftInfo nft;
      if (getNft(nft_id, nft))
        fn(nft);
      return true;
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_NFTS_BY_OWNER,
                          prefix, visitor);
  }

  void StateAccess::forEachNftForCollection(
      uint64_t collection_id,
      const std::function<void(const Core::NftInfo &)> &fn) const
  {
    uint8_t prefix_bytes[8];
    Common::writeU64(prefix_bytes, collection_id);
    std::vector<uint8_t> prefix(prefix_bytes, prefix_bytes + 8);

    auto visitor = [this, &fn](const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 16)
        return true;
      Id nft_id = Common::readU64(key.data() + 8);
      Core::NftInfo nft;
      if (getNft(nft_id, nft))
        fn(nft);
      return true;
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_NFTS_BY_COLLECTION,
                          prefix, visitor);
  }

  void StateAccess::forEachNftCollection(
      const std::function<void(const Core::NftCollection &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 8)
        return true;

      Core::NftCollection c;
      if (!Core::NftCollection::deserializeState(
              value.data(), value.size(), c))
        return true;

      fn(c);
      return true;
    };

    readForEach(StateDB::TBL_NFT_COLLECTIONS, visitor);
  }

  //  =========================================================================
  //  Orders
  //  =========================================================================

  bool StateAccess::getOrder(Id order_id, Core::Order &out) const
  {
    Crypto::Hash key = Keys::order(order_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::Order::deserializeState(value->data(), value->size(), out);
  }

  void StateAccess::putOrder(const Core::Order &order)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::order(order.id);
    auto value = order.serializeState();
    smt_.update(key, value, version_);

    indexOrderRow(order.id, order.owner,
                  order.sell_token, order.buy_token);
    indexOrderPoolRows(order);
  }

  void StateAccess::deleteOrder(Id order_id)
  {
    Core::Order order;
    const bool have_order = getOrder(order_id, order);

    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::order(order_id);
    smt_.remove(key, version_);

    if (have_order)
    {
      unindexOrderRow(order_id, order.owner,
                      order.sell_token, order.buy_token);
      unindexOrderPoolRows(order);
    }
  }

  void StateAccess::forEachOrder(
      const std::function<void(const Core::Order &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 8)
        return true;

      Core::Order order;
      if (!Core::Order::deserializeState(value.data(), value.size(), order))
        return true;

      fn(order);
      return true;
    };

    readForEach(StateDB::TBL_ORDERS, visitor);
  }

  void StateAccess::forEachOrderForOwner(
      const Crypto::Address &owner,
      const std::function<void(const Core::Order &)> &fn) const
  {
    std::vector<uint8_t> prefix(owner.data.begin(), owner.data.end());

    auto visitor = [this, &fn](const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 40)
        return true;
      Id order_id = Common::readU64(key.data() + 32);
      Core::Order order;
      if (getOrder(order_id, order))
        fn(order);
      return true;
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_ORDERS_BY_OWNER, prefix, visitor);
  }

  void StateAccess::forEachOrderForPair(
      Id sell_token, Id buy_token,
      const std::function<void(const Core::Order &)> &fn) const
  {
    uint8_t prefix_bytes[8];
    Common::writeU32(prefix_bytes, static_cast<uint32_t>(sell_token));
    Common::writeU32(prefix_bytes + 4, static_cast<uint32_t>(buy_token));
    std::vector<uint8_t> prefix(prefix_bytes, prefix_bytes + 8);

    auto visitor = [this, &fn](const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 16)
        return true;
      Id order_id = Common::readU64(key.data() + 8);
      Core::Order order;
      if (getOrder(order_id, order))
        fn(order);
      return true;
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_ORDERS_BY_PAIR, prefix, visitor);
  }

  void StateAccess::forEachOrderForPool(
      Id pool_id,
      const std::function<void(const Core::Order &)> &fn) const
  {
    uint8_t prefix_bytes[4];
    Common::writeU32(prefix_bytes, static_cast<uint32_t>(pool_id));
    std::vector<uint8_t> prefix(prefix_bytes, prefix_bytes + 4);

    auto visitor = [this, &fn](const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 12)
        return true;
      Id order_id = Common::readU64(key.data() + 4);
      Core::Order order;
      if (getOrder(order_id, order))
        fn(order);
      return true;
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_ORDERS_BY_POOL,
                          prefix, visitor);
  }

  //  =========================================================================
  //  Order book
  //  =========================================================================

  void StateAccess::addToOrderBook(const Core::Order &order, uint64_t sequence)
  {
    if (order.id == INVALID_ID)
      return;
    if (order.isFullyFilled())
      return;

    const Crypto::Hash pair_key =
        Core::OrderBook::pairKey(order.sell_token, order.buy_token);
    const uint8_t side = Core::OrderBook::sideOf(order);

    uint64_t canonical_price = 0;
    if (!Core::OrderBook::canonicalPrice(order, canonical_price))
      return;

    uint8_t key[49];
    encodeBookKey(pair_key, side, canonical_price, sequence, key);

    putU64Row(StateDB::TBL_INDEX_ORDER_BOOK,
              key, sizeof(key), static_cast<uint64_t>(order.id));

    releaseReadTxnIfHeld();

    Crypto::Hash seq_key = Keys::orderSequence(order.id);
    std::vector<uint8_t> seq_bytes(8);
    Common::writeU64(seq_bytes.data(), sequence);
    smt_.update(seq_key, seq_bytes, version_);
  }

  void StateAccess::removeFromOrderBook(const Core::Order &order)
  {
    if (order.id == INVALID_ID)
      return;

    Crypto::Hash seq_key = Keys::orderSequence(order.id);
    auto seq_bytes = smt_.get(seq_key);
    if (!seq_bytes.has_value() || seq_bytes->size() != 8)
      return;

    const uint64_t sequence = Common::readU64(seq_bytes->data());

    const Crypto::Hash pair_key =
        Core::OrderBook::pairKey(order.sell_token, order.buy_token);
    const uint8_t side = Core::OrderBook::sideOf(order);

    uint64_t canonical_price = 0;
    if (!Core::OrderBook::canonicalPrice(order, canonical_price))
      return;

    uint8_t key[49];
    encodeBookKey(pair_key, side, canonical_price, sequence, key);

    deleteRow(StateDB::TBL_INDEX_ORDER_BOOK, key, sizeof(key));

    releaseReadTxnIfHeld();
    smt_.remove(seq_key, version_);
  }

  void StateAccess::forEachBookLevel(
      Id sell_token, Id buy_token, uint8_t side,
      const std::function<bool(Id order_id,
                               uint64_t canonical_price,
                               uint64_t sequence)> &fn) const
  {
    const Crypto::Hash pair_key =
        Core::OrderBook::pairKey(sell_token, buy_token);

    uint8_t prefix[33];
    std::memcpy(prefix, pair_key.data.data(), 32);
    prefix[32] = side;

    std::vector<uint8_t> prefix_vec(prefix, prefix + sizeof(prefix));

    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 49 || value.size() != 8)
        return true;

      uint64_t price = 0;
      uint64_t seq = 0;
      decodeBookKey(key.data(), price, seq);

      const uint64_t order_id = Common::readU64(value.data());

      return fn(static_cast<Id>(order_id), price, seq);
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_ORDER_BOOK,
                          prefix_vec, visitor);
  }

  uint64_t StateAccess::nextOrderSequence()
  {
    uint64_t n = getGlobalU64("order:next_sequence");
    ++n;
    putGlobalU64("order:next_sequence", n);
    return n;
  }

  void StateAccess::refundOrder(const Core::Order &order, bool charge_fee)
  {
    if (order.id == INVALID_ID)
      return;
    if (order.owner.isNull())
      return;

    const uint64_t remaining = order.remainingAmount();
    if (remaining == 0)
      return;

    uint64_t refund = remaining;
    if (charge_fee)
    {
      if (refund > Core::ORDER_CANCEL_FEE_ATOMIC)
        refund -= Core::ORDER_CANCEL_FEE_ATOMIC;
      else
        refund = 0;
    }

    if (order.sell_token == NATIVE_TOKEN_ID)
    {
      Core::Account acct = getAccount(order.owner);
      acct.balance += refund;
      putAccount(order.owner, acct);
    }
    else
    {
      const uint64_t cur = getTokenBalance(order.owner, order.sell_token);
      putTokenBalance(order.owner, order.sell_token, cur + refund);
    }

    if (order.order_expires_at_height != 0)
      removeOrderExpiry(order.order_expires_at_height, order.id);

    removeFromOrderBook(order);

    deleteOrder(order.id);
  }

  //  =========================================================================
  //  Order expiry index
  //  =========================================================================

  std::vector<uint64_t> StateAccess::getOrdersExpiringAt(uint64_t height) const
  {
    std::vector<uint64_t> result;

    Crypto::Hash key = Keys::orderExpiry(height);
    auto value = smt_.get(key);
    if (!value.has_value())
      return result;

    decodeU64List(*value, result);
    return result;
  }

  void StateAccess::addOrderExpiry(uint64_t height, uint64_t order_id)
  {
    std::vector<uint64_t> ids = getOrdersExpiringAt(height);

    if (std::find(ids.begin(), ids.end(), order_id) != ids.end())
      return;

    ids.push_back(order_id);

    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::orderExpiry(height);
    auto value = encodeU64List(ids);
    smt_.update(key, value, version_);
  }

  void StateAccess::removeOrderExpiry(uint64_t height, uint64_t order_id)
  {
    std::vector<uint64_t> ids = getOrdersExpiringAt(height);

    auto it = std::find(ids.begin(), ids.end(), order_id);
    if (it == ids.end())
      return;

    ids.erase(it);

    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::orderExpiry(height);

    if (ids.empty())
    {
      smt_.remove(key, version_);
      return;
    }

    auto value = encodeU64List(ids);
    smt_.update(key, value, version_);
  }

  void StateAccess::clearOrderExpiry(uint64_t height)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::orderExpiry(height);
    smt_.remove(key, version_);
  }

  void StateAccess::deleteRestingOrder(const Core::Order &order)
  {
    if (order.id == INVALID_ID)
      return;

    removeFromOrderBook(order);

    if (order.order_expires_at_height != 0)
      removeOrderExpiry(order.order_expires_at_height, order.id);

    deleteOrder(order.id);
  }

  void StateAccess::indexFill(const Core::Fill &fill,
                              uint64_t height,
                              uint32_t tx_index_in_block,
                              uint16_t fill_index)
  {
    const auto bytes = fill.serializeState();

    const Crypto::Hash pair_key =
        Core::OrderBook::pairKey(fill.base_token, fill.quote_token);

    uint8_t pair_key_bytes[47];
    encodePairFillKey(pair_key, height, tx_index_in_block,
                      fill_index, pair_key_bytes);

    putBlobRow(StateDB::TBL_FILL_HISTORY,
               pair_key_bytes, sizeof(pair_key_bytes),
               bytes.data(), bytes.size());

    uint8_t maker_key[23];
    encodeOrderFillKey(fill.maker_order_id, height, tx_index_in_block,
                       fill_index, maker_key);
    putBlobRow(StateDB::TBL_FILL_HISTORY,
               maker_key, sizeof(maker_key),
               bytes.data(), bytes.size());

    uint8_t taker_key[23];
    encodeOrderFillKey(fill.taker_order_id, height, tx_index_in_block,
                       fill_index, taker_key);
    putBlobRow(StateDB::TBL_FILL_HISTORY,
               taker_key, sizeof(taker_key),
               bytes.data(), bytes.size());
  }

  void StateAccess::forEachRecentFillForPair(
      uint32_t base_token,
      uint32_t quote_token,
      size_t max_results,
      const std::function<bool(const Core::Fill &,
                               uint64_t,
                               uint32_t)> &fn) const
  {
    const Crypto::Hash pair_key = Core::OrderBook::pairKey(base_token, quote_token);

    uint8_t prefix_bytes[33];
    prefix_bytes[0] = 0x01;
    std::memcpy(prefix_bytes + 1, pair_key.data.data(), 32);
    std::vector<uint8_t> prefix(prefix_bytes, prefix_bytes + sizeof(prefix_bytes));

    size_t emitted = 0;

    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 47 || value.size() != Core::Fill::STATE_SIZE)
        return true;
      if (emitted >= max_results)
        return false;

      const uint64_t height = Common::readU64BE(key.data() + 33);
      const uint32_t tx_index = Common::readU32BE(key.data() + 41);

      Core::Fill f;
      if (!Core::Fill::deserializeState(value.data(), value.size(), f))
        return true;

      ++emitted;
      return fn(f, height, tx_index);
    };

    readForEachWithPrefixReverse(StateDB::TBL_FILL_HISTORY,
                                 prefix, visitor);
  }

  void StateAccess::forEachRecentFillForOrder(
      uint64_t order_id,
      size_t max_results,
      const std::function<bool(const Core::Fill &,
                               uint64_t,
                               uint32_t)> &fn) const
  {
    uint8_t prefix_bytes[9];
    prefix_bytes[0] = 0x02;
    for (int i = 0; i < 8; ++i)
      prefix_bytes[1 + i] = uint8_t(order_id >> ((7 - i) * 8));
    std::vector<uint8_t> prefix(prefix_bytes, prefix_bytes + sizeof(prefix_bytes));

    size_t emitted = 0;

    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 23 || value.size() != Core::Fill::STATE_SIZE)
        return true;
      if (emitted >= max_results)
        return false;

      const uint64_t height = Common::readU64BE(key.data() + 9);
      const uint32_t tx_index = Common::readU32BE(key.data() + 17);

      Core::Fill f;
      if (!Core::Fill::deserializeState(value.data(), value.size(), f))
        return true;

      ++emitted;
      return fn(f, height, tx_index);
    };

    readForEachWithPrefixReverse(StateDB::TBL_FILL_HISTORY,
                                 prefix, visitor);
  }

  void StateAccess::snapshotBookSide(
      Id sell_token,
      Id buy_token,
      uint8_t side,
      size_t depth,
      const std::function<void(uint64_t, uint64_t, size_t)> &fn) const
  {
    uint64_t current_price = 0;
    uint64_t current_total_base = 0;
    size_t current_count = 0;
    size_t emitted_levels = 0;
    bool have_level = false;

    auto flush = [&]() -> bool
    {
      if (!have_level)
        return true;
      fn(current_price, current_total_base, current_count);
      ++emitted_levels;
      have_level = false;
      current_total_base = 0;
      current_count = 0;
      return depth == 0 || emitted_levels < depth;
    };

    bool keep_going = true;

    forEachBookLevel(
        sell_token, buy_token, side,
        [&](Id order_id, uint64_t price, uint64_t) -> bool
        {
          if (!keep_going)
            return false;

          if (have_level && price != current_price)
          {
            keep_going = flush();
            if (!keep_going)
              return false;
          }

          Core::Order o;
          if (!getOrder(order_id, o))
            return true;

          const bool sells_base = (o.sell_token < o.buy_token);
          uint64_t rem = o.remainingAmount();
          if (!sells_base)
          {
            const unsigned __int128 prod =
                static_cast<unsigned __int128>(rem) *
                static_cast<unsigned __int128>(Core::OrderBook::BOOK_PRICE_SCALE);
            rem = static_cast<uint64_t>(prod / price);
          }

          current_price = price;
          current_total_base += rem;
          current_count += 1;
          have_level = true;

          return true;
        });

    if (keep_going)
      flush();
  }

  //  =========================================================================
  //  AMM Pools
  //  =========================================================================

  bool StateAccess::getAmmPool(Id pool_id, Core::AmmPool &out) const
  {
    Crypto::Hash key = Keys::ammPool(pool_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::AmmPool::deserializeState(value->data(), value->size(), out);
  }

  void StateAccess::putAmmPool(const Core::AmmPool &pool)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammPool(pool.id);
    auto value = pool.serializeState();
    smt_.update(key, value, version_);

    indexAmmPoolRow(pool.id, pool.token_a, pool.token_b);
  }

  void StateAccess::deleteAmmPool(Id pool_id)
  {
    Core::AmmPool pool;
    const bool have_pool = getAmmPool(pool_id, pool);

    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammPool(pool_id);
    smt_.remove(key, version_);

    if (have_pool)
      unindexAmmPoolRow(pool_id, pool.token_a, pool.token_b);
  }

  void StateAccess::forEachAmmPool(
      const std::function<void(const Core::AmmPool &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 8)
        return true;

      Core::AmmPool pool;
      if (!Core::AmmPool::deserializeState(value.data(), value.size(), pool))
        return true;

      fn(pool);
      return true;
    };

    readForEach(StateDB::TBL_AMM_POOLS, visitor);
  }

  void StateAccess::forEachPoolForToken(
      Id token_id,
      const std::function<void(const Core::AmmPool &)> &fn) const
  {
    uint8_t prefix_bytes[4];
    Common::writeU32(prefix_bytes, static_cast<uint32_t>(token_id));
    std::vector<uint8_t> prefix(prefix_bytes, prefix_bytes + 4);

    auto visitor = [this, &fn](const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 12)
        return true;
      Id pool_id = Common::readU64(key.data() + 4);
      Core::AmmPool pool;
      if (getAmmPool(pool_id, pool))
        fn(pool);
      return true;
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_POOLS_BY_TOKEN, prefix, visitor);
  }

  //  =========================================================================
  //  AMM Positions
  //  =========================================================================

  bool StateAccess::getAmmPosition(Id pos_id, Core::AmmPosition &out) const
  {
    Crypto::Hash key = Keys::ammPosition(pos_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::AmmPosition::deserializeState(value->data(), value->size(), out);
  }

  void StateAccess::putAmmPosition(const Core::AmmPosition &pos)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammPosition(pos.id);
    auto value = pos.serializeState();
    smt_.update(key, value, version_);

    indexAmmPositionRow(pos.id, pos.owner);
  }

  void StateAccess::deleteAmmPosition(Id pos_id)
  {
    Core::AmmPosition pos;
    const bool have_pos = getAmmPosition(pos_id, pos);

    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammPosition(pos_id);
    smt_.remove(key, version_);

    if (have_pos)
      unindexAmmPositionRow(pos_id, pos.owner);
  }

  void StateAccess::forEachAmmPosition(
      const std::function<void(const Core::AmmPosition &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 8)
        return true;

      Core::AmmPosition pos;
      if (!Core::AmmPosition::deserializeState(value.data(), value.size(), pos))
        return true;

      fn(pos);
      return true;
    };

    readForEach(StateDB::TBL_AMM_POSITIONS, visitor);
  }

  void StateAccess::forEachPositionForOwner(
      const Crypto::Address &owner,
      const std::function<void(const Core::AmmPosition &)> &fn) const
  {
    std::vector<uint8_t> prefix(owner.data.begin(), owner.data.end());

    auto visitor = [this, &fn](const std::vector<uint8_t> &key,
                               const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 40)
        return true;
      Id pos_id = Common::readU64(key.data() + 32);
      Core::AmmPosition pos;
      if (getAmmPosition(pos_id, pos))
        fn(pos);
      return true;
    };

    readForEachWithPrefix(StateDB::TBL_INDEX_POSITIONS_BY_OWNER, prefix, visitor);
  }

  //  =========================================================================
  //  LP position index
  //  =========================================================================

  bool StateAccess::getPositionIndex(const Crypto::Address &owner,
                                     uint64_t pool_id,
                                     uint64_t &position_id_out) const
  {
    Crypto::Hash key = Keys::ammPositionIndex(owner, pool_id);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return false;

    position_id_out = Common::readU64(value->data());
    return true;
  }

  void StateAccess::putPositionIndex(const Crypto::Address &owner,
                                     uint64_t pool_id,
                                     uint64_t position_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammPositionIndex(owner, pool_id);
    std::vector<uint8_t> value(8);
    Common::writeU64(value.data(), position_id);
    smt_.update(key, value, version_);
  }

  void StateAccess::deletePositionIndex(const Crypto::Address &owner,
                                        uint64_t pool_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammPositionIndex(owner, pool_id);
    smt_.remove(key, version_);
  }

  //  =========================================================================
  //  AMM farming
  //
  //  putAmmFarm and putAmmPositionAccrual are pure writes. They do
  //  not read the old record; the caller does, and calls
  //  deleteAmmFarm / deleteAmmPositionAccrual separately if cleanup
  //  is needed. This is the same discipline putNft follows (see the
  //  comment on putNft): a read interleaved with the tree's
  //  content-addressed node update buffer can cause subsequent
  //  updates in the same transaction to be silently dropped.
  //
  //  deleteAmmFarm does not refund the escrow. The refund is the
  //  caller's job: executeRemoveLiquidity refunds to the creator on
  //  a full-drain close, and executeCloseAmmFarm refunds on an
  //  explicit close. StateAccess primitives are pure data operations;
  //  policy lives in the executor.
  //  =========================================================================

  bool StateAccess::getAmmFarm(Id pool_id,
                               Core::AmmFarmSchedule &out) const
  {
    Crypto::Hash key = Keys::ammFarm(pool_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::AmmFarmSchedule::deserializeState(
        value->data(), value->size(), out);
  }

  void StateAccess::putAmmFarm(const Core::AmmFarmSchedule &farm)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammFarm(farm.pool_id);
    auto value = farm.serializeState();
    smt_.update(key, value, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, farm.pool_id);
    putBlobRow(StateDB::TBL_AMM_FARMS, id_key, sizeof(id_key),
               value.data(), value.size());
  }

  void StateAccess::deleteAmmFarm(Id pool_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammFarm(pool_id);
    smt_.remove(key, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, pool_id);
    deleteRow(StateDB::TBL_AMM_FARMS, id_key, sizeof(id_key));
  }

  void StateAccess::forEachAmmFarm(
      const std::function<void(const Core::AmmFarmSchedule &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 8)
        return true;

      Core::AmmFarmSchedule farm;
      if (!Core::AmmFarmSchedule::deserializeState(
              value.data(), value.size(), farm))
        return true;

      fn(farm);
      return true;
    };

    readForEach(StateDB::TBL_AMM_FARMS, visitor);
  }

  bool StateAccess::getAmmPositionAccrual(
      Id position_id, Core::AmmPositionAccrual &out) const
  {
    Crypto::Hash key = Keys::ammPositionAccrual(position_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::AmmPositionAccrual::deserializeState(
        value->data(), value->size(), out);
  }

  void StateAccess::putAmmPositionAccrual(
      const Core::AmmPositionAccrual &accrual)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammPositionAccrual(accrual.position_id);
    auto value = accrual.serializeState();
    smt_.update(key, value, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, accrual.position_id);
    putBlobRow(StateDB::TBL_AMM_POSITION_ACCRUALS,
               id_key, sizeof(id_key),
               value.data(), value.size());
  }

  void StateAccess::deleteAmmPositionAccrual(Id position_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::ammPositionAccrual(position_id);
    smt_.remove(key, version_);

    uint8_t id_key[8];
    Common::writeU64(id_key, position_id);
    deleteRow(StateDB::TBL_AMM_POSITION_ACCRUALS,
              id_key, sizeof(id_key));
  }

  //  =========================================================================
  //  Receipts
  //  =========================================================================

  bool StateAccess::getReceipt(const Crypto::Hash &tx_hash, Core::Receipt &out) const
  {
    Crypto::Hash key = Keys::receipt(tx_hash);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::Receipt::deserializeState(value->data(), value->size(), out);
  }

  void StateAccess::putReceipt(const Crypto::Hash &tx_hash, const Core::Receipt &receipt)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::receipt(tx_hash);
    auto value = receipt.serializeState();
    smt_.update(key, value, version_);
  }

  //  =========================================================================
  //  Bridge
  //  =========================================================================
  //
  //  Under the validator-is-watcher model there is no watcher record
  //  and no watcher index. The per-deposit and per-withdrawal
  //  attestation records, the chain registry, the withdrawal records,
  //  the event log, and the aggregate stats are all unchanged. The
  //  bridge executor resolves the active validator set with
  //  forEachActiveValidator / countActiveValidators, not with a
  //  per-chain watcher iterator.
  //
  //  TBL_INDEX_BRIDGE_WATCHERS_BY_OWNER is declared in StateDB.h as
  //  a reserved table. Nothing reads from it, nothing writes to it.
  //  Files from earlier builds open cleanly because the table exists;
  //  the rows are simply ignored.

  //  ---- Consumed deposits ----

  bool StateAccess::getBridgeConsumed(uint64_t source_chain_id,
                                      const Crypto::Hash &source_tx_hash,
                                      uint32_t source_output_index,
                                      uint64_t &mint_height_out) const
  {
    Crypto::Hash key = Keys::bridgeConsumed(source_chain_id, source_tx_hash,
                                            source_output_index);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return false;

    mint_height_out = Common::readU64(value->data());
    return true;
  }

  void StateAccess::putBridgeConsumed(uint64_t source_chain_id,
                                      const Crypto::Hash &source_tx_hash,
                                      uint32_t source_output_index,
                                      uint64_t mint_height)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::bridgeConsumed(source_chain_id, source_tx_hash,
                                            source_output_index);
    std::vector<uint8_t> value(8);
    Common::writeU64(value.data(), mint_height);
    smt_.update(key, value, version_);
  }

  //  ---- Withdrawals ----

  bool StateAccess::getBridgeWithdrawal(uint64_t withdrawal_id,
                                        Core::BridgeWithdrawal &out) const
  {
    Crypto::Hash key = Keys::bridgeWithdrawal(withdrawal_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::BridgeWithdrawal::deserializeState(
        value->data(), value->size(), out);
  }

  void StateAccess::putBridgeWithdrawal(const Core::BridgeWithdrawal &w)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::bridgeWithdrawal(w.id);
    auto value = w.serializeState();
    smt_.update(key, value, version_);

    indexBridgeWithdrawalRow(w);
  }

  void StateAccess::deleteBridgeWithdrawal(uint64_t withdrawal_id)
  {
    Core::BridgeWithdrawal w;
    const bool have = getBridgeWithdrawal(withdrawal_id, w);

    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::bridgeWithdrawal(withdrawal_id);
    smt_.remove(key, version_);

    if (!have)
      return;

    unindexBridgeWithdrawalRow(w);
  }

  void StateAccess::putBridgeEvent(const Core::BridgeEvent &evt)
  {
    const auto key = Core::BridgeEvent::makeKey(
        evt.source_chain_id, evt.block_height,
        evt.tx_index_in_block, evt.kind);
    const auto value = evt.serializeState();
    putBlobRow(StateDB::TBL_BRIDGE_EVENTS,
               key.data(), key.size(),
               value.data(), value.size());
  }

  void StateAccess::forEachBridgeEvent(
      uint64_t source_chain_id,
      uint64_t from_height,
      const std::function<bool(const Core::BridgeEvent &)> &fn) const
  {
    const auto prefix = Core::BridgeEvent::chainPrefix(source_chain_id);
    std::vector<uint8_t> prefix_vec(prefix.begin(), prefix.end());

    uint8_t seek_bytes[16];
    std::memcpy(seek_bytes, prefix.data(), 8);
    for (int i = 0; i < 8; ++i)
      seek_bytes[8 + i] = uint8_t(from_height >> ((7 - i) * 8));
    std::vector<uint8_t> seek_key(seek_bytes, seek_bytes + sizeof(seek_bytes));

    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != Core::BridgeEvent::KEY_SIZE)
        return true;

      Core::BridgeEvent evt;
      if (!Core::BridgeEvent::deserializeState(
              value.data(), value.size(), evt))
        return true;

      return fn(evt);
    };

    readForEachFromKey(StateDB::TBL_BRIDGE_EVENTS, seek_key, visitor);
  }

  void StateAccess::forEachBridgeEventForWithdrawal(
      uint64_t withdrawal_id,
      const std::function<bool(const Core::BridgeEvent &)> &fn) const
  {
    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != Core::BridgeEvent::KEY_SIZE)
        return true;

      Core::BridgeEvent evt;
      if (!Core::BridgeEvent::deserializeState(
              value.data(), value.size(), evt))
        return true;

      if (evt.withdrawal_id != withdrawal_id)
        return true;

      return fn(evt);
    };

    readForEach(StateDB::TBL_BRIDGE_EVENTS, visitor);
  }

  void StateAccess::forEachPendingBridgeWithdrawal(
      uint64_t from_height,
      size_t max_results,
      const std::function<bool(const Core::BridgeWithdrawal &)> &fn) const
  {
    uint8_t seek_bytes[16];
    encodeBridgeWithdrawalHeightKey(from_height, 0, seek_bytes);
    std::vector<uint8_t> seek_key(seek_bytes, seek_bytes + sizeof(seek_bytes));

    size_t yielded = 0;

    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 16)
        return true;

      uint64_t withdrawal_id = 0;
      for (int i = 0; i < 8; ++i)
        withdrawal_id = (withdrawal_id << 8) | key[8 + i];

      Core::BridgeWithdrawal w;
      if (!getBridgeWithdrawal(withdrawal_id, w))
        return true;

      if (!fn(w))
        return false;

      ++yielded;
      if (max_results != 0 && yielded >= max_results)
        return false;

      return true;
    };

    readForEachFromKey(StateDB::TBL_INDEX_BRIDGE_WITHDRAWALS_BY_HEIGHT,
                       seek_key, visitor);
  }

  //  ---- Chain registry ----

  bool StateAccess::getBridgeChainRegistration(
      uint64_t source_chain_id,
      Core::BridgeChainRegistration &out) const
  {
    Crypto::Hash key = Keys::bridgeChainRegistration(source_chain_id);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    return Core::BridgeChainRegistration::deserializeState(
        value->data(), value->size(), out);
  }

  void StateAccess::putBridgeChainRegistration(
      const Core::BridgeChainRegistration &reg)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::bridgeChainRegistration(reg.source_chain_id);
    auto value = reg.serializeState();
    smt_.update(key, value, version_);
  }

  void StateAccess::deleteBridgeChainRegistration(uint64_t source_chain_id)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::bridgeChainRegistration(source_chain_id);
    smt_.remove(key, version_);
  }

  //  ---- Attestations ----
  //
  //  Key layout (52 bytes):
  //    [8]  source_chain_id (LE)
  //    [32] source_tx_hash
  //    [4]  source_output_index (LE)
  //    [8]  validator_id (LE)
  //
  //  The 44-byte prefix (everything except validator_id) is what
  //  the per-deposit range scan seeks.
  //
  //  Attestation records are NOT written into the SMT. They are
  //  federation state — a per-deposit vote tally — and do not
  //  affect any other transaction's validity.

  std::array<uint8_t, 52> StateAccess::bridgeAttestationKey(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      uint64_t validator_id)
  {
    return bridgeAttestationKeyImpl(
        source_chain_id, source_tx_hash, source_output_index, validator_id);
  }

  void StateAccess::putBridgeAttestation(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      uint64_t validator_id,
      const Core::BridgeAttestation &attestation)
  {
    if (!attestation.isWellFormed())
      throw StateDBError("putBridgeAttestation: malformed attestation");

    const auto key = bridgeAttestationKeyImpl(
        source_chain_id, source_tx_hash, source_output_index, validator_id);
    const auto value = attestation.serializeState();
    putBlobRow(StateDB::TBL_BRIDGE_ATTESTATIONS,
               key.data(), key.size(),
               value.data(), value.size());
  }

  bool StateAccess::getBridgeAttestation(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      uint64_t validator_id,
      Core::BridgeAttestation &out) const
  {
    const auto key = bridgeAttestationKeyImpl(
        source_chain_id, source_tx_hash, source_output_index, validator_id);

    std::vector<uint8_t> value;
    if (!readRow(StateDB::TBL_BRIDGE_ATTESTATIONS,
                 key.data(), key.size(), value))
      return false;

    return Core::BridgeAttestation::deserializeState(
        value.data(), value.size(), out);
  }

  void StateAccess::forEachBridgeAttestationForDeposit(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index,
      const std::function<bool(uint64_t, const Core::BridgeAttestation &)> &fn) const
  {
    const auto prefix = bridgeAttestationPrefixImpl(
        source_chain_id, source_tx_hash, source_output_index);
    const std::vector<uint8_t> prefix_vec(prefix.begin(), prefix.end());

    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 52)
        return true;

      uint64_t validator_id = 0;
      for (int i = 0; i < 8; ++i)
        validator_id |= uint64_t(key[44 + i]) << (i * 8);

      Core::BridgeAttestation a;
      if (!Core::BridgeAttestation::deserializeState(
              value.data(), value.size(), a))
        return true;

      return fn(validator_id, a);
    };

    readForEachWithPrefix(StateDB::TBL_BRIDGE_ATTESTATIONS,
                          prefix_vec, visitor);
  }

  //  =========================================================================
  //  Bridge — withdrawal ack attestations
  //  =========================================================================

  std::array<uint8_t, 16> StateAccess::bridgeAckAttestationKey(
      uint64_t withdrawal_id,
      uint64_t validator_id)
  {
    return bridgeAckAttestationKeyImpl(withdrawal_id, validator_id);
  }

  void StateAccess::putBridgeAckAttestation(
      uint64_t withdrawal_id,
      uint64_t validator_id,
      const Core::BridgeAckAttestation &attestation)
  {
    if (!attestation.isWellFormed())
      throw StateDBError("putBridgeAckAttestation: malformed attestation");

    const auto key = bridgeAckAttestationKeyImpl(withdrawal_id, validator_id);
    const auto value = attestation.serializeState();
    putBlobRow(StateDB::TBL_BRIDGE_ACK_ATTESTATIONS,
               key.data(), key.size(),
               value.data(), value.size());
  }

  bool StateAccess::getBridgeAckAttestation(
      uint64_t withdrawal_id,
      uint64_t validator_id,
      Core::BridgeAckAttestation &out) const
  {
    const auto key = bridgeAckAttestationKeyImpl(withdrawal_id, validator_id);

    std::vector<uint8_t> value;
    if (!readRow(StateDB::TBL_BRIDGE_ACK_ATTESTATIONS,
                 key.data(), key.size(), value))
      return false;

    return Core::BridgeAckAttestation::deserializeState(
        value.data(), value.size(), out);
  }

  void StateAccess::forEachBridgeAckAttestationForWithdrawal(
      uint64_t withdrawal_id,
      const std::function<bool(uint64_t, const Core::BridgeAckAttestation &)> &fn) const
  {
    const auto prefix = bridgeAckAttestationPrefixImpl(withdrawal_id);
    const std::vector<uint8_t> prefix_vec(prefix.begin(), prefix.end());

    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 16)
        return true;

      uint64_t validator_id = 0;
      for (int i = 0; i < 8; ++i)
        validator_id |= uint64_t(key[8 + i]) << (i * 8);

      Core::BridgeAckAttestation a;
      if (!Core::BridgeAckAttestation::deserializeState(
              value.data(), value.size(), a))
        return true;

      return fn(validator_id, a);
    };

    readForEachWithPrefix(StateDB::TBL_BRIDGE_ACK_ATTESTATIONS,
                          prefix_vec, visitor);
  }

  size_t StateAccess::countBridgeAckAttestationsForWithdrawal(
      uint64_t withdrawal_id) const
  {
    size_t count = 0;
    forEachBridgeAckAttestationForWithdrawal(
        withdrawal_id,
        [&](uint64_t, const Core::BridgeAckAttestation &) -> bool
        {
          ++count;
          return true;
        });
    return count;
  }

  void StateAccess::forEachBridgeAckAttestation(
      const std::function<bool(uint64_t, uint64_t,
                               const Core::BridgeAckAttestation &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 16)
        return true;

      uint64_t withdrawal_id = 0;
      for (int i = 0; i < 8; ++i)
        withdrawal_id |= uint64_t(key[i]) << (i * 8);

      uint64_t validator_id = 0;
      for (int i = 0; i < 8; ++i)
        validator_id |= uint64_t(key[8 + i]) << (i * 8);

      Core::BridgeAckAttestation a;
      if (!Core::BridgeAckAttestation::deserializeState(
              value.data(), value.size(), a))
        return true;

      return fn(withdrawal_id, validator_id, a);
    };

    readForEach(StateDB::TBL_BRIDGE_ACK_ATTESTATIONS, visitor);
  }

  //  =========================================================================
  //  Bridge — unreleased withdrawals
  //  =========================================================================

  void StateAccess::forEachUnreleasedBridgeWithdrawal(
      uint64_t from_height,
      size_t max_results,
      const std::function<bool(const Core::BridgeWithdrawal &)> &fn) const
  {
    uint8_t seek_bytes[16];
    encodeBridgeWithdrawalHeightKey(from_height, 0, seek_bytes);
    std::vector<uint8_t> seek_key(seek_bytes, seek_bytes + sizeof(seek_bytes));

    size_t yielded = 0;

    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 16)
        return true;

      uint64_t withdrawal_id = 0;
      for (int i = 0; i < 8; ++i)
        withdrawal_id = (withdrawal_id << 8) | key[8 + i];

      Core::BridgeWithdrawal w;
      if (!getBridgeWithdrawal(withdrawal_id, w))
        return true;

      if (w.isReleased())
        return true;

      if (!fn(w))
        return false;

      ++yielded;
      if (max_results != 0 && yielded >= max_results)
        return false;

      return true;
    };

    readForEachFromKey(StateDB::TBL_INDEX_BRIDGE_WITHDRAWALS_BY_HEIGHT,
                       seek_key, visitor);
  }

  //  =========================================================================
  //  Bridge — stats
  //  =========================================================================

  bool StateAccess::getBridgeStats(uint64_t source_chain_id,
                                   Core::BridgeStats &out) const
  {
    uint8_t key[8];
    Common::writeU64(key, source_chain_id);

    std::vector<uint8_t> value;
    if (!readRow(StateDB::TBL_BRIDGE_STATS, key, sizeof(key), value))
      return false;

    return Core::BridgeStats::deserializeState(
        value.data(), value.size(), out);
  }

  void StateAccess::putBridgeStats(const Core::BridgeStats &stats)
  {
    if (!stats.isWellFormed())
      throw StateDBError("putBridgeStats: malformed stats");

    uint8_t key[8];
    Common::writeU64(key, stats.source_chain_id);

    const auto value = stats.serializeState();
    putBlobRow(StateDB::TBL_BRIDGE_STATS,
               key, sizeof(key),
               value.data(), value.size());
  }

  size_t StateAccess::countBridgeAttestationsForDeposit(
      uint64_t source_chain_id,
      const Crypto::Hash &source_tx_hash,
      uint32_t source_output_index) const
  {
    size_t count = 0;
    forEachBridgeAttestationForDeposit(
        source_chain_id, source_tx_hash, source_output_index,
        [&](uint64_t, const Core::BridgeAttestation &) -> bool
        {
          ++count;
          return true;
        });
    return count;
  }

  void StateAccess::forEachBridgeAttestation(
      const std::function<bool(uint64_t, const Crypto::Hash &, uint32_t,
                               uint64_t, const Core::BridgeAttestation &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 52)
        return true;

      uint64_t source_chain_id = 0;
      for (int i = 0; i < 8; ++i)
        source_chain_id |= uint64_t(key[i]) << (i * 8);

      Crypto::Hash tx_hash;
      std::memcpy(tx_hash.data.data(), key.data() + 8, 32);

      uint32_t output_index = 0;
      for (int i = 0; i < 4; ++i)
        output_index |= uint32_t(key[40 + i]) << (i * 8);

      uint64_t validator_id = 0;
      for (int i = 0; i < 8; ++i)
        validator_id |= uint64_t(key[44 + i]) << (i * 8);

      Core::BridgeAttestation a;
      if (!Core::BridgeAttestation::deserializeState(
              value.data(), value.size(), a))
        return true;

      return fn(source_chain_id, tx_hash, output_index,
                validator_id, a);
    };

    readForEach(StateDB::TBL_BRIDGE_ATTESTATIONS, visitor);
  }

  //  =========================================================================
  //  Global state
  //  =========================================================================

  bool StateAccess::getGlobal(const std::string &name, std::vector<uint8_t> &out) const
  {
    Crypto::Hash key = Keys::global(name);
    auto value = smt_.get(key);
    if (!value.has_value())
      return false;
    out = std::move(*value);
    return true;
  }

  void StateAccess::putGlobal(const std::string &name,
                              const std::vector<uint8_t> &value)
  {
    releaseReadTxnIfHeld();

    Crypto::Hash key = Keys::global(name);
    smt_.update(key, value, version_);
  }

  uint64_t StateAccess::getGlobalU64(const std::string &name) const
  {
    std::vector<uint8_t> bytes;
    if (!getGlobal(name, bytes) || bytes.size() != 8)
      return 0;
    return Common::readU64(bytes.data());
  }

  void StateAccess::putGlobalU64(const std::string &name, uint64_t value)
  {
    std::vector<uint8_t> bytes(8);
    Common::writeU64(bytes.data(), value);
    putGlobal(name, bytes);
  }

  uint64_t StateAccess::getMetaU64(const std::string &key) const
  {
    std::vector<uint8_t> bytes;
    if (!getMetaImpl(key, bytes) || bytes.size() != 8)
      return 0;
    return Common::readU64(bytes.data());
  }

  void StateAccess::putMetaU64(const std::string &key, uint64_t value)
  {
    std::vector<uint8_t> bytes(8);
    Common::writeU64(bytes.data(), value);
    putMetaImpl(key, bytes);
  }

  //  =========================================================================
  //  Raw SMT access
  //  =========================================================================

  std::optional<std::vector<uint8_t>> StateAccess::getRaw(const Crypto::Hash &smt_key) const
  {
    return smt_.get(smt_key);
  }

  void StateAccess::putRaw(const Crypto::Hash &smt_key,
                           const std::vector<uint8_t> &value)
  {
    releaseReadTxnIfHeld();

    smt_.update(smt_key, value, version_);
  }

  void StateAccess::deleteRaw(const Crypto::Hash &smt_key)
  {
    releaseReadTxnIfHeld();

    smt_.remove(smt_key, version_);
  }

  //  =========================================================================
  //  Commit
  //  =========================================================================

  void StateAccess::commit(uint64_t version)
  {
    version_ = version;

    releaseReadTxnIfHeld();

    smt_.save(version);

    if (!txn_)
      db_.flush();
  }

  //  =========================================================================
  //  Indexes
  //  =========================================================================

  void StateAccess::indexStaker(const Crypto::Address &address)
  {
    putSentinel(StateDB::TBL_INDEX_STAKERS,
                address.data.data(), address.data.size());
  }

  void StateAccess::unindexStaker(const Crypto::Address &address)
  {
    deleteRow(StateDB::TBL_INDEX_STAKERS,
              address.data.data(), address.data.size());
  }

  void StateAccess::forEachStaker(
      const std::function<void(const Crypto::Address &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> &) -> bool
    {
      if (key.size() != 32)
        return true;
      Crypto::Address addr;
      std::memcpy(addr.data.data(), key.data(), 32);
      fn(addr);
      return true;
    };

    readForEach(StateDB::TBL_INDEX_STAKERS, visitor);
  }

  //  =========================================================================
  //  Transaction history queries
  //  =========================================================================

  void StateAccess::forEachRecentTxForAddress(
      const Crypto::Address &address,
      size_t max_results,
      const std::function<bool(const Crypto::Hash &txid,
                               uint64_t block_height,
                               uint32_t tx_index)> &fn) const
  {
    std::vector<uint8_t> prefix(address.data.begin(), address.data.end());

    size_t emitted = 0;

    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 44 || value.size() != 32)
        return true;
      if (emitted >= max_results)
        return false;

      uint64_t height = Common::readU64BE(key.data() + 32);
      uint32_t tx_idx = Common::readU32BE(key.data() + 40);

      Crypto::Hash txid;
      std::memcpy(txid.data.data(), value.data(), 32);

      ++emitted;
      return fn(txid, height, tx_idx);
    };

    readForEachWithPrefixReverse(
        StateDB::TBL_INDEX_TX_BY_ADDRESS, prefix, visitor);
  }

  void StateAccess::forEachRecentTxForToken(
      Id token_id,
      size_t max_results,
      const std::function<bool(const Crypto::Hash &txid,
                               uint64_t block_height,
                               uint32_t tx_index)> &fn) const
  {
    uint8_t prefix_bytes[4];
    Common::writeU32(prefix_bytes, static_cast<uint32_t>(token_id));
    std::vector<uint8_t> prefix(prefix_bytes, prefix_bytes + 4);

    size_t emitted = 0;

    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 16 || value.size() != 32)
        return true;
      if (emitted >= max_results)
        return false;

      uint64_t height = Common::readU64BE(key.data() + 4);
      uint32_t tx_idx = Common::readU32BE(key.data() + 12);

      Crypto::Hash txid;
      std::memcpy(txid.data.data(), value.data(), 32);

      ++emitted;
      return fn(txid, height, tx_idx);
    };

    readForEachWithPrefixReverse(
        StateDB::TBL_INDEX_TX_BY_TOKEN, prefix, visitor);
  }

  void StateAccess::forEachRecentTxOfType(
      uint8_t tx_type,
      size_t max_results,
      const std::function<bool(const Crypto::Hash &txid,
                               uint64_t block_height,
                               uint32_t tx_index)> &fn) const
  {
    std::vector<uint8_t> prefix{tx_type};

    size_t emitted = 0;

    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 13 || value.size() != 32)
        return true;
      if (emitted >= max_results)
        return false;

      uint64_t height = Common::readU64BE(key.data() + 1);
      uint32_t tx_idx = Common::readU32BE(key.data() + 9);

      Crypto::Hash txid;
      std::memcpy(txid.data.data(), value.data(), 32);

      ++emitted;
      return fn(txid, height, tx_idx);
    };

    readForEachWithPrefixReverse(
        StateDB::TBL_INDEX_TX_BY_TYPE, prefix, visitor);
  }

  void StateAccess::forEachBlockByProducer(
      const Crypto::Address &proposer,
      size_t max_results,
      const std::function<bool(uint64_t block_height,
                               const Crypto::Hash &block_hash)> &fn) const
  {
    std::vector<uint8_t> prefix(proposer.data.begin(), proposer.data.end());

    size_t emitted = 0;

    auto visitor = [&](const std::vector<uint8_t> &key,
                       const std::vector<uint8_t> &value) -> bool
    {
      if (key.size() != 40 || value.size() != 32)
        return true;
      if (emitted >= max_results)
        return false;

      uint64_t height = Common::readU64BE(key.data() + 32);

      Crypto::Hash block_hash;
      std::memcpy(block_hash.data.data(), value.data(), 32);

      ++emitted;
      return fn(height, block_hash);
    };

    readForEachWithPrefixReverse(
        StateDB::TBL_INDEX_BLOCKS_BY_PRODUCER, prefix, visitor);
  }

  //  =========================================================================
  //  Txn-aware helpers
  //  =========================================================================

  void StateAccess::putMetaImpl(const std::string &key,
                                const std::vector<uint8_t> &value)
  {
    if (txn_)
    {
      txn_->put(StateDB::TBL_META,
                key.data(), key.size(),
                value.data(), value.size());
      return;
    }

    releaseReadTxnIfHeld();
    db_.putMeta(key, value);
  }

  bool StateAccess::getMetaImpl(const std::string &key,
                                std::vector<uint8_t> &out) const
  {
    return readRow(StateDB::TBL_META,
                   key.data(), key.size(), out);
  }

  //  =========================================================================
  //  Versioned reads
  //  =========================================================================

  bool StateAccess::versionIsAvailable(uint64_t version) const noexcept
  {
    if (history_window_ == UINT64_MAX)
      return true;

    if (version >= version_)
      return true;

    if (version_ > history_window_)
    {
      const uint64_t oldest = version_ - history_window_;
      return version >= oldest;
    }

    return true;
  }

  uint64_t StateAccess::oldestAvailableVersion() const noexcept
  {
    if (history_window_ == UINT64_MAX)
      return 0;
    if (version_ <= history_window_)
      return 0;
    return version_ - history_window_;
  }

  std::optional<Crypto::Hash> StateAccess::smtRootAtVersion(uint64_t version) const
  {
    if (!versionIsAvailable(version))
      return std::nullopt;
    return smt_.rootAtVersion(version);
  }

  std::optional<std::vector<uint8_t>> StateAccess::getRawAtVersion(
      const Crypto::Hash &smt_key, uint64_t version) const
  {
    if (!versionIsAvailable(version))
      return std::nullopt;
    return smt_.getAtVersion(smt_key, version);
  }

  Core::Account StateAccess::getAccountAtVersion(
      const Crypto::Address &address, uint64_t version) const
  {
    Core::Account result;

    if (!versionIsAvailable(version))
      return result;

    Crypto::Hash key = Keys::account(address);
    auto value = smt_.getAtVersion(key, version);
    if (!value.has_value())
      return result;

    Core::Account::deserializeState(value->data(), value->size(), result);
    return result;
  }

  bool StateAccess::getValidatorAtVersion(uint64_t validator_id,
                                          uint64_t version,
                                          Core::ValidatorInfo &out) const
  {
    if (!versionIsAvailable(version))
      return false;

    Crypto::Hash key = Keys::validator(validator_id);
    auto value = smt_.getAtVersion(key, version);
    if (!value.has_value())
      return false;
    return Core::ValidatorInfo::deserializeState(value->data(), value->size(), out);
  }

  bool StateAccess::getGlobalAtVersion(const std::string &name,
                                       uint64_t version,
                                       std::vector<uint8_t> &out) const
  {
    if (!versionIsAvailable(version))
      return false;

    Crypto::Hash key = Keys::global(name);
    auto value = smt_.getAtVersion(key, version);
    if (!value.has_value())
      return false;
    out = std::move(*value);
    return true;
  }

  ProofResult StateAccess::proveAtVersion(const Crypto::Hash &key,
                                          uint64_t version) const
  {
    ProofResult result;

    if (!versionIsAvailable(version))
    {
      result.status = ProofResultStatus::VersionUnavailable;
      return result;
    }

    auto root = smt_.rootAtVersion(version);
    if (!root.has_value())
    {
      result.status = ProofResultStatus::VersionUnavailable;
      return result;
    }

    auto proof = State::proveAtRoot(smt_, *root, key);
    if (!proof.has_value())
    {
      result.status = ProofResultStatus::KeyNotFound;
      return result;
    }

    result.status = ProofResultStatus::Ok;
    result.proof = std::move(proof);
    return result;
  }

  void StateAccess::indexBridgeWithdrawalRow(
      const Core::BridgeWithdrawal &w)
  {
    uint8_t height_key[16];
    encodeBridgeWithdrawalHeightKey(w.created_at_height, w.id, height_key);
    putSentinel(StateDB::TBL_INDEX_BRIDGE_WITHDRAWALS_BY_HEIGHT,
                height_key, sizeof(height_key));
  }

  void StateAccess::unindexBridgeWithdrawalRow(
      const Core::BridgeWithdrawal &w)
  {
    uint8_t height_key[16];
    encodeBridgeWithdrawalHeightKey(w.created_at_height, w.id, height_key);
    deleteRow(StateDB::TBL_INDEX_BRIDGE_WITHDRAWALS_BY_HEIGHT,
              height_key, sizeof(height_key));
  }

  //  =========================================================================
  //  Table stats
  //  =========================================================================

  size_t StateAccess::tableEntryCount(uint32_t table_id) const
  {
    return readTableCount(table_id);
  }

  StateDB::TableStats StateAccess::tableStats(uint32_t table_id) const
  {
    return db_.tableStats(table_id);
  }

  bool StateAccess::getMeta(const std::string &key,
                            std::vector<uint8_t> &out) const
  {
    return getMetaImpl(key, out);
  }

  void StateAccess::putMeta(const std::string &key,
                            const std::vector<uint8_t> &value)
  {
    putMetaImpl(key, value);
  }

} // namespace State