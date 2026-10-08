// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StateAccess.h"

#include "Common/Wire.h"
#include "Core/GlobalState.h"
#include "Core/RewardTypes.h"

#include <algorithm>
#include <cstring>

namespace State
{

  //  Little-endian list encoding helpers.
  //
  //  Order-expiry lists are stored as a 4-byte count followed by N
  //  8-byte LE IDs. This is specific to the order-expiry index and
  //  isn't a general-purpose format, so it stays here rather than in
  //  Common/Wire.h.

  namespace
  {
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
  } // anonymous namespace

  //  Construction

  StateAccess::StateAccess(StateDB &db, uint64_t version)
      : db_(db), txn_(nullptr), version_(version), smt_(db)
  {
    smt_.load();
  }

  StateAccess::StateAccess(StateDB &db, StateDB::Txn &txn, uint64_t version)
      : db_(db), txn_(&txn), version_(version), smt_(db)
  {
    smt_.setTxn(txn_);
    smt_.load();
  }

  // ===========================================================================
  //  Low-level index primitives
  // ===========================================================================

  void StateAccess::putSentinel(uint32_t table_id,
                                const void *key, size_t key_len)
  {
    static const uint8_t SENTINEL[1] = {0x01};

    if (txn_)
    {
      txn_->put(table_id, key, key_len, SENTINEL, sizeof(SENTINEL));
      return;
    }
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
    db_.rawDel(table_id, key, key_len);
  }

  // ===========================================================================
  //  Index writers — one per entity type
  // ===========================================================================

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
    // Two directions:
    //   TBL_TOKEN_BALANCES          key = address(32) || token_id(4 LE)
    //   TBL_INDEX_BALANCES_BY_TOKEN key = token_id(4 LE) || address(32)
    //
    // Both hold the balance as an 8-byte LE value.

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

    // Two index rows, one per token, so forEachPoolForToken works
    // regardless of which side of the pair a token is on.
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

    // Owner index. Key = owner(32) || position_id(8 LE).
    // Value = pool_id(8 LE), so callers can resolve the pool without
    // a second lookup.
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

    // Owner index.
    uint8_t owner_key[40];
    std::memcpy(owner_key, owner.data.data(), 32);
    Common::writeU64(owner_key + 32, order_id);
    putSentinel(StateDB::TBL_INDEX_ORDERS_BY_OWNER,
                owner_key, sizeof(owner_key));

    // Pair index. Key = sell(4 LE) || buy(4 LE) || order_id(8 LE).
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

  // ===========================================================================
  //  Transaction and block indexes (called by BlockProcessor)
  // ===========================================================================

  void StateAccess::indexTransaction(
      const Crypto::Hash &txid,
      uint64_t block_height,
      uint32_t tx_index_in_block,
      const std::vector<Crypto::Address> &addresses,
      const std::vector<Id> &token_ids,
      uint8_t tx_type)
  {
    // By-address. One row per unique address.
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

    // By-token. One row per unique token.
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

    // By-type.
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

  // ===========================================================================
  //  Accounts
  // ===========================================================================

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

    // ---- Update staker_since_height based on the transition ----

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

    // ---- Write the account record ----

    Crypto::Hash key = Keys::account(address);
    auto value = copy.serializeState();
    smt_.update(key, value, version_);

    // ---- Write the index row ----
    //
    // The MDBX table holds a serialized copy for enumeration. Both
    // writes happen in the same txn, so the two representations
    // cannot drift.
    {
      auto bytes = copy.serializeState();
      putBlobRow(StateDB::TBL_ACCOUNTS,
                 address.data.data(), address.data.size(),
                 bytes.data(), bytes.size());
    }

    // Helper: read a uint64 from a global state entry via the SMT.
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

    // ---- Maintain total_staked ----

    if (copy.staked != old.staked)
    {
      uint64_t total = readGlobalU64("total_staked");

      if (copy.staked >= old.staked)
        total += copy.staked - old.staked;
      else
        total -= (old.staked - copy.staked);

      writeGlobalU64("total_staked", total);
    }

    // ---- Maintain the staker index and staker_count ----

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

    Crypto::Hash key = Keys::account(address);
    smt_.remove(key, version_);

    unindexAccountRow(address);

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
    // The MDBX table holds the serialized Account inline, so no SMT
    // read is required per entry.
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

    if (txn_)
    {
      txn_->forEach(StateDB::TBL_ACCOUNTS, visitor);
      return;
    }
    db_.forEachEntry(StateDB::TBL_ACCOUNTS, visitor);
  }

  // ===========================================================================
  //  Token balances
  // ===========================================================================

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
    Crypto::Hash key = Keys::tokenBalance(address, token_id);
    smt_.remove(key, version_);
    unindexTokenBalanceRow(address, token_id);
  }

  void StateAccess::forEachTokenBalanceForOwner(
      const Crypto::Address &owner,
      const std::function<void(Id token_id, uint64_t balance)> &fn) const
  {
    // Key layout: address(32) || token_id(4 LE). Value: balance(8 LE).
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

    if (txn_)
    {
      txn_->forEachWithPrefix(StateDB::TBL_TOKEN_BALANCES, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefix(StateDB::TBL_TOKEN_BALANCES, prefix, visitor);
  }

  void StateAccess::forEachHolderOfToken(
      Id token_id,
      const std::function<void(const Crypto::Address &, uint64_t balance)> &fn) const
  {
    // Key layout: token_id(4 LE) || address(32). Value: balance(8 LE).
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
      fn(addr, balance);
      return true;
    };

    if (txn_)
    {
      txn_->forEachWithPrefix(StateDB::TBL_INDEX_BALANCES_BY_TOKEN, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefix(StateDB::TBL_INDEX_BALANCES_BY_TOKEN, prefix, visitor);
  }

  // ===========================================================================
  //  Token metadata
  // ===========================================================================

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

    if (txn_)
    {
      txn_->forEach(StateDB::TBL_TOKENS, visitor);
      return;
    }
    db_.forEachEntry(StateDB::TBL_TOKENS, visitor);
  }

  // ===========================================================================
  //  Token supply
  // ===========================================================================

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

  // ===========================================================================
  //  Validators
  // ===========================================================================

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
    Crypto::Hash key = Keys::validator(validator.id);
    auto value = validator.serializeState();
    smt_.update(key, value, version_);

    // Write to two tables:
    //   TBL_INDEX_VALIDATORS  key = id(8 LE) -> sentinel
    //   TBL_VALIDATORS        key = id(8 LE) -> serialized record

    uint8_t id_key[8];
    Common::writeU64(id_key, validator.id);

    putSentinel(StateDB::TBL_INDEX_VALIDATORS, id_key, sizeof(id_key));
    putBlobRow(StateDB::TBL_VALIDATORS, id_key, sizeof(id_key),
               value.data(), value.size());
  }

  void StateAccess::deleteValidator(uint64_t validator_id)
  {
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
    // Read the full records from TBL_VALIDATORS, which holds the
    // serialized ValidatorInfo inline.
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

    if (txn_)
    {
      txn_->forEach(StateDB::TBL_VALIDATORS, visitor);
      return;
    }
    db_.forEachEntry(StateDB::TBL_VALIDATORS, visitor);
  }

  // ===========================================================================
  //  Validator by address
  // ===========================================================================

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
    Crypto::Hash key = Keys::validatorByAddress(address);
    std::vector<uint8_t> value(8);
    Common::writeU64(value.data(), validator_id);
    smt_.update(key, value, version_);
  }

  void StateAccess::deleteValidatorByAddress(const Crypto::Address &address)
  {
    Crypto::Hash key = Keys::validatorByAddress(address);
    smt_.remove(key, version_);
  }

  // ===========================================================================
  //  Orders
  // ===========================================================================

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
    Crypto::Hash key = Keys::order(order.id);
    auto value = order.serializeState();
    smt_.update(key, value, version_);

    indexOrderRow(order.id, order.owner, order.sell_token, order.buy_token);
  }

  void StateAccess::deleteOrder(Id order_id)
  {
    // Fetch the order first so we know the owner and pair to unindex.
    Core::Order order;
    const bool have_order = getOrder(order_id, order);

    Crypto::Hash key = Keys::order(order_id);
    smt_.remove(key, version_);

    if (have_order)
      unindexOrderRow(order_id, order.owner, order.sell_token, order.buy_token);
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

    if (txn_)
    {
      txn_->forEach(StateDB::TBL_ORDERS, visitor);
      return;
    }
    db_.forEachEntry(StateDB::TBL_ORDERS, visitor);
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

    if (txn_)
    {
      txn_->forEachWithPrefix(StateDB::TBL_INDEX_ORDERS_BY_OWNER, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefix(StateDB::TBL_INDEX_ORDERS_BY_OWNER, prefix, visitor);
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

    if (txn_)
    {
      txn_->forEachWithPrefix(StateDB::TBL_INDEX_ORDERS_BY_PAIR, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefix(StateDB::TBL_INDEX_ORDERS_BY_PAIR, prefix, visitor);
  }

  // ===========================================================================
  //  Order expiry index
  // ===========================================================================

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
    Crypto::Hash key = Keys::orderExpiry(height);
    smt_.remove(key, version_);
  }

  // ===========================================================================
  //  AMM Pools
  // ===========================================================================

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
    Crypto::Hash key = Keys::ammPool(pool.id);
    auto value = pool.serializeState();
    smt_.update(key, value, version_);

    indexAmmPoolRow(pool.id, pool.token_a, pool.token_b);
  }

  void StateAccess::deleteAmmPool(Id pool_id)
  {
    // Fetch the pool first so we know its token pair for unindexing.
    Core::AmmPool pool;
    const bool have_pool = getAmmPool(pool_id, pool);

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

    if (txn_)
    {
      txn_->forEach(StateDB::TBL_AMM_POOLS, visitor);
      return;
    }
    db_.forEachEntry(StateDB::TBL_AMM_POOLS, visitor);
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

    if (txn_)
    {
      txn_->forEachWithPrefix(StateDB::TBL_INDEX_POOLS_BY_TOKEN, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefix(StateDB::TBL_INDEX_POOLS_BY_TOKEN, prefix, visitor);
  }

  // ===========================================================================
  //  AMM Positions
  // ===========================================================================

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
    Crypto::Hash key = Keys::ammPosition(pos.id);
    auto value = pos.serializeState();
    smt_.update(key, value, version_);

    indexAmmPositionRow(pos.id, pos.owner);
  }

  void StateAccess::deleteAmmPosition(Id pos_id)
  {
    Core::AmmPosition pos;
    const bool have_pos = getAmmPosition(pos_id, pos);

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

    if (txn_)
    {
      txn_->forEach(StateDB::TBL_AMM_POSITIONS, visitor);
      return;
    }
    db_.forEachEntry(StateDB::TBL_AMM_POSITIONS, visitor);
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

    if (txn_)
    {
      txn_->forEachWithPrefix(StateDB::TBL_INDEX_POSITIONS_BY_OWNER, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefix(StateDB::TBL_INDEX_POSITIONS_BY_OWNER, prefix, visitor);
  }

  // ===========================================================================
  //  LP position index
  // ===========================================================================

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
    Crypto::Hash key = Keys::ammPositionIndex(owner, pool_id);
    std::vector<uint8_t> value(8);
    Common::writeU64(value.data(), position_id);
    smt_.update(key, value, version_);
  }

  void StateAccess::deletePositionIndex(const Crypto::Address &owner,
                                        uint64_t pool_id)
  {
    Crypto::Hash key = Keys::ammPositionIndex(owner, pool_id);
    smt_.remove(key, version_);
  }

  // ===========================================================================
  //  Receipts
  // ===========================================================================

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
    Crypto::Hash key = Keys::receipt(tx_hash);
    auto value = receipt.serializeState();
    smt_.update(key, value, version_);
  }

  // ===========================================================================
  //  Global state
  // ===========================================================================

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

  // ===========================================================================
  //  Raw SMT access
  // ===========================================================================

  std::optional<std::vector<uint8_t>> StateAccess::getRaw(const Crypto::Hash &smt_key) const
  {
    return smt_.get(smt_key);
  }

  void StateAccess::putRaw(const Crypto::Hash &smt_key,
                           const std::vector<uint8_t> &value)
  {
    smt_.update(smt_key, value, version_);
  }

  void StateAccess::deleteRaw(const Crypto::Hash &smt_key)
  {
    smt_.remove(smt_key, version_);
  }

  // ===========================================================================
  //  Commit
  // ===========================================================================

  void StateAccess::commit(uint64_t version)
  {
    version_ = version;
    smt_.save(version);

    if (!txn_)
      db_.flush();
  }

  // ===========================================================================
  //  Indexes
  // ===========================================================================

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

    if (txn_)
    {
      txn_->forEach(StateDB::TBL_INDEX_STAKERS, visitor);
      return;
    }
    db_.forEachEntry(StateDB::TBL_INDEX_STAKERS, visitor);
  }

  // ===========================================================================
  //  Transaction history queries
  // ===========================================================================

  void StateAccess::forEachRecentTxForAddress(
      const Crypto::Address &address,
      size_t max_results,
      const std::function<void(const Crypto::Hash &txid,
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

      fn(txid, height, tx_idx);
      ++emitted;
      return true;
    };

    if (txn_)
    {
      txn_->forEachWithPrefixReverse(
          StateDB::TBL_INDEX_TX_BY_ADDRESS, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefixReverse(
        StateDB::TBL_INDEX_TX_BY_ADDRESS, prefix, visitor);
  }

  void StateAccess::forEachRecentTxForToken(
      Id token_id,
      size_t max_results,
      const std::function<void(const Crypto::Hash &txid,
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

      fn(txid, height, tx_idx);
      ++emitted;
      return true;
    };

    if (txn_)
    {
      txn_->forEachWithPrefixReverse(
          StateDB::TBL_INDEX_TX_BY_TOKEN, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefixReverse(
        StateDB::TBL_INDEX_TX_BY_TOKEN, prefix, visitor);
  }

  void StateAccess::forEachRecentTxOfType(
      uint8_t tx_type,
      size_t max_results,
      const std::function<void(const Crypto::Hash &txid,
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

      fn(txid, height, tx_idx);
      ++emitted;
      return true;
    };

    if (txn_)
    {
      txn_->forEachWithPrefixReverse(
          StateDB::TBL_INDEX_TX_BY_TYPE, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefixReverse(
        StateDB::TBL_INDEX_TX_BY_TYPE, prefix, visitor);
  }

  void StateAccess::forEachBlockByProducer(
      const Crypto::Address &proposer,
      size_t max_results,
      const std::function<void(uint64_t block_height,
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

      fn(height, block_hash);
      ++emitted;
      return true;
    };

    if (txn_)
    {
      txn_->forEachWithPrefixReverse(
          StateDB::TBL_INDEX_BLOCKS_BY_PRODUCER, prefix, visitor);
      return;
    }
    db_.forEachEntryWithPrefixReverse(
        StateDB::TBL_INDEX_BLOCKS_BY_PRODUCER, prefix, visitor);
  }

  // ===========================================================================
  //  Txn-aware helpers
  // ===========================================================================

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
    db_.putMeta(key, value);
  }

  bool StateAccess::getMetaImpl(const std::string &key,
                                std::vector<uint8_t> &out) const
  {
    if (txn_)
    {
      return txn_->get(StateDB::TBL_META,
                       key.data(), key.size(), out);
    }
    return db_.getMeta(key, out);
  }

  std::optional<Crypto::Hash> StateAccess::smtRootAtVersion(uint64_t version) const
  {
    return smt_.rootAtVersion(version);
  }

  // ===========================================================================
  //  Versioned reads
  // ===========================================================================

  std::optional<std::vector<uint8_t>> StateAccess::getRawAtVersion(
      const Crypto::Hash &smt_key, uint64_t version) const
  {
    return smt_.getAtVersion(smt_key, version);
  }

  Core::Account StateAccess::getAccountAtVersion(
      const Crypto::Address &address, uint64_t version) const
  {
    Core::Account result;

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
    Crypto::Hash key = Keys::global(name);
    auto value = smt_.getAtVersion(key, version);
    if (!value.has_value())
      return false;
    out = std::move(*value);
    return true;
  }

  std::optional<State::SmtProof> StateAccess::proveAtVersion(
      const Crypto::Hash &key, uint64_t version) const
  {
    auto root = smt_.rootAtVersion(version);
    if (!root.has_value())
      return std::nullopt;

    return State::proveAtRoot(smt_, *root, key);
  }

  // ===========================================================================
  //  Table stats
  // ===========================================================================

  size_t StateAccess::tableEntryCount(uint32_t table_id) const
  {
    return db_.entryCount(table_id);
  }

} // namespace State