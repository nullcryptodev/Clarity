// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StateAccess.h"

#include "Core/GlobalState.h"
#include "Core/RewardTypes.h"

#include <algorithm>
#include <cstring>

namespace State
{

  //  Little-endian list encoding helpers

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

  //  Accounts

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
    copy.recalculateStaked(Core::AUTO_STAKE_THRESHOLD);

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

    // Helper: read a uint64 from a global state entry via the SMT.
    auto readGlobalU64 = [this](const char *name) -> uint64_t
    {
      std::vector<uint8_t> bytes;
      if (!getGlobal(name, bytes) || bytes.size() != 8)
        return 0;
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(bytes[i]) << (i * 8);
      return v;
    };

    auto writeGlobalU64 = [this](const char *name, uint64_t v)
    {
      std::vector<uint8_t> bytes(8);
      for (int i = 0; i < 8; ++i)
        bytes[i] = uint8_t(v >> (i * 8));
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

    if (!was_staker)
      return;

    auto readGlobalU64 = [this](const char *name) -> uint64_t
    {
      std::vector<uint8_t> bytes;
      if (!getGlobal(name, bytes) || bytes.size() != 8)
        return 0;
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(bytes[i]) << (i * 8);
      return v;
    };

    auto writeGlobalU64 = [this](const char *name, uint64_t v)
    {
      std::vector<uint8_t> bytes(8);
      for (int i = 0; i < 8; ++i)
        bytes[i] = uint8_t(v >> (i * 8));
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

  //  Token balances

  uint64_t StateAccess::getTokenBalance(const Crypto::Address &address, Id token_id) const
  {
    Crypto::Hash key = Keys::tokenBalance(address, token_id);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return 0;

    uint64_t balance = 0;
    for (int i = 0; i < 8; ++i)
      balance |= uint64_t((*value)[i]) << (i * 8);
    return balance;
  }

  void StateAccess::putTokenBalance(const Crypto::Address &address, Id token_id, uint64_t balance)
  {
    Crypto::Hash key = Keys::tokenBalance(address, token_id);

    if (balance == 0)
    {
      smt_.remove(key, version_);
      return;
    }

    std::vector<uint8_t> value(8);
    for (int i = 0; i < 8; ++i)
      value[i] = uint8_t(balance >> (i * 8));
    smt_.update(key, value, version_);
  }

  void StateAccess::deleteTokenBalance(const Crypto::Address &address, Id token_id)
  {
    Crypto::Hash key = Keys::tokenBalance(address, token_id);
    smt_.remove(key, version_);
  }

  //  Token metadata

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
  }

  //  Token supply

  uint64_t StateAccess::getTokenSupply(Id token_id) const
  {
    Crypto::Hash key = Keys::tokenSupply(token_id);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return 0;

    uint64_t supply = 0;
    for (int i = 0; i < 8; ++i)
      supply |= uint64_t((*value)[i]) << (i * 8);
    return supply;
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
    for (int i = 0; i < 8; ++i)
      value[i] = uint8_t(supply >> (i * 8));
    smt_.update(key, value, version_);
  }

  //  Validators

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
  }

  void StateAccess::deleteValidator(uint64_t validator_id)
  {
    Crypto::Hash key = Keys::validator(validator_id);
    smt_.remove(key, version_);
  }

  //  Validator by address

  bool StateAccess::getValidatorByAddress(const Crypto::Address &address,
                                          uint64_t &validator_id_out) const
  {
    Crypto::Hash key = Keys::validatorByAddress(address);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return false;

    uint64_t id = 0;
    for (int i = 0; i < 8; ++i)
      id |= uint64_t((*value)[i]) << (i * 8);
    validator_id_out = id;
    return true;
  }

  void StateAccess::putValidatorByAddress(const Crypto::Address &address,
                                          uint64_t validator_id)
  {
    Crypto::Hash key = Keys::validatorByAddress(address);
    std::vector<uint8_t> value(8);
    for (int i = 0; i < 8; ++i)
      value[i] = uint8_t(validator_id >> (i * 8));
    smt_.update(key, value, version_);
  }

  void StateAccess::deleteValidatorByAddress(const Crypto::Address &address)
  {
    Crypto::Hash key = Keys::validatorByAddress(address);
    smt_.remove(key, version_);
  }

  //  Orders

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
  }

  void StateAccess::deleteOrder(Id order_id)
  {
    Crypto::Hash key = Keys::order(order_id);
    smt_.remove(key, version_);
  }

  //  Order expiry index

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

  //  AMM Pools

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
  }

  //  AMM Positions

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
  }

  void StateAccess::deleteAmmPosition(Id pos_id)
  {
    Crypto::Hash key = Keys::ammPosition(pos_id);
    smt_.remove(key, version_);
  }

  //  LP position index

  bool StateAccess::getPositionIndex(const Crypto::Address &owner,
                                     uint64_t pool_id,
                                     uint64_t &position_id_out) const
  {
    Crypto::Hash key = Keys::ammPositionIndex(owner, pool_id);
    auto value = smt_.get(key);
    if (!value.has_value() || value->size() != 8)
      return false;

    uint64_t id = 0;
    for (int i = 0; i < 8; ++i)
      id |= uint64_t((*value)[i]) << (i * 8);
    position_id_out = id;
    return true;
  }

  void StateAccess::putPositionIndex(const Crypto::Address &owner,
                                     uint64_t pool_id,
                                     uint64_t position_id)
  {
    Crypto::Hash key = Keys::ammPositionIndex(owner, pool_id);
    std::vector<uint8_t> value(8);
    for (int i = 0; i < 8; ++i)
      value[i] = uint8_t(position_id >> (i * 8));
    smt_.update(key, value, version_);
  }

  void StateAccess::deletePositionIndex(const Crypto::Address &owner,
                                        uint64_t pool_id)
  {
    Crypto::Hash key = Keys::ammPositionIndex(owner, pool_id);
    smt_.remove(key, version_);
  }

  //  Receipts

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

  //  Global state

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

  //  Raw SMT access

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

  //  Commit

  void StateAccess::commit(uint64_t version)
  {
    version_ = version;
    smt_.save(version);

    if (!txn_)
      db_.flush();
  }

  //  Indexes

  void StateAccess::indexStaker(const Crypto::Address &address)
  {
    static const uint8_t SENTINEL[1] = {0x01};

    if (txn_)
    {
      txn_->put(StateDB::TBL_INDEX_STAKERS,
                address.data.data(), address.data.size(),
                SENTINEL, sizeof(SENTINEL));
      return;
    }
    db_.rawPut(StateDB::TBL_INDEX_STAKERS,
               address.data.data(), address.data.size(),
               SENTINEL, sizeof(SENTINEL));
  }

  void StateAccess::unindexStaker(const Crypto::Address &address)
  {
    if (txn_)
    {
      txn_->del(StateDB::TBL_INDEX_STAKERS,
                address.data.data(), address.data.size());
      return;
    }
    db_.rawDel(StateDB::TBL_INDEX_STAKERS,
               address.data.data(), address.data.size());
  }

  void StateAccess::forEachStaker(
      const std::function<void(const Crypto::Address &)> &fn) const
  {
    auto visitor = [&fn](const std::vector<uint8_t> &key,
                         const std::vector<uint8_t> & /*value*/)
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

  //  Txn-aware helpers

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

} // namespace State