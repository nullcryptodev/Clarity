// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "Core/Account.h"
#include "Core/AmmPool.h"
#include "Core/AmmPosition.h"
#include "Core/Order.h"
#include "Core/Receipt.h"
#include "Core/TokenTypes.h"
#include "Core/ValidatorTypes.h"
#include "Crypto/Types.h"
#include "SparseMerkleTree.h"
#include "StateDB.h"

namespace State
{
  class StateAccess
  {
  public:
    // Autocommit mode: each operation opens its own txn internally.
    StateAccess(StateDB &db, uint64_t version);

    // Txn-bound mode: all writes go through the given txn.
    // The txn is NOT owned by StateAccess. Caller commits or aborts.
    StateAccess(StateDB &db, StateDB::Txn &txn, uint64_t version);

    // ---- Accounts ----

    Core::Account getAccount(const Crypto::Address &address) const;
    bool accountExists(const Crypto::Address &address) const;
    void putAccount(const Crypto::Address &address,
                    const Core::Account &account);
    void deleteAccount(const Crypto::Address &address);

    // ---- Token balances ----

    uint64_t getTokenBalance(const Crypto::Address &address, Id token_id) const;
    void putTokenBalance(const Crypto::Address &address, Id token_id, uint64_t balance);
    void deleteTokenBalance(const Crypto::Address &address, Id token_id);

    // ---- Token metadata ----

    bool getToken(Id token_id, Core::TokenInfo &out) const;
    void putToken(const Core::TokenInfo &token);

    // ---- Token supply ----
    //
    // The cumulative minted supply per token, tracked separately from
    // the token's metadata. Used to enforce maxSupply on mint without
    // relying on any single account's balance, and decremented on burn.
    //
    // The native token's supply is tracked in global state under
    // "total_supply", not here — the native token has no mint/burn
    // path.

    uint64_t getTokenSupply(Id token_id) const;
    void putTokenSupply(Id token_id, uint64_t supply);

    // ---- Validators ----

    bool getValidator(uint64_t validator_id, Core::ValidatorInfo &out) const;
    void putValidator(const Core::ValidatorInfo &validator);
    void deleteValidator(uint64_t validator_id);

    // ---- Validator lookup by reward address ----
    //
    // Maps a validator's reward_address to its validator_id. Written
    // when a validator is registered or seeded at genesis. Read by the
    // reward distributor to identify the block proposer, and by any
    // caller that has only an address.

    bool getValidatorByAddress(const Crypto::Address &address,
                               uint64_t &validator_id_out) const;
    void putValidatorByAddress(const Crypto::Address &address,
                               uint64_t validator_id);
    void deleteValidatorByAddress(const Crypto::Address &address);

    // ---- Orders ----

    bool getOrder(Id order_id, Core::Order &out) const;
    void putOrder(const Core::Order &order);
    void deleteOrder(Id order_id);

    // ---- Order expiry index ----
    //
    // One SMT entry per expiry height. The value is a length-prefixed
    // list of 8-byte LE order IDs. Adding or removing an order is a
    // read-modify-write of the list. Used by BlockProcessor's order
    // expiry pass to find all orders due at the current height without
    // scanning the whole order ID space.

    std::vector<uint64_t> getOrdersExpiringAt(uint64_t height) const;
    void addOrderExpiry(uint64_t height, uint64_t order_id);
    void removeOrderExpiry(uint64_t height, uint64_t order_id);

    // ---- AMM Pools ----

    bool getAmmPool(Id pool_id, Core::AmmPool &out) const;
    void putAmmPool(const Core::AmmPool &pool);

    // ---- AMM Positions ----

    bool getAmmPosition(Id pos_id, Core::AmmPosition &out) const;
    void putAmmPosition(const Core::AmmPosition &pos);
    void deleteAmmPosition(Id pos_id);

    // ---- LP position index ----
    //
    // Maps (owner, pool_id) to a position_id. Enforces the invariant
    // that a given owner has at most one LP position per pool, so
    // AddLiquidity can merge into an existing position rather than
    // creating a new one on every call.

    bool getPositionIndex(const Crypto::Address &owner,
                          uint64_t pool_id,
                          uint64_t &position_id_out) const;
    void putPositionIndex(const Crypto::Address &owner,
                          uint64_t pool_id,
                          uint64_t position_id);
    void deletePositionIndex(const Crypto::Address &owner,
                             uint64_t pool_id);

    // ---- Receipts ----

    bool getReceipt(const Crypto::Hash &tx_hash, Core::Receipt &out) const;
    void putReceipt(const Crypto::Hash &tx_hash, const Core::Receipt &receipt);

    // ---- Global state ----

    bool getGlobal(const std::string &name, std::vector<uint8_t> &out) const;
    void putGlobal(const std::string &name, const std::vector<uint8_t> &value);

    // ---- Raw SMT access ----

    std::optional<std::vector<uint8_t>> getRaw(const Crypto::Hash &smt_key) const;
    void putRaw(const Crypto::Hash &smt_key, const std::vector<uint8_t> &value);
    void deleteRaw(const Crypto::Hash &smt_key);

    // ---- Commit ----

    void commit(uint64_t version);
    Crypto::Hash stateRoot() const { return smt_.root(); }

    // ---- Indexes (node-local) ----
    //
    // The staker index is txn-aware: if this StateAccess is bound to a
    // txn, indexStaker / unindexStaker / forEachStaker all route through
    // that txn, so writes made earlier in the same txn are visible to
    // a subsequent forEachStaker call.
    //
    // In autocommit mode, each call opens its own read/write txn.

    void indexStaker(const Crypto::Address &address);
    void unindexStaker(const Crypto::Address &address);
    void forEachStaker(const std::function<void(const Crypto::Address &)> &fn) const;

    // Clear the entire bucket for a height in one operation. Used by
    // BlockProcessor's expiry pass after processing every order in
    // the bucket, avoiding N read-modify-writes.
    void clearOrderExpiry(uint64_t height);

  private:
    // Txn-aware storage helpers.
    void putMetaImpl(const std::string &key,
                     const std::vector<uint8_t> &value);
    bool getMetaImpl(const std::string &key,
                     std::vector<uint8_t> &out) const;

    StateDB &db_;
    StateDB::Txn *txn_{nullptr};
    uint64_t version_;
    SparseMerkleTree smt_;
  };

} // namespace State