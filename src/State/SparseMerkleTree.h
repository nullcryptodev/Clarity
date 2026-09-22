// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "Crypto/Types.h"
#include "StateDB.h"

namespace State
{
  class SparseMerkleTree
  {
  public:
    static constexpr size_t DEPTH = 256;

    explicit SparseMerkleTree(StateDB &db);

    // Bind to a write transaction. All reads and writes route through it.
    // Pass nullptr to unbind and revert to autocommit behaviour.
    void setTxn(StateDB::Txn *txn) noexcept { txn_ = txn; }
    StateDB::Txn *txn() const noexcept { return txn_; }

    Crypto::Hash root() const noexcept { return root_; }

    std::optional<std::vector<uint8_t>> get(const Crypto::Hash &key) const;

    Crypto::Hash update(const Crypto::Hash &key,
                        const std::vector<uint8_t> &value,
                        uint64_t version);

    Crypto::Hash remove(const Crypto::Hash &key, uint64_t version);

    struct Update
    {
      Crypto::Hash key;
      std::vector<uint8_t> value;
      bool is_delete{false};
    };

    Crypto::Hash applyBatch(const std::vector<Update> &updates,
                            uint64_t version);

    std::optional<std::vector<uint8_t>> getAtVersion(
        const Crypto::Hash &key, uint64_t version) const;

    std::optional<Crypto::Hash> rootAtVersion(uint64_t version) const;

    void load();
    void save(uint64_t version);
    void pruneHistory(uint64_t keepFrom);

    bool readChildren(const Crypto::Hash &node_hash,
                      Crypto::Hash &left,
                      Crypto::Hash &right) const;

    static const Crypto::Hash &defaultHash(size_t depth) noexcept;

  private:
    struct InternalNode
    {
      Crypto::Hash left;
      Crypto::Hash right;
    };

    static Crypto::Hash hashInternal(const Crypto::Hash &left,
                                     const Crypto::Hash &right) noexcept;

    static Crypto::Hash hashLeaf(const Crypto::Hash &key,
                                 const std::vector<uint8_t> &value) noexcept;

    std::optional<InternalNode> fetchInternal(const Crypto::Hash &hash) const;

    void storeInternal(const Crypto::Hash &hash,
                       const InternalNode &node,
                       uint64_t version);

    Crypto::Hash updateRecursive(const Crypto::Hash &subtree_hash,
                                 const Crypto::Hash &key,
                                 const std::vector<uint8_t> &value,
                                 bool is_delete,
                                 size_t depth,
                                 uint64_t version);

    std::optional<std::vector<uint8_t>> getRecursive(
        const Crypto::Hash &subtree_hash,
        const Crypto::Hash &key,
        size_t depth) const;

    // ---- Txn-aware SMT storage helpers ----

    void putNodeImpl(const Crypto::Hash &hash,
                     const std::vector<uint8_t> &children,
                     uint64_t version);

    bool getNodeImpl(const Crypto::Hash &hash,
                     std::vector<uint8_t> &out) const;

    void putLeafDataImpl(const Crypto::Hash &leaf_hash,
                         const std::vector<uint8_t> &value,
                         uint64_t version);

    bool getLeafDataImpl(const Crypto::Hash &leaf_hash,
                         std::vector<uint8_t> &out) const;

    bool getMetaImpl(const std::string &key,
                     std::vector<uint8_t> &out) const;

    void putMetaImpl(const std::string &key,
                     const std::vector<uint8_t> &value);

    // ---- Members ----

    StateDB &db_;
    StateDB::Txn *txn_{nullptr};
    Crypto::Hash root_;
  };

  //  Key derivation
  //
  //  Every state object has a unique SMT position determined by
  //  Blake2b(domain4 || payload). The domain tag separates namespaces so
  //  no two object kinds can ever collide, and the payload determines
  //  the object's identity within its namespace.
  //
  //  Domain tags are 4 bytes and are chosen to be visually distinct.
  //  Once deployed, a tag must never change, that would move every key
  //  in the namespace and lose the state.

  namespace Keys
  {
    // Account record, keyed by address.
    Crypto::Hash account(const Crypto::Address &address) noexcept;

    // Token balance, keyed by (address, token_id).
    Crypto::Hash tokenBalance(const Crypto::Address &address, Id token_id) noexcept;

    // Token metadata, keyed by token_id.
    Crypto::Hash token(Id token_id) noexcept;

    // Cumulative minted supply per token. Tracked separately from the
    // token's metadata so the mint path can enforce maxSupply without
    // loading the whole TokenInfo record, and so a burn doesn't need to
    // rewrite the metadata.
    Crypto::Hash tokenSupply(Id token_id) noexcept;

    // Validator record, keyed by validator_id.
    Crypto::Hash validator(uint64_t validator_id) noexcept;

    // Validator lookup by reward address. Value is the 8-byte LE
    // validator_id. Written on registration and at genesis; read by the
    // reward distributor and by any caller that only has an address.
    Crypto::Hash validatorByAddress(const Crypto::Address &address) noexcept;

    // Order, keyed by order_id.
    Crypto::Hash order(uint64_t order_id) noexcept;

    // Order expiry index. One key per expiry height; the value is a
    // length-prefixed list of 8-byte LE order_ids expiring at that
    // height. Adding or removing an order is a read-modify-write of the
    // list. The list size is bounded by how many orders a user creates
    // for the same expiry height.
    Crypto::Hash orderExpiry(uint64_t height) noexcept;

    // Global state entry, keyed by name (max 64 bytes).
    Crypto::Hash global(const std::string &name) noexcept;

    // AMM pool, keyed by pool_id.
    Crypto::Hash ammPool(uint64_t pool_id) noexcept;

    // AMM LP position, keyed by position_id.
    Crypto::Hash ammPosition(uint64_t position_id) noexcept;

    // LP position index, keyed by (owner, pool_id). Value is the 8-byte
    // LE position_id. Enforces "one position per (owner, pool)" so
    // AddLiquidity merges into the existing position rather than creating
    // a new one on every call.
    Crypto::Hash ammPositionIndex(const Crypto::Address &owner,
                                  uint64_t pool_id) noexcept;

    // Receipt, keyed by transaction hash.
    Crypto::Hash receipt(const Crypto::Hash &tx_hash) noexcept;
  }

} // namespace State