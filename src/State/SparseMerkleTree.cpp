// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SparseMerkleTree.h"
#include "StateDB.h"
#include "SmtProof.h"

#include "Crypto/Blake2b.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace State
{
  namespace
  {
    // ---- Domain separators ----
    constexpr uint8_t NODE_INTERNAL = 0x01;
    constexpr uint8_t NODE_LEAF = 0x00;

    // ---- Hash helpers ----

    inline void blake2b(const uint8_t *data, size_t len, Crypto::Hash &out)
    {
      Crypto::blake2b(data, len, out.data.data(), 32);
    }

    Crypto::Hash computeLeaf(const Crypto::Hash &key,
                             const std::vector<uint8_t> &value) noexcept
    {
      Crypto::Hash value_hash;
      blake2b(value.data(), value.size(), value_hash);

      uint8_t buf[1 + 32 + 32];
      buf[0] = NODE_LEAF;
      std::memcpy(buf + 1, key.data.data(), 32);
      std::memcpy(buf + 33, value_hash.data.data(), 32);
      Crypto::Hash h;
      blake2b(buf, sizeof(buf), h);
      return h;
    }

    struct DefaultHashes
    {
      std::array<Crypto::Hash, SparseMerkleTree::DEPTH + 1> values;

      DefaultHashes() noexcept
      {
        uint8_t zero_leaf_buf[1 + 32];
        zero_leaf_buf[0] = NODE_LEAF;
        std::memset(zero_leaf_buf + 1, 0, 32);
        blake2b(zero_leaf_buf, sizeof(zero_leaf_buf), values[0]);

        for (size_t d = 1; d <= SparseMerkleTree::DEPTH; ++d)
        {
          uint8_t buf[1 + 32 + 32];
          buf[0] = NODE_INTERNAL;
          std::memcpy(buf + 1, values[d - 1].data.data(), 32);
          std::memcpy(buf + 33, values[d - 1].data.data(), 32);
          blake2b(buf, sizeof(buf), values[d]);
        }
      }
    };

    const DefaultHashes &getDefaultHashes() noexcept
    {
      static const DefaultHashes instance;
      return instance;
    }
  } // anonymous namespace

  //  Static helpers

  Crypto::Hash SparseMerkleTree::hashInternal(const Crypto::Hash &left,
                                              const Crypto::Hash &right) noexcept
  {
    uint8_t buf[1 + 32 + 32];
    buf[0] = NODE_INTERNAL;
    std::memcpy(buf + 1, left.data.data(), 32);
    std::memcpy(buf + 33, right.data.data(), 32);
    Crypto::Hash h;
    blake2b(buf, sizeof(buf), h);
    return h;
  }

  Crypto::Hash SparseMerkleTree::hashLeaf(const Crypto::Hash &key,
                                          const std::vector<uint8_t> &value) noexcept
  {
    return computeLeaf(key, value);
  }

  const Crypto::Hash &SparseMerkleTree::defaultHash(size_t depth) noexcept
  {
    if (depth > DEPTH)
      depth = DEPTH;
    return getDefaultHashes().values[depth];
  }

  //  Construction

  SparseMerkleTree::SparseMerkleTree(StateDB &db)
      : db_(db), root_(defaultHash(DEPTH))
  {
  }

  //  Txn-aware storage helpers
  //
  //  Every read/write of SMT nodes, leaves, and meta goes through one of
  //  these. If a txn is bound, the txn is used; otherwise the DB's raw
  //  autocommit path is used.

  bool SparseMerkleTree::getNodeImpl(const Crypto::Hash &hash,
                                     std::vector<uint8_t> &out) const
  {
    if (txn_)
    {
      return txn_->get(StateDB::TBL_SMT_NODES,
                       hash.data.data(), hash.data.size(), out);
    }
    return db_.getNode(hash, out);
  }

  void SparseMerkleTree::putNodeImpl(const Crypto::Hash &hash,
                                     const std::vector<uint8_t> &children,
                                     uint64_t /*version*/)
  {
    if (txn_)
    {
      txn_->put(StateDB::TBL_SMT_NODES,
                hash.data.data(), hash.data.size(),
                children.data(), children.size());
      return;
    }
    db_.putNode(hash, children, 0);
  }

  bool SparseMerkleTree::getLeafDataImpl(const Crypto::Hash &leaf_hash,
                                         std::vector<uint8_t> &out) const
  {
    if (txn_)
    {
      return txn_->get(StateDB::TBL_SMT_LEAVES,
                       leaf_hash.data.data(), leaf_hash.data.size(), out);
    }
    return db_.getLeafData(leaf_hash, out);
  }

  void SparseMerkleTree::putLeafDataImpl(const Crypto::Hash &leaf_hash,
                                         const std::vector<uint8_t> &value,
                                         uint64_t /*version*/)
  {
    if (txn_)
    {
      txn_->put(StateDB::TBL_SMT_LEAVES,
                leaf_hash.data.data(), leaf_hash.data.size(),
                value.data(), value.size());
      return;
    }
    db_.putLeafData(leaf_hash, value, 0);
  }

  bool SparseMerkleTree::getMetaImpl(const std::string &key,
                                     std::vector<uint8_t> &out) const
  {
    if (txn_)
    {
      return txn_->get(StateDB::TBL_META,
                       key.data(), key.size(), out);
    }
    return db_.getMeta(key, out);
  }

  void SparseMerkleTree::putMetaImpl(const std::string &key,
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

  //  Persistence

  void SparseMerkleTree::load()
  {
    std::vector<uint8_t> stored;
    if (getMetaImpl("smt_root", stored) && stored.size() == 32)
    {
      std::memcpy(root_.data.data(), stored.data(), 32);
    }
    else
    {
      root_ = defaultHash(DEPTH);
    }
  }

  void SparseMerkleTree::save(uint64_t version)
  {
    std::vector<uint8_t> root_bytes(root_.data.begin(), root_.data.end());
    putMetaImpl("smt_root", root_bytes);

    std::string version_key = "smt_root_at_" + std::to_string(version);
    putMetaImpl(version_key, root_bytes);
  }

  std::optional<Crypto::Hash> SparseMerkleTree::rootAtVersion(uint64_t version) const
  {
    std::string version_key = "smt_root_at_" + std::to_string(version);
    std::vector<uint8_t> stored;
    if (!getMetaImpl(version_key, stored) || stored.size() != 32)
    {
      return std::nullopt;
    }
    Crypto::Hash h;
    std::memcpy(h.data.data(), stored.data(), 32);
    return h;
  }

  //  Read

  std::optional<std::vector<uint8_t>> SparseMerkleTree::get(const Crypto::Hash &key) const
  {
    return getRecursive(root_, key, DEPTH);
  }

  std::optional<std::vector<uint8_t>> SparseMerkleTree::getRecursive(
      const Crypto::Hash &subtree_hash,
      const Crypto::Hash &key,
      size_t depth) const
  {
    if (subtree_hash == defaultHash(depth))
    {
      return std::nullopt;
    }

    if (depth == 0)
    {
      // The canonical empty leaf is a non-inclusion.
      if (subtree_hash == defaultHash(0))
        return std::nullopt;

      std::vector<uint8_t> leaf_value;
      if (getLeafDataImpl(subtree_hash, leaf_value))
        return leaf_value;
      return std::nullopt;
    }

    auto internal = fetchInternal(subtree_hash);
    if (!internal.has_value())
    {
      return std::nullopt;
    }

    const size_t bit_index = DEPTH - depth;
    const uint8_t byte = key.data[bit_index / 8];
    const uint8_t mask = 0x80 >> (bit_index % 8);
    const bool go_right = (byte & mask) != 0;

    const Crypto::Hash &child = go_right ? internal->right : internal->left;
    return getRecursive(child, key, depth - 1);
  }

  //  Fetch / store internal nodes

  std::optional<SparseMerkleTree::InternalNode>
  SparseMerkleTree::fetchInternal(const Crypto::Hash &hash) const
  {
    std::vector<uint8_t> bytes;
    if (!getNodeImpl(hash, bytes))
    {
      return std::nullopt;
    }
    if (bytes.size() != 64)
    {
      return std::nullopt;
    }

    InternalNode n;
    std::memcpy(n.left.data.data(), bytes.data(), 32);
    std::memcpy(n.right.data.data(), bytes.data() + 32, 32);
    return n;
  }

  void SparseMerkleTree::storeInternal(const Crypto::Hash &hash,
                                       const InternalNode &node,
                                       uint64_t version)
  {
    std::vector<uint8_t> bytes(64);
    std::memcpy(bytes.data(), node.left.data.data(), 32);
    std::memcpy(bytes.data() + 32, node.right.data.data(), 32);
    putNodeImpl(hash, bytes, version);
  }

  //  Update

  Crypto::Hash SparseMerkleTree::update(const Crypto::Hash &key,
                                        const std::vector<uint8_t> &value,
                                        uint64_t version)
  {
    root_ = updateRecursive(root_, key, value, /*is_delete=*/false, DEPTH, version);
    return root_;
  }

  Crypto::Hash SparseMerkleTree::remove(const Crypto::Hash &key, uint64_t version)
  {
    root_ = updateRecursive(root_, key, {}, /*is_delete=*/true, DEPTH, version);
    return root_;
  }

  Crypto::Hash SparseMerkleTree::updateRecursive(const Crypto::Hash &subtree_hash,
                                                 const Crypto::Hash &key,
                                                 const std::vector<uint8_t> &value,
                                                 bool is_delete,
                                                 size_t depth,
                                                 uint64_t version)
  {
    if (depth == 0)
    {
      if (is_delete)
      {
        putLeafDataImpl(defaultHash(0), {}, version);
        return defaultHash(0);
      }

      Crypto::Hash new_leaf = computeLeaf(key, value);
      putLeafDataImpl(new_leaf, value, version);
      return new_leaf;
    }

    const size_t bit_index = DEPTH - depth;
    const uint8_t byte = key.data[bit_index / 8];
    const uint8_t mask = 0x80 >> (bit_index % 8);
    const bool go_right = (byte & mask) != 0;

    Crypto::Hash left_child;
    Crypto::Hash right_child;

    if (subtree_hash == defaultHash(depth))
    {
      left_child = right_child = defaultHash(depth - 1);
    }
    else
    {
      auto internal = fetchInternal(subtree_hash);
      if (!internal.has_value())
      {
        left_child = right_child = defaultHash(depth - 1);
      }
      else
      {
        left_child = internal->left;
        right_child = internal->right;
      }
    }

    if (go_right)
    {
      right_child = updateRecursive(right_child, key, value, is_delete,
                                    depth - 1, version);
    }
    else
    {
      left_child = updateRecursive(left_child, key, value, is_delete,
                                   depth - 1, version);
    }

    Crypto::Hash new_internal = hashInternal(left_child, right_child);

    if (left_child == defaultHash(depth - 1) &&
        right_child == defaultHash(depth - 1))
    {
      return defaultHash(depth);
    }

    InternalNode n;
    n.left = left_child;
    n.right = right_child;
    storeInternal(new_internal, n, version);

    return new_internal;
  }

  //  Versioned reads

  std::optional<std::vector<uint8_t>> SparseMerkleTree::getAtVersion(
      const Crypto::Hash &key, uint64_t version) const
  {
    auto historic_root = rootAtVersion(version);
    if (!historic_root.has_value())
    {
      return std::nullopt;
    }

    if (*historic_root != root_)
    {
      // TODO: support historic reads via versioned nodes.
      return std::nullopt;
    }

    return get(key);
  }

  //  Batch operations

  Crypto::Hash SparseMerkleTree::applyBatch(const std::vector<Update> &updates,
                                            uint64_t version)
  {
    auto sorted = updates;
    std::sort(sorted.begin(), sorted.end(),
              [](const Update &a, const Update &b)
              {
                return a.key < b.key;
              });

    for (const auto &u : sorted)
    {
      if (u.is_delete)
      {
        root_ = updateRecursive(root_, u.key, {}, true, DEPTH, version);
      }
      else
      {
        root_ = updateRecursive(root_, u.key, u.value, false, DEPTH, version);
      }
    }

    return root_;
  }

  //  Historical pruning

  void SparseMerkleTree::pruneHistory(uint64_t /*keepFrom*/)
  {
    // TODO: implement when we have versioned node storage.
  }

  bool SparseMerkleTree::readChildren(const Crypto::Hash &node_hash,
                                      Crypto::Hash &left,
                                      Crypto::Hash &right) const
  {
    std::vector<uint8_t> bytes;
    if (!getNodeImpl(node_hash, bytes))
      return false;
    if (bytes.size() != 64)
      return false;

    std::memcpy(left.data.data(), bytes.data(), 32);
    std::memcpy(right.data.data(), bytes.data() + 32, 32);
    return true;
  }

  //  Key derivation

  namespace Keys
  {
    namespace
    {
      Crypto::Hash hashDomain(const char *domain4,
                              const uint8_t *data, size_t len) noexcept
      {
        uint8_t buf[4 + 64];
        std::memcpy(buf, domain4, 4);
        if (len > 64)
          len = 64;
        std::memcpy(buf + 4, data, len);
        Crypto::Hash h;
        blake2b(buf, 4 + len, h);
        return h;
      }
    } // anonymous namespace

    Crypto::Hash account(const Crypto::Address &address) noexcept
    {
      return hashDomain("acct", address.data.data(), 32);
    }

    Crypto::Hash tokenBalance(const Crypto::Address &address, Id token_id) noexcept
    {
      uint8_t buf[32 + 4];
      std::memcpy(buf, address.data.data(), 32);
      buf[32] = uint8_t(token_id);
      buf[33] = uint8_t(token_id >> 8);
      buf[34] = uint8_t(token_id >> 16);
      buf[35] = uint8_t(token_id >> 24);
      return hashDomain("bal ", buf, 36);
    }

    Crypto::Hash token(Id token_id) noexcept
    {
      uint8_t buf[4];
      buf[0] = uint8_t(token_id);
      buf[1] = uint8_t(token_id >> 8);
      buf[2] = uint8_t(token_id >> 16);
      buf[3] = uint8_t(token_id >> 24);
      return hashDomain("tok ", buf, 4);
    }

    Crypto::Hash tokenSupply(Id token_id) noexcept
    {
      uint8_t buf[4];
      buf[0] = uint8_t(token_id);
      buf[1] = uint8_t(token_id >> 8);
      buf[2] = uint8_t(token_id >> 16);
      buf[3] = uint8_t(token_id >> 24);
      return hashDomain("tsup", buf, 4);
    }

    Crypto::Hash validator(uint64_t validator_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(validator_id >> (i * 8));
      return hashDomain("val ", buf, 8);
    }

    Crypto::Hash validatorByAddress(const Crypto::Address &address) noexcept
    {
      return hashDomain("vadr", address.data.data(), 32);
    }

    Crypto::Hash order(uint64_t order_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(order_id >> (i * 8));
      return hashDomain("ord ", buf, 8);
    }

    Crypto::Hash orderExpiry(uint64_t height) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(height >> (i * 8));
      return hashDomain("oexh", buf, 8);
    }

    Crypto::Hash global(const std::string &name) noexcept
    {
      size_t len = name.size();
      if (len > 64)
        len = 64;
      return hashDomain("glob", reinterpret_cast<const uint8_t *>(name.data()), len);
    }

    Crypto::Hash ammPool(uint64_t pool_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(pool_id >> (i * 8));
      return hashDomain("pool", buf, 8);
    }

    Crypto::Hash ammPosition(uint64_t position_id) noexcept
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(position_id >> (i * 8));
      return hashDomain("pos ", buf, 8);
    }

    Crypto::Hash ammPositionIndex(const Crypto::Address &owner,
                                  uint64_t pool_id) noexcept
    {
      uint8_t buf[32 + 8];
      std::memcpy(buf, owner.data.data(), 32);
      for (int i = 0; i < 8; ++i)
        buf[32 + i] = uint8_t(pool_id >> (i * 8));
      return hashDomain("pidx", buf, 40);
    }

    Crypto::Hash receipt(const Crypto::Hash &tx_hash) noexcept
    {
      return hashDomain("rcpt", tx_hash.data.data(), 32);
    }
  } // namespace Keys

} // namespace State