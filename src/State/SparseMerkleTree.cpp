// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SparseMerkleTree.h"

#include "Common/StringTools.h"
#include "Crypto/Blake2b.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <sstream>
#include <stdexcept>

namespace State
{
  //  =========================================================================
  //  Default hashes
  //
  //  defaultHash(d) is the hash of the canonical empty subtree at
  //  remaining depth d. defaultHash(0) is the empty leaf; defaultHash(KEY_BITS)
  //  is the empty tree. The table is computed once on first use and cached
  //  for the process lifetime.
  //
  //  Domain tag: "dflt" || TAG_DEFAULT(0x02) || depth(BE16)
  //  where depth is the *remaining* depth. The BE16 encoding means the
  //  preimage's last two bytes change with the depth, so a hash for one
  //  depth cannot collide with a hash for another.
  //
  //  The recursion for defaultHash is:
  //    defaultHash(0)   = Blake2b("dflt" || 0x02 || 0x0000)
  //    defaultHash(d+1) = Blake2b("dflt" || 0x02 || BE16(d+1)
  //                               || defaultHash(d) || defaultHash(d))
  //
  //  A branch whose two children are both the default for their depth
  //  is itself the default for the branch's depth. This is what makes
  //  the tree sparse: an empty subtree is represented by a single hash,
  //  not by an exponential number of default nodes.
  //  =========================================================================

  namespace
  {
    //  Fixed 4-byte domain tags, matching the convention used by
    //  State::Keys::* (e.g. "acct", "ord ", "nft "). The trailing
    //  space is deliberate where present, so a tag is always exactly
    //  four bytes.
    constexpr char DOMAIN_LEAF[4] = {'l', 'e', 'a', 'f'};
    constexpr char DOMAIN_BRANCH[4] = {'b', 'r', 'c', 'h'};
    constexpr char DOMAIN_DEFAULT[4] = {'d', 'f', 'l', 't'};

    //  Encode a u16 as two big-endian bytes.
    inline void writeBE16(uint8_t *out, uint16_t v) noexcept
    {
      out[0] = uint8_t(v >> 8);
      out[1] = uint8_t(v & 0xFF);
    }

    //  Encode a u64 as eight big-endian bytes. Used for the version
    //  suffix in historical keys (the encoding must match StateDB's
    //  histKey and byVersionKey helpers).
    inline void writeBE64(uint8_t *out, uint64_t v) noexcept
    {
      for (int i = 0; i < 8; ++i)
        out[i] = uint8_t(v >> ((7 - i) * 8));
    }

    //  Extract bit `bit_index` from a 32-byte key, MSB first.
    //  bit_index 0 is the most significant bit of byte 0.
    inline uint8_t bitAt(const Crypto::Hash &key, size_t bit_index) noexcept
    {
      const uint8_t byte = key.data[bit_index / 8];
      const uint8_t mask = uint8_t(0x80 >> (bit_index % 8));
      return (byte & mask) ? 1 : 0;
    }

    //  Test whether the first `prefix_len` bits of the branch's prefix
    //  (which is stored relative to `start_bit` of the key) match the
    //  corresponding bits of `key`.
    //
    //  `start_bit` is the position in the key where the branch's
    //  prefix begins. It is `KEY_BITS - remaining_depth` at the call
    //  site: the number of bits already consumed by the walk from the
    //  root. Storing the prefix relative to that position, rather
    //  than to bit 0, is what keeps a deep branch's storage compact
    //  even when its parent's prefix was short.
    //
    //  The comparison is bit-by-bit rather than byte-wise because the
    //  two ends of the comparison are not byte-aligned in general:
    //  the branch's prefix starts at an arbitrary bit position in the
    //  key, and `prefix_bits` is packed starting from bit 0 of its
    //  own buffer.
    bool sharesPrefix(const Crypto::Hash &key,
                      size_t start_bit,
                      uint16_t prefix_len,
                      const std::vector<uint8_t> &prefix_bits) noexcept
    {
      for (uint16_t i = 0; i < prefix_len; ++i)
      {
        const uint8_t key_bit = bitAt(key, start_bit + i);
        const uint8_t pb =
            (prefix_bits[i / 8] >> (7 - (i % 8))) & 1;
        if (key_bit != pb)
          return false;
      }
      return true;
    }

    //  Compute the shared prefix of two keys, starting at `start_bit`.
    //  Returns the number of bits from `start_bit` where the two keys
    //  match, and a packed representation of those bits (starting
    //  from bit 0 of the output buffer).
    void sharedPrefix(const Crypto::Hash &a,
                      const Crypto::Hash &b,
                      size_t start_bit,
                      uint16_t &len_out,
                      std::vector<uint8_t> &bits_out) noexcept
    {
      size_t i = start_bit;
      while (i < SparseMerkleTree::KEY_BITS)
      {
        if (bitAt(a, i) != bitAt(b, i))
          break;
        ++i;
      }

      const size_t shared = i - start_bit;
      len_out = static_cast<uint16_t>(shared);

      const size_t bytes = (shared + 7) / 8;
      bits_out.assign(bytes, 0);

      for (size_t bit = 0; bit < shared; ++bit)
      {
        if (bitAt(a, start_bit + bit))
          bits_out[bit / 8] |= uint8_t(0x80 >> (bit % 8));
      }
    }

    //  Precomputed default-hash table. Lazily initialised on first
    //  call. The mutex guards the initialisation; after that, reads
    //  are lock-free.
    struct DefaultHashTable
    {
      std::array<Crypto::Hash, SparseMerkleTree::KEY_BITS + 1> values;
      std::once_flag init_flag;

      void ensureInit() noexcept
      {
        std::call_once(init_flag, [this]
                       {
          //  Depth 0: the empty leaf. Preimage is
          //    "dflt" || 0x02 || BE16(0)
          //  with no children.
          {
            uint8_t buf[4 + 1 + 2];
            std::memcpy(buf, DOMAIN_DEFAULT, 4);
            buf[4] = SparseMerkleTree::TAG_DEFAULT;
            writeBE16(buf + 5, 0);
            Crypto::blake2b(buf, sizeof(buf),
                            values[0].data.data(), 32);
          }

          //  Depth d: an internal node whose two children are both
          //  defaultHash(d-1). Preimage is
          //    "dflt" || 0x02 || BE16(d) || h || h
          //  where h = defaultHash(d-1).
          for (size_t d = 1; d <= SparseMerkleTree::KEY_BITS; ++d)
          {
            uint8_t buf[4 + 1 + 2 + 32 + 32];
            std::memcpy(buf, DOMAIN_DEFAULT, 4);
            buf[4] = SparseMerkleTree::TAG_DEFAULT;
            writeBE16(buf + 5, static_cast<uint16_t>(d));
            std::memcpy(buf + 7, values[d - 1].data.data(), 32);
            std::memcpy(buf + 7 + 32, values[d - 1].data.data(), 32);
            Crypto::blake2b(buf, sizeof(buf),
                            values[d].data.data(), 32);
          } });
      }
    };

    DefaultHashTable &defaultHashes() noexcept
    {
      static DefaultHashTable table;
      table.ensureInit();
      return table;
    }
  } // anonymous namespace

  const Crypto::Hash &SparseMerkleTree::defaultHash(size_t depth) noexcept
  {
    if (depth > KEY_BITS)
      depth = KEY_BITS;
    return defaultHashes().values[depth];
  }

  //  =========================================================================
  //  Hashing
  //
  //  hashLeaf:    "leaf" || TAG_LEAF(0x00)   || key(32) || value_hash(32)
  //  hashBranch:  "brch" || TAG_BRANCH(0x01) || prefix_len(BE16)
  //                       || prefix_bits_padded
  //                       || left(32) || right(32)
  //
  //  Both are pure and static. The prefix buffer is padded to
  //  ceil(prefix_len/8) bytes; trailing zero bits are included in the
  //  preimage but are deterministic, so two branches with the same
  //  logical prefix always hash identically.
  //  =========================================================================

  Crypto::Hash SparseMerkleTree::hashLeaf(const Crypto::Hash &key,
                                          const Crypto::Hash &value_hash) noexcept
  {
    uint8_t buf[4 + 1 + 32 + 32];
    std::memcpy(buf, DOMAIN_LEAF, 4);
    buf[4] = TAG_LEAF;
    std::memcpy(buf + 5, key.data.data(), 32);
    std::memcpy(buf + 5 + 32, value_hash.data.data(), 32);

    Crypto::Hash h;
    Crypto::blake2b(buf, sizeof(buf), h.data.data(), 32);
    return h;
  }

  Crypto::Hash SparseMerkleTree::hashBranch(
      uint16_t prefix_len,
      const std::vector<uint8_t> &prefix_bits,
      const Crypto::Hash &left,
      const Crypto::Hash &right) noexcept
  {
    const size_t prefix_bytes = (prefix_len + 7) / 8;

    //  The buffer is sized for the worst case: full 256-bit prefix
    //  is 32 bytes. HEADER is 4 (domain) + 1 (tag) + 2 (len), then
    //  prefix bytes, then 64 bytes of children.
    constexpr size_t HEADER = 4 + 1 + 2;
    std::array<uint8_t, HEADER + 32 + 32 + 32> buf{};

    std::memcpy(buf.data(), DOMAIN_BRANCH, 4);
    buf[4] = TAG_BRANCH;
    writeBE16(buf.data() + 5, prefix_len);

    if (prefix_bytes > 0)
    {
      std::memcpy(buf.data() + HEADER, prefix_bits.data(), prefix_bytes);
    }

    std::memcpy(buf.data() + HEADER + prefix_bytes,
                left.data.data(), 32);
    std::memcpy(buf.data() + HEADER + prefix_bytes + 32,
                right.data.data(), 32);

    Crypto::Hash h;
    Crypto::blake2b(buf.data(), HEADER + prefix_bytes + 64,
                    h.data.data(), 32);
    return h;
  }

  //  =========================================================================
  //  Node parsing
  //
  //  A malformed node in the DB is a fatal error: it means either a
  //  write was truncated, a hash collision occurred, or the DB was
  //  tampered with. parseLeaf and parseBranch return false rather
  //  than throwing so callers can log the offending hash and abort
  //  cleanly.
  //
  //  Expected layouts:
  //    leaf:   TAG_LEAF(1) || key(32) || value_hash(32)              = 65 bytes
  //    branch: TAG_BRANCH(1) || prefix_len(BE16) || prefix_padded
  //            || left(32) || right(32)
  //  =========================================================================

  bool SparseMerkleTree::parseLeaf(const std::vector<uint8_t> &bytes,
                                   LeafNode &out) noexcept
  {
    if (bytes.size() != 1 + 32 + 32)
      return false;
    if (bytes[0] != TAG_LEAF)
      return false;

    std::memcpy(out.key.data.data(), bytes.data() + 1, 32);
    std::memcpy(out.value_hash.data.data(), bytes.data() + 33, 32);
    return true;
  }

  bool SparseMerkleTree::parseBranch(const std::vector<uint8_t> &bytes,
                                     BranchNode &out) noexcept
  {
    if (bytes.size() < 1 + 2 + 32 + 32)
      return false;
    if (bytes[0] != TAG_BRANCH)
      return false;

    out.prefix_len = uint16_t(bytes[1]) << 8 | uint16_t(bytes[2]);
    if (out.prefix_len > MAX_PREFIX_BITS)
      return false;

    const size_t prefix_bytes = (out.prefix_len + 7) / 8;
    const size_t expected = 1 + 2 + prefix_bytes + 32 + 32;
    if (bytes.size() != expected)
      return false;

    out.prefix_bits.assign(bytes.begin() + 3,
                           bytes.begin() + 3 + prefix_bytes);
    std::memcpy(out.left.data.data(), bytes.data() + 3 + prefix_bytes, 32);
    std::memcpy(out.right.data.data(),
                bytes.data() + 3 + prefix_bytes + 32, 32);
    return true;
  }

  //  =========================================================================
  //  Construction
  //  =========================================================================

  SparseMerkleTree::SparseMerkleTree(StateDB &db)
      : db_(db), root_(defaultHash(KEY_BITS))
  {
  }

  void SparseMerkleTree::setTxn(StateDB::Txn *txn) noexcept
  {
    txn_ = txn;
    read_txn_ = nullptr;
  }

  void SparseMerkleTree::setReadTxn(StateDB::ReadTxn *read_txn) noexcept
  {
    read_txn_ = read_txn;
    txn_ = nullptr;
  }

  //  =========================================================================
  //  Txn-aware storage helpers
  //
  //  These are the only functions that touch the DB. The bindings are
  //  checked in this order:
  //
  //    1. txn_       write transaction, used for both reads and writes
  //    2. read_txn_  read transaction, used for reads; a write through
  //                  it is a programming error (asserts in debug)
  //    3. db_        autocommit; db_ internally reuses the per-thread
  //                  read txn if one is open on this thread
  //
  //  A write with no txn_ bound calls db_.putXAtVersion, which opens
  //  its own write txn. Callers that want the write to be atomic with
  //  the surrounding block should bind a txn_ first.
  //  =========================================================================

  bool SparseMerkleTree::getNodeImpl(const Crypto::Hash &hash,
                                     std::vector<uint8_t> &out) const
  {
    if (txn_)
      return txn_->get(StateDB::TBL_SMT_NODES,
                       hash.data.data(), hash.data.size(), out);
    if (read_txn_)
      return read_txn_->get(StateDB::TBL_SMT_NODES,
                            hash.data.data(), hash.data.size(), out);
    return db_.getNode(hash, out);
  }

  void SparseMerkleTree::putNodeImpl(const Crypto::Hash &hash,
                                     const std::vector<uint8_t> &bytes,
                                     uint64_t version)
  {
    if (txn_)
    {
      txn_->put(StateDB::TBL_SMT_NODES,
                hash.data.data(), hash.data.size(),
                bytes.data(), bytes.size());
      ++stats_.live_node_writes;

      if (version != 0)
      {
        //  The historical layout is (node_hash || version_be64)
        //  for the node table and (version_be64 || node_hash) for
        //  the by-version prune index. Both encodings must match
        //  StateDB's histKey and byVersionKey helpers, which build
        //  the same keys from the prune path.

        uint8_t hist_key[40];
        std::memcpy(hist_key, hash.data.data(), 32);
        writeBE64(hist_key + 32, version);
        txn_->put(StateDB::TBL_SMT_NODES_HIST,
                  hist_key, sizeof(hist_key),
                  bytes.data(), bytes.size());
        ++stats_.hist_node_writes;

        uint8_t by_ver_key[40];
        writeBE64(by_ver_key, version);
        std::memcpy(by_ver_key + 8, hash.data.data(), 32);
        txn_->put(StateDB::TBL_SMT_NODES_BY_VER,
                  by_ver_key, sizeof(by_ver_key),
                  nullptr, 0);
        ++stats_.by_ver_writes;
      }
      return;
    }

    //  No txn bound. The autocommit path opens its own write
    //  transaction inside StateDB. That is safe but not atomic with
    //  the caller's surrounding work; callers that need atomicity
    //  should bind a txn.
    db_.putNode(hash, bytes, 0);
    ++stats_.live_node_writes;

    if (version != 0)
    {
      db_.putNodeAtVersion(hash, version, bytes);
      ++stats_.hist_node_writes;
      ++stats_.by_ver_writes; // StateDB writes both rows in one txn
    }
  }

  bool SparseMerkleTree::getLeafDataImpl(const Crypto::Hash &leaf_hash,
                                         std::vector<uint8_t> &out) const
  {
    if (txn_)
      return txn_->get(StateDB::TBL_SMT_LEAVES,
                       leaf_hash.data.data(), leaf_hash.data.size(), out);
    if (read_txn_)
      return read_txn_->get(StateDB::TBL_SMT_LEAVES,
                            leaf_hash.data.data(), leaf_hash.data.size(), out);
    return db_.getLeafData(leaf_hash, out);
  }

  void SparseMerkleTree::putLeafDataImpl(const Crypto::Hash &leaf_hash,
                                         const std::vector<uint8_t> &value,
                                         uint64_t version)
  {
    if (txn_)
    {
      txn_->put(StateDB::TBL_SMT_LEAVES,
                leaf_hash.data.data(), leaf_hash.data.size(),
                value.data(), value.size());
      ++stats_.live_leaf_writes;

      if (version != 0)
      {
        uint8_t hist_key[40];
        std::memcpy(hist_key, leaf_hash.data.data(), 32);
        writeBE64(hist_key + 32, version);
        txn_->put(StateDB::TBL_SMT_LEAVES_HIST,
                  hist_key, sizeof(hist_key),
                  value.data(), value.size());
        ++stats_.hist_leaf_writes;

        uint8_t by_ver_key[40];
        writeBE64(by_ver_key, version);
        std::memcpy(by_ver_key + 8, leaf_hash.data.data(), 32);
        txn_->put(StateDB::TBL_SMT_LEAVES_BY_VER,
                  by_ver_key, sizeof(by_ver_key),
                  nullptr, 0);
        ++stats_.by_ver_writes;
      }
      return;
    }

    db_.putLeafData(leaf_hash, value, 0);
    ++stats_.live_leaf_writes;

    if (version != 0)
    {
      db_.putLeafDataAtVersion(leaf_hash, version, value);
      ++stats_.hist_leaf_writes;
      ++stats_.by_ver_writes;
    }
  }

  bool SparseMerkleTree::getNodeAtVersionImpl(const Crypto::Hash &hash,
                                              uint64_t version,
                                              std::vector<uint8_t> &out) const
  {
    //  The historical layout is (hash || version_be64) in both the
    //  txn and autocommit paths. StateDB's getNodeAtVersion builds
    //  the same key internally.
    if (txn_)
    {
      uint8_t key[40];
      std::memcpy(key, hash.data.data(), 32);
      writeBE64(key + 32, version);
      return txn_->get(StateDB::TBL_SMT_NODES_HIST,
                       key, sizeof(key), out);
    }
    return db_.getNodeAtVersion(hash, version, out);
  }

  bool SparseMerkleTree::getLeafDataAtVersionImpl(
      const Crypto::Hash &leaf_hash,
      uint64_t version,
      std::vector<uint8_t> &out) const
  {
    if (txn_)
    {
      uint8_t key[40];
      std::memcpy(key, leaf_hash.data.data(), 32);
      writeBE64(key + 32, version);
      return txn_->get(StateDB::TBL_SMT_LEAVES_HIST,
                       key, sizeof(key), out);
    }
    return db_.getLeafDataAtVersion(leaf_hash, version, out);
  }

  bool SparseMerkleTree::getMetaImpl(const std::string &key,
                                     std::vector<uint8_t> &out) const
  {
    if (txn_)
      return txn_->get(StateDB::TBL_META,
                       key.data(), key.size(), out);
    if (read_txn_)
      return read_txn_->get(StateDB::TBL_META,
                            key.data(), key.size(), out);
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

  //  =========================================================================
  //  Node construction
  //
  //  Each of these computes the node's hash, writes the node bytes to
  //  the live table, and (if version != 0) writes them to the
  //  historical tables. The leaf's *value* is written separately via
  //  putLeafDataImpl; makeLeaf only writes the leaf's *preimage* to
  //  TBL_SMT_NODES.
  //  =========================================================================

  Crypto::Hash SparseMerkleTree::makeLeaf(const Crypto::Hash &key,
                                          const Crypto::Hash &value_hash,
                                          uint64_t version)
  {
    const Crypto::Hash h = hashLeaf(key, value_hash);

    std::vector<uint8_t> bytes;
    bytes.reserve(1 + 32 + 32);
    bytes.push_back(TAG_LEAF);
    bytes.insert(bytes.end(), key.data.begin(), key.data.end());
    bytes.insert(bytes.end(), value_hash.data.begin(), value_hash.data.end());

    putNodeImpl(h, bytes, version);
    return h;
  }

  Crypto::Hash SparseMerkleTree::makeBranch(
      uint16_t prefix_len,
      const std::vector<uint8_t> &prefix_bits,
      const Crypto::Hash &left,
      const Crypto::Hash &right,
      uint64_t version)
  {
    const Crypto::Hash h = hashBranch(prefix_len, prefix_bits, left, right);

    const size_t prefix_bytes = (prefix_len + 7) / 8;

    std::vector<uint8_t> bytes;
    bytes.reserve(1 + 2 + prefix_bytes + 32 + 32);
    bytes.push_back(TAG_BRANCH);
    bytes.push_back(uint8_t(prefix_len >> 8));
    bytes.push_back(uint8_t(prefix_len & 0xFF));
    if (prefix_bytes > 0)
      bytes.insert(bytes.end(), prefix_bits.begin(),
                   prefix_bits.begin() + prefix_bytes);
    bytes.insert(bytes.end(), left.data.begin(), left.data.end());
    bytes.insert(bytes.end(), right.data.begin(), right.data.end());

    putNodeImpl(h, bytes, version);
    return h;
  }

  //  =========================================================================
  //  Read
  //  =========================================================================

  bool SparseMerkleTree::readNode(const Crypto::Hash &node_hash,
                                  std::vector<uint8_t> &out) const
  {
    return getNodeImpl(node_hash, out);
  }

  bool SparseMerkleTree::getLeafData(const Crypto::Hash &leaf_hash,
                                     std::vector<uint8_t> &out) const
  {
    return getLeafDataImpl(leaf_hash, out);
  }

  std::optional<std::vector<uint8_t>>
  SparseMerkleTree::getRecursive(const Crypto::Hash &node_hash,
                                 const Crypto::Hash &key,
                                 size_t remaining_depth) const
  {
    //  An empty subtree at this depth cannot contain the key.
    if (node_hash == defaultHash(remaining_depth))
      return std::nullopt;

    std::vector<uint8_t> bytes;
    if (!getNodeImpl(node_hash, bytes))
      return std::nullopt;

    if (!bytes.empty() && bytes[0] == TAG_LEAF)
    {
      LeafNode leaf;
      if (!parseLeaf(bytes, leaf))
        return std::nullopt;
      if (leaf.key != key)
        return std::nullopt;

      //  The leaf's value is stored separately from its preimage.
      std::vector<uint8_t> value;
      if (!getLeafDataImpl(node_hash, value))
        return std::nullopt;
      return value;
    }

    BranchNode branch;
    if (!parseBranch(bytes, branch))
      return std::nullopt;

    if (!sharesPrefix(key, KEY_BITS - remaining_depth,
                      branch.prefix_len, branch.prefix_bits))
      return std::nullopt;

    //  The branching bit is the bit immediately after the prefix,
    //  measured from the start of the key.
    const size_t branch_bit_index = KEY_BITS - remaining_depth + branch.prefix_len;
    const uint8_t bit = bitAt(key, branch_bit_index);

    const size_t child_remaining = remaining_depth - branch.prefix_len - 1;
    const Crypto::Hash &child = (bit == 0) ? branch.left : branch.right;
    return getRecursive(child, key, child_remaining);
  }

  std::optional<std::vector<uint8_t>>
  SparseMerkleTree::get(const Crypto::Hash &key) const
  {
    ++const_cast<Stats &>(stats_).reads;
    auto r = getRecursive(root_, key, KEY_BITS);
    if (r.has_value())
      ++const_cast<Stats &>(stats_).read_hits;
    return r;
  }

  //  =========================================================================
  //  Update
  //  =========================================================================

  Crypto::Hash SparseMerkleTree::updateRecursive(
      const Crypto::Hash &node_hash,
      const Crypto::Hash &key,
      const std::vector<uint8_t> &value,
      bool is_delete,
      size_t remaining_depth,
      uint64_t version)
  {
    //  Track the deepest leaf we've seen. This is a rough height
    //  estimate; the exact height of the tree is the length of the
    //  longest path from root to leaf, which we can only observe
    //  during a walk.
    if (remaining_depth > stats_.deepest_leaf_depth_seen)
      stats_.deepest_leaf_depth_seen = remaining_depth;

    //  Case 1: the subtree is empty. Insert a new leaf here, or, if
    //  this is a delete, no-op (returning the default).
    if (node_hash == defaultHash(remaining_depth))
    {
      if (is_delete)
        return defaultHash(remaining_depth);

      Crypto::Hash value_hash;
      Crypto::blake2b(value.data(), value.size(),
                      value_hash.data.data(), 32);

      //  Write the leaf's preimage to TBL_SMT_NODES and its value
      //  to TBL_SMT_LEAVES. Both rows are keyed by the leaf hash.
      const Crypto::Hash leaf_hash = makeLeaf(key, value_hash, version);
      putLeafDataImpl(leaf_hash, value, version);
      return leaf_hash;
    }

    //  Fetch and parse the current node.
    std::vector<uint8_t> bytes;
    if (!getNodeImpl(node_hash, bytes))
    {
      //  The DB claims this node exists (the hash came from a
      //  parent) but reading it failed. Treat as empty; the caller
      //  will overwrite with a leaf. This is the safest recovery
      //  in the presence of DB corruption.
      if (is_delete)
        return defaultHash(remaining_depth);
      Crypto::Hash value_hash;
      Crypto::blake2b(value.data(), value.size(),
                      value_hash.data.data(), 32);
      const Crypto::Hash leaf_hash = makeLeaf(key, value_hash, version);
      putLeafDataImpl(leaf_hash, value, version);
      return leaf_hash;
    }

    //  Case 2: leaf.
    if (!bytes.empty() && bytes[0] == TAG_LEAF)
    {
      LeafNode leaf;
      if (!parseLeaf(bytes, leaf))
      {
        //  Corrupt leaf. Same fallback as above.
        if (is_delete)
          return defaultHash(remaining_depth);
        Crypto::Hash value_hash;
        Crypto::blake2b(value.data(), value.size(),
                        value_hash.data.data(), 32);
        const Crypto::Hash leaf_hash = makeLeaf(key, value_hash, version);
        putLeafDataImpl(leaf_hash, value, version);
        return leaf_hash;
      }

      //  Same key: replace or delete.
      if (leaf.key == key)
      {
        if (is_delete)
          return defaultHash(remaining_depth);

        Crypto::Hash value_hash;
        Crypto::blake2b(value.data(), value.size(),
                        value_hash.data.data(), 32);
        const Crypto::Hash new_leaf = makeLeaf(key, value_hash, version);
        putLeafDataImpl(new_leaf, value, version);
        return new_leaf;
      }

      //  Different key.
      //
      //  If this is a delete, the key isn't in this subtree. Re-emit
      //  the existing leaf unchanged (which also records the
      //  historical row at this version) and return without
      //  creating any new structure. Without this, a delete of a
      //  nonexistent key would spuriously split the leaf and change
      //  the tree shape, breaking the "delete of absent key is a
      //  no-op" invariant.
      if (is_delete)
      {
        return makeLeaf(leaf.key, leaf.value_hash, version);
      }

      //  Split into a branch with two leaves.
      //
      //  The two keys differ somewhere in the range [start_bit,
      //  start_bit + remaining_depth). We compute the shared prefix
      //  from start_bit (not from bit 0 of the key) so that the
      //  branch we create reflects only the bits that distinguish
      //  the two keys from the current position. Storing the prefix
      //  relative to bit 0 would double-count the bits already
      //  consumed by ancestors and produce a tree whose walk
      //  arithmetic no longer matches.
      const size_t start_bit = KEY_BITS - remaining_depth;

      uint16_t shared_len = 0;
      std::vector<uint8_t> shared_bits;
      sharedPrefix(leaf.key, key, start_bit, shared_len, shared_bits);

      //  Sanity: the two keys must differ before the subtree ends.
      //  If they don't, they're equal (which we already handled), so
      //  this should never happen.
      if (shared_len >= remaining_depth)
      {
        //  Defensive: fall back to treating the new key as a
        //  replacement. This cannot happen with valid keys.
        if (is_delete)
          return defaultHash(remaining_depth);
        Crypto::Hash value_hash;
        Crypto::blake2b(value.data(), value.size(),
                        value_hash.data.data(), 32);
        const Crypto::Hash new_leaf = makeLeaf(key, value_hash, version);
        putLeafDataImpl(new_leaf, value, version);
        return new_leaf;
      }

      //  Re-write the existing leaf (its preimage is unchanged but
      //  we must ensure the historical row exists for this version
      //  if the same logical node appears at a new version).
      const Crypto::Hash old_leaf_hash = makeLeaf(leaf.key, leaf.value_hash, version);

      //  Write the new leaf.
      Crypto::Hash value_hash;
      Crypto::blake2b(value.data(), value.size(),
                      value_hash.data.data(), 32);
      const Crypto::Hash new_leaf_hash = makeLeaf(key, value_hash, version);
      putLeafDataImpl(new_leaf_hash, value, version);

      //  Order the two leaves by the branching bit.
      const size_t branch_bit_index = start_bit + shared_len;
      const uint8_t bit_of_old = bitAt(leaf.key, branch_bit_index);
      // bit_of_new is the opposite by construction of sharedPrefix.

      const Crypto::Hash &left = (bit_of_old == 0) ? old_leaf_hash : new_leaf_hash;
      const Crypto::Hash &right = (bit_of_old == 0) ? new_leaf_hash : old_leaf_hash;

      return makeBranch(shared_len, shared_bits, left, right, version);
    }

    //  Case 3: branch.
    BranchNode branch;
    if (!parseBranch(bytes, branch))
    {
      //  Corrupt branch. Replace with a leaf.
      if (is_delete)
        return defaultHash(remaining_depth);
      Crypto::Hash value_hash;
      Crypto::blake2b(value.data(), value.size(),
                      value_hash.data.data(), 32);
      const Crypto::Hash new_leaf = makeLeaf(key, value_hash, version);
      putLeafDataImpl(new_leaf, value, version);
      return new_leaf;
    }

    //  Case 3a: the key does not share the branch's prefix. Split
    //  the branch, inserting a new branch at the divergence point.
    if (!sharesPrefix(key, KEY_BITS - remaining_depth,
                      branch.prefix_len, branch.prefix_bits))
    {
      //  If this is a delete, the key isn't in this subtree, so
      //  no-op: return the existing node unchanged. We must still
      //  re-emit it at the new version so the historical row
      //  exists.
      if (is_delete)
      {
        //  Re-write the branch at this version.
        return makeBranch(branch.prefix_len, branch.prefix_bits,
                          branch.left, branch.right, version);
      }

      //  Compute the divergence point between the branch's prefix
      //  and the key. Since the key doesn't share the prefix, they
      //  diverge somewhere within the branch's prefix.
      const size_t prefix_start = KEY_BITS - remaining_depth;
      uint16_t diverge_at = 0;
      while (diverge_at < branch.prefix_len)
      {
        const size_t bit_index = prefix_start + diverge_at;
        const uint8_t key_bit = bitAt(key, bit_index);
        const uint8_t prefix_bit =
            (branch.prefix_bits[diverge_at / 8] >> (7 - (diverge_at % 8))) & 1;
        if (key_bit != prefix_bit)
          break;
        ++diverge_at;
      }

      //  Build the shared prefix for the new branch: the first
      //  `diverge_at` bits of the key (which equal the branch's
      //  prefix up to that point).
      std::vector<uint8_t> shared_bits((diverge_at + 7) / 8, 0);
      for (uint16_t b = 0; b < diverge_at; ++b)
      {
        const uint8_t key_bit = bitAt(key, prefix_start + b);
        if (key_bit)
          shared_bits[b / 8] |= uint8_t(0x80 >> (b % 8));
      }

      //  Two children of the new branch:
      //
      //    - The existing branch, with its prefix stripped of the
      //      `diverge_at + 1` bits (the shared bits plus the
      //      branching bit) and its remaining depth reduced.
      //    - A new leaf for the key, written at the new depth.
      //
      //  The existing branch gets a new prefix (its old prefix
      //  minus the shared part and the branching bit) but keeps
      //  its children. Its hash changes because its prefix changed.

      //  NOTE: the surviving prefix starts at `diverge_at + 1`, not
      //  `diverge_at`. The bit at `diverge_at` becomes the branching
      //  bit of the new parent, so it is consumed by the new
      //  branch's descent, and the rewritten child's prefix must
      //  begin at the next bit.
      const uint16_t remaining_prefix_len =
          uint16_t(branch.prefix_len - diverge_at - 1);
      std::vector<uint8_t> remaining_bits(
          (remaining_prefix_len + 7) / 8, 0);
      for (uint16_t b = 0; b < remaining_prefix_len; ++b)
      {
        const uint16_t src_bit = diverge_at + 1 + b;
        const uint8_t bit =
            (branch.prefix_bits[src_bit / 8] >> (7 - (src_bit % 8))) & 1;
        if (bit)
          remaining_bits[b / 8] |= uint8_t(0x80 >> (b % 8));
      }

      const Crypto::Hash rewritten_branch = makeBranch(
          remaining_prefix_len, remaining_bits,
          branch.left, branch.right, version);

      //  The new leaf.
      Crypto::Hash value_hash;
      Crypto::blake2b(value.data(), value.size(),
                      value_hash.data.data(), 32);
      const Crypto::Hash new_leaf = makeLeaf(key, value_hash, version);
      putLeafDataImpl(new_leaf, value, version);

      //  Which child is which? The branching bit is at position
      //  (prefix_start + diverge_at) in the key.
      const uint8_t key_bit = bitAt(key, prefix_start + diverge_at);
      const Crypto::Hash &left = (key_bit == 0) ? new_leaf : rewritten_branch;
      const Crypto::Hash &right = (key_bit == 0) ? rewritten_branch : new_leaf;

      return makeBranch(diverge_at, shared_bits, left, right, version);
    }

    //  Case 3b: the key shares the branch's prefix. Descend into
    //  the appropriate child.
    const size_t branch_bit_index = KEY_BITS - remaining_depth + branch.prefix_len;
    const uint8_t bit = bitAt(key, branch_bit_index);

    const size_t child_remaining = remaining_depth - branch.prefix_len - 1;

    Crypto::Hash new_left = branch.left;
    Crypto::Hash new_right = branch.right;

    if (bit == 0)
    {
      new_left = updateRecursive(branch.left, key, value,
                                 is_delete, child_remaining, version);
    }
    else
    {
      new_right = updateRecursive(branch.right, key, value,
                                  is_delete, child_remaining, version);
    }

    //  If both children are default for their depth, the branch
    //  itself becomes default. This is the empty-subtree
    //  propagation that keeps the tree sparse.
    const Crypto::Hash &child_default = defaultHash(child_remaining);
    if (new_left == child_default && new_right == child_default)
      return defaultHash(remaining_depth);

    //  If exactly one child is default, collapse the branch into
    //  the non-default child. The surviving child is either a
    //  branch (in which case the branch's prefix is extended by
    //  the branch's prefix plus the branching bit plus the child's
    //  prefix) or a leaf (in which case the branch is replaced by
    //  the leaf directly — a branch with a single leaf child is not
    //  a valid Patricia node).
    if (new_left == child_default || new_right == child_default)
    {
      const bool left_is_default = (new_left == child_default);
      const Crypto::Hash &surviving = left_is_default ? new_right : new_left;

      std::vector<uint8_t> surviving_bytes;
      if (!getNodeImpl(surviving, surviving_bytes))
      {
        //  Cannot read the surviving child; keep the branch.
        return makeBranch(branch.prefix_len, branch.prefix_bits,
                          new_left, new_right, version);
      }

      if (!surviving_bytes.empty() && surviving_bytes[0] == TAG_LEAF)
      {
        //  The surviving child is a leaf. The branch collapses
        //  into the leaf directly: a branch with one child is
        //  not a valid Patricia node, so the leaf moves up.
        return surviving;
      }

      if (!surviving_bytes.empty() && surviving_bytes[0] == TAG_BRANCH)
      {
        BranchNode sb;
        if (parseBranch(surviving_bytes, sb))
        {
          //  New prefix = old branch prefix
          //               + branching bit (0 or 1)
          //               + surviving child's prefix.
          //
          //  The branching bit is 0 if we kept the left child, 1
          //  if we kept the right. Both are relative to the
          //  branch's position.
          const uint16_t new_prefix_len =
              uint16_t(branch.prefix_len + 1 + sb.prefix_len);
          std::vector<uint8_t> new_prefix(
              (new_prefix_len + 7) / 8, 0);

          //  Copy the branch's prefix.
          for (uint16_t b = 0; b < branch.prefix_len; ++b)
          {
            const uint8_t pb =
                (branch.prefix_bits[b / 8] >> (7 - (b % 8))) & 1;
            if (pb)
              new_prefix[b / 8] |= uint8_t(0x80 >> (b % 8));
          }

          //  The branching bit.
          if (left_is_default)
          {
            //  We kept the right child, so the branching bit is 1.
            const uint16_t bit_pos = branch.prefix_len;
            new_prefix[bit_pos / 8] |= uint8_t(0x80 >> (bit_pos % 8));
          }
          //  Otherwise we kept the left child; the branching bit
          //  is 0, nothing to set.

          //  Copy the surviving child's prefix.
          for (uint16_t b = 0; b < sb.prefix_len; ++b)
          {
            const uint8_t pb =
                (sb.prefix_bits[b / 8] >> (7 - (b % 8))) & 1;
            if (pb)
            {
              const uint16_t bit_pos = branch.prefix_len + 1 + b;
              new_prefix[bit_pos / 8] |= uint8_t(0x80 >> (bit_pos % 8));
            }
          }

          return makeBranch(new_prefix_len, new_prefix,
                            sb.left, sb.right, version);
        }
      }

      //  Malformed surviving child. Keep the branch.
      return makeBranch(branch.prefix_len, branch.prefix_bits,
                        new_left, new_right, version);
    }

    //  Both children are non-default. Re-emit the branch.
    return makeBranch(branch.prefix_len, branch.prefix_bits,
                      new_left, new_right, version);
  }

  Crypto::Hash SparseMerkleTree::update(const Crypto::Hash &key,
                                        const std::vector<uint8_t> &value,
                                        uint64_t version)
  {
    ++stats_.updates;
    root_ = updateRecursive(root_, key, value, /*is_delete=*/false,
                            KEY_BITS, version);
    height_dirty_ = true;
    return root_;
  }

  Crypto::Hash SparseMerkleTree::remove(const Crypto::Hash &key,
                                        uint64_t version)
  {
    ++stats_.removes;
    root_ = updateRecursive(root_, key, {}, /*is_delete=*/true,
                            KEY_BITS, version);
    height_dirty_ = true;
    return root_;
  }

  Crypto::Hash SparseMerkleTree::applyBatch(
      const std::vector<Update> &updates,
      uint64_t version)
  {
    //  Sort by key and de-duplicate: if the same key appears more
    //  than once, the last write wins. This is the semantics a
    //  caller expects from "apply all these updates in this order."
    //
    //  De-duplication matters for cost: without it, the same key
    //  could walk the tree N times in the same block.
    std::vector<const Update *> ordered;
    ordered.reserve(updates.size());
    for (const auto &u : updates)
      ordered.push_back(&u);

    std::sort(ordered.begin(), ordered.end(),
              [](const Update *a, const Update *b)
              { return a->key < b->key; });

    //  De-dup: walk the sorted list, keeping only the last
    //  occurrence of each key.
    size_t write = 0;
    for (size_t i = 0; i < ordered.size(); ++i)
    {
      if (i + 1 < ordered.size() && ordered[i]->key == ordered[i + 1]->key)
        continue;
      ordered[write++] = ordered[i];
    }
    ordered.resize(write);

    ++stats_.batch_updates;

    for (const Update *u : ordered)
    {
      if (u->is_delete)
      {
        root_ = updateRecursive(root_, u->key, {}, true,
                                KEY_BITS, version);
      }
      else
      {
        root_ = updateRecursive(root_, u->key, u->value, false,
                                KEY_BITS, version);
      }
    }

    height_dirty_ = true;
    return root_;
  }

  //  =========================================================================
  //  Historical reads
  //  =========================================================================

  std::optional<std::vector<uint8_t>>
  SparseMerkleTree::getAtVersionRecursive(
      const Crypto::Hash &node_hash,
      const Crypto::Hash &key,
      size_t remaining_depth,
      uint64_t version) const
  {
    if (node_hash == defaultHash(remaining_depth))
      return std::nullopt;

    std::vector<uint8_t> bytes;
    if (!getNodeAtVersionImpl(node_hash, version, bytes))
      return std::nullopt;

    if (!bytes.empty() && bytes[0] == TAG_LEAF)
    {
      LeafNode leaf;
      if (!parseLeaf(bytes, leaf))
        return std::nullopt;
      if (leaf.key != key)
        return std::nullopt;

      std::vector<uint8_t> value;
      if (!getLeafDataAtVersionImpl(node_hash, version, value))
        return std::nullopt;
      return value;
    }

    BranchNode branch;
    if (!parseBranch(bytes, branch))
      return std::nullopt;

    if (!sharesPrefix(key, KEY_BITS - remaining_depth,
                      branch.prefix_len, branch.prefix_bits))
      return std::nullopt;

    const size_t branch_bit_index = KEY_BITS - remaining_depth + branch.prefix_len;
    const uint8_t bit = bitAt(key, branch_bit_index);

    const size_t child_remaining = remaining_depth - branch.prefix_len - 1;
    const Crypto::Hash &child = (bit == 0) ? branch.left : branch.right;
    return getAtVersionRecursive(child, key, child_remaining, version);
  }

  std::optional<Crypto::Hash>
  SparseMerkleTree::rootAtVersion(uint64_t version) const
  {
    std::string key = "smt_root_at_" + std::to_string(version);
    std::vector<uint8_t> stored;
    if (!getMetaImpl(key, stored) || stored.size() != 32)
      return std::nullopt;

    Crypto::Hash h;
    std::memcpy(h.data.data(), stored.data(), 32);
    return h;
  }

  std::optional<std::vector<uint8_t>>
  SparseMerkleTree::getAtVersion(const Crypto::Hash &key,
                                 uint64_t version) const
  {
    auto historic_root = rootAtVersion(version);
    if (!historic_root.has_value())
      return std::nullopt;

    //  Fast path: the historical root equals the current root.
    //  Either the requested version is the current one, or no
    //  state change has occurred since. Either way, the live
    //  tables are valid and we avoid the historical walk.
    if (*historic_root == root_)
      return get(key);

    return getAtVersionRecursive(*historic_root, key, KEY_BITS, version);
  }

  //  =========================================================================
  //  Lifecycle
  //  =========================================================================

  void SparseMerkleTree::load()
  {
    std::vector<uint8_t> stored;
    if (getMetaImpl("smt_root", stored) && stored.size() == 32)
    {
      std::memcpy(root_.data.data(), stored.data(), 32);
    }
    else
    {
      root_ = defaultHash(KEY_BITS);
    }

    //  The root may have changed, so the cached height is invalid.
    //  The next height() call will walk the tree to recompute it.
    height_dirty_ = true;
  }

  size_t SparseMerkleTree::height() const noexcept
  {
    if (!height_dirty_)
      return height_;

    size_t h = 0;
    if (root_ != defaultHash(KEY_BITS))
    {
      Crypto::Hash current = root_;
      size_t remaining = KEY_BITS;
      while (current != defaultHash(remaining))
      {
        std::vector<uint8_t> bytes;
        if (!getNodeImpl(current, bytes))
          break;

        if (!bytes.empty() && bytes[0] == TAG_LEAF)
        {
          ++h;
          break;
        }

        BranchNode b;
        if (!parseBranch(bytes, b))
          break;

        current = b.left;

        //  Guard against a malformed branch claiming a prefix
        //  longer than the remaining depth.
        if (b.prefix_len + 1 > remaining)
          break;

        remaining -= (b.prefix_len + 1);
        ++h;

        //  Guard against pathological depth. A well-formed tree
        //  with N leaves has height at most KEY_BITS.
        if (h > KEY_BITS)
          break;
      }
    }

    height_ = h;
    height_dirty_ = false;
    return h;
  }

  void SparseMerkleTree::save(uint64_t version)
  {
    std::vector<uint8_t> root_bytes(root_.data.begin(), root_.data.end());
    putMetaImpl("smt_root", root_bytes);

    std::string version_key = "smt_root_at_" + std::to_string(version);
    putMetaImpl(version_key, root_bytes);
  }

  void SparseMerkleTree::pruneHistory(uint64_t keepFrom)
  {
    //  The prune path is owned by StateDB, which knows the exact
    //  key layouts of the four historical tables and their
    //  by-version indexes. If a write txn is bound to this tree,
    //  the prune runs inside it, so rows written by the current
    //  block are visible to the scan and are deleted from the
    //  same view.
    //
    //  The prune does not touch the live tables or the current
    //  root, so a failure here cannot corrupt the live tree.

    ++stats_.prune_scans;

    if (txn_)
      db_.pruneHistoryBeforeTxn(*txn_, keepFrom);
    else
      db_.pruneHistoryBefore(keepFrom);
  }

  //  =========================================================================
  //  Debug
  //  =========================================================================

  std::string SparseMerkleTree::debugDump() const
  {
    std::ostringstream out;
    out << "SparseMerkleTree:\n";
    out << "  root:   " << Common::podToHex(root_) << "\n";
    out << "  height: " << height_ << "\n";
    out << "  empty:  " << (root_ == defaultHash(KEY_BITS) ? "yes" : "no")
        << "\n";
    return out.str();
  }

} // namespace State