// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "StateDB.h"

namespace State
{
  //  =========================================================================
  //  SparseMerkleTree — compressed radix Merkle trie
  //
  //  A 256-bit-key Merkle trie with path compression. Each node is one of:
  //
  //    Leaf     A key and the hash of its value. Hash preimage:
  //               "leaf" || TAG_LEAF || key(32) || value_hash(32)
  //
  //    Branch   A shared bit-prefix and two child hashes. The two
  //             children are distinguished by the bit immediately
  //             following the prefix. Hash preimage:
  //               "brch" || TAG_BRANCH || prefix_len(BE16)
  //                      || prefix_bits_padded || left(32) || right(32)
  //
  //    Default  The canonical empty subtree at a given remaining
  //             depth. Hash preimage:
  //               "dflt" || TAG_DEFAULT || depth(BE16)
  //
  //  Unlike the previous fixed-depth 256-level binary trie, this tree has
  //  no single-child internal nodes. A chain of single-child nodes is
  //  collapsed into a single branch by storing the shared prefix on the
  //  branch itself. The tree height for N random keys is O(log N), so a
  //  single update writes O(log N) nodes instead of a fixed 256.
  //
  //  The tree is a stateless façade over StateDB. The only in-memory
  //  state is the cached root hash and a lazily-computed height. Every
  //  read fetches nodes from the bound transaction (or the DB's
  //  autocommit path), and every write stores them there. This keeps the
  //  tree correct across restarts and makes it usable both from the
  //  block processor (txn-bound) and from the RPC layer (autocommit
  //  read-only).
  //
  //  =========================================================================
  //
  //  Storage layout
  //
  //  Live tables:
  //
  //    TBL_SMT_NODES    key = node hash (32)
  //                     value = node bytes
  //                       leaf:   TAG_LEAF(1)   || key(32) || value_hash(32)
  //                       branch: TAG_BRANCH(1) || prefix_len(BE16)
  //                               || prefix_bits_padded
  //                               || left_hash(32) || right_hash(32)
  //
  //    TBL_SMT_LEAVES   key = leaf hash (32)
  //                     value = leaf value (arbitrary length)
  //
  //  Historical tables (each row is keyed by (hash, version) or
  //  (version, hash) — see StateDB.h for the exact layouts):
  //
  //    TBL_SMT_NODES_HIST      node bytes at a specific version
  //    TBL_SMT_LEAVES_HIST     leaf value at a specific version
  //    TBL_SMT_NODES_BY_VER    prune index: (version, hash) → empty
  //    TBL_SMT_LEAVES_BY_VER   prune index: (version, hash) → empty
  //
  //  The current root lives in TBL_META["smt_root"]; each version's
  //  root lives in TBL_META["smt_root_at_<version>"]. Both are pruned
  //  along with the historical tables.
  //
  //  =========================================================================
  //
  //  Versioning
  //
  //  The version is the block height. Version 0 is the genesis bootstrap
  //  and is written to the live tables only — never to the historical
  //  tables. This is because:
  //
  //    - No block has been applied yet, so there is no "prior state"
  //      to look back at.
  //    - Genesis construction runs through the same code path as a
  //      normal update; skipping the historical write keeps the
  //      bootstrap from filling the DB with rows nobody will read.
  //
  //  The live-tree write is unconditional. Every update, at every
  //  version including 0, writes the new nodes to TBL_SMT_NODES and
  //  TBL_SMT_LEAVES. Without this, the tree would not be readable.
  //
  //  =========================================================================
  //
  //  Txn binding
  //
  //  Two bindings are supported:
  //
  //    setTxn(StateDB::Txn*)          — bound to a write transaction
  //    setReadTxn(StateDB::ReadTxn*)  — bound to a read transaction
  //
  //  Exactly one may be non-null at a time. If both are null, the tree
  //  falls back to StateDB's autocommit path, which itself reuses the
  //  per-thread read txn if one is open. This means the tree can be
  //  constructed and used without any explicit binding; the binding is
  //  an optimisation and a correctness mechanism for callers that need
  //  to see their own uncommitted writes.
  //
  //  =========================================================================

  class SparseMerkleTree
  {
  public:
    //  ---- Key geometry ----

    //  The tree reads keys one bit at a time, MSB first. KEY_BITS is
    //  the total key length in bits; KEY_BYTES is the on-disk key
    //  length. Changing either is a hard fork.
    static constexpr size_t KEY_BITS = 256;
    static constexpr size_t KEY_BYTES = KEY_BITS / 8;

    //  ---- Node kind tags ----
    //
    //  These are baked into every node's hash preimage. Once a chain
    //  ships with them, they can never change without a state-root
    //  change.
    static constexpr uint8_t TAG_LEAF = 0x00;
    static constexpr uint8_t TAG_BRANCH = 0x01;
    static constexpr uint8_t TAG_DEFAULT = 0x02;

    //  Maximum prefix length on a single branch. A branch whose prefix
    //  would exceed this cannot be constructed; in practice the value
    //  only appears as a bound check on hostile input.
    static constexpr size_t MAX_PREFIX_BITS = KEY_BITS;

    //  ---- Diagnostics ----
    //
    //  Monotonic counters, reset only by resetStats(). The write
    //  counters are the ones that matter for storage budgeting; the
    //  read counters for cache hit-rate visibility; the proof counters
    //  for light-client observability.
    //
    //  These are exposed to the metrics endpoint as clrty_smt_* series.
    //  Field names are stable; renaming any of them is a breaking
    //  change for dashboards and alerting rules.
    struct Stats
    {
      //  Operation counters.
      uint64_t updates = 0;
      uint64_t removes = 0;
      uint64_t reads = 0;
      uint64_t read_hits = 0;
      uint64_t batch_updates = 0;

      //  Write counters, split by table. These are the storage
      //  cost of the tree, per operation.
      uint64_t live_node_writes = 0;
      uint64_t live_leaf_writes = 0;
      uint64_t hist_node_writes = 0;
      uint64_t hist_leaf_writes = 0;
      uint64_t by_ver_writes = 0;

      //  Pruning counters.
      uint64_t prune_scans = 0;
      uint64_t prune_deletes = 0;

      //  Aggregate size hints, updated as the tree is walked. These
      //  are informative, not authoritative: the tree does not
      //  maintain a live count of nodes, and computing one exactly
      //  would require a full scan. The values here are drawn from
      //  the walks the tree already does.
      uint64_t deepest_leaf_depth_seen = 0;
    };

    //  ---- Construction ----

    explicit SparseMerkleTree(StateDB &db);
    ~SparseMerkleTree() = default;

    SparseMerkleTree(const SparseMerkleTree &) = delete;
    SparseMerkleTree &operator=(const SparseMerkleTree &) = delete;

    //  ---- Txn binding ----
    //
    //  Binding one disables the other. Passing a non-null pointer to
    //  one clears the other. Passing nullptr to both reverts to
    //  autocommit behaviour.
    void setTxn(StateDB::Txn *txn) noexcept;
    void setReadTxn(StateDB::ReadTxn *read_txn) noexcept;
    StateDB::Txn *txn() const noexcept { return txn_; }
    StateDB::ReadTxn *readTxn() const noexcept { return read_txn_; }

    //  ---- Root access ----

    //  The cached root hash. For an empty tree this is
    //  defaultHash(KEY_BITS).
    Crypto::Hash root() const noexcept { return root_; }

    //  Height of the tree: the maximum number of branch hops from the
    //  root to any leaf. Zero for an empty tree, one for a single
    //  leaf, O(log N) for N random keys. Used by tests and by the
    //  diagnostics endpoint; not consensus-relevant.
    //
    //  Lazily computed: the tree marks a flag whenever the root
    //  changes, and this method walks the tree once to compute the
    //  height when the flag is set. Subsequent calls with no
    //  intervening write return the cached value.
    size_t height() const noexcept;

    //  ---- Core operations ----

    //  Look up a key. Returns nullopt if the key is absent. Reads
    //  through the bound txn if any, else through the DB's
    //  autocommit path. The walk reads one node per level.
    std::optional<std::vector<uint8_t>> get(const Crypto::Hash &key) const;

    //  Update or insert a key. Returns the new root. Every node on
    //  the path from the root to the leaf is written to the live
    //  tables; if version != 0, each is also written to the
    //  historical tables.
    Crypto::Hash update(const Crypto::Hash &key,
                        const std::vector<uint8_t> &value,
                        uint64_t version);

    //  Remove a key. Returns the new root. The leaf is replaced by
    //  the default for its depth; on the way back up, any branch
    //  with a default child is collapsed into the non-default child
    //  with an extended prefix.
    Crypto::Hash remove(const Crypto::Hash &key, uint64_t version);

    //  Apply a batch of updates. The batch is sorted by key and
    //  de-duplicated before being applied, so the same key is
    //  written once even if it appears multiple times. This is the
    //  path used by the block processor to apply the state
    //  transition of a whole block.
    struct Update
    {
      Crypto::Hash key;
      std::vector<uint8_t> value;
      bool is_delete{false};
    };

    Crypto::Hash applyBatch(const std::vector<Update> &updates,
                            uint64_t version);

    //  ---- Historical reads ----
    //
    //  Both return nullopt if the version has no saved root
    //  (outside the retention window, or never written). Callers
    //  that need to distinguish "no such key" from "no such
    //  version" should call rootAtVersion first and check.

    std::optional<std::vector<uint8_t>> getAtVersion(
        const Crypto::Hash &key, uint64_t version) const;

    std::optional<Crypto::Hash> rootAtVersion(uint64_t version) const;

    //  ---- Lifecycle ----

    //  Read the current root from TBL_META["smt_root"]. If absent,
    //  the tree is treated as empty and root_ is set to
    //  defaultHash(KEY_BITS). Marks the height cache as dirty so the
    //  next height() call recomputes it.
    void load();

    //  Persist the current root and the per-version root to
    //  TBL_META. Called by the block processor after applyBatch.
    void save(uint64_t version);

    //  Delete every historical row whose version is strictly less
    //  than keepFrom, from all four historical tables. The live
    //  tables and the current root are untouched.
    //
    //  Runs inside the caller's txn if one is bound; otherwise opens
    //  its own write txn.
    void pruneHistory(uint64_t keepFrom);

    //  ---- Node fetch (for proof generation and tests) ----
    //
    //  These read through the bound txn if any, else through the
    //  DB's autocommit path. They are exposed publicly so that
    //  SmtProof can construct proofs without needing to be a friend
    //  of the tree, and so that tests can drive the tree at the node
    //  level. They are not part of the state-transition API and
    //  should not be called from block processing.

    //  Read a node's bytes by hash. For a leaf, this returns the
    //  leaf's preimage (TAG_LEAF || key || value_hash), not the
    //  leaf's value — value bytes are fetched separately via
    //  getLeafData.
    bool readNode(const Crypto::Hash &node_hash,
                  std::vector<uint8_t> &out) const;

    //  Read a leaf's value by the leaf's hash.
    bool getLeafData(const Crypto::Hash &leaf_hash,
                     std::vector<uint8_t> &out) const;

    //  ---- Default hashes ----

    //  defaultHash(d) is the hash of the canonical empty subtree at
    //  remaining depth d. defaultHash(0) is the empty leaf.
    //  defaultHash(KEY_BITS) is the empty tree's root. Values are
    //  computed once at first use and cached.
    static const Crypto::Hash &defaultHash(size_t depth) noexcept;

    //  ---- Stats ----

    const Stats &stats() const noexcept { return stats_; }
    void resetStats() noexcept { stats_ = Stats{}; }

    //  ---- Debug ----

    //  Walk the tree from the root and emit a textual representation.
    //  Not for production use; intended for tests and for operators
    //  diagnosing a corrupted DB. The format is not stable and may
    //  change without notice.
    std::string debugDump() const;

  private:
    //  ---- Node parsing ----

    //  A parsed leaf node.
    struct LeafNode
    {
      Crypto::Hash key;
      Crypto::Hash value_hash;
    };

    //  A parsed branch node.
    struct BranchNode
    {
      uint16_t prefix_len{0};
      std::vector<uint8_t> prefix_bits; // ceil(prefix_len/8) bytes
      Crypto::Hash left;
      Crypto::Hash right;
    };

    //  Parse a node's bytes. Returns false on a malformed node (bad
    //  tag, truncated prefix, wrong length). A false return from a
    //  read path means the DB is corrupt; callers should treat it as
    //  a fatal error and log the node hash.
    static bool parseLeaf(const std::vector<uint8_t> &bytes,
                          LeafNode &out) noexcept;
    static bool parseBranch(const std::vector<uint8_t> &bytes,
                            BranchNode &out) noexcept;

    //  ---- Node construction ----
    //
    //  Each of these computes the node's hash, writes the node to
    //  the live and (if version != 0) historical tables, and returns
    //  the hash. The caller does not write to the DB itself.

    Crypto::Hash makeLeaf(const Crypto::Hash &key,
                          const Crypto::Hash &value_hash,
                          uint64_t version);

    Crypto::Hash makeBranch(uint16_t prefix_len,
                            const std::vector<uint8_t> &prefix_bits,
                            const Crypto::Hash &left,
                            const Crypto::Hash &right,
                            uint64_t version);

    //  ---- Hashing ----
    //
    //  All three are static and pure. They are the only places the
    //  hash preimage is constructed.

    static Crypto::Hash hashLeaf(const Crypto::Hash &key,
                                 const Crypto::Hash &value_hash) noexcept;

    static Crypto::Hash hashBranch(uint16_t prefix_len,
                                   const std::vector<uint8_t> &prefix_bits,
                                   const Crypto::Hash &left,
                                   const Crypto::Hash &right) noexcept;

    //  ---- Recursion ----
    //
    //  Both walk from the root, following the key's bits. They read
    //  through the bound txn (or autocommit path) and write through
    //  the same channel. The depth parameter is the number of
    //  remaining key bits from the current node down to the leaf.
    //
    //  updateRecursive may write to the DB; getRecursive does not.

    Crypto::Hash updateRecursive(const Crypto::Hash &node_hash,
                                 const Crypto::Hash &key,
                                 const std::vector<uint8_t> &value,
                                 bool is_delete,
                                 size_t remaining_depth,
                                 uint64_t version);

    std::optional<std::vector<uint8_t>> getRecursive(
        const Crypto::Hash &node_hash,
        const Crypto::Hash &key,
        size_t remaining_depth) const;

    std::optional<std::vector<uint8_t>> getAtVersionRecursive(
        const Crypto::Hash &node_hash,
        const Crypto::Hash &key,
        size_t remaining_depth,
        uint64_t version) const;

    //  ---- Txn-aware storage helpers ----
    //
    //  Every read and write of an SMT row goes through one of these.
    //  If a write txn is bound, it is used; else if a read txn is
    //  bound, it is used for reads and a write through it is an
    //  error (the tree cannot write through a read-only txn); else
    //  the DB's autocommit path is used.

    bool getNodeImpl(const Crypto::Hash &hash,
                     std::vector<uint8_t> &out) const;

    void putNodeImpl(const Crypto::Hash &hash,
                     const std::vector<uint8_t> &bytes,
                     uint64_t version);

    bool getLeafDataImpl(const Crypto::Hash &leaf_hash,
                         std::vector<uint8_t> &out) const;

    void putLeafDataImpl(const Crypto::Hash &leaf_hash,
                         const std::vector<uint8_t> &value,
                         uint64_t version);

    bool getNodeAtVersionImpl(const Crypto::Hash &hash,
                              uint64_t version,
                              std::vector<uint8_t> &out) const;

    bool getLeafDataAtVersionImpl(const Crypto::Hash &leaf_hash,
                                  uint64_t version,
                                  std::vector<uint8_t> &out) const;

    bool getMetaImpl(const std::string &key,
                     std::vector<uint8_t> &out) const;

    void putMetaImpl(const std::string &key,
                     const std::vector<uint8_t> &value);

    //  ---- Members ----

    StateDB &db_;
    StateDB::Txn *txn_{nullptr};
    StateDB::ReadTxn *read_txn_{nullptr};
    Crypto::Hash root_{};

    //  Cached tree height. Invalidated by any operation that
    //  changes the root. Read only through height(), which
    //  recomputes the value if the cache is dirty.
    mutable size_t height_{0};
    mutable bool height_dirty_{true};

    Stats stats_{};
  };

} // namespace State