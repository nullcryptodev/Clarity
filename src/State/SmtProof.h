// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "Crypto/Types.h"
#include "SparseMerkleTree.h"

namespace State
{
  //  =========================================================================
  //  SmtProof — compressed Merkle proof
  //
  //  A proof for a key in a SparseMerkleTree. Consists of three parts:
  //
  //    - The key being proven.
  //    - A terminal descriptor: what the walk actually stopped on. The
  //      terminal is either an inclusion (a leaf whose key matches), or
  //      one of three flavours of non-inclusion (a default subtree, a
  //      different leaf, or a divergent branch).
  //    - A list of siblings from the terminal up to the root, each
  //      carrying the branch prefix needed to reconstruct that branch.
  //
  //  The verifier computes the terminal hash from the terminal
  //  descriptor, then walks the sibling list in reverse
  //  (root-first), reconstructing each branch hash in turn. The
  //  reconstructed root must equal the expected root.
  //
  //  Why a terminal descriptor is needed
  //  -----------------------------------
  //
  //  A naive design would have the proof carry only "value or not" and
  //  let the verifier start from the leaf hash (for inclusion) or the
  //  empty-leaf hash (for non-inclusion). That works for inclusion and
  //  for non-inclusion at a default subtree, but it is wrong for the
  //  two other non-inclusion cases:
  //
  //    - Non-inclusion at a leaf: the walk stops at a leaf whose key
  //      is different from the proven key. The verifier must compute
  //      that leaf's hash, so the proof must carry the leaf's key and
  //      value hash.
  //
  //    - Non-inclusion at a divergent branch: the walk stops at a
  //      branch whose prefix does not match the proven key. The
  //      verifier must compute that branch's hash, so the proof must
  //      carry the branch's prefix and both child hashes.
  //
  //  An earlier design of this file omitted the terminal descriptor and
  //  silently produced invalid proofs for the divergent-branch case.
  //  The terminal descriptor fixes that.
  //
  //  Wire format
  //  -----------
  //
  //    [32] key
  //    [1]  terminal_kind
  //           0 = inclusion (leaf with matching key)
  //           1 = non-inclusion, default subtree
  //           2 = non-inclusion, different leaf
  //           3 = non-inclusion, divergent branch
  //    ... terminal-specific bytes (see below)
  //    [1]  sibling_count
  //    [sibling_count] sibling
  //
  //    Terminal kind 0 (inclusion):
  //      [4]  value_len (LE u32)
  //      [N]  value
  //
  //    Terminal kind 1 (default):
  //      (no extra bytes; the depth is derivable from the siblings)
  //
  //    Terminal kind 2 (different leaf):
  //      [32] leaf_key
  //      [32] leaf_value_hash
  //
  //    Terminal kind 3 (divergent branch):
  //      [2]  prefix_len (BE u16)
  //      [ceil(prefix_len / 8)] prefix_bits_padded
  //      [32] left_hash
  //      [32] right_hash
  //
  //    Sibling:
  //      [2]  prefix_len (BE u16)
  //      [ceil(prefix_len / 8)] prefix_bits_padded
  //      [32] sibling_hash
  //
  //  The wire format is self-describing and rejects trailing bytes: a
  //  proof's length must equal exactly what its field values imply.
  //
  //  sibling_count is a u8, capped at KEY_BITS. A proof claiming more
  //  siblings than that is rejected before allocation, so a hostile
  //  peer cannot cause unbounded memory use.
  //  =========================================================================

  enum class ProofTerminalKind : uint8_t
  {
    Inclusion = 0,
    Default = 1,
    DifferentLeaf = 2,
    DivergentBranch = 3,
  };

  struct ProofSibling
  {
    //  The prefix length, in bits, of the branch this sibling belongs
    //  to. Zero is valid: a branch with no shared prefix.
    uint16_t prefix_len{0};

    //  The branch's prefix bits, padded to ceil(prefix_len / 8)
    //  bytes. Trailing bits in the last byte are zero.
    std::vector<uint8_t> prefix_bits;

    //  The sibling's hash: the hash of the subtree opposite the path
    //  being proven.
    Crypto::Hash hash{};

    bool isValid() const noexcept
    {
      if (prefix_len > SparseMerkleTree::KEY_BITS)
        return false;
      const size_t expected_bytes = (prefix_len + 7) / 8;
      return prefix_bits.size() == expected_bytes;
    }
  };

  struct SmtProof
  {
    //  The key being proven. For an inclusion proof, this is the leaf's
    //  key. For a non-inclusion proof, this is the key the caller
    //  asked about — the walk never finds it.
    Crypto::Hash key{};

    //  What the walk stopped on.
    ProofTerminalKind terminal_kind{ProofTerminalKind::Default};

    //  Inclusion (terminal_kind == Inclusion): the leaf's value.
    //  Empty for every other kind.
    std::optional<std::vector<uint8_t>> value;

    //  DifferentLeaf (terminal_kind == DifferentLeaf): the divergent
    //  leaf's key and value hash. The verifier uses these to compute
    //  the leaf hash.
    Crypto::Hash divergent_leaf_key{};
    Crypto::Hash divergent_leaf_value_hash{};

    //  DivergentBranch (terminal_kind == DivergentBranch): the branch's
    //  prefix and child hashes. The verifier uses these to compute the
    //  branch hash.
    uint16_t divergent_branch_prefix_len{0};
    std::vector<uint8_t> divergent_branch_prefix_bits;
    Crypto::Hash divergent_branch_left{};
    Crypto::Hash divergent_branch_right{};

    //  Siblings from terminal up to (but not including) the root,
    //  stored leaf-first. Empty for a proof against a tree whose root
    //  is the terminal itself (a single-leaf tree with an inclusion
    //  proof, or an empty tree with a non-inclusion proof).
    std::vector<ProofSibling> siblings;

    bool isInclusion() const noexcept
    {
      return terminal_kind == ProofTerminalKind::Inclusion;
    }

    //  Serialize to wire format.
    std::vector<uint8_t> serialize() const;

    //  Deserialize from wire format. Returns false on malformed input:
    //  truncated, trailing bytes, unknown terminal kind, prefix_len >
    //  KEY_BITS, prefix bytes inconsistent with prefix_len, or
    //  sibling_count > KEY_BITS.
    static bool deserialize(const uint8_t *data, size_t len, SmtProof &out);

    //  Size in bytes when serialized.
    size_t serializedSize() const noexcept;

    //  Structural validity check, without verifying against a root.
    bool isValid() const noexcept;
  };

  //  =========================================================================
  //  Proof generation
  //  =========================================================================

  //  Generate a proof for `key` at the tree's current root.
  //
  //  Returns nullopt if the tree is corrupted (a node along the path
  //  is missing or malformed). In a consistent DB this never happens.
  std::optional<SmtProof> prove(const SparseMerkleTree &tree,
                                const Crypto::Hash &key);

  //  Generate a proof for `key` at an explicit root.
  //
  //  Walks from `root` rather than from `tree.root()`. Used by the P2P
  //  GetProof handler to serve proofs against historical roots, and by
  //  tests that want to verify against a specific root.
  std::optional<SmtProof> proveAtRoot(const SparseMerkleTree &tree,
                                      const Crypto::Hash &root,
                                      const Crypto::Hash &key);

  //  =========================================================================
  //  Proof verification
  //  =========================================================================

  //  Recompute the root from the proof and compare to `expected_root`.
  //
  //  Pure function: no DB access, no side effects. Safe to call from a
  //  light client that only knows the expected root.
  bool verifyProof(const Crypto::Hash &expected_root,
                   const SmtProof &proof);

  //  =========================================================================
  //  Key derivation
  //  =========================================================================

  namespace ProofKeys
  {
    Crypto::Hash forAccount(const Crypto::Address &address);
    Crypto::Hash forTokenBalance(const Crypto::Address &address, Id token_id);
    Crypto::Hash forGlobal(const std::string &name);
    Crypto::Hash nft(uint64_t nft_id) noexcept;
    Crypto::Hash nftCollection(uint64_t collection_id) noexcept;
    Crypto::Address nftAddress(uint64_t nft_id) noexcept;
    Crypto::Address nftCollectionAddress(uint64_t collection_id) noexcept;
  }

} // namespace State