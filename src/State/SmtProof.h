// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "Crypto/Types.h"
#include "SparseMerkleTree.h"

namespace State
{
  //  SmtProof
  //
  //  A Merkle proof for a key in the Sparse Merkle Tree. The proof consists
  //  of the sibling hash at each level, from root down to leaf.
  //
  //  The proof is depth-first (root's child first, leaf's sibling last).
  //  Exactly 256 siblings, since the tree is fixed-depth.
  //
  //  For non-inclusion proofs, `value` is nullopt and the proof demonstrates
  //  the leaf at the key's position is the empty leaf (or the default hash
  //  for that subtree if the entire subtree is empty).
  //
  //  Wire format (for transmission to light clients):
  //    [32] key
  //    [1]  has_value (0 or 1)
  //    [0 or N] value (variable, only if has_value)
  //    [32 * 256] siblings (root-first)

  struct SmtProof
  {
    Crypto::Hash key;
    std::optional<std::vector<uint8_t>> value; // nullopt = non-inclusion
    std::vector<Crypto::Hash> siblings;        // exactly 256, root-first

    bool isInclusion() const noexcept { return value.has_value(); }

    // Serialize for wire transmission.
    std::vector<uint8_t> serialize() const;

    // Deserialize from wire format. Returns false on malformed input.
    static bool deserialize(const uint8_t *data, size_t len, SmtProof &out);

    // Size in bytes when serialized.
    size_t serializedSize() const noexcept;
  };

  //  Proof generation
  //
  //  Generates a proof for `key` at the current tree root. Reads the tree's
  //  nodes from the DB.
  //
  //  Returns nullopt if the tree is corrupted (missing nodes along the path).
  //  Should never happen with a consistent DB.

  std::optional<SmtProof> prove(const SparseMerkleTree &tree, const Crypto::Hash &key);

  //  Proof verification
  //
  //  Recomputes the root from the proof and compares to `expected_root`.
  //  Returns true iff the proof is valid.
  //
  //  This is a pure function — no DB access, no side effects. Safe to call
  //  from a light client with only the state root.

  bool verifyProof(const Crypto::Hash &expected_root,
                   const SmtProof &proof);

  //  Key derivation for proofs
  //
  //  When a light client asks for a proof of "Alice's balance", it needs
  //  the SMT key. These helpers convert public identifiers to SMT keys.

  namespace ProofKeys
  {
    // Account state proof key.
    Crypto::Hash forAccount(const Crypto::Address &address);

    // Token balance proof key.
    Crypto::Hash forTokenBalance(const Crypto::Address &address, Id token_id);

    // Generic: proof for a global state variable.
    Crypto::Hash forGlobal(const std::string &name);
  }

} // namespace State