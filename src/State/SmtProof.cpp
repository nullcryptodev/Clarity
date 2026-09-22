// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>

#include "SmtProof.h"
#include "SparseMerkleTree.h"

#include "Crypto/Blake2b.h"

#include "Common/Put.h"
#include "Common/Read.h"

namespace State
{

  //  Serialization

  namespace
  {
    constexpr size_t PROOF_SIBLINGS = SparseMerkleTree::DEPTH; // 256
  } // anonymous namespace

  size_t SmtProof::serializedSize() const noexcept
  {
    size_t sz = 32 + 1 + 4;
    if (value.has_value())
      sz += value->size();
    sz += 32 * PROOF_SIBLINGS;
    return sz;
  }

  std::vector<uint8_t> SmtProof::serialize() const
  {
    std::vector<uint8_t> out;
    out.reserve(serializedSize());

    out.insert(out.end(), key.data.begin(), key.data.end());
    out.push_back(value.has_value() ? 1 : 0);

    uint32_t value_size = value.has_value()
                              ? static_cast<uint32_t>(value->size())
                              : 0;
    Common::putU32(out, value_size);

    if (value.has_value() && !value->empty())
    {
      out.insert(out.end(), value->begin(), value->end());
    }

    for (const auto &sib : siblings)
    {
      out.insert(out.end(), sib.data.begin(), sib.data.end());
    }

    return out;
  }

  bool SmtProof::deserialize(const uint8_t *data, size_t len, SmtProof &out)
  {
    if (len < 32 + 1 + 4 + 32 * PROOF_SIBLINGS)
      return false;

    size_t off = 0;

    std::memcpy(out.key.data.data(), data + off, 32);
    off += 32;

    uint8_t has_value = data[off++];

    uint32_t value_size = Common::readU32(data + off);
    off += 4;

    if (value_size > 64 * 1024)
      return false;

    if (off + value_size + 32 * PROOF_SIBLINGS > len)
      return false;

    if (has_value)
    {
      std::vector<uint8_t> v(data + off, data + off + value_size);
      out.value = std::move(v);
    }
    else
    {
      out.value.reset();
    }
    off += value_size;

    out.siblings.clear();
    out.siblings.reserve(PROOF_SIBLINGS);

    for (size_t i = 0; i < PROOF_SIBLINGS; ++i)
    {
      Crypto::Hash sib;
      std::memcpy(sib.data.data(), data + off, 32);
      off += 32;
      out.siblings.push_back(sib);
    }

    return true;
  }

  //  Proof generation

  namespace
  {
    Crypto::Hash computeLeafHash(const Crypto::Hash &key,
                                 const std::vector<uint8_t> &value) noexcept
    {
      Crypto::Hash value_hash;
      Crypto::blake2b(value.data(), value.size(), value_hash.data.data(), 32);

      uint8_t buf[1 + 32 + 32];
      buf[0] = 0x00;
      std::memcpy(buf + 1, key.data.data(), 32);
      std::memcpy(buf + 33, value_hash.data.data(), 32);

      Crypto::Hash h;
      Crypto::blake2b(buf, sizeof(buf), h.data.data(), 32);
      return h;
    }

    // SMT stores a single canonical empty leaf at defaultHash(0), not
    // a per-key hash.
    Crypto::Hash computeEmptyLeafHash(const Crypto::Hash & /*key*/) noexcept
    {
      return SparseMerkleTree::defaultHash(0);
    }

    Crypto::Hash computeInternalHash(const Crypto::Hash &left,
                                     const Crypto::Hash &right) noexcept
    {
      uint8_t buf[1 + 32 + 32];
      buf[0] = 0x01;
      std::memcpy(buf + 1, left.data.data(), 32);
      std::memcpy(buf + 33, right.data.data(), 32);

      Crypto::Hash h;
      Crypto::blake2b(buf, sizeof(buf), h.data.data(), 32);
      return h;
    }
  } // anonymous namespace

  std::optional<SmtProof> prove(const SparseMerkleTree &tree, const Crypto::Hash &key)
  {
    SmtProof proof;
    proof.key = key;
    proof.siblings.resize(SparseMerkleTree::DEPTH);

    // Read the leaf value (nullopt for non-inclusion).
    proof.value = tree.get(key);

    // Walk down from the root. Siblings are stored root-first:
    //   siblings[0]  = sibling at the root level (depth 256)
    //   siblings[i]  = sibling at depth (DEPTH - i)
    //   siblings[255]= sibling at the leaf's parent level (depth 1)
    Crypto::Hash current = tree.root();

    for (size_t i = 0; i < SparseMerkleTree::DEPTH; ++i)
    {
      const size_t depth = SparseMerkleTree::DEPTH - i;

      // Once we enter an empty subtree, every remaining sibling is a
      // default hash for its own depth, and every subsequent parent
      // hash will be the default for one level up.
      if (current == SparseMerkleTree::defaultHash(depth))
      {
        for (size_t j = i; j < SparseMerkleTree::DEPTH; ++j)
        {
          proof.siblings[j] =
              SparseMerkleTree::defaultHash(SparseMerkleTree::DEPTH - j - 1);
        }
        return proof;
      }

      Crypto::Hash left, right;
      if (!tree.readChildren(current, left, right))
      {
        return std::nullopt; // corrupted tree
      }

      const uint8_t byte = key.data[i / 8];
      const uint8_t mask = 0x80 >> (i % 8);
      const bool go_right = (byte & mask) != 0;

      if (go_right)
      {
        proof.siblings[i] = left;
        current = right;
      }
      else
      {
        proof.siblings[i] = right;
        current = left;
      }
    }

    return proof;
  }

  //  Proof verification

  bool verifyProof(const Crypto::Hash &expected_root,
                   const SmtProof &proof)
  {
    if (proof.siblings.size() != SparseMerkleTree::DEPTH)
      return false;

    // Compute the leaf hash.
    Crypto::Hash current;
    if (proof.value.has_value())
      current = computeLeafHash(proof.key, *proof.value);
    else
      current = computeEmptyLeafHash(proof.key);

    // Walk up from the leaf. Siblings are stored root-first, so the
    // sibling for level (from leaf) is at index DEPTH - 1 - level.
    for (size_t level = 0; level < SparseMerkleTree::DEPTH; ++level)
    {
      const Crypto::Hash &sibling = proof.siblings[SparseMerkleTree::DEPTH - 1 - level];

      // Bit index from the root for this level.
      const size_t bit_index = SparseMerkleTree::DEPTH - 1 - level;
      const uint8_t byte = proof.key.data[bit_index / 8];
      const uint8_t mask = 0x80 >> (bit_index % 8);
      const bool was_right = (byte & mask) != 0;

      if (was_right)
        current = computeInternalHash(sibling, current);
      else
        current = computeInternalHash(current, sibling);
    }

    return current == expected_root;
  }

  //  Proof key helpers

  namespace ProofKeys
  {
    Crypto::Hash forAccount(const Crypto::Address &address)
    {
      return Keys::account(address);
    }

    Crypto::Hash forTokenBalance(const Crypto::Address &address, Id token_id)
    {
      return Keys::tokenBalance(address, token_id);
    }

    Crypto::Hash forGlobal(const std::string &name)
    {
      return Keys::global(name);
    }
  } // namespace ProofKeys

} // namespace State