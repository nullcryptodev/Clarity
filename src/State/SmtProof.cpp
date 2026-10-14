// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SmtProof.h"
#include "Keys.h"

#include "Crypto/Blake2b.h"
#include "Common/Wire.h"

#include <array>
#include <cstring>

namespace State
{

  //  =========================================================================
  //  Shared constants and helpers
  //  =========================================================================

  namespace
  {
    //  A proof can carry at most KEY_BITS siblings. Each branch
    //  consumes at least one bit (the branching bit), so the depth of
    //  a path is bounded by KEY_BITS.
    constexpr size_t MAX_SIBLINGS = SparseMerkleTree::KEY_BITS;

    //  Maximum leaf value length. Bounds the allocation on the decode
    //  side, so a hostile input cannot trigger a large alloc before
    //  the structural checks fail.
    constexpr uint32_t MAX_VALUE_LEN = 64 * 1024;

    //  Domain strings and tags. These MUST match the constants in
    //  SparseMerkleTree.cpp byte for byte. A mismatch would make every
    //  proof fail verification while the tree itself remains internally
    //  consistent, which is the worst kind of bug to diagnose.
    constexpr char DOMAIN_LEAF[4] = {'l', 'e', 'a', 'f'};
    constexpr char DOMAIN_BRANCH[4] = {'b', 'r', 'c', 'h'};
    constexpr char DOMAIN_DEFAULT[4] = {'d', 'f', 'l', 't'};

    inline void writeBE16(uint8_t *out, uint16_t v) noexcept
    {
      out[0] = uint8_t(v >> 8);
      out[1] = uint8_t(v & 0xFF);
    }

    inline uint16_t readBE16(const uint8_t *in) noexcept
    {
      return uint16_t(in[0]) << 8 | uint16_t(in[1]);
    }

    inline uint8_t bitAt(const Crypto::Hash &key, size_t bit_index) noexcept
    {
      const uint8_t byte = key.data[bit_index / 8];
      const uint8_t mask = uint8_t(0x80 >> (bit_index % 8));
      return (byte & mask) ? 1 : 0;
    }

    //  Test whether `key`, starting at `start_bit`, shares the
    //  `prefix_len` bits stored in `prefix_bits`. `prefix_bits` is a
    //  packed representation of the bits starting from bit 0 of its
    //  own buffer.
    //
    //  This mirrors the tree's sharesPrefix exactly. It is duplicated
    //  here rather than exposed by SparseMerkleTree because proof
    //  generation must not depend on the tree's private state — the
    //  verifying side of a proof does not need a tree object at all.
    bool sharesPrefixAt(const Crypto::Hash &key,
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

    //  The three hash functions. Each mirrors the tree's internal
    //  hashing exactly; see the comment on DOMAIN_LEAF above.
    Crypto::Hash hashLeafForProof(const Crypto::Hash &key,
                                  const Crypto::Hash &value_hash) noexcept
    {
      uint8_t buf[4 + 1 + 32 + 32];
      std::memcpy(buf, DOMAIN_LEAF, 4);
      buf[4] = SparseMerkleTree::TAG_LEAF;
      std::memcpy(buf + 5, key.data.data(), 32);
      std::memcpy(buf + 5 + 32, value_hash.data.data(), 32);

      Crypto::Hash h;
      Crypto::blake2b(buf, sizeof(buf), h.data.data(), 32);
      return h;
    }

    Crypto::Hash hashBranchForProof(
        uint16_t prefix_len,
        const std::vector<uint8_t> &prefix_bits,
        const Crypto::Hash &left,
        const Crypto::Hash &right) noexcept
    {
      const size_t prefix_bytes = (prefix_len + 7) / 8;

      constexpr size_t HEADER = 4 + 1 + 2;
      std::array<uint8_t, HEADER + 32 + 32 + 32> buf{};

      std::memcpy(buf.data(), DOMAIN_BRANCH, 4);
      buf[4] = SparseMerkleTree::TAG_BRANCH;
      writeBE16(buf.data() + 5, prefix_len);

      if (prefix_bytes > 0)
        std::memcpy(buf.data() + HEADER, prefix_bits.data(), prefix_bytes);

      std::memcpy(buf.data() + HEADER + prefix_bytes,
                  left.data.data(), 32);
      std::memcpy(buf.data() + HEADER + prefix_bytes + 32,
                  right.data.data(), 32);

      Crypto::Hash h;
      Crypto::blake2b(buf.data(), HEADER + prefix_bytes + 64,
                      h.data.data(), 32);
      return h;
    }

    //  Depth of the terminal, given the sibling list. Each sibling
    //  consumes (prefix_len + 1) bits of the remaining depth, starting
    //  from KEY_BITS. Used to reconstruct the terminal hash for a
    //  default terminal, whose only identifying information is its
    //  depth.
    size_t terminalDepth(const std::vector<ProofSibling> &siblings) noexcept
    {
      size_t remaining = SparseMerkleTree::KEY_BITS;
      for (const auto &s : siblings)
      {
        const size_t consumed = size_t(s.prefix_len) + 1;
        if (consumed > remaining)
          return 0; // malformed; caller will reject
        remaining -= consumed;
      }
      return remaining;
    }
  } // anonymous namespace

  //  =========================================================================
  //  Serialization
  //  =========================================================================

  size_t SmtProof::serializedSize() const noexcept
  {
    size_t sz = 32 + 1; // key + terminal_kind

    switch (terminal_kind)
    {
    case ProofTerminalKind::Inclusion:
      sz += 4; // value_len
      if (value.has_value())
        sz += value->size();
      break;

    case ProofTerminalKind::Default:
      //  no extra bytes
      break;

    case ProofTerminalKind::DifferentLeaf:
      sz += 32 + 32; // divergent_leaf_key + value_hash
      break;

    case ProofTerminalKind::DivergentBranch:
      sz += 2; // prefix_len
      sz += (divergent_branch_prefix_len + 7) / 8;
      sz += 32 + 32; // left + right
      break;
    }

    sz += 1; // sibling_count
    for (const auto &s : siblings)
    {
      sz += 2;
      sz += (s.prefix_len + 7) / 8;
      sz += 32;
    }

    return sz;
  }

  std::vector<uint8_t> SmtProof::serialize() const
  {
    std::vector<uint8_t> out;
    out.reserve(serializedSize());

    Common::Writer w(out);
    w.writeBytes(key.data.data(), key.data.size());
    w.writeU8(static_cast<uint8_t>(terminal_kind));

    switch (terminal_kind)
    {
    case ProofTerminalKind::Inclusion:
    {
      const uint32_t value_size =
          value.has_value() ? static_cast<uint32_t>(value->size()) : 0;
      w.writeU32(value_size);
      if (value.has_value() && !value->empty())
        w.writeBytes(value->data(), value->size());
      break;
    }

    case ProofTerminalKind::Default:
      break;

    case ProofTerminalKind::DifferentLeaf:
      w.writeBytes(divergent_leaf_key.data.data(), 32);
      w.writeBytes(divergent_leaf_value_hash.data.data(), 32);
      break;

    case ProofTerminalKind::DivergentBranch:
    {
      w.writeU16(divergent_branch_prefix_len);
      const size_t prefix_bytes = (divergent_branch_prefix_len + 7) / 8;
      if (prefix_bytes > 0)
        w.writeBytes(divergent_branch_prefix_bits.data(), prefix_bytes);
      w.writeBytes(divergent_branch_left.data.data(), 32);
      w.writeBytes(divergent_branch_right.data.data(), 32);
      break;
    }
    }

    w.writeU8(static_cast<uint8_t>(siblings.size()));

    for (const auto &s : siblings)
    {
      w.writeU16(s.prefix_len);
      const size_t prefix_bytes = (s.prefix_len + 7) / 8;
      if (prefix_bytes > 0)
        w.writeBytes(s.prefix_bits.data(), prefix_bytes);
      w.writeBytes(s.hash.data.data(), 32);
    }

    return out;
  }

  bool SmtProof::deserialize(const uint8_t *data, size_t len, SmtProof &out)
  {
    out = SmtProof{};

    if (len < 32 + 1 + 1)
      return false;

    Common::Reader r(data, len);

    r.readBytes(out.key.data.data(), out.key.data.size());
    const uint8_t kind_byte = r.readU8();
    if (kind_byte > static_cast<uint8_t>(ProofTerminalKind::DivergentBranch))
      return false;
    out.terminal_kind = static_cast<ProofTerminalKind>(kind_byte);

    switch (out.terminal_kind)
    {
    case ProofTerminalKind::Inclusion:
    {
      const uint32_t value_size = r.readU32();
      if (!r.ok() || value_size > MAX_VALUE_LEN)
        return false;
      if (r.remaining() < static_cast<size_t>(value_size) + 1)
        return false;
      out.value = r.readVector(value_size);
      break;
    }

    case ProofTerminalKind::Default:
      break;

    case ProofTerminalKind::DifferentLeaf:
    {
      if (r.remaining() < 64 + 1)
        return false;
      r.readBytes(out.divergent_leaf_key.data.data(), 32);
      r.readBytes(out.divergent_leaf_value_hash.data.data(), 32);
      break;
    }

    case ProofTerminalKind::DivergentBranch:
    {
      if (r.remaining() < 2)
        return false;
      out.divergent_branch_prefix_len = r.readU16();
      if (out.divergent_branch_prefix_len > SparseMerkleTree::KEY_BITS)
        return false;

      const size_t prefix_bytes =
          (out.divergent_branch_prefix_len + 7) / 8;
      if (r.remaining() < prefix_bytes + 64 + 1)
        return false;

      if (prefix_bytes > 0)
        out.divergent_branch_prefix_bits = r.readVector(prefix_bytes);

      r.readBytes(out.divergent_branch_left.data.data(), 32);
      r.readBytes(out.divergent_branch_right.data.data(), 32);
      break;
    }
    }

    const uint8_t sibling_count = r.readU8();
    if (sibling_count > MAX_SIBLINGS)
      return false;

    out.siblings.clear();
    out.siblings.reserve(sibling_count);

    for (uint8_t i = 0; i < sibling_count; ++i)
    {
      ProofSibling s;
      if (r.remaining() < 2)
        return false;
      s.prefix_len = r.readU16();
      if (s.prefix_len > SparseMerkleTree::KEY_BITS)
        return false;

      const size_t prefix_bytes = (s.prefix_len + 7) / 8;
      if (r.remaining() < prefix_bytes + 32)
        return false;

      if (prefix_bytes > 0)
        s.prefix_bits = r.readVector(prefix_bytes);

      r.readBytes(s.hash.data.data(), 32);
      out.siblings.push_back(std::move(s));
    }

    if (!r.ok())
      return false;
    if (r.remaining() != 0)
      return false;

    return out.isValid();
  }

  bool SmtProof::isValid() const noexcept
  {
    if (siblings.size() > MAX_SIBLINGS)
      return false;

    switch (terminal_kind)
    {
    case ProofTerminalKind::Inclusion:
      break;

    case ProofTerminalKind::Default:
      break;

    case ProofTerminalKind::DifferentLeaf:
      if (divergent_leaf_key == key)
        return false;
      break;

    case ProofTerminalKind::DivergentBranch:
    {
      if (divergent_branch_prefix_len > SparseMerkleTree::KEY_BITS)
        return false;
      if (divergent_branch_prefix_bits.size() !=
          (divergent_branch_prefix_len + 7) / 8)
        return false;

      size_t start_bit = 0;
      for (const auto &s : siblings)
      {
        start_bit += s.prefix_len + 1;
        if (start_bit > SparseMerkleTree::KEY_BITS)
          return false;
      }
      if (sharesPrefixAt(key, start_bit, divergent_branch_prefix_len,
                         divergent_branch_prefix_bits))
        return false;
      break;
    }

    default:
      return false;
    }

    for (const auto &s : siblings)
    {
      if (!s.isValid())
        return false;
    }

    return true;
  }

  //  =========================================================================
  //  Proof generation
  //  =========================================================================

  std::optional<SmtProof> proveFromRoot(const SparseMerkleTree &tree,
                                        const Crypto::Hash &root,
                                        const Crypto::Hash &key)
  {
    SmtProof proof;
    proof.key = key;

    Crypto::Hash current = root;
    size_t remaining_depth = SparseMerkleTree::KEY_BITS;

    while (true)
    {
      if (current == SparseMerkleTree::defaultHash(remaining_depth))
      {
        proof.terminal_kind = ProofTerminalKind::Default;
        return proof;
      }

      std::vector<uint8_t> bytes;
      if (!tree.readNode(current, bytes))
        return std::nullopt;

      if (!bytes.empty() && bytes[0] == SparseMerkleTree::TAG_LEAF)
      {
        if (bytes.size() != 1 + 32 + 32)
          return std::nullopt;

        Crypto::Hash leaf_key;
        std::memcpy(leaf_key.data.data(), bytes.data() + 1, 32);

        if (leaf_key == key)
        {
          std::vector<uint8_t> value;
          if (!tree.getLeafData(current, value))
            return std::nullopt;

          proof.terminal_kind = ProofTerminalKind::Inclusion;
          proof.value = std::move(value);
          return proof;
        }

        proof.terminal_kind = ProofTerminalKind::DifferentLeaf;
        proof.divergent_leaf_key = leaf_key;
        std::memcpy(proof.divergent_leaf_value_hash.data.data(),
                    bytes.data() + 33, 32);
        return proof;
      }

      if (bytes.empty() || bytes[0] != SparseMerkleTree::TAG_BRANCH)
        return std::nullopt;
      if (bytes.size() < 1 + 2 + 32 + 32)
        return std::nullopt;

      const uint16_t prefix_len = readBE16(bytes.data() + 1);
      if (prefix_len > remaining_depth)
        return std::nullopt;

      const size_t prefix_bytes = (prefix_len + 7) / 8;
      const size_t expected = 1 + 2 + prefix_bytes + 32 + 32;
      if (bytes.size() != expected)
        return std::nullopt;

      std::vector<uint8_t> prefix_bits(
          bytes.begin() + 3, bytes.begin() + 3 + prefix_bytes);

      Crypto::Hash left, right;
      std::memcpy(left.data.data(), bytes.data() + 3 + prefix_bytes, 32);
      std::memcpy(right.data.data(),
                  bytes.data() + 3 + prefix_bytes + 32, 32);

      const size_t prefix_start =
          SparseMerkleTree::KEY_BITS - remaining_depth;

      if (!sharesPrefixAt(key, prefix_start, prefix_len, prefix_bits))
      {
        proof.terminal_kind = ProofTerminalKind::DivergentBranch;
        proof.divergent_branch_prefix_len = prefix_len;
        proof.divergent_branch_prefix_bits = std::move(prefix_bits);
        proof.divergent_branch_left = left;
        proof.divergent_branch_right = right;
        return proof;
      }

      ProofSibling sib;
      sib.prefix_len = prefix_len;
      sib.prefix_bits = std::move(prefix_bits);

      const size_t branch_bit_index = prefix_start + prefix_len;
      const uint8_t bit = bitAt(key, branch_bit_index);

      if (bit == 0)
      {
        sib.hash = right;
        current = left;
      }
      else
      {
        sib.hash = left;
        current = right;
      }

      proof.siblings.push_back(std::move(sib));
      remaining_depth -= (prefix_len + 1);
    }
  }

  std::optional<SmtProof> prove(const SparseMerkleTree &tree,
                                const Crypto::Hash &key)
  {
    return proveFromRoot(tree, tree.root(), key);
  }

  std::optional<SmtProof> proveAtRoot(const SparseMerkleTree &tree,
                                      const Crypto::Hash &root,
                                      const Crypto::Hash &key)
  {
    return proveFromRoot(tree, root, key);
  }

  //  =========================================================================
  //  Proof verification
  //  =========================================================================

  bool verifyProof(const Crypto::Hash &expected_root,
                   const SmtProof &proof)
  {
    if (!proof.isValid())
      return false;

    Crypto::Hash current;
    switch (proof.terminal_kind)
    {
    case ProofTerminalKind::Inclusion:
    {
      if (!proof.value.has_value())
        return false;
      Crypto::Hash value_hash;
      Crypto::blake2b(proof.value->data(), proof.value->size(),
                      value_hash.data.data(), 32);
      current = hashLeafForProof(proof.key, value_hash);
      break;
    }

    case ProofTerminalKind::Default:
    {
      const size_t depth = terminalDepth(proof.siblings);
      current = SparseMerkleTree::defaultHash(depth);
      break;
    }

    case ProofTerminalKind::DifferentLeaf:
    {
      current = hashLeafForProof(proof.divergent_leaf_key,
                                 proof.divergent_leaf_value_hash);
      break;
    }

    case ProofTerminalKind::DivergentBranch:
    {
      current = hashBranchForProof(
          proof.divergent_branch_prefix_len,
          proof.divergent_branch_prefix_bits,
          proof.divergent_branch_left,
          proof.divergent_branch_right);
      break;
    }
    }

    //  Pre-compute the remaining depth at each sibling. Siblings are
    //  stored top-down: siblings[0] is the branch closest to the root,
    //  siblings[size-1] is the branch closest to the leaf. The
    //  remaining depth decreases by (prefix_len + 1) at each step.
    //
    //  The reconstruction loop iterates bottom-up, but needs to know
    //  each sibling's remaining depth to compute its prefix_start.
    //  The wire format does not carry the depth (it is derivable), so
    //  we compute it in a forward pass first.
    std::vector<size_t> sibling_remaining_depth(proof.siblings.size());
    {
      size_t rd = SparseMerkleTree::KEY_BITS;
      for (size_t i = 0; i < proof.siblings.size(); ++i)
      {
        sibling_remaining_depth[i] = rd;
        const size_t consumed = size_t(proof.siblings[i].prefix_len) + 1;
        if (consumed > rd)
          return false;
        rd -= consumed;
      }
    }

    //  Reconstruction, bottom-up.
    for (size_t i = proof.siblings.size(); i-- > 0;)
    {
      const ProofSibling &s = proof.siblings[i];
      const size_t remaining_depth = sibling_remaining_depth[i];

      const size_t prefix_start =
          SparseMerkleTree::KEY_BITS - remaining_depth;

      if (!sharesPrefixAt(proof.key, prefix_start,
                          s.prefix_len, s.prefix_bits))
        return false;

      const size_t branch_bit_index = prefix_start + s.prefix_len;
      if (branch_bit_index >= SparseMerkleTree::KEY_BITS)
        return false;

      const uint8_t bit = bitAt(proof.key, branch_bit_index);

      if (bit == 0)
        current = hashBranchForProof(s.prefix_len, s.prefix_bits,
                                     current, s.hash);
      else
        current = hashBranchForProof(s.prefix_len, s.prefix_bits,
                                     s.hash, current);
    }

    return current == expected_root;
  }

  //  =========================================================================
  //  Key derivation
  //  =========================================================================

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

    Crypto::Hash nft(uint64_t nft_id) noexcept
    {
      return Keys::nft(nft_id);
    }

    Crypto::Hash nftCollection(uint64_t collection_id) noexcept
    {
      return Keys::nftCollection(collection_id);
    }

    Crypto::Address nftAddress(uint64_t nft_id) noexcept
    {
      return Keys::nftAddress(nft_id);
    }

    Crypto::Address nftCollectionAddress(uint64_t collection_id) noexcept
    {
      return Keys::nftCollectionAddress(collection_id);
    }
  } // namespace ProofKeys

} // namespace State