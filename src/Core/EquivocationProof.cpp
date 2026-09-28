// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "EquivocationProof.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Ed25519.h"
#include "State/StateAccess.h"

#include <cstring>

namespace Core
{
  namespace
  {
    //  Wire-format sizes, matching Consensus::encodeVote.
    //
    //    [8]  height
    //    [8]  round
    //    [2]  signer_index
    //    [1]  is_nil
    //    [32] block_hash
    //    [64] signature
    //
    //  Total: 115 bytes.
    constexpr size_t VOTE_WIRE_SIZE = 8 + 8 + 2 + 1 + 32 + 64;
    constexpr size_t VOTE_PREFIX_SIZE = 8 + 8 + 2 + 1 + 32; // no signature

    //  Core-local mirror of Consensus::Vote. Only the fields needed
    //  for verification, decoded from the wire bytes. Kept private
    //  to this file so nothing outside can accidentally depend on it.
    struct DecodedVote
    {
      uint64_t height{0};
      uint64_t round{0};
      uint16_t signer_index{0};
      bool is_nil{false};
      Crypto::Hash block_hash{};
      Crypto::Signature signature{};
    };

    uint16_t readU16LE(const uint8_t *p)
    {
      return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
    }

    uint64_t readU64LE(const uint8_t *p)
    {
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(p[i]) << (i * 8);
      return v;
    }

    bool decodeVoteBytes(const uint8_t *data, size_t len, DecodedVote &out)
    {
      if (len != VOTE_WIRE_SIZE)
        return false;

      size_t off = 0;

      out.height = readU64LE(data + off);
      off += 8;
      out.round = readU64LE(data + off);
      off += 8;
      out.signer_index = readU16LE(data + off);
      off += 2;
      out.is_nil = (data[off] != 0);
      off += 1;

      std::memcpy(out.block_hash.data.data(), data + off, 32);
      off += 32;
      std::memcpy(out.signature.data.data(), data + off, 64);
      off += 64;

      return true;
    }
    //  Domain-separated signing hash for a vote.
    //
    //  MUST match Consensus::voteSigningHash byte for byte. The
    //  implementation here re-derives it so Core doesn't link against
    //  Consensus; a test asserts the two are equal across a range of
    //  inputs. If the domain string or field order ever changes in
    //  Consensus, this function and the test that guards it must
    //  change together — a silent divergence would let a forged proof
    //  verify or a real proof fail, either of which is a consensus
    //  split.
    Crypto::Hash localVoteSigningHash(uint64_t height,
                                      uint64_t round,
                                      bool is_nil,
                                      const Crypto::Hash &block_hash)
    {
      static constexpr const char *DOMAIN = "CLRTY_VOTE_V1";
      const size_t dlen = std::strlen(DOMAIN);

      std::vector<uint8_t> buf;
      buf.reserve(dlen + 8 + 8 + 1 + 32);

      buf.insert(buf.end(),
                 reinterpret_cast<const uint8_t *>(DOMAIN),
                 reinterpret_cast<const uint8_t *>(DOMAIN) + dlen);

      for (int i = 0; i < 8; ++i)
        buf.push_back(uint8_t(height >> (i * 8)));
      for (int i = 0; i < 8; ++i)
        buf.push_back(uint8_t(round >> (i * 8)));
      buf.push_back(is_nil ? 1 : 0);
      buf.insert(buf.end(), block_hash.data.begin(), block_hash.data.end());

      Crypto::Hash h;
      Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
      return h;
    }
  } // anonymous namespace

  std::vector<uint8_t> encodeSlashPayload(
      const std::vector<uint8_t> &vote_a_bytes,
      const std::vector<uint8_t> &vote_b_bytes)
  {
    std::vector<uint8_t> out;
    out.reserve(4 + vote_a_bytes.size() + vote_b_bytes.size());

    uint32_t len_a = static_cast<uint32_t>(vote_a_bytes.size());
    out.push_back(uint8_t(len_a));
    out.push_back(uint8_t(len_a >> 8));
    out.push_back(uint8_t(len_a >> 16));
    out.push_back(uint8_t(len_a >> 24));

    out.insert(out.end(), vote_a_bytes.begin(), vote_a_bytes.end());
    out.insert(out.end(), vote_b_bytes.begin(), vote_b_bytes.end());

    return out;
  }

  Crypto::Hash voteSigningHashForCore(uint64_t height,
                                      uint64_t round,
                                      bool is_nil,
                                      const Crypto::Hash &block_hash)
  {
    return localVoteSigningHash(height, round, is_nil, block_hash);
  }

  std::optional<Id> verifyEquivocationProof(
      const std::vector<uint8_t> &payload,
      const std::vector<Id> &active_set,
      State::StateAccess &state)
  {
    //  ---- 1. Decode framing ----

    if (payload.size() < 4)
      return std::nullopt;

    uint32_t len_a = uint32_t(payload[0]) |
                     (uint32_t(payload[1]) << 8) |
                     (uint32_t(payload[2]) << 16) |
                     (uint32_t(payload[3]) << 24);

    if (len_a != VOTE_WIRE_SIZE)
      return std::nullopt;

    const size_t vote_a_off = 4;
    const size_t vote_b_off = vote_a_off + len_a;

    if (payload.size() != vote_b_off + VOTE_WIRE_SIZE)
      return std::nullopt;

    DecodedVote va, vb;
    if (!decodeVoteBytes(payload.data() + vote_a_off, len_a, va))
      return std::nullopt;
    if (!decodeVoteBytes(payload.data() + vote_b_off, VOTE_WIRE_SIZE, vb))
      return std::nullopt;

    //  ---- 2. Same (height, round, signer_index) ----

    if (va.height != vb.height)
      return std::nullopt;
    if (va.round != vb.round)
      return std::nullopt;
    if (va.signer_index != vb.signer_index)
      return std::nullopt;

    //  ---- 3. Different value ----
    //
    //  "Different" is (block_hash, is_nil) treated as a pair. Two
    //  votes for the same block with the same is_nil flag are a
    //  duplicate, not an equivocation. A block vote and a nil vote
    //  at the same round are an equivocation even though the block
    //  hashes can't be compared.
    const bool same_block = (va.block_hash == vb.block_hash);
    const bool same_nil = (va.is_nil == vb.is_nil);
    if (same_block && same_nil)
      return std::nullopt;

    //  ---- 4. signer_index in range ----

    if (va.signer_index >= active_set.size())
      return std::nullopt;

    //  ---- 5. Validator is registered ----

    const Id validator_id = active_set[va.signer_index];

    ValidatorInfo v;
    if (!state.getValidator(validator_id, v))
      return std::nullopt;

    //  ---- 6. Both signatures verify ----

    //  Codebase convention: a validator's signing key is its
    //  reward_address. Same convention as BlockProcessor::checkQuorum
    //  and Node::getSignerPublicKey.
    const Crypto::PublicKey pk = v.reward_address;

    Crypto::Hash ha = localVoteSigningHash(va.height, va.round,
                                           va.is_nil, va.block_hash);
    if (!Crypto::verify(ha, pk, va.signature))
      return std::nullopt;

    Crypto::Hash hb = localVoteSigningHash(vb.height, vb.round,
                                           vb.is_nil, vb.block_hash);
    if (!Crypto::verify(hb, pk, vb.signature))
      return std::nullopt;

    return validator_id;
  }
} // namespace Core