// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "EquivocationProof.h"

#include "Consensus/Message.h"
#include "Consensus/Types.h"
#include "Crypto/Blake2b.h"
#include "Crypto/Ed25519.h"
#include "State/StateAccess.h"

#include <cstring>

namespace Core
{
  namespace
  {
    //  Wire size of one Consensus::Vote, computed once from a
    //  default-constructed vote. Using encodeVote itself means this
    //  constant tracks the encoder: if the wire format changes, this
    //  changes with it.
    const size_t VOTE_WIRE_SIZE = []
    {
      Consensus::Vote v;
      return Consensus::encodeVote(v).size();
    }();
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
    //  Wire format: the two votes back-to-back, no framing. Both are
    //  fixed-size (VOTE_WIRE_SIZE bytes each), so no length prefix is
    //  needed. The total is 2 * VOTE_WIRE_SIZE.
    std::vector<uint8_t> out;
    out.reserve(vote_a_bytes.size() + vote_b_bytes.size());
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

    //  Wire format: two fixed-size votes, back to back, no framing.
    if (payload.size() != 2 * VOTE_WIRE_SIZE)
      return std::nullopt;

    DecodedVote va, vb;
    if (!decodeVoteBytes(payload.data(), VOTE_WIRE_SIZE, va))
      return std::nullopt;
    if (!decodeVoteBytes(payload.data() + VOTE_WIRE_SIZE, VOTE_WIRE_SIZE, vb))
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

  std::optional<Consensus::EquivocationEvidence> decodeSlashEvidence(
      const std::vector<uint8_t> &payload)
  {
    if (payload.size() != 2 * VOTE_WIRE_SIZE)
      return std::nullopt;

    Consensus::Vote vote_a;
    if (!Consensus::decodeVote(payload.data(), VOTE_WIRE_SIZE, vote_a))
      return std::nullopt;

    Consensus::Vote vote_b;
    if (!Consensus::decodeVote(payload.data() + VOTE_WIRE_SIZE,
                               VOTE_WIRE_SIZE, vote_b))
      return std::nullopt;

    Consensus::EquivocationEvidence ev;
    ev.vote_a = vote_a;
    ev.vote_b = vote_b;
    return ev;
  }
} // namespace Core