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
    //  changes with it. The only assumption the rest of this file
    //  makes about the wire format is that both votes in a proof
    //  have the same fixed size — which is guaranteed by construction,
    //  since encodeVote always writes the same number of bytes.
    const size_t VOTE_WIRE_SIZE = []
    {
      Consensus::Vote v;
      return Consensus::encodeVote(v).size();
    }();

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
    //
    //  Wire format: two fixed-size votes, back to back, no framing.
    //
    //  The decoding is delegated to Consensus::decodeVote. A local
    //  hand-rolled decoder used to live here, and it silently went
    //  out of sync with encodeVote when the Vote wire format gained
    //  signer_id. Every field it read after (round) was off by the
    //  width of the new field, so signer_index decoded to the low
    //  half of signer_id and every proof failed verification. Calling
    //  the canonical decoder removes the class of bug entirely.
    if (payload.size() != 2 * VOTE_WIRE_SIZE)
      return std::nullopt;

    Consensus::Vote va, vb;
    if (!Consensus::decodeVote(payload.data(), VOTE_WIRE_SIZE, va))
      return std::nullopt;
    if (!Consensus::decodeVote(payload.data() + VOTE_WIRE_SIZE,
                               VOTE_WIRE_SIZE, vb))
      return std::nullopt;

    //  ---- 2. Same (height, round, signer) ----
    //
    //  signer_id is authoritative. Two votes that agree on
    //  signer_index but disagree on signer_id are not a valid proof
    //  of anything: the index means different things in different
    //  sets, and the id is the only field that identifies the
    //  equivocator unambiguously.
    if (va.height != vb.height)
      return std::nullopt;
    if (va.round != vb.round)
      return std::nullopt;
    if (va.signer_id == INVALID_ID || vb.signer_id == INVALID_ID)
      return std::nullopt;
    if (va.signer_id != vb.signer_id)
      return std::nullopt;

    //  If the votes carry signer_index at all, they must agree. A
    //  mismatch means the two votes were cast against different sets,
    //  which cannot be an equivocation by a single validator at a
    //  single (height, round) — it's two different validators, or a
    //  malformed proof.
    if (va.signer_index != INVALID_INDEX &&
        vb.signer_index != INVALID_INDEX &&
        va.signer_index != vb.signer_index)
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

    //  ---- 4. Validator is registered ----
    //
    //  Resolve from signer_id, not from active_set[signer_index].
    //  The active_set lookup would tie the proof's validity to the
    //  set that happens to be current when the proof is applied —
    //  which, after an emergency rotation, is not the set the votes
    //  were cast against. The id is stable; the index is not.
    const Id validator_id = va.signer_id;

    ValidatorInfo v;
    if (!state.getValidator(validator_id, v))
      return std::nullopt;

    //  ---- 5. The signer is in the set the proof is being applied
    //          against ----
    //
    //  A validator that has been fully removed from the active set
    //  shouldn't be slashable by a fresh proof; the removal already
    //  happened. The active_set parameter is the caller's view of
    //  the set the proof must be against. If it's empty, the caller
    //  is saying "don't require set membership" — used during
    //  migration and by tests that want to verify a proof's signature
    //  without constructing a set.
    if (!active_set.empty())
    {
      const bool in_set =
          std::find(active_set.begin(), active_set.end(), validator_id) !=
          active_set.end();
      if (!in_set)
        return std::nullopt;
    }

    //  ---- 6. Both signatures verify ----
    //
    //  Codebase convention: a validator's signing key is its
    //  reward_address. Same convention as BlockProcessor::checkQuorum
    //  and Node::getSignerPublicKey.
    const Crypto::PublicKey pk = v.effectiveConsensusKey();

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
    ev.signer_id = vote_a.signer_id;
    return ev;
  }
} // namespace Core