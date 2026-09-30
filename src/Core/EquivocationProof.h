// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "Crypto/Types.h"
#include "TransactionTypes.h"
#include "ValidatorTypes.h"

namespace State
{
  class StateAccess;
}

namespace Consensus
{
  struct EquivocationEvidence;
}

namespace Core
{
  //  Equivocation proof verification.
  //
  //  An equivocation proof consists of two Consensus::Vote structs,
  //  both produced by the same validator at the same (height, round),
  //  that disagree on the value voted for. "Disagree" means either a
  //  different block_hash or a different is_nil flag — a validator
  //  that prevotes the block and nil at the same round is equivocating
  //  even if the block hashes happen to match.
  //
  //  The proof travels inside a TxType::Slash system transaction. The
  //  proposer, which is the only node that scans for conflicts, embeds
  //  the proof in the block; every node verifies it independently when
  //  applying the block. Verification is deterministic: two nodes
  //  applying the same block always reach the same verdict, because
  //  the verdict depends only on (payload bytes, active_set, state).
  //
  //  Layering: this file lives in Core and depends on Core types only.
  //  The vote structs are encoded as raw bytes by Consensus before they
  //  reach here, and decoded back into a private Core-local struct by
  //  decodeVoteBytes. This keeps Core free of a Consensus dependency
  //  at the type level.

  //  Verify an equivocation proof.
  //
  //  Returns the validator id the proof is against on success, or
  //  nullopt if any of the following fails:
  //
  //    1. The payload does not decode into exactly two votes of the
  //       expected size, with no trailing bytes.
  //    2. The two votes do not share (height, round, signer_index).
  //    3. The two votes do not differ in (block_hash, is_nil).
  //    4. signer_index is out of range for active_set.
  //    5. The validator at active_set[signer_index] is not registered.
  //    6. Either signature fails to verify against the validator's
  //       public key over voteSigningHash(height, round, is_nil,
  //       block_hash).
  //
  //  Seeds are NOT rejected here. The seed exemption is a slashing
  //  policy, not a proof-validity question — a seed that equivocates
  //  produces a valid proof, and TransactionExecutor::executeSystemSlash
  //  is what refuses to act on it. Splitting the two lets the proof
  //  verifier stay a pure function of (bytes, active_set, state), and
  //  keeps the policy decision in one place.
  //
  //  The public key is looked up the same way BlockProcessor::checkQuorum
  //  does: active_set[signer_index] -> ValidatorInfo -> reward_address.
  std::optional<Id> verifyEquivocationProof(
      const std::vector<uint8_t> &payload,
      const std::vector<Id> &active_set,
      State::StateAccess &state);

  //  Recompute the wire encoding of a proof from its two votes. Used
  //  by tests and by the proposer when building a Slash transaction.
  //  The caller supplies the already-encoded vote bytes (via
  //  Consensus::encodeVote); this function just frames them.
  std::vector<uint8_t> encodeSlashPayload(
      const std::vector<uint8_t> &vote_a_bytes,
      const std::vector<uint8_t> &vote_b_bytes);

  //  Signed-vote hashing. Mirrors Consensus::voteSigningHash, but
  //  defined here so Core can verify without including Consensus.
  //  The two MUST produce identical output; a test asserts this.
  Crypto::Hash voteSigningHashForCore(Id height,
                                      uint64_t round,
                                      bool is_nil,
                                      const Crypto::Hash &block_hash);

  //  Decode the payload of a Slash transaction into the two votes it
  //  carries, without verifying anything.
  //
  //  The payload is two votes back-to-back in the wire format produced
  //  by Consensus::encodeVote. Both are fixed-size; no length prefix.
  //
  //  Returns std::nullopt if the payload length isn't exactly two
  //  votes, or if either vote fails to decode structurally.
  //
  //  Callers that need cryptographic verification must use
  //  verifyEquivocationProof instead. This function is used by
  //  BftConsensus to identify which evidence a committed block
  //  contains, so it can erase that evidence from its local pending
  //  list. The block was already verified on-chain; re-verifying here
  //  would be redundant.
  std::optional<Consensus::EquivocationEvidence> decodeSlashEvidence(
      const std::vector<uint8_t> &payload);
} // namespace Core