// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Types.h"
#include "Crypto/Types.h"

namespace Consensus
{
  // ---- Proposal ----
  //
  // Wire format:
  //   [8]  height
  //   [8]  round
  //   [8]  signer_id
  //   [2]  signer_index
  //   [4]  block_size
  //   [N]  block_bytes
  //   [64] signature
  //
  //  signer_id is authoritative. signer_index is advisory: it is the
  //  position of the signer in the set the proposer believed applied
  //  at (height, round). A receiver resolves the proposer's public
  //  key from signer_id, then verifies that the resolved key matches
  //  the set the block's emergency flag selects for the block's own
  //  height — the index is retained only so the receiver can compare
  //  against what it derives, and to keep the on-chain format's
  //  quorum_signatures compact.
  //
  //  A proposal whose signer_id and signer_index disagree with the
  //  receiver's own derivation is rejected, not repaired.

  std::vector<uint8_t> encodeProposal(const Proposal &p);
  bool decodeProposal(const uint8_t *data, size_t len, Proposal &out);

  // ---- Vote (shared by Prevote and Precommit) ----
  //
  // Wire format:
  //   [8]  height
  //   [8]  round
  //   [8]  signer_id
  //   [2]  signer_index
  //   [1]  is_nil
  //   [32] block_hash
  //   [64] signature
  //
  //  signer_id is authoritative for resolution. signer_index is
  //  advisory and is used only when packing a committed block's
  //  quorum_signatures. A nil vote carries no block, so signer_id is
  //  the only way to disambiguate which set the vote was cast
  //  against when the committed and emergency sets differ.

  std::vector<uint8_t> encodeVote(const Vote &v);
  bool decodeVote(const uint8_t *data, size_t len, Vote &out);

  // ---- Signing hashes ----

  Crypto::Hash proposalSigningHash(Height height, Round round,
                                   const Crypto::Hash &block_hash);

  Crypto::Hash voteSigningHash(Height height, Round round,
                               bool is_nil, const Crypto::Hash &block_hash);

} // namespace Consensus