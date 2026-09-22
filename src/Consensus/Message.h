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
  //   [2]  signer_index
  //   [4]  block_size
  //   [N]  block_bytes
  //   [64] signature

  std::vector<uint8_t> encodeProposal(const Proposal &p);
  bool decodeProposal(const uint8_t *data, size_t len, Proposal &out);

  // ---- Vote (shared by Prevote and Precommit) ----
  //
  // Wire format:
  //   [8]  height
  //   [8]  round
  //   [2]  signer_index
  //   [1]  is_nil
  //   [32] block_hash
  //   [64] signature

  std::vector<uint8_t> encodeVote(const Vote &v);
  bool decodeVote(const uint8_t *data, size_t len, Vote &out);

  // ---- Signing hashes ----

  Crypto::Hash proposalSigningHash(Height height, Round round,
                                   const Crypto::Hash &block_hash);

  Crypto::Hash voteSigningHash(Height height, Round round,
                               bool is_nil, const Crypto::Hash &block_hash);

} // namespace Consensus