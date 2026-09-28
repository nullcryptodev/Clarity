// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "GlobalConfig.h"
#include "Crypto/Types.h"

namespace Consensus
{
  enum class Step : uint8_t
  {
    NewHeight = 0,
    Propose = 1,
    Prevote = 2,
    Precommit = 3,
    Commit = 4,
  };

  const char *stepName(Step s) noexcept;

  struct Vote
  {
    Height height{0};
    Round round{0};
    Index signer_index{INVALID_INDEX};
    bool is_nil{false};
    Crypto::Hash block_hash{};
    Crypto::Signature signature{};

    bool isValid() const noexcept
    {
      return signer_index != INVALID_INDEX && !signature.isNull();
    }
  };

  struct Proposal
  {
    Height height{0};
    Round round{0};
    Index signer_index{INVALID_INDEX};
    Crypto::Hash block_hash{};
    std::vector<uint8_t> block_bytes;
    Crypto::Signature signature{};

    bool isValid() const noexcept
    {
      return signer_index != INVALID_INDEX && !signature.isNull() && !block_hash.isNull() && !block_bytes.empty();
    }
  };

  struct Quorum
  {
    std::vector<Vote> votes;
    Crypto::Hash block_hash{};
    bool is_nil{false};

    size_t count() const noexcept { return votes.size(); }
  };

  // Evidence of a validator signing two conflicting votes at the
  // same (height, round). Produced by BftConsensus::recordVote when
  // a second vote from the same signer disagrees with the first.
  // Consumed by the proposer when building a block: it becomes the
  // payload of a TxType::Slash system transaction.
  struct EquivocationEvidence
  {
    Vote vote_a;
    Vote vote_b;

    // The validator the evidence is against. Both votes must share
    // this signer for the evidence to be usable.
    Index signer_index{INVALID_INDEX};

    // Convenience: does this evidence describe a real conflict?
    // Same (height, round, signer) and different (block_hash, is_nil).
    bool isValid() const noexcept
    {
      if (vote_a.height != vote_b.height)
        return false;
      if (vote_a.round != vote_b.round)
        return false;
      if (vote_a.signer_index != vote_b.signer_index)
        return false;
      if (vote_a.signer_index == INVALID_INDEX)
        return false;
      if (vote_a.is_nil == vote_b.is_nil &&
          vote_a.block_hash == vote_b.block_hash)
        return false;
      return true;
    }
  };
} // namespace Consensus