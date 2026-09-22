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

} // namespace Consensus