// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ProposerSelection.h"

namespace Consensus
{

  size_t proposerIndex(Height height, Round round, size_t active_size) noexcept
  {
    if (active_size == 0)
      return 0;
    return static_cast<size_t>((height + round) % active_size);
  }

  Id proposerFor(
      Height height,
      Round round,
      const std::vector<Id> &active_set) noexcept
  {
    if (active_set.empty())
      return INVALID_ID;
    return active_set[proposerIndex(height, round, active_set.size())];
  }

} // namespace Consensus