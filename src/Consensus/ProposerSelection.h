// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "Types.h"
#include "Core/ValidatorTypes.h"

namespace Consensus
{
  // Index into active_set for the proposer of (height, round).
  // Formula: (height + round) % active_size
  size_t proposerIndex(Height height, Round round, size_t active_size) noexcept;

  // Validator ID of the proposer for (height, round).
  // Returns INVALID_ID if the active set is empty.
  Id proposerFor(
      Height height,
      Round round,
      const std::vector<Id> &active_set) noexcept;

} // namespace Consensus