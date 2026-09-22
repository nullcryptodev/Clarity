// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "RewardTypes.h"
#include "ValidatorTypes.h"

namespace Core
{
  //  Validator rotation
  //
  //  Two independent mechanisms:
  //
  //    1. Normal rotation: every ROTATION_INTERVAL (60) blocks, rotate K
  //       validators based on lowest uptime. Balances active time fairly.
  //
  //    2. Offline check: every OFFLINE_CHECK_INTERVAL (10) blocks, remove
  //       validators who have been offline for OFFLINE_KICK_BLOCKS (20)
  //       consecutive blocks. Fast response to dropouts.
  //
  //  Both mechanisms mutate the active set. The threshold (2/3 + 1) is
  //  recomputed automatically from the active set size.

  // ---- Normal rotation ----

  uint64_t computeRotationCount(uint64_t active_set_size) noexcept;
  uint64_t computeTargetActiveSetSize(uint64_t avg_tx_per_block) noexcept;

  struct RotationPlan
  {
    std::vector<Id> to_remove;
    std::vector<Id> to_add;
    uint64_t new_target_size{0};
  };

  RotationPlan planRotation(const ValidatorRegistry &registry,
                            uint64_t avg_tx_per_block);

  void applyRotation(ValidatorRegistry &registry,
                     const RotationPlan &plan,
                     uint64_t current_height);

  // ---- Offline detection ----

  struct OfflineCheckResult
  {
    std::vector<Id> removed;
    std::vector<Id> promoted;
  };

  // Identify active validators who have been offline too long, and pick
  // replacements from the pool. Pure function; does not mutate the registry.
  OfflineCheckResult planOfflineRemoval(const ValidatorRegistry &registry,
                                        uint64_t current_height);

  // Apply the plan to the registry.
  void applyOfflineRemoval(ValidatorRegistry &registry,
                           const OfflineCheckResult &plan,
                           uint64_t current_height);

  // ---- Uptime scoring ----

  uint16_t updateUptimeScore(uint16_t old_score,
                             uint32_t pings_responded,
                             uint32_t pings_sent) noexcept;

  // ---- Health ----

  std::vector<Id> findUnhealthy(const ValidatorRegistry &registry);

  // ---- Slashing ----

  // Reduce a validator's reward_multiplier by the infraction penalty.
  // Returns true if the penalty was applied (multiplier was above the floor).
  bool applyInfractionPenalty(ValidatorInfo &validator,
                              uint64_t current_height) noexcept;

} // namespace Core