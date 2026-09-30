// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "RewardTypes.h"
#include "ValidatorTypes.h"

namespace State
{
  class StateAccess;
}

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

  //  Emergency active set
  //
  //  Derives a replacement active set when the committed set can no
  //  longer form quorum. Uses block-height-based liveness (via
  //  ValidatorInfo::isOffline against the current height) rather
  //  than wall clock, because the derivation must be deterministic
  //  across nodes: two honest nodes with the same registry and the
  //  same current_height must compute the same emergency set.
  //
  //  Returns `committed` unchanged unless `force_rotation` is true.
  //  The caller (consensus) sets `force_rotation` when it has observed
  //  enough consecutive round timeouts to conclude the committed set
  //  is not producing blocks. The threshold and the observation live
  //  in the consensus layer; this function is a pure derivation.
  //
  //  When `force_rotation` is true:
  //    - Validators whose last_seen_height is older than
  //      OFFLINE_KICK_BLOCKS relative to `current_height` are dropped.
  //    - Pool candidates are promoted one-for-one, using the same
  //      ordering as planRotation.
  //    - If the pool is empty, the set shrinks rather than the chain
  //      halting outright.
  //
  //  Seeds are never dropped, matching planOfflineRemoval.
  std::vector<Id> computeEmergencyActiveSet(
      const ValidatorRegistry &registry,
      const std::vector<Id> &committed,
      uint64_t current_height,
      bool force_rotation);

  //  Resolve the active set for a block, taking emergency rotation
  //  into account.
  //
  //  Under normal conditions this returns `committed` unchanged. If
  //  `emergency` is true, the set is derived from the same inputs both
  //  the proposer and every verifier use:
  //
  //      committed - offline_validators + pool_promotions
  //
  //  `committed` is the committed active set read from state (the
  //  "active_set" global). It's passed in rather than read here so
  //  callers that already have it don't pay for a second read.
  //
  //  Every honest node with the same committed set, the same registry,
  //  and the same current height computes the same result. That's what
  //  makes an emergency block verifiable by nodes that didn't propose
  //  it.
  //
  //  This is the single call site for the derivation. Both Node (for
  //  the consensus proposer's view) and BlockProcessor (for
  //  verification) call this function, so the two can't drift.
  std::vector<Id> resolveActiveSet(
      State::StateAccess &state,
      const std::vector<Id> &committed,
      uint64_t current_height,
      bool emergency);
} // namespace Core