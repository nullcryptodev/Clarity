// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <algorithm>
#include <cstdint>
#include <vector>

#include "Crypto/Types.h"
#include "RewardTypes.h"
#include "Serialization/ISerializer.h"
#include "GlobalConfig.h"

namespace Core
{
  struct ValidatorInfo
  {
    // ---- Identity ----
    Id id{INVALID_ID};
    Crypto::Address reward_address{};
    Crypto::PublicKey node_key{};
    Crypto::Address owner{};

    // ---- Registration ----
    uint64_t registered_at_height{0};
    uint64_t stake{0};

    // ---- Uptime tracking ----
    uint16_t uptime_score{10'000};
    uint64_t last_ping_height{0};
    uint32_t pings_responded_this_epoch{0};
    uint32_t pings_sent_this_epoch{0};

    // ---- Liveness ----
    //
    // Updated every block from the block's `participants` list.
    // A validator is "offline" if `current_height - last_seen_height
    // >= OFFLINE_KICK_BLOCKS`.
    uint64_t last_seen_height{0};

    // ---- Reward multiplier (slashing) ----
    //
    // Starts at REWARD_MULTIPLIER_START (10000 bps = 100%).
    // Decreases by REWARD_MULTIPLIER_PENALTY per proven infraction.
    // Floor at REWARD_MULTIPLIER_FLOOR (2000 bps = 20%).
    // No automatic recovery.
    uint16_t reward_multiplier{REWARD_MULTIPLIER_START};

    // ---- Infraction tracking ----
    uint16_t infraction_count{0};
    uint64_t last_infraction_height{0};

    // ---- Stats ----
    uint64_t total_blocks_produced{0};
    uint64_t total_rewards_earned{0};
    uint64_t epochs_active{0};

    // ---- Rotation position ----
    bool is_seed{false};
    bool is_active{false};
    uint64_t became_active_at{0};
    uint64_t last_active_at{0};

    // ---- Health checks ----

    bool isHealthy() const noexcept
    {
      return uptime_score >= UPTIME_REMOVAL_THRESHOLD_BPS;
    }

    bool canBeActive() const noexcept
    {
      return isHealthy() && uptime_score >= UPTIME_ACTIVE_MIN_BPS;
    }

    bool meetsStakeRequirement() const noexcept
    {
      return stake >= VALIDATOR_MIN_STAKE;
    }

    // True if the validator has been offline too long.
    bool isOffline(uint64_t current_height) const noexcept
    {
      if (current_height < last_seen_height)
        return false; // future, ignore
      return (current_height - last_seen_height) >= OFFLINE_KICK_BLOCKS;
    }

    // ------------------------------------------------------------------
    //  State serialization (compact, deterministic)
    // ------------------------------------------------------------------
    //
    // Layout (little-endian, in field order):
    //    [8]   id
    //    [32]  reward_address
    //    [32]  node_key
    //    [32]  owner
    //    [8]   registered_at_height
    //    [8]   stake
    //    [2]   uptime_score
    //    [8]   last_ping_height
    //    [4]   pings_responded_this_epoch
    //    [4]   pings_sent_this_epoch
    //    [8]   last_seen_height
    //    [2]   reward_multiplier
    //    [2]   infraction_count
    //    [8]   last_infraction_height
    //    [8]   total_blocks_produced
    //    [8]   total_rewards_earned
    //    [8]   epochs_active
    //    [1]   flags (bit 0 = is_seed, bit 1 = is_active)
    //    [8]   became_active_at
    //    [8]   last_active_at
    //
    // Total: 237 bytes.

    std::vector<uint8_t> serializeState() const;

    static bool deserializeState(const uint8_t *data, size_t len,
                                 ValidatorInfo &out);

    static constexpr size_t STATE_SIZE =
        8 + 32 + 32 + 32 + 8 + 8 + 2 + 8 + 4 + 4 + 8 + 2 + 2 + 8 + 8 + 8 + 8 + 1 + 8 + 8;

    // ------------------------------------------------------------------
    //  Framework serialization
    // ------------------------------------------------------------------

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  struct ValidatorRegistry
  {
    std::vector<ValidatorInfo> validators;
    std::vector<Id> active_set;
    Id next_id{1};
    uint64_t last_rotation_height{0};
    uint64_t target_size{ACTIVE_SET_DEFAULT};

    // Find a validator by id. Linear scan over the vector rather than
    // index-based lookup, so gaps in the id space (created by unregister
    // followed by re-register, or by any future migration) don't cause
    // false negatives.
    //
    // The vector is small (bounded by the total validator pool size,
    // hundreds at most) and rotation runs once per epoch, so the O(n)
    // cost is not meaningful.
    ValidatorInfo *find(Id id) noexcept
    {
      if (id == INVALID_ID)
        return nullptr;
      for (auto &v : validators)
      {
        if (v.id == id)
          return &v;
      }
      return nullptr;
    }

    const ValidatorInfo *find(Id id) const noexcept
    {
      if (id == INVALID_ID)
        return nullptr;
      for (const auto &v : validators)
      {
        if (v.id == id)
          return &v;
      }
      return nullptr;
    }

    size_t activeCount() const noexcept { return active_set.size(); }
    uint64_t quorum() const noexcept { return bftQuorum(active_set.size()); }

    bool isActive(Id id) const noexcept
    {
      return std::find(active_set.begin(), active_set.end(), id) !=
             active_set.end();
    }

    size_t totalCount() const noexcept
    {
      // Previously returned validators.size() - 1 to account for the
      // sentinel at index 0. With a linear scan we no longer need a
      // sentinel, so this is the raw size, minus any empty slots.
      size_t count = 0;
      for (const auto &v : validators)
      {
        if (v.id != INVALID_ID)
          ++count;
      }
      return count;
    }

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core