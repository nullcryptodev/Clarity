// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ValidatorRotation.h"

#include <algorithm>
#include <unordered_set>

namespace Core
{

  //  Rotation count

  uint64_t computeRotationCount(uint64_t active_set_size) noexcept
  {
    if (active_set_size == 0)
      return 0;

    // Number of validators to rotate per epoch: one full turnover over
    // TARGET_ROTATION_EPOCHS epochs, rounded up.
    uint64_t count = (active_set_size + TARGET_ROTATION_EPOCHS - 1) / TARGET_ROTATION_EPOCHS;

    // BFT safety margin: never rotate more than (n - quorum). Rotating
    // more than that can take the set below the quorum threshold if the
    // incoming validators aren't yet confirmed online.
    const uint64_t quorum = bftQuorum(active_set_size);
    if (quorum >= active_set_size)
      return 0; // rotation would break quorum — refuse

    const uint64_t max_rotate = active_set_size - quorum;
    if (count > max_rotate)
      count = max_rotate;

    // Note: we deliberately do NOT floor at 1. If the safety margin is 0,
    // rotation is legitimately impossible at this set size, and the caller
    // must grow the set before rotating.
    return count;
  }

  uint64_t computeTargetActiveSetSize(uint64_t avg_tx_per_block) noexcept
  {
    if (avg_tx_per_block >= TRAFFIC_SATURATION_TX)
    {
      return ACTIVE_SET_MAX;
    }

    uint64_t range = ACTIVE_SET_MAX - ACTIVE_SET_MIN;
    uint64_t scaled = (avg_tx_per_block * range) / TRAFFIC_SATURATION_TX;
    uint64_t target = ACTIVE_SET_MIN + scaled;

    return std::clamp(target, ACTIVE_SET_MIN, ACTIVE_SET_MAX);
  }

  //  Planning

  namespace
  {
    bool removalOrder(const ValidatorInfo &a, const ValidatorInfo &b) noexcept
    {
      if (a.uptime_score != b.uptime_score)
      {
        return a.uptime_score < b.uptime_score;
      }
      return a.became_active_at < b.became_active_at;
    }

    bool additionOrder(const ValidatorInfo &a, const ValidatorInfo &b) noexcept
    {
      if (a.uptime_score != b.uptime_score)
      {
        return a.uptime_score > b.uptime_score;
      }
      return a.last_active_at < b.last_active_at;
    }
  } // anonymous namespace

  RotationPlan planRotation(const ValidatorRegistry &registry,
                            uint64_t avg_tx_per_block)
  {
    RotationPlan plan;

    uint64_t target_size = computeTargetActiveSetSize(avg_tx_per_block);
    if (target_size < SEED_NODES)
      target_size = SEED_NODES;
    plan.new_target_size = target_size;

    const uint64_t current_size = registry.active_set.size();

    if (target_size < current_size)
    {
      uint64_t to_remove_count = current_size - target_size;
      plan.to_remove.reserve(to_remove_count);

      std::vector<const ValidatorInfo *> candidates;
      candidates.reserve(current_size);
      for (auto vid : registry.active_set)
      {
        const auto *v = registry.find(vid);
        if (v && !v->is_seed)
        {
          candidates.push_back(v);
        }
      }

      std::sort(candidates.begin(), candidates.end(),
                [](const ValidatorInfo *a, const ValidatorInfo *b)
                {
                  return removalOrder(*a, *b);
                });

      // Note: if every active validator is a seed, candidates is empty
      // and the set cannot shrink below its current size. This is a
      // deliberate invariant — seeds are always active.
      for (uint64_t i = 0; i < to_remove_count && i < candidates.size(); ++i)
      {
        plan.to_remove.push_back(candidates[i]->id);
      }

      return plan;
    }

    if (target_size > current_size)
    {
      uint64_t to_add_count = target_size - current_size;

      std::vector<const ValidatorInfo *> candidates;
      candidates.reserve(registry.validators.size());

      for (const auto &v : registry.validators)
      {
        if (v.id == INVALID_ID)
          continue;
        if (v.is_active)
          continue;
        if (!v.canBeActive())
          continue;
        candidates.push_back(&v);
      }

      std::sort(candidates.begin(), candidates.end(),
                [](const ValidatorInfo *a, const ValidatorInfo *b)
                {
                  return additionOrder(*a, *b);
                });

      for (uint64_t i = 0; i < to_add_count && i < candidates.size(); ++i)
      {
        plan.to_add.push_back(candidates[i]->id);
      }

      return plan;
    }

    // Same size: normal rotation. Swap out the lowest-uptime non-seeds,
    // swap in the highest-uptime waiting validators.
    uint64_t rotate = computeRotationCount(current_size);

    std::vector<const ValidatorInfo *> removable;
    removable.reserve(current_size);
    for (auto vid : registry.active_set)
    {
      const auto *v = registry.find(vid);
      if (v && !v->is_seed)
      {
        removable.push_back(v);
      }
    }

    std::sort(removable.begin(), removable.end(),
              [](const ValidatorInfo *a, const ValidatorInfo *b)
              {
                return removalOrder(*a, *b);
              });

    uint64_t removed = 0;
    for (const auto *v : removable)
    {
      if (removed >= rotate)
        break;
      plan.to_remove.push_back(v->id);
      ++removed;
    }

    std::vector<const ValidatorInfo *> addable;
    addable.reserve(registry.validators.size());
    for (const auto &v : registry.validators)
    {
      if (v.id == INVALID_ID)
        continue;
      if (v.is_active)
        continue;
      if (!v.canBeActive())
        continue;
      addable.push_back(&v);
    }

    std::sort(addable.begin(), addable.end(),
              [](const ValidatorInfo *a, const ValidatorInfo *b)
              {
                return additionOrder(*a, *b);
              });

    for (size_t i = 0; i < plan.to_remove.size() && i < addable.size(); ++i)
    {
      plan.to_add.push_back(addable[i]->id);
    }

    return plan;
  }

  //  Application

  void applyRotation(ValidatorRegistry &registry,
                     const RotationPlan &plan,
                     uint64_t current_height)
  {
    std::unordered_set<Id> removals(
        plan.to_remove.begin(), plan.to_remove.end());

    auto &active = registry.active_set;
    active.erase(std::remove_if(active.begin(), active.end(),
                                [&](Id id)
                                {
                                  return removals.count(id) > 0;
                                }),
                 active.end());

    for (auto vid : plan.to_remove)
    {
      if (auto *v = registry.find(vid))
      {
        v->is_active = false;
        v->last_active_at = current_height;
      }
    }

    for (auto vid : plan.to_add)
    {
      if (auto *v = registry.find(vid))
      {
        v->is_active = true;
        v->became_active_at = current_height;
        active.push_back(vid);
      }
    }

    std::sort(active.begin(), active.end());

    registry.last_rotation_height = current_height;
    registry.target_size = plan.new_target_size;
  }

  //  Offline detection

  OfflineCheckResult planOfflineRemoval(const ValidatorRegistry &registry,
                                        uint64_t current_height)
  {
    OfflineCheckResult plan;

    // Find active validators who have been offline too long.
    for (auto vid : registry.active_set)
    {
      const auto *v = registry.find(vid);
      if (!v)
        continue;
      if (v->is_seed)
        continue; // seeds are never removed

      if (v->isOffline(current_height))
      {
        plan.removed.push_back(vid);
      }
    }

    if (plan.removed.empty())
    {
      return plan;
    }

    // Pick replacements from the waiting pool.
    std::unordered_set<Id> removed_set(
        plan.removed.begin(), plan.removed.end());

    std::vector<const ValidatorInfo *> candidates;
    candidates.reserve(registry.validators.size());

    for (const auto &v : registry.validators)
    {
      if (v.id == INVALID_ID)
        continue;
      if (v.is_active)
        continue;
      if (removed_set.count(v.id) > 0)
        continue;
      if (!v.canBeActive())
        continue;
      candidates.push_back(&v);
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const ValidatorInfo *a, const ValidatorInfo *b)
              {
                return additionOrder(*a, *b);
              });

    for (size_t i = 0; i < plan.removed.size() && i < candidates.size(); ++i)
    {
      plan.promoted.push_back(candidates[i]->id);
    }

    return plan;
  }

  void applyOfflineRemoval(ValidatorRegistry &registry,
                           const OfflineCheckResult &plan,
                           uint64_t current_height)
  {
    std::unordered_set<Id> removals(
        plan.removed.begin(), plan.removed.end());

    auto &active = registry.active_set;
    active.erase(std::remove_if(active.begin(), active.end(),
                                [&](Id id)
                                {
                                  return removals.count(id) > 0;
                                }),
                 active.end());

    for (auto vid : plan.removed)
    {
      if (auto *v = registry.find(vid))
      {
        v->is_active = false;
        v->last_active_at = current_height;
      }
    }

    for (auto vid : plan.promoted)
    {
      if (auto *v = registry.find(vid))
      {
        v->is_active = true;
        v->became_active_at = current_height;
        active.push_back(vid);
      }
    }

    std::sort(active.begin(), active.end());
  }

  //  Uptime scoring

  uint16_t updateUptimeScore(uint16_t old_score,
                             uint32_t pings_responded,
                             uint32_t pings_sent) noexcept
  {
    if (pings_sent == 0)
    {
      return old_score;
    }

    uint32_t epoch_uptime = static_cast<uint32_t>(
        (static_cast<uint64_t>(pings_responded) * 10'000) / pings_sent);
    if (epoch_uptime > 10'000)
      epoch_uptime = 10'000;

    uint32_t alpha = UPTIME_EMA_ALPHA_BPS;
    uint32_t one_minus = 10'000 - alpha;

    uint32_t new_score = (alpha * epoch_uptime + one_minus * old_score) / 10'000;

    return static_cast<uint16_t>(new_score);
  }

  //  Health

  std::vector<Id> findUnhealthy(const ValidatorRegistry &registry)
  {
    std::vector<Id> result;
    for (const auto &v : registry.validators)
    {
      if (v.id == INVALID_ID)
        continue;
      if (v.is_seed)
        continue;
      if (!v.isHealthy())
      {
        result.push_back(v.id);
      }
    }
    return result;
  }

  //  Slashing

  bool applyInfractionPenalty(ValidatorInfo &validator,
                              uint64_t current_height) noexcept
  {
    uint16_t current = validator.reward_multiplier;
    if (current <= REWARD_MULTIPLIER_FLOOR)
    {
      // Already at floor. Still record the infraction.
      validator.infraction_count++;
      validator.last_infraction_height = current_height;
      return false;
    }

    uint16_t next = current > REWARD_MULTIPLIER_PENALTY
                        ? uint16_t(current - REWARD_MULTIPLIER_PENALTY)
                        : REWARD_MULTIPLIER_FLOOR;

    if (next < REWARD_MULTIPLIER_FLOOR)
    {
      next = REWARD_MULTIPLIER_FLOOR;
    }

    validator.reward_multiplier = next;
    validator.infraction_count++;
    validator.last_infraction_height = current_height;

    return true;
  }

} // namespace Core