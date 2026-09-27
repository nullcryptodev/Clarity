#include "ValidatorEncoder.h"
#include "Encoding.h"

namespace Rpc
{

  Common::Json encodeValidator(const Core::ValidatorInfo &v,
                               uint64_t current_height,
                               const std::string &hrp)
  {
    Common::Json j = Common::Json::object();

    putU64(j, "id", v.id);
    putAddress(j, "reward_address", v.reward_address, hrp);
    putHash(j, "node_key", Crypto::Hash(v.node_key.data.data()));
    putAddress(j, "owner", v.owner, hrp);

    putU64(j, "registered_at_height", v.registered_at_height);
    putU64(j, "stake", v.stake);

    j["uptime_score"] = v.uptime_score;
    putU64(j, "last_ping_height", v.last_ping_height);
    putU64(j, "last_seen_height", v.last_seen_height);

    j["reward_multiplier"] = v.reward_multiplier;
    j["infraction_count"] = v.infraction_count;
    putU64(j, "last_infraction_height", v.last_infraction_height);

    putU64(j, "total_blocks_produced", v.total_blocks_produced);
    putU64(j, "total_rewards_earned", v.total_rewards_earned);
    putU64(j, "epochs_active", v.epochs_active);

    j["is_seed"] = v.is_seed;
    j["is_active"] = v.is_active;
    putU64(j, "became_active_at", v.became_active_at);
    putU64(j, "last_active_at", v.last_active_at);

    // ---- Derived ----
    //
    // These are pure functions of the struct plus current height.
    // Exposing them server-side saves every client re-implementing the
    // thresholds and getting them subtly wrong.

    j["can_be_active"] = v.canBeActive();
    j["meets_stake_req"] = v.meetsStakeRequirement();
    j["is_offline"] = v.isOffline(current_height);

    return j;
  }

  Common::Json encodeValidatorList(
      const std::vector<Core::ValidatorInfo> &validators,
      uint64_t current_height,
      const std::string &hrp)
  {
    auto sorted = validators;
    std::sort(sorted.begin(), sorted.end(),
              [](const Core::ValidatorInfo &a, const Core::ValidatorInfo &b)
              {
                return a.id < b.id;
              });

    Common::Json arr = Common::Json::array();
    for (const auto &v : sorted)
    {
      arr.push_back(encodeValidator(v, current_height, hrp));
    }
    return arr;
  }
}