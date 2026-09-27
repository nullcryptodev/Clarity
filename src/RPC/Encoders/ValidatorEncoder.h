#pragma once

#include "Common/Json.h"
#include "Core/ValidatorTypes.h"

namespace Rpc
{
  //  ValidatorInfo -> JSON
  //
  //  Fields:
  //    id                    (hex)
  //    reward_address        (Bech32m)
  //    node_key              (0x-prefixed)
  //    owner                 (Bech32m)
  //    registered_at_height  (hex)
  //    stake                 (hex)
  //    uptime_score          (number, bps)
  //    last_ping_height      (hex)
  //    last_seen_height      (hex)
  //    reward_multiplier     (number, bps)
  //    infraction_count      (number)
  //    last_infraction_height(hex)
  //    total_blocks_produced (hex)
  //    total_rewards_earned  (hex)
  //    epochs_active         (hex)
  //    is_seed               (bool)
  //    is_active             (bool)
  //    became_active_at      (hex)
  //    last_active_at        (hex)
  //    can_be_active         (bool; derived)
  //    meets_stake_req       (bool; derived)
  //    is_offline            (bool; derived; requires current height)
  //
  //  `current_height` is used for the derived `is_offline` field. Pass
  //  the node's current height. The two other derived fields don't
  //  depend on height and are computed from the struct.

  Common::Json encodeValidator(const Core::ValidatorInfo &v,
                               uint64_t current_height,
                               const std::string &hrp);

  //  Validator list -> JSON array
  //
  //  Sorted by validator id for stable output. Clients can rely on
  //  the array order matching numeric id order.
  Common::Json encodeValidatorList(
      const std::vector<Core::ValidatorInfo> &validators,
      uint64_t current_height,
      const std::string &hrp);
}