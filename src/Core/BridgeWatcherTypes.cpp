// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BridgeWatcherTypes.h"

#include "Common/Wire.h"

namespace Core
{
  //  =========================================================================
  //  BridgeWatcherInfo
  //  =========================================================================

  std::vector<uint8_t> BridgeWatcherInfo::serializeState() const
  {
    if (!isWellFormed())
      return {};

    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(id);
    w.writeU64(validator_id);
    w.writeU64(source_chain_id);
    w.writeBytes(reward_address.data.data(), reward_address.data.size());
    w.writeU64(registered_at_height);
    w.writeU64(stake);
    w.writeU64(last_seen_height);
    w.writeU8(is_active ? 1 : 0);
    w.writeU64(became_active_at);
    w.writeU64(last_active_at);
    w.writeU64(pending_unbond_height);
    w.writeU16(infraction_count);
    w.writeU64(last_infraction_height);

    return out;
  }

  bool BridgeWatcherInfo::deserializeState(const uint8_t *data, size_t len,
                                           BridgeWatcherInfo &out)
  {
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    BridgeWatcherInfo w;
    w.id                    = r.readU64();
    w.validator_id          = r.readU64();
    w.source_chain_id       = r.readU64();
    r.readBytes(w.reward_address.data.data(), w.reward_address.data.size());
    w.registered_at_height  = r.readU64();
    w.stake                 = r.readU64();
    w.last_seen_height      = r.readU64();
    w.is_active             = (r.readU8() != 0);
    w.became_active_at      = r.readU64();
    w.last_active_at        = r.readU64();
    w.pending_unbond_height = r.readU64();
    w.infraction_count      = r.readU16();
    w.last_infraction_height = r.readU64();

    if (!r.ok())
      return false;

    if (!w.isWellFormed())
      return false;

    out = std::move(w);
    return true;
  }

  void BridgeWatcherInfo::serialize(Serialization::ISerializer &s)
  {
    s(id,                    "id");
    s(validator_id,          "validator_id");
    s(source_chain_id,       "source_chain_id");
    s(reward_address,        "reward_address");
    s(registered_at_height,  "registered_at_height");
    s(stake,                 "stake");
    s(last_seen_height,      "last_seen_height");
    s(is_active,             "is_active");
    s(became_active_at,      "became_active_at");
    s(last_active_at,        "last_active_at");
    s(pending_unbond_height, "pending_unbond_height");
    s(infraction_count,      "infraction_count");
    s(last_infraction_height, "last_infraction_height");
  }

  void BridgeWatcherInfo::serialize(Serialization::ISerializer &s) const
  {
    s(id,                    "id");
    s(validator_id,          "validator_id");
    s(source_chain_id,       "source_chain_id");
    s(reward_address,        "reward_address");
    s(registered_at_height,  "registered_at_height");
    s(stake,                 "stake");
    s(last_seen_height,      "last_seen_height");
    s(is_active,             "is_active");
    s(became_active_at,      "became_active_at");
    s(last_active_at,        "last_active_at");
    s(pending_unbond_height, "pending_unbond_height");
    s(infraction_count,      "infraction_count");
    s(last_infraction_height, "last_infraction_height");
  }

  const char *bridgeWatcherStatusName(BridgeWatcherStatus s) noexcept
  {
    switch (s)
    {
    case BridgeWatcherStatus::Ok:                    return "ok";
    case BridgeWatcherStatus::NotAValidator:         return "not_a_validator";
    case BridgeWatcherStatus::AlreadyRegistered:     return "already_registered";
    case BridgeWatcherStatus::StakeTooLow:           return "stake_too_low";
    case BridgeWatcherStatus::ChainNotRegistered:    return "chain_not_registered";
    case BridgeWatcherStatus::InsufficientBalance:   return "insufficient_balance";
    case BridgeWatcherStatus::PendingUnbondInFlight: return "pending_unbond_in_flight";
    case BridgeWatcherStatus::NotRegistered:         return "not_registered";
    case BridgeWatcherStatus::AlreadyUnbonding:      return "already_unbonding";
    case BridgeWatcherStatus::ActiveSetWouldShrink:  return "active_set_would_shrink";
    }
    return "unknown";
  }
}