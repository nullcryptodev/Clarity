// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ValidatorTypes.h"

#include "Common/Wire.h"

namespace Core
{
  //  State serialization

  std::vector<uint8_t> ValidatorInfo::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(id);
    w.writeBytes(reward_address.data.data(), reward_address.data.size());
    w.writeBytes(consensus_key.data.data(), consensus_key.data.size());
    w.writeBytes(node_key.data.data(), node_key.data.size());
    w.writeBytes(owner.data.data(), owner.data.size());
    w.writeU64(registered_at_height);
    w.writeU64(stake);
    w.writeU16(uptime_score);
    w.writeU64(last_ping_height);
    w.writeU32(pings_responded_this_epoch);
    w.writeU32(pings_sent_this_epoch);
    w.writeU64(last_seen_height);
    w.writeU16(reward_multiplier);
    w.writeU16(infraction_count);
    w.writeU64(last_infraction_height);
    w.writeU64(total_blocks_produced);
    w.writeU64(total_rewards_earned);
    w.writeU64(epochs_active);

    uint8_t flags = 0;
    if (is_seed)
      flags |= 0x01;
    if (is_active)
      flags |= 0x02;
    w.writeU8(flags);

    w.writeU64(became_active_at);
    w.writeU64(last_active_at);
    w.writeU64(pending_unbond_height);

    return out;
  }

  bool ValidatorInfo::deserializeState(const uint8_t *data, size_t len,
                                       ValidatorInfo &out)
  {
    //  Exact-length check. A serialized ValidatorInfo is exactly
    //  STATE_SIZE bytes; anything else is malformed.
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    out.id = r.readU64();
    r.readBytes(out.reward_address.data.data(), out.reward_address.data.size());
    r.readBytes(out.consensus_key.data.data(), out.consensus_key.data.size());
    r.readBytes(out.node_key.data.data(), out.node_key.data.size());
    r.readBytes(out.owner.data.data(), out.owner.data.size());

    out.registered_at_height = r.readU64();
    out.stake = r.readU64();
    out.uptime_score = r.readU16();
    out.last_ping_height = r.readU64();
    out.pings_responded_this_epoch = r.readU32();
    out.pings_sent_this_epoch = r.readU32();
    out.last_seen_height = r.readU64();
    out.reward_multiplier = r.readU16();
    out.infraction_count = r.readU16();
    out.last_infraction_height = r.readU64();
    out.total_blocks_produced = r.readU64();
    out.total_rewards_earned = r.readU64();
    out.epochs_active = r.readU64();

    const uint8_t flags = r.readU8();
    out.is_seed = (flags & 0x01) != 0;
    out.is_active = (flags & 0x02) != 0;

    out.became_active_at = r.readU64();
    out.last_active_at = r.readU64();
    out.pending_unbond_height = r.readU64();

    return r.ok();
  }

  //  Framework serialization

  void ValidatorInfo::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(reward_address, "reward_address");
    s(consensus_key, "consensus_key");
    s(node_key, "node_key");
    s(owner, "owner");
    s(registered_at_height, "registered_at_height");
    s(stake, "stake");
    s(uptime_score, "uptime_score");
    s(last_ping_height, "last_ping_height");
    s(pings_responded_this_epoch, "pings_responded_this_epoch");
    s(pings_sent_this_epoch, "pings_sent_this_epoch");
    s(last_seen_height, "last_seen_height");
    s(reward_multiplier, "reward_multiplier");
    s(infraction_count, "infraction_count");
    s(last_infraction_height, "last_infraction_height");
    s(total_blocks_produced, "total_blocks_produced");
    s(total_rewards_earned, "total_rewards_earned");
    s(epochs_active, "epochs_active");
    s(is_seed, "is_seed");
    s(is_active, "is_active");
    s(became_active_at, "became_active_at");
    s(last_active_at, "last_active_at");
    s(pending_unbond_height, "pending_unbond_height");
  }

  void ValidatorInfo::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(reward_address, "reward_address");
    s(consensus_key, "consensus_key");
    s(node_key, "node_key");
    s(owner, "owner");
    s(registered_at_height, "registered_at_height");
    s(stake, "stake");
    s(uptime_score, "uptime_score");
    s(last_ping_height, "last_ping_height");
    s(pings_responded_this_epoch, "pings_responded_this_epoch");
    s(pings_sent_this_epoch, "pings_sent_this_epoch");
    s(last_seen_height, "last_seen_height");
    s(reward_multiplier, "reward_multiplier");
    s(infraction_count, "infraction_count");
    s(last_infraction_height, "last_infraction_height");
    s(total_blocks_produced, "total_blocks_produced");
    s(total_rewards_earned, "total_rewards_earned");
    s(epochs_active, "epochs_active");
    s(is_seed, "is_seed");
    s(is_active, "is_active");
    s(became_active_at, "became_active_at");
    s(last_active_at, "last_active_at");
    s(pending_unbond_height, "pending_unbond_height");
  }

  //  ValidatorRegistry

  void ValidatorRegistry::serialize(Serialization::ISerializer &s)
  {
    s(validators, "validators");
    s(active_set, "active_set");
    s(next_id, "next_id");
    s(last_rotation_height, "last_rotation_height");
    s(target_size, "target_size");
  }

  void ValidatorRegistry::serialize(Serialization::ISerializer &s) const
  {
    s(validators, "validators");
    s(active_set, "active_set");
    s(next_id, "next_id");
    s(last_rotation_height, "last_rotation_height");
    s(target_size, "target_size");
  }

} // namespace Core