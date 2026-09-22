// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ValidatorTypes.h"

#include "Common/Put.h"
#include "Common/Read.h"

#include <cstring>

namespace Core
{
  //  State serialization

  std::vector<uint8_t> ValidatorInfo::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::putU64(out, id);
    Common::putBytes(out, reward_address.data.data(), reward_address.data.size());
    Common::putBytes(out, node_key.data.data(), node_key.data.size());
    Common::putBytes(out, owner.data.data(), owner.data.size());
    Common::putU64(out, registered_at_height);
    Common::putU64(out, stake);
    Common::putU16(out, uptime_score);
    Common::putU64(out, last_ping_height);
    Common::putU32(out, pings_responded_this_epoch);
    Common::putU32(out, pings_sent_this_epoch);
    Common::putU64(out, last_seen_height);
    Common::putU16(out, reward_multiplier);
    Common::putU16(out, infraction_count);
    Common::putU64(out, last_infraction_height);
    Common::putU64(out, total_blocks_produced);
    Common::putU64(out, total_rewards_earned);
    Common::putU64(out, epochs_active);

    uint8_t flags = 0;
    if (is_seed)
      flags |= 0x01;
    if (is_active)
      flags |= 0x02;
    out.push_back(flags);

    Common::putU64(out, became_active_at);
    Common::putU64(out, last_active_at);

    return out;
  }

  bool ValidatorInfo::deserializeState(const uint8_t *data, size_t len,
                                       ValidatorInfo &out)
  {
    if (len < STATE_SIZE)
      return false;

    size_t off = 0;

    out.id = Common::readU64(data + off);
    off += 8;
    std::memcpy(out.reward_address.data.data(), data + off, 32);
    off += 32;
    std::memcpy(out.node_key.data.data(), data + off, 32);
    off += 32;
    std::memcpy(out.owner.data.data(), data + off, 32);
    off += 32;

    out.registered_at_height = Common::readU64(data + off);
    off += 8;
    out.stake = Common::readU64(data + off);
    off += 8;
    out.uptime_score = Common::readU16(data + off);
    off += 2;
    out.last_ping_height = Common::readU64(data + off);
    off += 8;
    out.pings_responded_this_epoch = Common::readU32(data + off);
    off += 4;
    out.pings_sent_this_epoch = Common::readU32(data + off);
    off += 4;
    out.last_seen_height = Common::readU64(data + off);
    off += 8;
    out.reward_multiplier = Common::readU16(data + off);
    off += 2;
    out.infraction_count = Common::readU16(data + off);
    off += 2;
    out.last_infraction_height = Common::readU64(data + off);
    off += 8;
    out.total_blocks_produced = Common::readU64(data + off);
    off += 8;
    out.total_rewards_earned = Common::readU64(data + off);
    off += 8;
    out.epochs_active = Common::readU64(data + off);
    off += 8;

    uint8_t flags = data[off++];
    out.is_seed = (flags & 0x01) != 0;
    out.is_active = (flags & 0x02) != 0;

    out.became_active_at = Common::readU64(data + off);
    off += 8;
    out.last_active_at = Common::readU64(data + off);
    off += 8;

    return true;
  }

  //  Framework serialization

  void ValidatorInfo::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(reward_address, "reward_address");
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
  }

  void ValidatorInfo::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(reward_address, "reward_address");
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