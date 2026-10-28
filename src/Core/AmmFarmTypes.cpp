// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AmmFarmTypes.h"

#include "Common/Wire.h"

namespace Core
{
  // =================================================================
  //  AmmFarmSchedule codec
  // =================================================================

  std::vector<uint8_t> AmmFarmSchedule::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);

    w.writeU64(pool_id);
    w.writeBytes(creator.data.data(), creator.data.size());
    w.writeU32(reward_token_id);
    w.writeU64(reward_rate_per_epoch);
    w.writeU64(reward_escrow_remaining);
    w.writeU8(reward_paused ? 1 : 0);
    w.writeU64(rps_per_share);
    w.writeU64(created_at_height);

    return out;
  }

  bool AmmFarmSchedule::deserializeState(const uint8_t *data, size_t len,
                                         AmmFarmSchedule &out)
  {
    //  Exact-length check. A serialized AmmFarmSchedule is exactly
    //  STATE_SIZE bytes; anything else is malformed.
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    out.pool_id = r.readU64();
    r.readBytes(out.creator.data.data(), out.creator.data.size());
    out.reward_token_id = r.readU32();
    out.reward_rate_per_epoch = r.readU64();
    out.reward_escrow_remaining = r.readU64();

    const uint8_t paused_byte = r.readU8();
    if (!r.ok() || paused_byte > 1)
      return false;
    out.reward_paused = (paused_byte == 1);

    out.rps_per_share = r.readU64();
    out.created_at_height = r.readU64();

    if (!r.ok())
      return false;

    //  No trailing bytes. The fixed-size check above guarantees this,
    //  but the explicit check is cheap and matches NftTypes.
    if (r.remaining() != 0)
      return false;

    return out.isValid();
  }

  void AmmFarmSchedule::serialize(Serialization::ISerializer &s)
  {
    s(pool_id, "pool_id");
    s(creator, "creator");
    s(reward_token_id, "reward_token_id");
    s(reward_rate_per_epoch, "reward_rate_per_epoch");
    s(reward_escrow_remaining, "reward_escrow_remaining");
    s(reward_paused, "reward_paused");
    s(rps_per_share, "rps_per_share");
    s(created_at_height, "created_at_height");
  }

  void AmmFarmSchedule::serialize(Serialization::ISerializer &s) const
  {
    s(pool_id, "pool_id");
    s(creator, "creator");
    s(reward_token_id, "reward_token_id");
    s(reward_rate_per_epoch, "reward_rate_per_epoch");
    s(reward_escrow_remaining, "reward_escrow_remaining");
    s(reward_paused, "reward_paused");
    s(rps_per_share, "rps_per_share");
    s(created_at_height, "created_at_height");
  }

  // =================================================================
  //  AmmPositionAccrual codec
  // =================================================================

  std::vector<uint8_t> AmmPositionAccrual::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);

    w.writeU64(position_id);
    w.writeU64(last_rps);

    return out;
  }

  bool AmmPositionAccrual::deserializeState(const uint8_t *data, size_t len,
                                            AmmPositionAccrual &out)
  {
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    out.position_id = r.readU64();
    out.last_rps = r.readU64();

    if (!r.ok())
      return false;

    if (r.remaining() != 0)
      return false;

    return out.isValid();
  }

  void AmmPositionAccrual::serialize(Serialization::ISerializer &s)
  {
    s(position_id, "position_id");
    s(last_rps, "last_rps");
  }

  void AmmPositionAccrual::serialize(Serialization::ISerializer &s) const
  {
    s(position_id, "position_id");
    s(last_rps, "last_rps");
  }

} // namespace Core