// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>

#include "AmmPool.h"

#include "Common/Wire.h"

namespace Core
{
  std::vector<uint8_t> AmmPool::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(id);
    w.writeBytes(creator.data.data(), creator.data.size());
    w.writeU32(token_a);
    w.writeU32(token_b);
    w.writeU64(reserve_a);
    w.writeU64(reserve_b);
    w.writeU64(total_liquidity);
    w.writeU16(fee_bps);
    w.writeU64(created_at_height);
    w.writeU8(active ? 1 : 0);

    return out;
  }

  bool AmmPool::deserializeState(const uint8_t *data, size_t len, AmmPool &out)
  {
    //  Exact-length check. A serialized AmmPool is exactly STATE_SIZE
    //  bytes; anything else is malformed (either truncated or carrying
    //  trailing bytes from a caller bug).
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    out.id = r.readU64();
    r.readBytes(out.creator.data.data(), out.creator.data.size());
    out.token_a = r.readU32();
    out.token_b = r.readU32();
    out.reserve_a = r.readU64();
    out.reserve_b = r.readU64();
    out.total_liquidity = r.readU64();
    out.fee_bps = r.readU16();
    out.created_at_height = r.readU64();
    out.active = (r.readU8() != 0);

    if (!r.ok())
      return false;

    return out.isValid();
  }

  void AmmPool::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(creator, "creator");
    s(token_a, "token_a");
    s(token_b, "token_b");
    s(reserve_a, "reserve_a");
    s(reserve_b, "reserve_b");
    s(total_liquidity, "total_liquidity");
    s(fee_bps, "fee_bps");
    s(created_at_height, "created_at_height");
    s(active, "active");
  }

  void AmmPool::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(creator, "creator");
    s(token_a, "token_a");
    s(token_b, "token_b");
    s(reserve_a, "reserve_a");
    s(reserve_b, "reserve_b");
    s(total_liquidity, "total_liquidity");
    s(fee_bps, "fee_bps");
    s(created_at_height, "created_at_height");
    s(active, "active");
  }

} // namespace Core