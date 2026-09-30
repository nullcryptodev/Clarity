// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AmmPosition.h"

#include "Common/Wire.h"

namespace Core
{
  std::vector<uint8_t> AmmPosition::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(id);
    w.writeBytes(owner.data.data(), owner.data.size());
    w.writeU64(pool_id);
    w.writeU64(liquidity);
    w.writeU64(created_at_height);

    return out;
  }

  bool AmmPosition::deserializeState(const uint8_t *data, size_t len,
                                     AmmPosition &out)
  {
    //  Exact-length check. A serialized AmmPosition is exactly
    //  STATE_SIZE bytes; anything else is malformed.
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    out.id = r.readU64();
    r.readBytes(out.owner.data.data(), out.owner.data.size());
    out.pool_id = r.readU64();
    out.liquidity = r.readU64();
    out.created_at_height = r.readU64();

    if (!r.ok())
      return false;

    return out.isValid();
  }

  void AmmPosition::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(owner, "owner");
    s(pool_id, "pool_id");
    s(liquidity, "liquidity");
    s(created_at_height, "created_at_height");
  }

} // namespace Core