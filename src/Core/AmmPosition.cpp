// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AmmPosition.h"

#include "Common/Put.h"
#include "Common/Read.h"

#include <cstring>

namespace Core
{
  std::vector<uint8_t> AmmPosition::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::putU64(out, id);
    Common::putBytes(out, owner.data.data(), owner.data.size());
    Common::putU64(out, pool_id);
    Common::putU64(out, liquidity);
    Common::putU64(out, created_at_height);

    return out;
  }

  bool AmmPosition::deserializeState(const uint8_t *data, size_t len,
                                     AmmPosition &out)
  {
    if (len < STATE_SIZE)
      return false;

    size_t off = 0;
    out.id = Common::readU64(data + off);
    off += 8;
    std::memcpy(out.owner.data.data(), data + off, 32);
    off += 32;
    out.pool_id = Common::readU64(data + off);
    off += 8;
    out.liquidity = Common::readU64(data + off);
    off += 8;
    out.created_at_height = Common::readU64(data + off);
    off += 8;

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