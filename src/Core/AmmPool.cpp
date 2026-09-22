// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AmmPool.h"

#include "Common/Put.h"
#include "Common/Read.h"

#include <cstring>

namespace Core
{
  std::vector<uint8_t> AmmPool::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::putU64(out, id);
    Common::putBytes(out, creator.data.data(), creator.data.size());
    Common::putU32(out, token_a);
    Common::putU32(out, token_b);
    Common::putU64(out, reserve_a);
    Common::putU64(out, reserve_b);
    Common::putU64(out, total_liquidity);
    Common::putU16(out, fee_bps);
    Common::putU64(out, created_at_height);
    Common::putU8(out, active ? 1 : 0);

    return out;
  }

  bool AmmPool::deserializeState(const uint8_t *data, size_t len, AmmPool &out)
  {
    if (len < STATE_SIZE)
      return false;

    size_t off = 0;

    out.id = Common::readU64(data + off);
    off += 8;
    std::memcpy(out.creator.data.data(), data + off, 32);
    off += 32;
    out.token_a = Common::readU32(data + off);
    off += 4;
    out.token_b = Common::readU32(data + off);
    off += 4;
    out.reserve_a = Common::readU64(data + off);
    off += 8;
    out.reserve_b = Common::readU64(data + off);
    off += 8;
    out.total_liquidity = Common::readU64(data + off);
    off += 8;
    out.fee_bps = Common::readU16(data + off);
    off += 2;
    out.created_at_height = Common::readU64(data + off);
    off += 8;
    out.active = (Common::readU8(data + off) != 0);
    off += 1;

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