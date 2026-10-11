// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fill.h"

#include "Common/Wire.h"

namespace Core
{
  std::vector<uint8_t> Fill::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU8(static_cast<uint8_t>(source));
    w.writeU64(maker_order_id);
    w.writeU64(taker_order_id);
    w.writeU32(pool_id);
    w.writeU64(qty_base);
    w.writeU64(qty_quote);
    w.writeU64(price);
    w.writeU32(base_token);
    w.writeU32(quote_token);

    return out;
  }

  bool Fill::deserializeState(const uint8_t *data, size_t len, Fill &out)
  {
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);
    out.source = static_cast<FillSource>(r.readU8());
    out.maker_order_id = r.readU64();
    out.taker_order_id = r.readU64();
    out.pool_id = r.readU32();
    out.qty_base = r.readU64();
    out.qty_quote = r.readU64();
    out.price = r.readU64();
    out.base_token = r.readU32();
    out.quote_token = r.readU32();

    if (!r.ok())
      return false;

    return out.isValid();
  }
} // namespace Core