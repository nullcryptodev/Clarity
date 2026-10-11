// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Order.h"

#include "Common/Wire.h"

#include <cstring>

namespace Core
{
  void OrderCondition::serializeState(std::vector<uint8_t> &out) const
  {
    uint8_t buf[STATE_SIZE];
    size_t off = 0;

    buf[off++] = static_cast<uint8_t>(type);

    for (int i = 0; i < 8; ++i)
      buf[off++] = uint8_t(param1 >> (i * 8));

    for (int i = 0; i < 4; ++i)
      buf[off++] = uint8_t(param2 >> (i * 8));

    out.insert(out.end(), buf, buf + STATE_SIZE);
  }

  bool OrderCondition::deserializeState(const uint8_t *data, size_t len,
                                        size_t &offset, OrderCondition &out)
  {
    if (offset + STATE_SIZE > len)
      return false;

    const uint8_t *p = data + offset;

    out.type = static_cast<OrderConditionType>(p[0]);

    uint64_t p1 = 0;
    for (int i = 0; i < 8; ++i)
      p1 |= uint64_t(p[1 + i]) << (i * 8);
    out.param1 = p1;

    uint32_t p2 = 0;
    for (int i = 0; i < 4; ++i)
      p2 |= uint32_t(p[9 + i]) << (i * 8);
    out.param2 = p2;

    offset += STATE_SIZE;

    return out.isValid();
  }

  std::vector<uint8_t> Order::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE_FIXED + condition_count * OrderCondition::STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(id);
    w.writeBytes(owner.data.data(), owner.data.size());
    w.writeU8(static_cast<uint8_t>(mode));
    w.writeU32(pool_id);
    w.writeU32(sell_token);
    w.writeU32(buy_token);
    w.writeU64(sell_amount);
    w.writeU64(min_buy_amount);
    w.writeU64(created_at_height);
    w.writeU64(order_expires_at_height);
    w.writeU64(filled_amount);
    w.writeU8(condition_count);

    for (uint8_t i = 0; i < condition_count && i < ORDER_MAX_CONDITIONS; ++i)
    {
      conditions[i].serializeState(out);
    }

    return out;
  }

  bool Order::deserializeState(const uint8_t *data, size_t len, Order &out)
  {
    if (len < STATE_SIZE_FIXED)
      return false;

    Common::Reader r(data, len);

    out.id = r.readU64();
    r.readBytes(out.owner.data.data(), out.owner.data.size());
    out.mode = static_cast<OrderExecutionMode>(r.readU8());
    out.pool_id = r.readU32();
    out.sell_token = r.readU32();
    out.buy_token = r.readU32();
    out.sell_amount = r.readU64();
    out.min_buy_amount = r.readU64();
    out.created_at_height = r.readU64();
    out.order_expires_at_height = r.readU64();
    out.filled_amount = r.readU64();
    out.condition_count = r.readU8();

    if (!r.ok())
      return false;

    if (out.condition_count > ORDER_MAX_CONDITIONS)
      return false;

    const size_t expected_len =
        STATE_SIZE_FIXED +
        static_cast<size_t>(out.condition_count) * OrderCondition::STATE_SIZE;

    if (len != expected_len)
      return false;

    size_t off = STATE_SIZE_FIXED;

    for (uint8_t i = 0; i < out.condition_count; ++i)
    {
      if (!OrderCondition::deserializeState(data, len, off, out.conditions[i]))
        return false;
    }

    if (off != len)
      return false;

    return out.isValid();
  }

} // namespace Core