// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Order.h"

#include "Common/Put.h"
#include "Common/Read.h"

#include <cstring>

namespace Core
{
  //  OrderCondition

  void OrderCondition::serializeState(std::vector<uint8_t> &out) const
  {
    Common::putU8(out, static_cast<uint8_t>(type));
    Common::putU64(out, param1);
    Common::putU32(out, param2);
  }

  bool OrderCondition::deserializeState(const uint8_t *data, size_t len,
                                        size_t &offset, OrderCondition &out)
  {
    if (offset + STATE_SIZE > len)
      return false;

    out.type = static_cast<OrderConditionType>(Common::readU8(data + offset));
    offset += 1;
    out.param1 = Common::readU64(data + offset);
    offset += 8;
    out.param2 = Common::readU32(data + offset);
    offset += 4;

    return out.isValid();
  }

  //  Order

  std::vector<uint8_t> Order::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE_FIXED + condition_count * OrderCondition::STATE_SIZE);

    Common::putU64(out, id);
    Common::putBytes(out, owner.data.data(), owner.data.size());
    Common::putU8(out, static_cast<uint8_t>(mode));
    Common::putU32(out, sell_token);
    Common::putU32(out, buy_token);
    Common::putU64(out, sell_amount);
    Common::putU64(out, min_buy_amount);
    Common::putU64(out, created_at_height);
    Common::putU64(out, order_expires_at_height);
    Common::putU64(out, filled_amount);
    Common::putU8(out, condition_count);

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

    size_t off = 0;

    out.id = Common::readU64(data + off);
    off += 8;
    std::memcpy(out.owner.data.data(), data + off, 32);
    off += 32;
    out.mode = static_cast<OrderExecutionMode>(Common::readU8(data + off));
    off += 1;
    out.sell_token = Common::readU32(data + off);
    off += 4;
    out.buy_token = Common::readU32(data + off);
    off += 4;
    out.sell_amount = Common::readU64(data + off);
    off += 8;
    out.min_buy_amount = Common::readU64(data + off);
    off += 8;
    out.created_at_height = Common::readU64(data + off);
    off += 8;
    out.order_expires_at_height = Common::readU64(data + off);
    off += 8;
    out.filled_amount = Common::readU64(data + off);
    off += 8;
    out.condition_count = Common::readU8(data + off);
    off += 1;

    if (out.condition_count > ORDER_MAX_CONDITIONS)
      return false;

    for (uint8_t i = 0; i < out.condition_count; ++i)
    {
      if (!OrderCondition::deserializeState(data, len, off, out.conditions[i]))
      {
        return false;
      }
    }

    return out.isValid();
  }

  //  Framework serialization

  void Order::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(owner, "owner");
    s(mode, "mode");
    s(sell_token, "sell_token");
    s(buy_token, "buy_token");
    s(sell_amount, "sell_amount");
    s(min_buy_amount, "min_buy_amount");
    s(created_at_height, "created_at_height");
    s(order_expires_at_height, "order_expires_at_height");
    s(filled_amount, "filled_amount");
    s(condition_count, "condition_count");
    // Note: conditions array is not serialized via framework, use state
    // codec for full fidelity.
  }

  void Order::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(owner, "owner");
    s(mode, "mode");
    s(sell_token, "sell_token");
    s(buy_token, "buy_token");
    s(sell_amount, "sell_amount");
    s(min_buy_amount, "min_buy_amount");
    s(created_at_height, "created_at_height");
    s(order_expires_at_height, "order_expires_at_height");
    s(filled_amount, "filled_amount");
    s(condition_count, "condition_count");
  }

} // namespace Core