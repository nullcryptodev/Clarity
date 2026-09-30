// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Order.h"

#include "Common/Wire.h"

namespace Core
{
  //  OrderCondition

  void OrderCondition::serializeState(std::vector<uint8_t> &out) const
  {
    Common::Writer w(out);
    w.writeU8(static_cast<uint8_t>(type));
    w.writeU64(param1);
    w.writeU32(param2);
  }

  bool OrderCondition::deserializeState(const uint8_t *data, size_t len,
                                        size_t &offset, OrderCondition &out)
  {
    if (offset + STATE_SIZE > len)
      return false;

    Common::Reader r(data + offset, STATE_SIZE);

    out.type = static_cast<OrderConditionType>(r.readU8());
    out.param1 = r.readU64();
    out.param2 = r.readU32();

    if (!r.ok())
      return false;

    //  Only advance the caller's offset on success. On failure the
    //  caller's cursor is left untouched, so it can decide whether to
    //  retry, skip, or abort without having to unwind a half-consumed
    //  read.
    offset += STATE_SIZE;

    return out.isValid();
  }

  //  Order

  std::vector<uint8_t> Order::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE_FIXED + condition_count * OrderCondition::STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(id);
    w.writeBytes(owner.data.data(), owner.data.size());
    w.writeU8(static_cast<uint8_t>(mode));
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

    //  Conditions are fixed-size and follow the fixed-size header
    //  immediately. Track the cursor manually because
    //  OrderCondition::deserializeState takes a raw byte offset, not a
    //  Reader — see the note in that function.
    size_t off = STATE_SIZE_FIXED;

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