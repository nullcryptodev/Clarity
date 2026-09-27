// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "OrderEncoder.h"
#include "Encoding.h"

namespace Rpc
{

  namespace
  {
    const char *conditionName(Core::OrderConditionType t) noexcept
    {
      switch (t)
      {
      case Core::OrderConditionType::Invalid:
        return "invalid";
      case Core::OrderConditionType::ExpiresAtHeight:
        return "expires_at_height";
      case Core::OrderConditionType::PriceAbove:
        return "price_above";
      case Core::OrderConditionType::PriceBelow:
        return "price_below";
      case Core::OrderConditionType::VolumeBelow:
        return "volume_below";
      case Core::OrderConditionType::BalanceBelow:
        return "balance_below";
      }
      return "unknown";
    }

    const char *modeName(Core::OrderExecutionMode m) noexcept
    {
      switch (m)
      {
      case Core::OrderExecutionMode::Passive:
        return "passive";
      case Core::OrderExecutionMode::Active:
        return "active";
      }
      return "unknown";
    }

    // Human-readable explanation of a condition. For display only;
    // clients should switch on type_code for programmatic handling.
    std::string describeCondition(const Core::OrderCondition &c)
    {
      switch (c.type)
      {
      case Core::OrderConditionType::ExpiresAtHeight:
        return "expires at height " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::PriceAbove:
        return "cancels if price above " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::PriceBelow:
        return "cancels if price below " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::VolumeBelow:
        return "cancels if 24h volume below " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::BalanceBelow:
        return "cancels if balance below " + encodeU64Hex(c.param1);
      case Core::OrderConditionType::Invalid:
        return "invalid condition";
      }
      return "unknown condition";
    }

    Common::Json encodeCondition(const Core::OrderCondition &c)
    {
      Common::Json j = Common::Json::object();
      j["type"] = conditionName(c.type);
      j["type_code"] = static_cast<uint32_t>(c.type);
      putU64(j, "param1", c.param1);
      putU64(j, "param2", c.param2);
      j["description"] = describeCondition(c);
      return j;
    }
  } // anonymous namespace

  Common::Json encodeOrder(const Core::Order &order, const std::string &hrp)
  {
    Common::Json j = Common::Json::object();

    putU64(j, "id", order.id);
    putAddress(j, "owner", order.owner, hrp);
    j["mode"] = modeName(order.mode);
    j["mode_code"] = static_cast<uint32_t>(order.mode);

    putU64(j, "sell_token", order.sell_token);
    putU64(j, "buy_token", order.buy_token);
    putU64(j, "sell_amount", order.sell_amount);
    putU64(j, "min_buy_amount", order.min_buy_amount);
    putU64(j, "filled_amount", order.filled_amount);
    putU64(j, "remaining_amount", order.remainingAmount());

    putU64(j, "created_at_height", order.created_at_height);
    putU64(j, "order_expires_at_height", order.order_expires_at_height);
    j["is_fully_filled"] = order.isFullyFilled();

    j["condition_count"] = static_cast<uint32_t>(order.condition_count);

    Common::Json arr = Common::Json::array();
    for (uint8_t i = 0; i < order.condition_count && i < Core::ORDER_MAX_CONDITIONS; ++i)
    {
      arr.push_back(encodeCondition(order.conditions[i]));
    }
    j["conditions"] = std::move(arr);

    return j;
  }

} // namespace Rpc