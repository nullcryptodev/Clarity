// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Order.h"
#include "RPC/Encoders.h"

using Common::Json;
using Rpc::encodeOrder;

namespace
{
  Core::Order makeOrder()
  {
    Core::Order o;
    o.id = 1;
    o.owner = Crypto::addrFromHex(
        "4444444444444444444444444444444444444444444444444444444444444444");
    o.mode = Core::OrderExecutionMode::Passive;
    o.sell_token = 0;
    o.buy_token = 42;
    o.sell_amount = 1000;
    o.min_buy_amount = 500;
    o.created_at_height = 10;
    o.order_expires_at_height = 100;
    o.filled_amount = 0;
    o.condition_count = 1;
    o.conditions[0].type = Core::OrderConditionType::ExpiresAtHeight;
    o.conditions[0].param1 = 100;
    return o;
  }
} // namespace

TEST(RPC_OrderEncoder, BasicFields)
{
  Json j = encodeOrder(makeOrder(), "clrty");

  EXPECT_EQ(j["id"], "0x1");
  EXPECT_EQ(j["mode"], "passive");
  EXPECT_EQ(j["mode_code"], 0);
  EXPECT_EQ(j["sell_token"], "0x0");
  EXPECT_EQ(j["buy_token"], "0x2a");
  EXPECT_EQ(j["sell_amount"], "0x3e8");
  EXPECT_EQ(j["min_buy_amount"], "0x1f4");
  EXPECT_EQ(j["filled_amount"], "0x0");
  EXPECT_EQ(j["remaining_amount"], "0x3e8");
  EXPECT_EQ(j["is_fully_filled"], false);
  EXPECT_EQ(j["condition_count"], 1);
}

TEST(RPC_OrderEncoder, ActiveMode)
{
  Core::Order o = makeOrder();
  o.mode = Core::OrderExecutionMode::Active;

  Json j = encodeOrder(o, "clrty");
  EXPECT_EQ(j["mode"], "active");
  EXPECT_EQ(j["mode_code"], 1);
}

TEST(RPC_OrderEncoder, ConditionsSerialized)
{
  Json j = encodeOrder(makeOrder(), "clrty");
  ASSERT_TRUE(j["conditions"].is_array());
  ASSERT_EQ(j["conditions"].size(), 1u);

  const auto &c = j["conditions"][0];
  EXPECT_EQ(c["type"], "expires_at_height");
  EXPECT_EQ(c["type_code"], 1);
  EXPECT_EQ(c["param1"], "0x64"); // 100
  EXPECT_TRUE(c.contains("description"));
}

TEST(RPC_OrderEncoder, FullyFilledOrder)
{
  Core::Order o = makeOrder();
  o.filled_amount = o.sell_amount;

  Json j = encodeOrder(o, "clrty");
  EXPECT_EQ(j["is_fully_filled"], true);
  EXPECT_EQ(j["remaining_amount"], "0x0");
}