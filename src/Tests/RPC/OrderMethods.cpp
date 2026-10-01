// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <string>

#include "Fixtures.h"

#include "RPC/JsonRpcError.h"

using namespace Tests;

// ============================================================================
//  clrty_getOrder
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetOrder_MissingParam)
{
  Common::Json resp = callRaw("getOrder", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetOrder_UnknownId)
{
  Common::Json resp = callRaw("getOrder", {{"order_id", "0x1"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::OrderNotFound);
}

TEST_F(RPC_MethodTestFixture, GetOrder_MalformedId)
{
  Common::Json resp = callRaw("getOrder", {{"order_id", "not-a-number"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

// ============================================================================
//  clrty_getOrdersExpiringAt
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetOrdersExpiringAt_MissingParam)
{
  Common::Json resp = callRaw("getOrdersExpiringAt", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetOrdersExpiringAt_Empty)
{
  // No orders have been created in the shared fixture, so any height
  // returns an empty list, not an error.
  Common::Json v = call("getOrdersExpiringAt", {{"height", "0x64"}});
  ASSERT_TRUE(v.is_object());
  EXPECT_TRUE(v.contains("height"));
  EXPECT_TRUE(v.contains("count"));
  EXPECT_TRUE(v.contains("order_ids"));
  ASSERT_TRUE(v["order_ids"].is_array());
  EXPECT_TRUE(v["order_ids"].empty());
  EXPECT_EQ(v["count"], "0x0");
}

TEST_F(RPC_MethodTestFixture, GetOrdersExpiringAt_EchoesHeight)
{
  Common::Json v = call("getOrdersExpiringAt", {{"height", "0x2A"}});
  EXPECT_EQ(v["height"], "0x2a"); // hex, lowercase, no leading zeros
}

TEST_F(RPC_MethodTestFixture, GetOrdersExpiringAt_AcceptsDecimal)
{
  Common::Json v = call("getOrdersExpiringAt", {{"height", "42"}});
  ASSERT_TRUE(v.is_object());
  EXPECT_EQ(v["height"], "0x2a");
}