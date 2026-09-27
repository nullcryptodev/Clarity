// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <string>

#include "Fixtures.h"

#include "RPC/JsonRpcError.h"

using namespace Tests;

// clrty_getPool

TEST_F(RPC_MethodTestFixture, GetPool_MissingParam)
{
  Common::Json resp = callRaw("clrty_getPool", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetPool_UnknownId)
{
  // Shared fixture has no AMM pools.
  Common::Json resp = callRaw("clrty_getPool", {{"pool_id", "0x1"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::PoolNotFound);
}

TEST_F(RPC_MethodTestFixture, GetPool_MalformedId)
{
  Common::Json resp = callRaw("clrty_getPool", {{"pool_id", "not-a-number"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

// clrty_getPosition

TEST_F(RPC_MethodTestFixture, GetPosition_MissingParam)
{
  Common::Json resp = callRaw("clrty_getPosition", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetPosition_UnknownId)
{
  Common::Json resp = callRaw("clrty_getPosition", {{"position_id", "0x1"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::PoolNotFound);
}

// clrty_getPositionByOwner

TEST_F(RPC_MethodTestFixture, GetPositionByOwner_MissingAddress)
{
  Common::Json resp = callRaw("clrty_getPositionByOwner", {{"pool_id", "0x1"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetPositionByOwner_MissingPoolId)
{
  std::string addr = encodeAddr(addrFromU64(100));
  Common::Json resp = callRaw("clrty_getPositionByOwner", {{"address", addr}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetPositionByOwner_NoPosition)
{
  std::string addr = encodeAddr(addrFromU64(101));
  Common::Json resp = callRaw("clrty_getPositionByOwner",
                              {{"address", addr}, {"pool_id", "0x1"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::PoolNotFound);
}

TEST_F(RPC_MethodTestFixture, GetPositionByOwner_MalformedAddress)
{
  Common::Json resp = callRaw("clrty_getPositionByOwner",
                              {{"address", "not-an-address"}, {"pool_id", "0x1"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}
