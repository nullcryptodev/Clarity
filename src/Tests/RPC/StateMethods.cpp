// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <string>

#include "Fixtures.h"
#include "GlobalConfig.h"

#include "RPC/JsonRpcError.h"

using namespace Tests;

// ============================================================================
//  clrty_getBalance
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetBalance_ZeroForUnknownAddress)
{
  std::string addr = encodeAddr(addrFromU64(1));
  Common::Json v = call("clrty_getBalance", {{"address", addr}});
  ASSERT_TRUE(v.is_object());
  EXPECT_EQ(v["balance"], "0x0");
  EXPECT_EQ(v["token_id"], "0x0"); // native token default
}

TEST_F(RPC_MethodTestFixture, GetBalance_AcceptsHexAddress)
{
  // Raw 64-char hex is accepted as input.
  std::string hex = "0x" + std::string(64, '1');
  Common::Json v = call("clrty_getBalance", {{"address", hex}});
  ASSERT_TRUE(v.is_object());
  EXPECT_TRUE(v.contains("balance"));
}

TEST_F(RPC_MethodTestFixture, GetBalance_MissingAddress)
{
  Common::Json resp = callRaw("clrty_getBalance", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetBalance_MalformedAddress)
{
  Common::Json resp = callRaw("clrty_getBalance", {{"address", "not-an-address"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetBalance_ExplicitNativeTokenId)
{
  std::string addr = encodeAddr(addrFromU64(2));
  Common::Json v = call("clrty_getBalance",
                        {{"address", addr}, {"token_id", "0x0"}});
  ASSERT_TRUE(v.is_object());
  EXPECT_EQ(v["token_id"], "0x0");
  EXPECT_EQ(v["balance"], "0x0");
}

TEST_F(RPC_MethodTestFixture, GetBalance_CustomTokenDefaultsZero)
{
  // Custom token balance for an address that has never held it.
  std::string addr = encodeAddr(addrFromU64(3));
  Common::Json v = call("clrty_getBalance",
                        {{"address", addr}, {"token_id", "0x64"}});
  ASSERT_TRUE(v.is_object());
  EXPECT_EQ(v["token_id"], "0x64");
  EXPECT_EQ(v["balance"], "0x0");
}

// ============================================================================
//  clrty_getAccount
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetAccount_UnknownIsEmpty)
{
  std::string addr = encodeAddr(addrFromU64(10));
  Common::Json a = call("clrty_getAccount", {{"address", addr}});
  ASSERT_TRUE(a.is_object());
  EXPECT_TRUE(a.contains("address"));
  EXPECT_TRUE(a.contains("balance"));
  EXPECT_TRUE(a.contains("nonce"));
}

TEST_F(RPC_MethodTestFixture, GetAccount_MissingAddress)
{
  Common::Json resp = callRaw("clrty_getAccount", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetAccount_MalformedAddress)
{
  Common::Json resp = callRaw("clrty_getAccount", {{"address", "0x1234"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

// ============================================================================
//  clrty_getNonce
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetNonce_ZeroForUnknown)
{
  std::string addr = encodeAddr(addrFromU64(20));
  Common::Json v = call("clrty_getNonce", {{"address", addr}});
  ASSERT_TRUE(v.is_object());
  EXPECT_EQ(v["nonce"], "0x0");
}

TEST_F(RPC_MethodTestFixture, GetNonce_MissingAddress)
{
  Common::Json resp = callRaw("clrty_getNonce", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

// ============================================================================
//  clrty_getTokenInfo
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetTokenInfo_NativeTokenExists)
{
  // Token 0 is the native CLRTY token, written at genesis.
  Common::Json t = call("clrty_getTokenInfo", {{"token_id", "0x0"}});
  ASSERT_TRUE(t.is_object());
  EXPECT_TRUE(t.contains("id"));
  EXPECT_TRUE(t.contains("symbol"));
}

TEST_F(RPC_MethodTestFixture, GetTokenInfo_MissingParam)
{
  Common::Json resp = callRaw("clrty_getTokenInfo", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetTokenInfo_Unknown)
{
  Common::Json resp = callRaw("clrty_getTokenInfo", {{"token_id", "0xFFFF"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::TokenNotFound);
}

// ============================================================================
//  clrty_getTokenSupply
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetTokenSupply_Native)
{
  Common::Json s = call("clrty_getTokenSupply", {{"token_id", "0x0"}});
  ASSERT_TRUE(s.is_object());
  EXPECT_TRUE(s.contains("supply"));
  ASSERT_TRUE(s["supply"].is_string());
  EXPECT_EQ(s["supply"].get<std::string>().substr(0, 2), "0x");
}

TEST_F(RPC_MethodTestFixture, GetTokenSupply_UnknownReturnsZero)
{
  // The handler doesn't throw for unknown tokens; it reports supply 0.
  Common::Json s = call("clrty_getTokenSupply", {{"token_id", "0xFFFF"}});
  ASSERT_TRUE(s.is_object());
  EXPECT_EQ(s["supply"], "0x0");
}

TEST_F(RPC_MethodTestFixture, GetTokenSupply_MissingParam)
{
  Common::Json resp = callRaw("clrty_getTokenSupply", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}