// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <string>

#include "Fixtures.h"

#include "RPC/JsonRpcError.h"

using namespace Tests;

// ============================================================================
//  clrty_getTransactionByHash
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetTransactionByHash_MissingParam)
{
  Common::Json resp = callRaw("getTransactionByHash", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetTransactionByHash_MalformedHash)
{
  Common::Json resp = callRaw("getTransactionByHash", {{"hash", "0xnotahash"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetTransactionByHash_Unknown)
{
  const std::string fake = "0x" + std::string(64, 'a');
  Common::Json resp = callRaw("getTransactionByHash", {{"hash", fake}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::TransactionNotFound);
}

// ============================================================================
//  clrty_getTransactionReceipt
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetTransactionReceipt_MissingParam)
{
  Common::Json resp = callRaw("getTransactionReceipt", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetTransactionReceipt_MalformedHash)
{
  Common::Json resp = callRaw("getTransactionReceipt", {{"hash", "0x1234"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetTransactionReceipt_Unknown)
{
  const std::string fake = "0x" + std::string(64, 'b');
  Common::Json resp = callRaw("getTransactionReceipt", {{"hash", fake}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::ReceiptNotFound);
}

// ============================================================================
//  clrty_simulateTransaction
// ============================================================================

TEST_F(RPC_MethodTestFixture, SimulateTransaction_MissingParam)
{
  Common::Json resp = callRaw("simulateTransaction", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, SimulateTransaction_NotHex)
{
  Common::Json resp = callRaw("simulateTransaction",
                              {{"tx", "this is not hex"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, SimulateTransaction_EmptyHex)
{
  Common::Json resp = callRaw("simulateTransaction", {{"tx", "0x"}});
  ASSERT_TRUE(resp.contains("error"));
  // Empty bytes for a tx is "malformed", not "invalid params".
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::TxMalformed);
}

TEST_F(RPC_MethodTestFixture, SimulateTransaction_GarbageBytes)
{
  // Valid hex, but not a valid serialized Transaction.
  std::string junk = "0x" + std::string(100, 'f');
  Common::Json resp = callRaw("simulateTransaction", {{"tx", junk}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::TxMalformed);
}

// ============================================================================
//  clrty_sendRawTransaction
// ============================================================================

TEST_F(RPC_MethodTestFixture, SendRawTransaction_MissingParam)
{
  Common::Json resp = callRaw("sendRawTransaction", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, SendRawTransaction_NotHex)
{
  Common::Json resp = callRaw("sendRawTransaction",
                              {{"tx", "zzz not hex"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, SendRawTransaction_EmptyHex)
{
  Common::Json resp = callRaw("sendRawTransaction", {{"tx", "0x"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::TxMalformed);
}

TEST_F(RPC_MethodTestFixture, SendRawTransaction_GarbageBytes)
{
  std::string junk = "0x" + std::string(200, 'a');
  Common::Json resp = callRaw("sendRawTransaction", {{"tx", junk}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::TxMalformed);
}