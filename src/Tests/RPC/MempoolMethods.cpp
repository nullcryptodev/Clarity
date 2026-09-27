// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <string>

#include "Fixtures.h"

#include "RPC/JsonRpcError.h"

using namespace Tests;

// ============================================================================
//  clrty_getMempoolStats
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetStats_EmptyPool)
{
  Common::Json s = call("clrty_getMempoolStats");
  ASSERT_TRUE(s.is_object());
  EXPECT_TRUE(s.contains("total_txs"));
  EXPECT_TRUE(s.contains("priority_txs"));
  EXPECT_TRUE(s.contains("standard_txs"));
  EXPECT_TRUE(s.contains("total_bytes"));
  EXPECT_TRUE(s.contains("min_fee_rate"));
  EXPECT_TRUE(s.contains("max_fee_rate"));
  EXPECT_TRUE(s.contains("avg_fee_rate"));

  // The shared fixture never submits txs, so the pool is empty.
  EXPECT_EQ(s["total_txs"], "0x0");
  EXPECT_EQ(s["priority_txs"], "0x0");
  EXPECT_EQ(s["standard_txs"], "0x0");
  EXPECT_EQ(s["total_bytes"], "0x0");
}

TEST_F(RPC_MethodTestFixture, GetStats_AllFieldsHexStrings)
{
  Common::Json s = call("clrty_getMempoolStats");
  for (const char *k : {"total_txs", "priority_txs", "standard_txs",
                        "total_bytes", "min_fee_rate", "max_fee_rate",
                        "avg_fee_rate"})
  {
    ASSERT_TRUE(s.contains(k)) << k;
    ASSERT_TRUE(s[k].is_string()) << k;
    EXPECT_EQ(s[k].get<std::string>().substr(0, 2), "0x") << k;
  }
}

// ============================================================================
//  clrty_getMempoolTx
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetTx_MissingParam)
{
  Common::Json resp = callRaw("clrty_getMempoolTx", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetTx_MalformedHash)
{
  Common::Json resp = callRaw("clrty_getMempoolTx", {{"hash", "0xnotahash"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetTx_UnknownReturnsNull)
{
  // The handler returns JSON null for a miss, not an error.
  const std::string fake = "0x" + std::string(64, 'a');
  Common::Json v = call("clrty_getMempoolTx", {{"hash", fake}});
  EXPECT_TRUE(v.is_null());
}