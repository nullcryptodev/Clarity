// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <string>

#include "Fixtures.h"
#include "GlobalConfig.h"

#include "RPC/JsonRpcError.h"

using namespace Tests;

// ============================================================================
//  clrty_chainId
// ============================================================================

TEST_F(RPC_MethodTestFixture, ChainId_ReturnsObject)
{
  Common::Json v = call("clrty_chainId");
  ASSERT_TRUE(v.is_object());
  ASSERT_TRUE(v.contains("chain_id"));
  ASSERT_TRUE(v["chain_id"].is_string());
  EXPECT_EQ(v["chain_id"].get<std::string>().substr(0, 2), "0x");
}

TEST_F(RPC_MethodTestFixture, ChainId_MatchesNode)
{
  Common::Json v = call("clrty_chainId");
  const std::string reported = v["chain_id"].get<std::string>();
  // Same call must be stable across invocations.
  Common::Json v2 = call("clrty_chainId");
  EXPECT_EQ(reported, v2["chain_id"].get<std::string>());
}

// ============================================================================
//  clrty_blockNumber
// ============================================================================

TEST_F(RPC_MethodTestFixture, BlockNumber_IsHexString)
{
  Common::Json v = call("clrty_blockNumber");
  ASSERT_TRUE(v.is_object());
  ASSERT_TRUE(v["height"].is_string());
  EXPECT_EQ(v["height"].get<std::string>().substr(0, 2), "0x");
}

TEST_F(RPC_MethodTestFixture, BlockNumber_StableAcrossCalls)
{
  // The chain isn't advancing in this fixture, so height is constant.
  Common::Json a = call("clrty_blockNumber");
  Common::Json b = call("clrty_blockNumber");
  EXPECT_EQ(a["height"], b["height"]);
}

// ============================================================================
//  clrty_getBlockByNumber
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetBlockByNumber_Genesis)
{
  Common::Json b = call("clrty_getBlockByNumber", {{"height", "0x0"}});
  ASSERT_TRUE(b.is_object());
  // Header fields are flat-packed at the top level, not nested.
  EXPECT_TRUE(b.contains("height"));
  EXPECT_TRUE(b.contains("hash"));
  EXPECT_TRUE(b.contains("state_root"));
  EXPECT_EQ(b["height"], "0x0");
}

TEST_F(RPC_MethodTestFixture, GetBlockByNumber_AcceptsDecimal)
{
  Common::Json b = call("clrty_getBlockByNumber", {{"height", "0"}});
  ASSERT_TRUE(b.is_object());
  EXPECT_TRUE(b.contains("height"));
  EXPECT_EQ(b["height"], "0x0");
}

TEST_F(RPC_MethodTestFixture, GetBlockByNumber_MissingParam)
{
  Common::Json resp = callRaw("clrty_getBlockByNumber", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetBlockByNumber_UnknownHeight)
{
  // Height 99999999 doesn't exist. Error must be BlockNotFound, not
  // InvalidParams — the param was fine, the resource was not found.
  Common::Json resp = callRaw("clrty_getBlockByNumber", {{"height", "0x5F5E0FF"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::BlockNotFound);
}

TEST_F(RPC_MethodTestFixture, GetBlockByNumber_FullFlag)
{
  Common::Json b = call("clrty_getBlockByNumber",
                        {{"height", "0x0"}, {"full", true}});
  ASSERT_TRUE(b.is_object());
  EXPECT_TRUE(b.contains("height"));
  // full=true means transactions is an array of full tx objects,
  // not hashes. Genesis has none, so it's an empty array either way.
  ASSERT_TRUE(b.contains("transactions"));
  EXPECT_TRUE(b["transactions"].is_array());
}

// ============================================================================
//  clrty_getBlockByHash
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetBlockByHash_RoundTrip)
{
  Common::Json byNumber = call("clrty_getBlockByNumber", {{"height", "0x0"}});
  ASSERT_TRUE(byNumber.contains("hash"));
  const std::string hash = byNumber["hash"].get<std::string>();

  Common::Json byHash = call("clrty_getBlockByHash", {{"hash", hash}});
  ASSERT_TRUE(byHash.is_object());
  EXPECT_EQ(byHash["hash"], hash);
  EXPECT_EQ(byHash["height"], "0x0");
}

TEST_F(RPC_MethodTestFixture, GetBlockByHash_MissingParam)
{
  Common::Json resp = callRaw("clrty_getBlockByHash", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetBlockByHash_MalformedHash)
{
  Common::Json resp = callRaw("clrty_getBlockByHash", {{"hash", "0xnotahash"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetBlockByHash_Unknown)
{
  // Valid-looking hash that doesn't exist in the chain.
  const std::string fake = "0x" + std::string(64, 'a');
  Common::Json resp = callRaw("clrty_getBlockByHash", {{"hash", fake}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::BlockNotFound);
}

// ============================================================================
//  clrty_getBlockHeaderByNumber
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetBlockHeaderByNumber_Genesis)
{
  Common::Json h = call("clrty_getBlockHeaderByNumber", {{"height", "0x0"}});
  ASSERT_TRUE(h.is_object());
  EXPECT_TRUE(h.contains("height"));
  EXPECT_EQ(h["height"], "0x0");
  EXPECT_TRUE(h.contains("hash"));
}

TEST_F(RPC_MethodTestFixture, GetBlockHeaderByNumber_MissingParam)
{
  Common::Json resp = callRaw("clrty_getBlockHeaderByNumber", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetBlockHeaderByNumber_UnknownHeight)
{
  Common::Json resp = callRaw("clrty_getBlockHeaderByNumber", {{"height", "0x5F5E0FF"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::BlockNotFound);
}

// ============================================================================
//  clrty_getStateRoot
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetStateRoot_Genesis)
{
  // The genesis block commits a state root at version 0.
  Common::Json s = call("clrty_getStateRoot", {{"height", "0x0"}});
  ASSERT_TRUE(s.is_object());
  ASSERT_TRUE(s.contains("state_root"));
  ASSERT_TRUE(s["state_root"].is_string());
  const std::string root = s["state_root"].get<std::string>();
  EXPECT_EQ(root.substr(0, 2), "0x");
  EXPECT_EQ(root.size(), 66u); // "0x" + 64 hex
}

TEST_F(RPC_MethodTestFixture, GetStateRoot_MissingParam)
{
  Common::Json resp = callRaw("clrty_getStateRoot", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetStateRoot_UnknownHeight)
{
  Common::Json resp = callRaw("clrty_getStateRoot", {{"height", "0x5F5E0FF"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::BlockNotFound);
}

TEST_F(RPC_MethodTestFixture, GetStateRoot_Deterministic)
{
  Common::Json a = call("clrty_getStateRoot", {{"height", "0x0"}});
  Common::Json b = call("clrty_getStateRoot", {{"height", "0x0"}});
  EXPECT_EQ(a["state_root"], b["state_root"]);
}

// ============================================================================
//  clrty_methods
// ============================================================================

TEST_F(RPC_MethodTestFixture, Methods_ReturnsArray)
{
  Common::Json m = call("clrty_methods");
  ASSERT_TRUE(m.is_object());
  ASSERT_TRUE(m.contains("methods"));
  ASSERT_TRUE(m["methods"].is_array());
  EXPECT_FALSE(m["methods"].empty());
}

TEST_F(RPC_MethodTestFixture, Methods_ContainsKnownEntries)
{
  Common::Json m = call("clrty_methods");
  const auto &arr = m["methods"];
  auto contains = [&](const std::string &name)
  {
    for (const auto &item : arr)
      if (item.is_string() && item.get<std::string>() == name)
        return true;
    return false;
  };
  // A few methods that must always be registered.
  EXPECT_TRUE(contains("clrty_ping"));
  EXPECT_TRUE(contains("clrty_status"));
  EXPECT_TRUE(contains("clrty_chainId"));
  EXPECT_TRUE(contains("clrty_blockNumber"));
}
