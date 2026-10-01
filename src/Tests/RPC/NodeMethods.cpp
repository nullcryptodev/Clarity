// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <cctype>
#include <string>

#include "Fixtures.h"
#include "GlobalConfig.h"

#include "RPC/JsonRpcError.h"

using namespace Tests;

// ============================================================================
//  clrty_ping
// ============================================================================

TEST_F(RPC_MethodTestFixture, Ping_ReturnsPong)
{
  Common::Json result = call("ping");
  EXPECT_EQ(result, "pong");
}

TEST_F(RPC_MethodTestFixture, Ping_IgnoresExtraParams)
{
  Common::Json result = call("ping", {{"bogus", 42}});
  EXPECT_EQ(result, "pong");
}

// ============================================================================
//  clrty_status
// ============================================================================

TEST_F(RPC_MethodTestFixture, Status_HasExpectedFields)
{
  Common::Json s = call("status");

  // Fields the spec promises.
  ASSERT_TRUE(s.is_object());
  EXPECT_TRUE(s.contains("height"));
  EXPECT_TRUE(s.contains("best_peer_height"));
  EXPECT_TRUE(s.contains("peer_count"));
  EXPECT_TRUE(s.contains("mempool_size"));
  EXPECT_TRUE(s.contains("mempool_bytes"));
  EXPECT_TRUE(s.contains("is_validator"));
  EXPECT_TRUE(s.contains("validator_id"));
  EXPECT_TRUE(s.contains("consensus_height"));
  EXPECT_TRUE(s.contains("consensus_round"));
  EXPECT_TRUE(s.contains("consensus_step"));
  EXPECT_TRUE(s.contains("network"));
  EXPECT_TRUE(s.contains("chain_id"));
  EXPECT_TRUE(s.contains("running"));
  EXPECT_TRUE(s.contains("state_root"));
}

TEST_F(RPC_MethodTestFixture, Status_HeightIsHexString)
{
  Common::Json s = call("status");
  ASSERT_TRUE(s["height"].is_string());
  const std::string h = s["height"].get<std::string>();
  ASSERT_GE(h.size(), 2u);
  EXPECT_EQ(h.substr(0, 2), "0x");
}

TEST_F(RPC_MethodTestFixture, Status_RunningIsTrue)
{
  Common::Json s = call("status");
  ASSERT_TRUE(s["running"].is_boolean());
  EXPECT_TRUE(s["running"].get<bool>());
}

TEST_F(RPC_MethodTestFixture, Status_NetworkIsRegtest)
{
  Common::Json s = call("status");
  ASSERT_TRUE(s["network"].is_string());
  EXPECT_EQ(s["network"].get<std::string>(), "regtest");
}

// ============================================================================
//  clrty_health
// ============================================================================

TEST_F(RPC_MethodTestFixture, Health_OkWhenRunning)
{
  Common::Json h = call("health");
  ASSERT_TRUE(h.is_object());
  ASSERT_TRUE(h["ok"].is_boolean());
  EXPECT_TRUE(h["ok"].get<bool>());
  EXPECT_TRUE(h.contains("height"));
  EXPECT_TRUE(h.contains("peers"));
  EXPECT_TRUE(h.contains("is_validator"));
}

// ============================================================================
//  clrty_getPeers
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetPeers_EmptyWhenNoP2P)
{
  Common::Json p = call("getPeers");
  ASSERT_TRUE(p.is_object());
  EXPECT_TRUE(p.contains("count"));
  EXPECT_TRUE(p.contains("peers"));
  ASSERT_TRUE(p["peers"].is_array());

  // P2P is disabled in the shared fixture, so count must be 0.
  ASSERT_TRUE(p["count"].is_string());
  EXPECT_EQ(p["count"].get<std::string>(), "0x0");
  EXPECT_TRUE(p["peers"].empty());
}

// ============================================================================
//  clrty_getConfig
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetConfig_DoesNotLeakAdminToken)
{
  Common::Json c = call("getConfig");
  ASSERT_TRUE(c.is_object());

  // The wire format must never contain the admin token itself.
  EXPECT_FALSE(c.contains("admin_token"));
  // But it can expose whether one is set.
  EXPECT_TRUE(c.contains("admin_enabled"));
  ASSERT_TRUE(c["admin_enabled"].is_boolean());
}

TEST_F(RPC_MethodTestFixture, GetConfig_HasOperationalFields)
{
  Common::Json c = call("getConfig");
  EXPECT_TRUE(c.contains("enabled"));
  EXPECT_TRUE(c.contains("bind_address"));
  EXPECT_TRUE(c.contains("port"));
  EXPECT_TRUE(c.contains("worker_threads"));
  EXPECT_TRUE(c.contains("max_request_bytes"));
  EXPECT_TRUE(c.contains("socket_timeout_seconds"));
  EXPECT_TRUE(c.contains("rate_limit_burst"));
  EXPECT_TRUE(c.contains("rate_limit_per_second"));
  EXPECT_TRUE(c.contains("verbose_errors"));
}

// ============================================================================
//  web3_clientVersion
// ============================================================================

TEST_F(RPC_MethodTestFixture, Web3ClientVersion_ReturnsString)
{
  Common::Json v = call("web3_clientVersion");
  ASSERT_TRUE(v.is_string());
  const std::string s = v.get<std::string>();
  EXPECT_FALSE(s.empty());
  ASSERT_GE(s.size(), 5u);
  EXPECT_EQ(s.substr(0, 5), "clrty");
}

// ============================================================================
//  net_version
// ============================================================================

TEST_F(RPC_MethodTestFixture, NetVersion_IsDecimalString)
{
  Common::Json v = call("net_version");
  ASSERT_TRUE(v.is_string());

  // Ethereum convention: decimal string of the chain id.
  const std::string s = v.get<std::string>();
  ASSERT_FALSE(s.empty());
  for (char c : s)
    EXPECT_TRUE(std::isdigit(static_cast<unsigned char>(c)))
        << "net_version returned non-digit: " << s;

  // Should match the node's chain id.
  uint64_t chain_id = std::stoull(s);
  EXPECT_NE(chain_id, 0u);
}

// ============================================================================
//  net_peerCount
// ============================================================================

TEST_F(RPC_MethodTestFixture, NetPeerCount_IsHexString)
{
  Common::Json v = call("net_peerCount");
  ASSERT_TRUE(v.is_string());
  const std::string s = v.get<std::string>();
  ASSERT_GE(s.size(), 2u);
  EXPECT_EQ(s.substr(0, 2), "0x");

  // No P2P in this fixture, so 0x0.
  EXPECT_EQ(s, "0x0");
}

// ============================================================================
//  net_listening
// ============================================================================

TEST_F(RPC_MethodTestFixture, NetListening_FalseWithNoPeers)
{
  Common::Json v = call("net_listening");
  ASSERT_TRUE(v.is_boolean());
  EXPECT_FALSE(v.get<bool>());
}

// ============================================================================
//  Unknown method — should be an error, not a crash
// ============================================================================

TEST_F(RPC_MethodTestFixture, UnknownMethodReturnsError)
{
  Common::Json resp = callRaw("thisMethodDoesNotExist",
                              Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  ASSERT_TRUE(resp["error"].is_object());
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::MethodNotFound);
}

// ============================================================================
//  Missing method field — malformed request
// ============================================================================

TEST_F(RPC_MethodTestFixture, MissingMethodFieldIsInvalidRequest)
{
  Common::Json req = {
      {"jsonrpc", "2.0"},
      {"params", Common::Json::object()},
      {"id", 1},
  };
  Common::Json resp = dispatchRaw(req.dump());
  ASSERT_TRUE(resp.contains("error"));
  ASSERT_TRUE(resp["error"].is_object());
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidRequest);
}