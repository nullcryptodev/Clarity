// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <string>

#include "Fixtures.h"

#include "RPC/JsonRpcError.h"

using namespace Tests;

// ============================================================================
//  clrty_getValidators
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetValidators_ReturnsArray)
{
  // encodeValidatorList returns a bare JSON array, sorted by id.
  Common::Json v = call("getValidators");
  ASSERT_TRUE(v.is_array());

  // The shared fixture has one seed validator at genesis.
  ASSERT_GE(v.size(), 1u);
  for (const auto &entry : v)
  {
    ASSERT_TRUE(entry.is_object());
    EXPECT_TRUE(entry.contains("id"));
    EXPECT_TRUE(entry.contains("reward_address"));
    EXPECT_TRUE(entry.contains("stake"));
    EXPECT_TRUE(entry.contains("is_active"));
    EXPECT_TRUE(entry.contains("is_seed"));
  }
}

TEST_F(RPC_MethodTestFixture, GetValidators_ActiveOnlyAccepted)
{
  Common::Json v = call("getValidators", {{"active_only", true}});
  ASSERT_TRUE(v.is_array());

  // Every returned validator should have is_active == true.
  for (const auto &entry : v)
  {
    ASSERT_TRUE(entry.is_object());
    ASSERT_TRUE(entry.contains("is_active"));
    EXPECT_TRUE(entry["is_active"].get<bool>());
  }
}

TEST_F(RPC_MethodTestFixture, GetValidators_WrongTypeFlag)
{
  // active_only is a bool; a string should be rejected.
  Common::Json resp = callRaw("getValidators", {{"active_only", "yes"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

// ============================================================================
//  clrty_getValidator
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetValidator_MissingParam)
{
  Common::Json resp = callRaw("getValidator", Common::Json::object());
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::InvalidParams);
}

TEST_F(RPC_MethodTestFixture, GetValidator_UnknownId)
{
  // A high id that certainly doesn't exist.
  Common::Json resp = callRaw("getValidator", {{"id", "0xFFFF"}});
  ASSERT_TRUE(resp.contains("error"));
  EXPECT_EQ(resp["error"]["code"], Rpc::ErrorCode::ValidatorNotFound);
}

// ============================================================================
//  clrty_getActiveSet
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetActiveSet_WellFormed)
{
  Common::Json v = call("getActiveSet");
  ASSERT_TRUE(v.is_object());
  EXPECT_TRUE(v.contains("ids"));
  EXPECT_TRUE(v.contains("size"));
  EXPECT_TRUE(v.contains("quorum"));
  ASSERT_TRUE(v["ids"].is_array());
  ASSERT_TRUE(v["size"].is_string());
  ASSERT_TRUE(v["quorum"].is_string());
}

TEST_F(RPC_MethodTestFixture, GetActiveSet_SizeMatchesArray)
{
  Common::Json v = call("getActiveSet");
  const std::string size_hex = v["size"].get<std::string>();
  // Parse the hex size back to a number and compare with the array length.
  uint64_t reported = std::stoull(size_hex.substr(2), nullptr, 16);
  EXPECT_EQ(reported, v["ids"].size());
}

// ============================================================================
//  clrty_getConsensusState
// ============================================================================

TEST_F(RPC_MethodTestFixture, GetConsensusState_Fields)
{
  Common::Json v = call("getConsensusState");
  ASSERT_TRUE(v.is_object());
  EXPECT_TRUE(v.contains("height"));
  EXPECT_TRUE(v.contains("round"));
  EXPECT_TRUE(v.contains("step"));
  EXPECT_TRUE(v.contains("is_validator"));
  EXPECT_TRUE(v.contains("validator_id"));
  EXPECT_TRUE(v.contains("chain_height"));
  EXPECT_TRUE(v.contains("best_peer_height"));
}

TEST_F(RPC_MethodTestFixture, GetConsensusState_HeightIsHex)
{
  Common::Json v = call("getConsensusState");
  ASSERT_TRUE(v["height"].is_string());
  EXPECT_EQ(v["height"].get<std::string>().substr(0, 2), "0x");
}

TEST_F(RPC_MethodTestFixture, GetConsensusState_IsValidatorBool)
{
  Common::Json v = call("getConsensusState");
  ASSERT_TRUE(v["is_validator"].is_boolean());
}