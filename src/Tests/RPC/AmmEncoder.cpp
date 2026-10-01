// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/AmmPool.h"
#include "Core/AmmPosition.h"
#include "RPC/Encoders.h"
#include "Tests/Utils.h"

using Common::Json;
using Rpc::encodeAmmPool;
using Rpc::encodeAmmPosition;

using namespace Tests;

TEST(RPC_AmmEncoder, PoolFields)
{
  Json j = encodeAmmPool(makePool(), "clrty");

  EXPECT_EQ(j["id"], "0x1");
  EXPECT_EQ(j["token_a"], "0x0");
  EXPECT_EQ(j["token_b"], "0x2a");
  EXPECT_EQ(j["reserve_a"], "0xf4240");
  EXPECT_EQ(j["reserve_b"], "0x1e8480");
  EXPECT_EQ(j["total_liquidity"], "0x3e8");
  EXPECT_EQ(j["fee_bps"], 30);
  EXPECT_EQ(j["active"], true);
  EXPECT_TRUE(j.contains("k"));
  EXPECT_TRUE(j.contains("price_a_per_b"));
  EXPECT_TRUE(j.contains("price_b_per_a"));
}

TEST(RPC_AmmEncoder, PoolKIsHexString)
{
  // reserve_a = 1_000_000, reserve_b = 2_000_000
  // k = 2e12 = 0x1D1A94A2000
  Json j = encodeAmmPool(makePool(), "clrty");
  ASSERT_TRUE(j["k"].is_string());
  EXPECT_EQ(j["k"].get<std::string>().substr(0, 2), "0x");
}

TEST(RPC_AmmEncoder, PositionWithPool)
{
  Core::AmmPosition pos;
  pos.id = 5;
  pos.owner = Crypto::addrFromHex(
      "3333333333333333333333333333333333333333333333333333333333333333");
  pos.pool_id = 1;
  pos.liquidity = 250;
  pos.created_at_height = 20;

  Core::AmmPool pool = makePool();
  pool.total_liquidity = 1000;

  Json j = encodeAmmPosition(pos, &pool, "clrty");
  EXPECT_EQ(j["id"], "0x5");
  EXPECT_EQ(j["liquidity"], "0xfa"); // 250
  EXPECT_EQ(j["pool_id"], "0x1");
  // 250 / 1000 = 25% = 2500 bps
  EXPECT_EQ(j["share_bps"], 2500);
}

TEST(RPC_AmmEncoder, PositionWithoutPoolOmitsShare)
{
  Core::AmmPosition pos;
  pos.id = 5;
  pos.owner = Crypto::addrFromHex(
      "3333333333333333333333333333333333333333333333333333333333333333");
  pos.pool_id = 1;
  pos.liquidity = 250;

  Json j = encodeAmmPosition(pos, nullptr, "clrty");
  EXPECT_FALSE(j.contains("share_bps"));
}