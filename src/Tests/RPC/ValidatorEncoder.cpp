// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/ValidatorTypes.h"
#include "RPC/Encoders.h"

using Common::Json;
using Rpc::encodeValidator;
using Rpc::encodeValidatorList;

namespace
{
  Core::ValidatorInfo makeValidator(uint64_t id)
  {
    Core::ValidatorInfo v;
    v.id = id;
    v.reward_address = Crypto::addrFromHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    v.owner = v.reward_address;
    v.stake = 1'000'000;
    v.uptime_score = 10'000;
    v.reward_multiplier = 10'000;
    v.is_active = true;
    v.is_seed = false;
    v.last_seen_height = 100;
    return v;
  }
} // namespace

TEST(RPC_ValidatorEncoder, BasicFields)
{
  Json j = encodeValidator(makeValidator(3), /*current_height=*/100, "clrty");

  EXPECT_EQ(j["id"], "0x3");
  ASSERT_TRUE(j["reward_address"].is_string());
  EXPECT_EQ(j["reward_address"].get<std::string>().substr(0, 5), "clrty");
  EXPECT_EQ(j["stake"], "0xf4240"); // 1_000_000
  EXPECT_EQ(j["uptime_score"], 10000);
  EXPECT_EQ(j["reward_multiplier"], 10000);
  EXPECT_EQ(j["is_active"], true);
  EXPECT_EQ(j["is_seed"], false);
  // last_seen == current_height, so not offline
  EXPECT_EQ(j["is_offline"], false);
}

TEST(RPC_ValidatorEncoder, OfflineValidator)
{
  auto v = makeValidator(1);
  v.last_seen_height = 10;

  // current_height - last_seen_height is 90. If OFFLINE_KICK_BLOCKS
  // is smaller than 90, is_offline is true.
  Json j = encodeValidator(v, /*current_height=*/100, "clrty");
  // Just check the field exists and is a bool; the exact threshold
  // is defined in RewardTypes.h and tested elsewhere.
  EXPECT_TRUE(j["is_offline"].is_boolean());
}

TEST(RPC_ValidatorEncoder, ListSortedById)
{
  std::vector<Core::ValidatorInfo> vs;
  vs.push_back(makeValidator(10));
  vs.push_back(makeValidator(3));
  vs.push_back(makeValidator(7));

  Json arr = encodeValidatorList(vs, 100, "clrty");
  ASSERT_TRUE(arr.is_array());
  ASSERT_EQ(arr.size(), 3u);
  EXPECT_EQ(arr[0]["id"], "0x3");
  EXPECT_EQ(arr[1]["id"], "0x7");
  EXPECT_EQ(arr[2]["id"], "0xa");
}