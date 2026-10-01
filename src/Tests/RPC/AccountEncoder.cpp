// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Account.h"
#include "RPC/Encoders.h"

using Common::Json;
using Rpc::encodeAccount;

TEST(RPC_AccountEncoder, ZeroAccount)
{
  Core::Account a;
  Json j = encodeAccount(a);

  EXPECT_EQ(j["nonce"], "0x0");
  EXPECT_EQ(j["balance"], "0x0");
  EXPECT_EQ(j["staked"], "0x0");
  EXPECT_EQ(j["pending_rewards"], "0x0");
  EXPECT_EQ(j["last_reward_epoch"], "0x0");
  EXPECT_EQ(j["staker_since_height"], "0x0");
  EXPECT_EQ(j["created_at_height"], "0x0");
  EXPECT_EQ(j["staking_opted_out"], false);
  EXPECT_EQ(j["is_empty"], true);
  EXPECT_EQ(j["total_value"], "0x0");
}

TEST(RPC_AccountEncoder, PopulatedAccount)
{
  Core::Account a;
  a.nonce = 7;
  a.balance = 1'000'000;
  a.staked = 500'000;
  a.pending_rewards = 100;
  a.last_reward_epoch = 5;
  a.staker_since_height = 100;
  a.created_at_height = 50;
  a.staking_opted_out = false;

  Json j = encodeAccount(a);

  EXPECT_EQ(j["nonce"], "0x7");
  EXPECT_EQ(j["balance"], "0x" + std::string("f4240")); // 1_000_000
  EXPECT_EQ(j["staked"], "0x" + std::string("7a120"));  //   500_000
  EXPECT_EQ(j["pending_rewards"], "0x64");              //       100
  EXPECT_EQ(j["last_reward_epoch"], "0x5");
  EXPECT_EQ(j["staker_since_height"], "0x64");
  EXPECT_EQ(j["created_at_height"], "0x32");
  EXPECT_EQ(j["staking_opted_out"], false);
  EXPECT_EQ(j["is_empty"], false);
}

TEST(RPC_AccountEncoder, OptedOutAccount)
{
  Core::Account a;
  a.balance = 100;
  a.staking_opted_out = true;

  Json j = encodeAccount(a);
  EXPECT_EQ(j["staking_opted_out"], true);
  EXPECT_EQ(j["is_empty"], false); // has balance
}

TEST(RPC_AccountEncoder, TotalValueIncludesPendingRewards)
{
  Core::Account a;
  a.balance = 500;
  a.pending_rewards = 300;

  Json j = encodeAccount(a);
  EXPECT_EQ(j["total_value"], "0x320"); // 0x320 = 800
}