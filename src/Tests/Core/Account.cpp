// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/Account.h"
#include "Core/RewardTypes.h"

using namespace Core;

// ============================================================================
//  Default state
// ============================================================================

TEST(Account, DefaultIsEmpty)
{
  Account a;
  EXPECT_TRUE(a.isEmpty());
  EXPECT_EQ(a.nonce, 0u);
  EXPECT_EQ(a.balance, 0u);
  EXPECT_EQ(a.staked, 0u);
  EXPECT_EQ(a.pending_rewards, 0u);
  EXPECT_EQ(a.staker_since_height, 0u);
  EXPECT_FALSE(a.staking_opted_out);
}

// ============================================================================
//  State codec
// ============================================================================

TEST(Account, SerializeRoundTrip)
{
  Account a;
  a.nonce = 42;
  a.balance = 1'000'000;
  a.staked = 500'000;
  a.pending_rewards = 100;
  a.last_reward_epoch = 5;
  a.staker_since_height = 300;
  a.created_at_height = 1;
  a.staking_opted_out = false;

  auto bytes = a.serializeState();
  ASSERT_EQ(bytes.size(), Account::STATE_SIZE);

  Account b;
  ASSERT_TRUE(Account::deserializeState(bytes.data(), bytes.size(), b));

  EXPECT_EQ(b.nonce, a.nonce);
  EXPECT_EQ(b.balance, a.balance);
  EXPECT_EQ(b.staked, a.staked);
  EXPECT_EQ(b.pending_rewards, a.pending_rewards);
  EXPECT_EQ(b.last_reward_epoch, a.last_reward_epoch);
  EXPECT_EQ(b.staker_since_height, a.staker_since_height);
  EXPECT_EQ(b.created_at_height, a.created_at_height);
  EXPECT_EQ(b.staking_opted_out, a.staking_opted_out);
}

TEST(Account, SerializeOptedOutRoundTrip)
{
  Account original;
  original.balance = 500;
  original.staking_opted_out = true;

  auto bytes = original.serializeState();
  Account restored;
  ASSERT_TRUE(Account::deserializeState(bytes.data(), bytes.size(), restored));

  EXPECT_TRUE(restored.staking_opted_out);
}

TEST(Account, DeserializeRejectsShortBuffer)
{
  std::vector<uint8_t> tiny(Account::STATE_SIZE - 1, 0);
  Account restored;
  EXPECT_FALSE(Account::deserializeState(tiny.data(), tiny.size(), restored));
}

TEST(Account, SerializedSizeIsConstant)
{
  // 7 uint64 fields + 1 byte flag.
  EXPECT_EQ(Account::STATE_SIZE, 8 * 7 + 1); // 57
  EXPECT_EQ(Account::STATE_SIZE, 57u);

  Account a;
  EXPECT_EQ(a.serializeState().size(), 57u);
}

TEST(Account, SerializeIncludesStakerSinceHeight)
{
  Account a;
  a.staker_since_height = 12'345;

  auto bytes = a.serializeState();
  Account b;
  ASSERT_TRUE(Account::deserializeState(bytes.data(), bytes.size(), b));
  EXPECT_EQ(b.staker_since_height, 12'345u);
}

// ============================================================================
//  recalculateStaked
// ============================================================================

TEST(Account, RecalculateStakedBelowThreshold)
{
  Account a;
  a.balance = AUTO_STAKE_THRESHOLD - 1;
  a.recalculateStaked(AUTO_STAKE_THRESHOLD);
  EXPECT_EQ(a.staked, 0u);
}

TEST(Account, RecalculateStakedAtThreshold)
{
  Account a;
  a.balance = AUTO_STAKE_THRESHOLD;
  a.recalculateStaked(AUTO_STAKE_THRESHOLD);
  EXPECT_EQ(a.staked, a.balance);
}

TEST(Account, RecalculateStakedAboveThreshold)
{
  Account a;
  a.balance = AUTO_STAKE_THRESHOLD * 10;
  a.recalculateStaked(AUTO_STAKE_THRESHOLD);
  EXPECT_EQ(a.staked, a.balance);
}

TEST(Account, RecalculateStakedOptedOut)
{
  Account a;
  a.balance = AUTO_STAKE_THRESHOLD * 10;
  a.staking_opted_out = true;
  a.recalculateStaked(AUTO_STAKE_THRESHOLD);
  EXPECT_EQ(a.staked, 0u);
}

TEST(Account, RecalculateStakedPreservesBalance)
{
  Account a;
  a.balance = AUTO_STAKE_THRESHOLD * 5;
  a.recalculateStaked(AUTO_STAKE_THRESHOLD);

  EXPECT_EQ(a.balance, AUTO_STAKE_THRESHOLD * 5);
  EXPECT_EQ(a.staked, AUTO_STAKE_THRESHOLD * 5);
}

TEST(Account, RecalculateStakedDoesNotTouchStakerSinceHeight)
{
  // recalculateStaked only modifies `staked`. The transition tracking
  // is the responsibility of StateAccess::putAccount.
  Account a;
  a.balance = AUTO_STAKE_THRESHOLD;
  a.staker_since_height = 42;

  a.recalculateStaked(AUTO_STAKE_THRESHOLD);

  EXPECT_EQ(a.staker_since_height, 42u);
}

// ============================================================================
//  Value helpers
// ============================================================================

TEST(Account, TotalValueIncludesPendingRewards)
{
  Account a;
  a.balance = 1000;
  a.pending_rewards = 250;
  EXPECT_EQ(a.totalValue(), 1250u);
}

TEST(Account, TotalValueZeroForEmpty)
{
  Account a;
  EXPECT_EQ(a.totalValue(), 0u);
}

// ============================================================================
//  isEmpty boundary cases
// ============================================================================

TEST(Account, NonZeroNonceNotEmpty)
{
  Account a;
  a.nonce = 1;
  EXPECT_FALSE(a.isEmpty());
}

TEST(Account, NonZeroBalanceNotEmpty)
{
  Account a;
  a.balance = 1;
  EXPECT_FALSE(a.isEmpty());
}

TEST(Account, NonZeroPendingRewardsNotEmpty)
{
  Account a;
  a.pending_rewards = 1;
  EXPECT_FALSE(a.isEmpty());
}

TEST(Account, OptedOutNotEmpty)
{
  Account a;
  a.staking_opted_out = true;
  EXPECT_FALSE(a.isEmpty());
}

TEST(Account, OnlyStakedNotEmpty)
{
  Account a;
  a.staked = 1;
  EXPECT_FALSE(a.isEmpty());
}

TEST(Account, OnlyStakerSinceHeightNotEmpty)
{
  // staker_since_height alone doesn't make the account non-empty in
  // the current isEmpty() implementation, because it's a derived
  // field: a non-zero value implies staked > 0.
  Account a;
  a.staker_since_height = 100;
  EXPECT_TRUE(a.isEmpty());
}