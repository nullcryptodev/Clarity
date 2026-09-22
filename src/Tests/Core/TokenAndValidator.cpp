// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Core/TokenTypes.h"
#include "Core/ValidatorTypes.h"
#include "Core/RewardTypes.h"

using namespace Core;
using namespace Tests;

TEST(TokenInfo, DefaultIsNativePlaceholder)
{
  TokenInfo t;
  EXPECT_TRUE(t.isNative());
  EXPECT_FALSE(t.isBridged());
}

TEST(TokenInfo, ValidToken)
{
  EXPECT_TRUE(makeToken().isValid());
}

TEST(TokenInfo, RejectsShortSymbol)
{
  TokenInfo t = makeToken();
  t.symbol = "AB";
  EXPECT_FALSE(t.isValid());
}

TEST(TokenInfo, RejectsLongSymbol)
{
  TokenInfo t = makeToken();
  t.symbol = "ABCDEFGHI";
  EXPECT_FALSE(t.isValid());
}

TEST(TokenInfo, RejectsEmptyName)
{
  TokenInfo t = makeToken();
  t.name = "";
  EXPECT_FALSE(t.isValid());
}

TEST(TokenInfo, RejectsOverlongName)
{
  TokenInfo t = makeToken();
  t.name.assign(TOKEN_NAME_MAX + 1, 'x');
  EXPECT_FALSE(t.isValid());
}

TEST(TokenInfo, RejectsTooManyDecimals)
{
  TokenInfo t = makeToken();
  t.decimals = 19;
  EXPECT_FALSE(t.isValid());
}

TEST(TokenInfo, RejectsExcessiveRoyalty)
{
  TokenInfo t = makeToken();
  t.royaltyBps = 10'001;
  EXPECT_FALSE(t.isValid());
}

TEST(TokenInfo, StateRoundTrip)
{
  TokenInfo original = makeToken();

  auto bytes = original.serializeState();
  TokenInfo restored;
  ASSERT_TRUE(TokenInfo::deserializeState(bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.id, original.id);
  EXPECT_EQ(restored.name, original.name);
  EXPECT_EQ(restored.symbol, original.symbol);
  EXPECT_EQ(restored.decimals, original.decimals);
  EXPECT_EQ(restored.creator.toString(), original.creator.toString());
  EXPECT_EQ(restored.backing, original.backing);
  EXPECT_EQ(restored.maxSupply, original.maxSupply);
  EXPECT_EQ(restored.royaltyBps, original.royaltyBps);
  EXPECT_FALSE(restored.fingerprint.has_value());
}

TEST(TokenInfo, StateRoundTripWithFingerprint)
{
  TokenInfo original = makeToken();
  Crypto::Hash fp;
  for (size_t i = 0; i < 32; ++i)
    fp.data[i] = static_cast<uint8_t>(0x40 + i);
  original.fingerprint = fp;

  auto bytes = original.serializeState();
  TokenInfo restored;
  ASSERT_TRUE(TokenInfo::deserializeState(bytes.data(), bytes.size(), restored));

  ASSERT_TRUE(restored.fingerprint.has_value());
  EXPECT_EQ(restored.fingerprint->toString(), fp.toString());
  EXPECT_TRUE(restored.isBridged());
}

TEST(TokenInfo, StateDeterministic)
{
  TokenInfo t = makeToken();
  EXPECT_EQ(t.serializeState(), t.serializeState());
}

TEST(TokenInfo, DeserializeRejectsTruncated)
{
  TokenInfo t = makeToken();
  auto bytes = t.serializeState();

  TokenInfo restored;
  EXPECT_FALSE(TokenInfo::deserializeState(bytes.data(), bytes.size() / 2, restored));
}

// ============================================================================
//  ValidatorInfo
// ============================================================================

namespace
{
  ValidatorInfo makeValidator()
  {
    ValidatorInfo v;
    v.id = 7;
    v.reward_address = Crypto::Address{};
    for (int i = 0; i < 32; ++i)
      v.reward_address.data[i] = static_cast<uint8_t>(i);
    v.node_key = Crypto::PublicKey{};
    for (int i = 0; i < 32; ++i)
      v.node_key.data[i] = static_cast<uint8_t>(0x80 + i);
    v.owner = v.reward_address;
    v.registered_at_height = 100;
    v.stake = VALIDATOR_MIN_STAKE;
    v.uptime_score = 9'800;
    v.last_ping_height = 150;
    v.pings_responded_this_epoch = 55;
    v.pings_sent_this_epoch = 60;
    v.last_seen_height = 200;
    v.reward_multiplier = REWARD_MULTIPLIER_START;
    v.infraction_count = 0;
    v.last_infraction_height = 0;
    v.total_blocks_produced = 42;
    v.total_rewards_earned = 5000;
    v.epochs_active = 7;
    v.is_seed = false;
    v.is_active = true;
    v.became_active_at = 100;
    v.last_active_at = 200;
    return v;
  }
}

TEST(ValidatorInfo, DefaultIsInvalid)
{
  ValidatorInfo v;
  EXPECT_EQ(v.id, INVALID_ID);
  EXPECT_EQ(v.reward_multiplier, REWARD_MULTIPLIER_START);
  EXPECT_EQ(v.infraction_count, 0);
}

TEST(ValidatorInfo, MeetsStakeRequirement)
{
  ValidatorInfo v = makeValidator();
  EXPECT_TRUE(v.meetsStakeRequirement());

  v.stake = VALIDATOR_MIN_STAKE - 1;
  EXPECT_FALSE(v.meetsStakeRequirement());
}

TEST(ValidatorInfo, IsHealthy)
{
  ValidatorInfo v = makeValidator();
  v.uptime_score = UPTIME_REMOVAL_THRESHOLD_BPS;
  EXPECT_TRUE(v.isHealthy());

  v.uptime_score = UPTIME_REMOVAL_THRESHOLD_BPS - 1;
  EXPECT_FALSE(v.isHealthy());
}

TEST(ValidatorInfo, CanBeActive)
{
  ValidatorInfo v = makeValidator();
  v.uptime_score = UPTIME_ACTIVE_MIN_BPS;
  EXPECT_TRUE(v.canBeActive());

  v.uptime_score = UPTIME_ACTIVE_MIN_BPS - 1;
  EXPECT_FALSE(v.canBeActive());
}

TEST(ValidatorInfo, IsOfflineUnderThreshold)
{
  ValidatorInfo v = makeValidator();
  v.last_seen_height = 1000;
  EXPECT_FALSE(v.isOffline(1000 + OFFLINE_KICK_BLOCKS - 1));
}

TEST(ValidatorInfo, IsOfflineAtThreshold)
{
  ValidatorInfo v = makeValidator();
  v.last_seen_height = 1000;
  EXPECT_TRUE(v.isOffline(1000 + OFFLINE_KICK_BLOCKS));
}

TEST(ValidatorInfo, IsOfflineRejectsFuture)
{
  ValidatorInfo v = makeValidator();
  v.last_seen_height = 2000;
  // Current height is before last_seen — can't be offline.
  EXPECT_FALSE(v.isOffline(1500));
}

TEST(ValidatorInfo, StateRoundTrip)
{
  ValidatorInfo original = makeValidator();

  auto bytes = original.serializeState();
  ASSERT_EQ(bytes.size(), ValidatorInfo::STATE_SIZE);

  ValidatorInfo restored;
  ASSERT_TRUE(ValidatorInfo::deserializeState(bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.id, original.id);
  EXPECT_EQ(restored.reward_address.toString(), original.reward_address.toString());
  EXPECT_EQ(restored.node_key.toString(), original.node_key.toString());
  EXPECT_EQ(restored.owner.toString(), original.owner.toString());
  EXPECT_EQ(restored.registered_at_height, original.registered_at_height);
  EXPECT_EQ(restored.stake, original.stake);
  EXPECT_EQ(restored.uptime_score, original.uptime_score);
  EXPECT_EQ(restored.last_ping_height, original.last_ping_height);
  EXPECT_EQ(restored.pings_responded_this_epoch, original.pings_responded_this_epoch);
  EXPECT_EQ(restored.pings_sent_this_epoch, original.pings_sent_this_epoch);
  EXPECT_EQ(restored.last_seen_height, original.last_seen_height);
  EXPECT_EQ(restored.reward_multiplier, original.reward_multiplier);
  EXPECT_EQ(restored.infraction_count, original.infraction_count);
  EXPECT_EQ(restored.last_infraction_height, original.last_infraction_height);
  EXPECT_EQ(restored.total_blocks_produced, original.total_blocks_produced);
  EXPECT_EQ(restored.total_rewards_earned, original.total_rewards_earned);
  EXPECT_EQ(restored.epochs_active, original.epochs_active);
  EXPECT_EQ(restored.is_seed, original.is_seed);
  EXPECT_EQ(restored.is_active, original.is_active);
  EXPECT_EQ(restored.became_active_at, original.became_active_at);
  EXPECT_EQ(restored.last_active_at, original.last_active_at);
}

TEST(ValidatorInfo, StateRoundTripPreservesFlags)
{
  ValidatorInfo original = makeValidator();
  original.is_seed = true;
  original.is_active = false;

  auto bytes = original.serializeState();
  ValidatorInfo restored;
  ASSERT_TRUE(ValidatorInfo::deserializeState(bytes.data(), bytes.size(), restored));

  EXPECT_TRUE(restored.is_seed);
  EXPECT_FALSE(restored.is_active);
}

TEST(ValidatorInfo, StateDeterministic)
{
  ValidatorInfo v = makeValidator();
  EXPECT_EQ(v.serializeState(), v.serializeState());
}

TEST(ValidatorInfo, DeserializeRejectsShortBuffer)
{
  ValidatorInfo v = makeValidator();
  auto bytes = v.serializeState();

  ValidatorInfo restored;
  EXPECT_FALSE(ValidatorInfo::deserializeState(
      bytes.data(), bytes.size() - 1, restored));
}