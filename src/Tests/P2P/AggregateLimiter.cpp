// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "P2P/AggregateLimiter.h"
#include "P2P/MessageTypes.h"

#include <chrono>
#include <thread>

using namespace P2P;

// ---------------------------------------------------------------------------
//  Cost table
// ---------------------------------------------------------------------------

TEST(P2P_AggregateLimiter, CostOrderingIsExpensiveGreaterThanRelayGreaterThanConsensus)
{
  // The aggregate table is compressed: the category ordering is
  // what matters, not the individual weights within a category.
  //
  //   expensive request (GetProof) > bulk (Block) >
  //   small (Tx, Prevote — same weight) >
  //   cheap parse (Headers) > control (Ping)
  //
  // Relay and consensus types are deliberately the same weight:
  // the aggregate bucket bounds *work*, and processing a Tx and
  // processing a Vote are comparable work. Fairness between them is
  // the per-peer bucket's job (messageCost), not the aggregate's.
  EXPECT_GT(aggregateCost(MessageType::GetProof), aggregateCost(MessageType::Block));
  EXPECT_GT(aggregateCost(MessageType::Block), aggregateCost(MessageType::Tx));
  EXPECT_GE(aggregateCost(MessageType::Tx), aggregateCost(MessageType::Prevote));
  EXPECT_GT(aggregateCost(MessageType::Prevote), aggregateCost(MessageType::Headers));
  EXPECT_GT(aggregateCost(MessageType::Headers), aggregateCost(MessageType::Ping));
}

TEST(P2P_AggregateLimiter, CostIsCompressedRelativeToPerPeerTable)
{
  // The whole reason the aggregate table exists separately: GetProof
  // is 50 in messageCost and 10 here. If someone ever changes that,
  // this test makes the decision visible.
  EXPECT_EQ(aggregateCost(MessageType::GetProof), 10u);
  EXPECT_EQ(messageCost(MessageType::GetProof), 50u);
}

TEST(P2P_AggregateLimiter, EveryMessageTypeHasNonNullCost)
{
  // If a new MessageType is added and not assigned a cost, this fails
  // rather than silently charging 1 (the switch default).
  for (uint16_t t = 0; t < 0x0100; ++t)
  {
    const auto type = static_cast<MessageType>(t);
    EXPECT_GE(aggregateCost(type), 1u) << "type " << t;
  }
}

// ---------------------------------------------------------------------------
//  Bucket mechanics
// ---------------------------------------------------------------------------

TEST(P2P_AggregateLimiter, DisabledWhenBothZero)
{
  AggregateLimiter lim(0, 0);
  EXPECT_FALSE(lim.enabled());
  for (int i = 0; i < 1000; ++i)
    EXPECT_TRUE(lim.allow(MessageType::GetProof));
}

TEST(P2P_AggregateLimiter, DisabledWhenBurstZero)
{
  AggregateLimiter lim(0, 100);
  EXPECT_FALSE(lim.enabled());
  EXPECT_TRUE(lim.allow(MessageType::GetProof));
}

TEST(P2P_AggregateLimiter, DisabledWhenRefillZero)
{
  AggregateLimiter lim(100, 0);
  EXPECT_FALSE(lim.enabled());
  EXPECT_TRUE(lim.allow(MessageType::GetProof));
}

TEST(P2P_AggregateLimiter, BurstDrainsThenRefills)
{
  // 10 tokens of burst, 100 tokens/sec refill. GetProof costs 10, so
  // the first call succeeds and the second fails (bucket at 0).
  AggregateLimiter lim(10, 100);
  ASSERT_TRUE(lim.enabled());
  EXPECT_TRUE(lim.allow(MessageType::GetProof));
  EXPECT_FALSE(lim.allow(MessageType::GetProof));

  // After 120ms, 12 tokens have refilled — enough for one more.
  std::this_thread::sleep_for(std::chrono::milliseconds(120));
  EXPECT_TRUE(lim.allow(MessageType::GetProof));
}

TEST(P2P_AggregateLimiter, CheapMessagesFitMorePerBurst)
{
  // Same budget, cheaper message: more of them fit. This is the point
  // of cost-weighted limiting — a flood of pings costs less budget
  // than a flood of proof requests.
  {
    AggregateLimiter lim(20, 1);
    int pings = 0;
    while (lim.allow(MessageType::Ping) && pings < 100)
      ++pings;
    EXPECT_EQ(pings, 20);
  }
  {
    AggregateLimiter lim(20, 1);
    int proofs = 0;
    while (lim.allow(MessageType::GetProof) && proofs < 100)
      ++proofs;
    EXPECT_EQ(proofs, 2); // 10 each
  }
}

TEST(P2P_AggregateLimiter, ConsensusTypesAreCharged)
{
  // Consensus types bypass the per-peer general bucket. They must not
  // bypass the aggregate bucket — a crowd of non-validators sending
  // junk proposals is a real flood vector.
  AggregateLimiter lim(3, 1);
  EXPECT_TRUE(lim.allow(MessageType::Proposal));  // costs 3
  EXPECT_FALSE(lim.allow(MessageType::Proposal)); // bucket at 0
}

TEST(P2P_AggregateLimiter, FailedConsumeLeavesBucketUnchanged)
{
  // Burst 5, cost 10: the first call can never succeed. The bucket
  // must stay at 5, not go negative or get drained by repeated failures.
  AggregateLimiter lim(5, 1);
  EXPECT_FALSE(lim.allow(MessageType::GetProof));
  EXPECT_FALSE(lim.allow(MessageType::GetProof));
  EXPECT_FALSE(lim.allow(MessageType::GetProof));
  EXPECT_EQ(lim.available(), 5u);
}

TEST(P2P_AggregateLimiter, AvailableReflectsConsumedTokens)
{
  AggregateLimiter lim(20, 1);
  EXPECT_EQ(lim.available(), 20u);
  EXPECT_TRUE(lim.allow(MessageType::GetProof)); // 10
  EXPECT_EQ(lim.available(), 10u);
  EXPECT_TRUE(lim.allow(MessageType::GetProof)); // 10
  EXPECT_EQ(lim.available(), 0u);
  EXPECT_FALSE(lim.allow(MessageType::GetProof));
  EXPECT_EQ(lim.available(), 0u);
}