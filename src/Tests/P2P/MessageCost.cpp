// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/RateLimiter.h"
#include "P2P/MessageTypes.h"

using namespace P2P;

// ============================================================================
//  Cost table
// ============================================================================

TEST(P2P_MessageCost, SyncRequestsAreExpensive)
{
  // The server does O(limit) work per GetHeaders/GetBlocks. These must
  // be the most expensive messages in the table.
  EXPECT_EQ(messageCost(MessageType::GetHeaders), 20u);
  EXPECT_EQ(messageCost(MessageType::GetBlocks), 20u);
}

TEST(P2P_MessageCost, BulkResponsesAreExpensive)
{
  // We pay for deserialization of each block.
  EXPECT_EQ(messageCost(MessageType::Blocks), 10u);
  EXPECT_EQ(messageCost(MessageType::Block), 10u);
}

TEST(P2P_MessageCost, TxIsModeratelyExpensive)
{
  // Signature verify + state view + re-broadcast to N peers.
  EXPECT_EQ(messageCost(MessageType::Tx), 5u);
}

TEST(P2P_MessageCost, ControlMessagesAreCheap)
{
  EXPECT_EQ(messageCost(MessageType::Version), 1u);
  EXPECT_EQ(messageCost(MessageType::Verack), 1u);
  EXPECT_EQ(messageCost(MessageType::Ping), 1u);
  EXPECT_EQ(messageCost(MessageType::Pong), 1u);
  EXPECT_EQ(messageCost(MessageType::GetPeers), 1u);
  EXPECT_EQ(messageCost(MessageType::Peers), 1u);
  EXPECT_EQ(messageCost(MessageType::Auth), 1u);
  EXPECT_EQ(messageCost(MessageType::AuthReady), 1u);
  EXPECT_EQ(messageCost(MessageType::Inv), 1u);
  EXPECT_EQ(messageCost(MessageType::GetData), 1u);
  EXPECT_EQ(messageCost(MessageType::Disconnect), 1u);
}

TEST(P2P_MessageCost, HeadersAreCheap)
{
  // Headers is a small response; parsing it is cheap.
  EXPECT_EQ(messageCost(MessageType::Headers), 1u);
}

TEST(P2P_MessageCost, ConsensusTypesHaveNominalCost)
{
  // Consensus types aren't charged to the general bucket — they use
  // the consensus bucket. But messageCost() must still return a
  // meaningful value if it's ever called on one. 1 is the minimum.
  EXPECT_EQ(messageCost(MessageType::Proposal), 1u);
  EXPECT_EQ(messageCost(MessageType::Prevote), 1u);
  EXPECT_EQ(messageCost(MessageType::Precommit), 1u);
}

// ============================================================================
//  Weighted bucket behavior
// ============================================================================

TEST(P2P_MessageCost, GetHeadersDrainsBucketInFiveMessages)
{
  // burst = 100, refill = 1/sec. Five GetHeaders at 20 each = 100
  // tokens = exactly the burst. The sixth needs another 20, but the
  // bucket has ~0 (refill is 1/sec and the loop takes microseconds).
  Common::RateLimiter bucket(100, 1);

  for (int i = 0; i < 5; ++i)
  {
    EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::GetHeaders)))
        << "message " << i << " should fit in the burst";
  }

  EXPECT_FALSE(bucket.tryConsume(messageCost(MessageType::GetHeaders)))
      << "the sixth GetHeaders should exhaust the bucket";
}

TEST(P2P_MessageCost, TxDrainsBucketInTwentyMessages)
{
  // burst = 100, refill = 1/sec. Twenty Txs at 5 each = 100 tokens.
  Common::RateLimiter bucket(100, 1);

  for (int i = 0; i < 20; ++i)
  {
    EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::Tx)))
        << "message " << i << " should fit in the burst";
  }

  EXPECT_FALSE(bucket.tryConsume(messageCost(MessageType::Tx)))
      << "the twenty-first Tx should exhaust the bucket";
}

TEST(P2P_MessageCost, PingStillAllowsManyMessages)
{
  // burst = 100, refill = 1/sec. Pings at 1 each = 100 messages.
  Common::RateLimiter bucket(100, 1);

  for (int i = 0; i < 100; ++i)
  {
    EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::Ping)))
        << "message " << i << " should fit in the burst";
  }

  EXPECT_FALSE(bucket.tryConsume(messageCost(MessageType::Ping)))
      << "the 101st Ping should exhaust the bucket";
}

TEST(P2P_MessageCost, MixedCostsSumCorrectly)
{
  // Interleaved messages: their costs sum.
  //   2 GetHeaders (40) + 2 Tx (10) + 5 Ping (5) + 2 Blocks (20) = 75.
  //   100 - 75 = 25 left. One more GetHeaders (20) fits; a second
  //   (20) would push us to 115, so it fails.
  Common::RateLimiter bucket(100, 1);

  EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::GetHeaders)));
  EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::GetHeaders)));
  EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::Tx)));
  EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::Tx)));
  for (int i = 0; i < 5; ++i)
    EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::Ping)));
  EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::Blocks)));
  EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::Blocks)));

  // 25 tokens left.
  EXPECT_TRUE(bucket.tryConsume(messageCost(MessageType::GetHeaders)));  // -20, 5 left
  EXPECT_FALSE(bucket.tryConsume(messageCost(MessageType::GetHeaders))); // -20 would go negative
}