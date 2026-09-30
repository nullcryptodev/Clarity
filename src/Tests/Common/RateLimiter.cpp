// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/RateLimiter.h"

#include <chrono>
#include <thread>

using namespace Common;

namespace
{
  // Refill test helper. Sleeps roughly `ms` milliseconds. On a loaded
  // CI box a sleep can overshoot; the tests below account for that by
  // asserting on lower bounds rather than exact values.
  void sleepMs(int ms)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
  }
} // anonymous namespace

// ============================================================================
//  Disabled bucket
// ============================================================================

TEST(Common_RateLimiter, ZeroBurstIsDisabled)
{
  RateLimiter rl(0, 100);
  EXPECT_FALSE(rl.enabled());
  EXPECT_TRUE(rl.tryConsume());
  EXPECT_TRUE(rl.tryConsume(1'000'000));
}

TEST(Common_RateLimiter, ZeroRefillIsDisabled)
{
  RateLimiter rl(100, 0);
  EXPECT_FALSE(rl.enabled());
  EXPECT_TRUE(rl.tryConsume());
  EXPECT_TRUE(rl.tryConsume(1'000'000));
}

TEST(Common_RateLimiter, BothZeroIsDisabled)
{
  RateLimiter rl(0, 0);
  EXPECT_FALSE(rl.enabled());
  EXPECT_TRUE(rl.tryConsume());
}

TEST(Common_RateLimiter, DefaultConstructorIsDisabled)
{
  RateLimiter rl;
  EXPECT_FALSE(rl.enabled());
  EXPECT_TRUE(rl.tryConsume());
}

TEST(Common_RateLimiter, DisabledAvailableIsBurst)
{
  // When disabled, available() returns burst() so callers can report
  // "capacity" without special-casing.
  RateLimiter rl(42, 0);
  EXPECT_FALSE(rl.enabled());
  EXPECT_EQ(rl.available(), 42u);
}

// ============================================================================
//  Accessors
// ============================================================================

TEST(Common_RateLimiter, AccessorsReflectConstructorArgs)
{
  RateLimiter rl(10, 5);
  EXPECT_TRUE(rl.enabled());
  EXPECT_EQ(rl.burst(), 10u);
  EXPECT_EQ(rl.refillPerSecond(), 5u);
}

TEST(Common_RateLimiter, StartsFull)
{
  // A freshly constructed bucket has `burst` tokens available. This is
  // the "capacity at idle" invariant — it matters for the first
  // connection / request after a quiet period.
  RateLimiter rl(10, 1);
  EXPECT_EQ(rl.available(), 10u);
}

// ============================================================================
//  Consumption — deterministic, no time dependence
// ============================================================================

TEST(Common_RateLimiter, ConsumeOneAtATime)
{
  RateLimiter rl(3, 1); // refill is slow enough not to interfere

  EXPECT_TRUE(rl.tryConsume());
  EXPECT_TRUE(rl.tryConsume());
  EXPECT_TRUE(rl.tryConsume());
  EXPECT_FALSE(rl.tryConsume());
}

TEST(Common_RateLimiter, ConsumeMultiTokenSuccess)
{
  RateLimiter rl(10, 1);

  EXPECT_TRUE(rl.tryConsume(4));
  EXPECT_TRUE(rl.tryConsume(6));
  // Bucket is now empty.
  EXPECT_FALSE(rl.tryConsume());
}

TEST(Common_RateLimiter, ConsumeMultiTokenInsufficientLeavesBucketUnchanged)
{
  // The whole point of the "atomic" tryConsume contract: a failed
  // multi-token consume must not partially deduct. Otherwise a caller
  // retrying the same request would slowly drain the bucket.
  RateLimiter rl(5, 1);

  EXPECT_TRUE(rl.tryConsume(3));
  // 2 tokens left. Asking for 3 must fail and leave 2 available.
  EXPECT_FALSE(rl.tryConsume(3));
  EXPECT_EQ(rl.available(), 2u);
}

TEST(Common_RateLimiter, ConsumeMoreThanBurst)
{
  RateLimiter rl(5, 1);
  EXPECT_FALSE(rl.tryConsume(6));
  EXPECT_EQ(rl.available(), 5u);
}

TEST(Common_RateLimiter, ConsumeExactlyBurst)
{
  RateLimiter rl(5, 1);
  EXPECT_TRUE(rl.tryConsume(5));
  EXPECT_EQ(rl.available(), 0u);
  EXPECT_FALSE(rl.tryConsume());
}

TEST(Common_RateLimiter, ConsumeZeroTokens)
{
  // tryConsume(0) is a no-op that succeeds even on an empty bucket.
  RateLimiter rl(1, 1);
  EXPECT_TRUE(rl.tryConsume(1));
  EXPECT_FALSE(rl.tryConsume(1));
  // Now empty. Consuming 0 must still succeed.
  EXPECT_TRUE(rl.tryConsume(0));
}

TEST(Common_RateLimiter, AvailableReflectsConsumption)
{
  RateLimiter rl(10, 1);

  EXPECT_EQ(rl.available(), 10u);
  rl.tryConsume(3);
  EXPECT_EQ(rl.available(), 7u);
  rl.tryConsume(7);
  EXPECT_EQ(rl.available(), 0u);
}

// ============================================================================
//  Refill — real time, generous margins
// ============================================================================

TEST(Common_RateLimiter, RefillOneTokenAfterOneSecond)
{
  // refillPerSecond = 100 → one token every 10 ms. Sleep 50 ms to
  // give plenty of headroom on a loaded box. We assert we got *at
  // least* one token back, not exactly 5, because scheduling
  // jitter can go either way.
  RateLimiter rl(10, 100);
  ASSERT_TRUE(rl.tryConsume(10)); // empty the bucket
  EXPECT_EQ(rl.available(), 0u);

  sleepMs(50);

  EXPECT_GE(rl.available(), 1u);
}

TEST(Common_RateLimiter, RefillDoesNotExceedBurst)
{
  // refillPerSecond = 1000 → one token per millisecond. Sleep 20 ms
  // → roughly 20 tokens of refill attempted, but the bucket must cap
  // at burst. A rate of 1M/sec would refill within a microsecond and
  // defeat the "starts empty" assertion below.
  RateLimiter rl(5, 1'000);
  ASSERT_TRUE(rl.tryConsume(5));
  EXPECT_EQ(rl.available(), 0u);

  sleepMs(20);

  EXPECT_LE(rl.available(), 5u);
  EXPECT_EQ(rl.available(), 5u); // should have refilled to cap
}

TEST(Common_RateLimiter, RefillIsProportionalToElapsed)
{
  // At 1000 tokens/sec, 100 ms should yield ~100 tokens. Assert on a
  // generous lower bound (>= 50) so a heavily loaded CI box doesn't
  // flake. The upper bound is implied by the cap, but assert it too
  // so a runaway refill() (e.g. a broken micro-unit conversion)
  // fails loudly.
  RateLimiter rl(10'000, 1'000);
  ASSERT_TRUE(rl.tryConsume(10'000));

  sleepMs(100);

  const uint32_t got = rl.available();
  EXPECT_GE(got, 50u) << "after 100ms at 1000/s, expected >= 50, got " << got;
  EXPECT_LE(got, 200u) << "after 100ms at 1000/s, expected <= 200, got " << got;
}

TEST(Common_RateLimiter, SubSecondRefillAccumulatesMicroTokens)
{
  // This test exercises the micro-token accumulator. refillPerSecond
  // = 1 means one token per second. Over several short sleeps we
  // should eventually accumulate a whole token rather than losing
  // fractional refill each time.
  RateLimiter rl(1, 1);
  ASSERT_TRUE(rl.tryConsume(1));
  EXPECT_EQ(rl.available(), 0u);

  // Four sleeps of 300 ms = 1.2 s total. Should be enough to earn
  // one full token. If microTokens_ weren't accumulated, each 300 ms
  // interval would be truncated to zero whole tokens and we'd still
  // be at 0.
  for (int i = 0; i < 4; ++i)
    sleepMs(300);

  EXPECT_GE(rl.available(), 1u);
}

// ============================================================================
//  Edge cases
// ============================================================================

TEST(Common_RateLimiter, LargeBurst)
{
  RateLimiter rl(1'000'000, 1);
  EXPECT_EQ(rl.available(), 1'000'000u);
  EXPECT_TRUE(rl.tryConsume(1'000'000));
  EXPECT_EQ(rl.available(), 0u);
}

TEST(Common_RateLimiter, RepeatedFailedConsumeDoesNotAccumulateState)
{
  // A caller that keeps asking for more than is available must not
  // corrupt the bucket in any way. This is the retry-loop case.
  RateLimiter rl(2, 1);
  rl.tryConsume(2); // empty

  for (int i = 0; i < 100; ++i)
    EXPECT_FALSE(rl.tryConsume(1));

  // Still empty, no error state, and a subsequent valid consume on
  // a refilled bucket works.
  EXPECT_EQ(rl.available(), 0u);
}

TEST(Common_RateLimiter, InterleavedConsumeAndAvailable)
{
  // available() must not have side effects that change the bucket
  // in a way that breaks subsequent consumes. Calling available()
  // repeatedly on an idle bucket should not drain it.
  RateLimiter rl(3, 1);

  EXPECT_EQ(rl.available(), 3u);
  EXPECT_EQ(rl.available(), 3u);
  EXPECT_EQ(rl.available(), 3u);

  EXPECT_TRUE(rl.tryConsume());
  EXPECT_EQ(rl.available(), 2u);
  EXPECT_EQ(rl.available(), 2u);
}

TEST(Common_RateLimiter, AvailableRefillsBeforeReporting)
{
  // available() calls refill() internally, so it should report a
  // post-refill count even if no tryConsume() happened in between.
  RateLimiter rl(10, 1'000'000); // effectively instant refill
  rl.tryConsume(10);

  // Give refill() a moment. Even without a sleep, the act of calling
  // available() reads the clock, and on most machines at least a
  // microsecond has passed since the consume.
  sleepMs(1);

  EXPECT_GT(rl.available(), 0u);
}