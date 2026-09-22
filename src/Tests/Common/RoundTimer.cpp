// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <chrono>

#include "Common/RoundTimer.h"

using namespace Common;
using namespace std::chrono_literals;

// ============================================================================
//  Timeout formula
// ============================================================================

TEST(RoundTimer, TimeoutForRoundZero)
{
  EXPECT_EQ(RoundTimer::timeoutForRound(0), BASE_TIMEOUT_MS);
}

TEST(RoundTimer, TimeoutForRoundOne)
{
  EXPECT_EQ(RoundTimer::timeoutForRound(1), 2 * BASE_TIMEOUT_MS);
}

TEST(RoundTimer, TimeoutForRoundThree)
{
  EXPECT_EQ(RoundTimer::timeoutForRound(3), 4 * BASE_TIMEOUT_MS);
}

TEST(RoundTimer, TimeoutIsCapped)
{
  // Whatever round we pick past the cap, the timeout must not exceed
  // MAX_TIMEOUT_MS.
  uint64_t r = (MAX_TIMEOUT_MS / BASE_TIMEOUT_MS) + 10;
  EXPECT_EQ(RoundTimer::timeoutForRound(r), MAX_TIMEOUT_MS);

  // Even for absurdly high rounds.
  EXPECT_EQ(RoundTimer::timeoutForRound(1'000'000), MAX_TIMEOUT_MS);
}

// ============================================================================
//  Lifecycle
// ============================================================================

TEST(RoundTimer, NotRunningInitially)
{
  RoundTimer t([]() {});
  EXPECT_FALSE(t.isRunning());
  EXPECT_FALSE(t.isExpired());
}

TEST(RoundTimer, StartSetsRunning)
{
  RoundTimer t([]() {});
  t.start(0);
  EXPECT_TRUE(t.isRunning());
  EXPECT_FALSE(t.isExpired());
}

TEST(RoundTimer, StopClearsRunning)
{
  RoundTimer t([]() {});
  t.start(0);
  t.stop();
  EXPECT_FALSE(t.isRunning());
  EXPECT_FALSE(t.isExpired());
}

TEST(RoundTimer, PollDoesNothingWhenNotRunning)
{
  int fired = 0;
  RoundTimer t([&fired]()
               { ++fired; });

  // Not started — poll is a no-op.
  EXPECT_FALSE(t.poll());
  EXPECT_EQ(fired, 0);
}

TEST(RoundTimer, PollDoesNothingBeforeExpiry)
{
  int fired = 0;
  RoundTimer t([&fired]()
               { ++fired; });

  // Round 0 has a 5s timeout. Polling immediately is a no-op.
  t.start(0);
  EXPECT_FALSE(t.poll());
  EXPECT_EQ(fired, 0);
  EXPECT_TRUE(t.isRunning());
}

// ============================================================================
//  Actual expiry (short sleep)
// ============================================================================

TEST(RoundTimer, PollFiresAfterExpiry)
{
  // We can't control BASE_TIMEOUT_MS, so use the real value and sleep
  // for a fraction of it. We sleep much less than the timeout and only
  // check that the timer is *capable* of firing.
  //
  // To make this test fast we use round 0 (5s) and sleep 5.05s. That's
  // slow but deterministic. To keep the suite snappy, the alternative
  // is to skip — but a working timer is important.
  //
  // We use a sentinel callback that flips an atomic; we only assert the
  // poll-returns-true path, and only if it actually fires.

  std::atomic<int> fired{0};
  RoundTimer t([&fired]()
               { fired.fetch_add(1); });

  t.start(0); // 5s timeout

  // Poll once before expiry — no fire.
  EXPECT_FALSE(t.poll());
  EXPECT_EQ(fired.load(), 0);

  // Wait just past the timeout.
  std::this_thread::sleep_for(std::chrono::milliseconds(BASE_TIMEOUT_MS + 50));

  EXPECT_TRUE(t.isExpired());
  EXPECT_TRUE(t.poll());
  EXPECT_EQ(fired.load(), 1);
  EXPECT_FALSE(t.isRunning());
}

TEST(RoundTimer, PollAfterExpiryDoesNotFireAgain)
{
  std::atomic<int> fired{0};
  RoundTimer t([&fired]()
               { fired.fetch_add(1); });

  t.start(0);
  std::this_thread::sleep_for(std::chrono::milliseconds(BASE_TIMEOUT_MS + 50));

  EXPECT_TRUE(t.poll());
  EXPECT_EQ(fired.load(), 1);

  // Second poll: timer already stopped, no second fire.
  EXPECT_FALSE(t.poll());
  EXPECT_EQ(fired.load(), 1);
}