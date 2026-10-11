// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <limits>

#include "Core/ActiveRouter.h"
#include "Core/OrderBook.h"

using namespace Core;
using namespace Core::ActiveRouter;

namespace
{
  constexpr uint64_t S = OrderBook::BOOK_PRICE_SCALE; // 10^10

  //  Convenience: the canonical limit for a price given as an
  //  integer ratio. `priceAsScaled(num, den)` is the limit that
  //  says "at least num/den quote per base."
  constexpr uint64_t priceAsScaled(uint64_t num, uint64_t den)
  {
    return static_cast<uint64_t>(
        static_cast<unsigned __int128>(num) * S / den);
  }
}

// =================================================================
//  computeOutput
// =================================================================

TEST(ActiveRouterComputeOutput, MatchesHandComputedAnchor)
{
  //  reserve_in = 1000, reserve_out = 1000, fee = 30 bps, in = 10.
  //  in_with_fee = 10 * 9970 / 10000 = 9
  //  out = 1000 * 9 / (1000 + 9) = 8 (floored)
  //
  //  This is the same anchor used by the AMM SwapXForY test. If
  //  the two ever disagree, one of them is wrong and the tests
  //  catch it before the divergence reaches consensus.
  ASSERT_EQ(computeOutput(1000, 1000, 30, 10), 8u);
}

TEST(ActiveRouterComputeOutput, ZeroOnEmptyReserveIn)
{
  ASSERT_EQ(computeOutput(0, 1000, 30, 10), 0u);
}

TEST(ActiveRouterComputeOutput, ZeroOnEmptyReserveOut)
{
  ASSERT_EQ(computeOutput(1000, 0, 30, 10), 0u);
}

TEST(ActiveRouterComputeOutput, ZeroOnZeroInput)
{
  ASSERT_EQ(computeOutput(1000, 1000, 30, 0), 0u);
}

TEST(ActiveRouterComputeOutput, FloorsNotCeils)
{
  //  Construct an input where the exact output has a fractional
  //  part, and assert the floor is what comes back. reserve_in = 3,
  //  reserve_out = 3, fee = 0, in = 1:
  //    in_with_fee = 1
  //    out = 3 * 1 / (3 + 1) = 0 (floor of 0.75)
  ASSERT_EQ(computeOutput(3, 3, 0, 1), 0u);
}

TEST(ActiveRouterComputeOutput, FeeReducesOutput)
{
  //  With a fee, the output is strictly less than without.
  const uint64_t no_fee = computeOutput(1000, 1000, 0, 100);
  const uint64_t with_fee = computeOutput(1000, 1000, 30, 100);
  ASSERT_LT(with_fee, no_fee);
}

// =================================================================
//  computeEffectivePrice
// =================================================================

TEST(ActiveRouterComputeEffectivePrice, ZeroOnZeroInput)
{
  ASSERT_EQ(computeEffectivePrice(1000, 1000, 30, 0), 0u);
}

TEST(ActiveRouterComputeEffectivePrice, ZeroOnZeroOutput)
{
  //  An input too small to produce any output has an undefined
  //  effective price. The implementation reports it as 0.
  ASSERT_EQ(computeEffectivePrice(3, 3, 0, 1), 0u);
}

TEST(ActiveRouterComputeEffectivePrice, EqualsOutputOverInputScaled)
{
  const uint64_t in = 10;
  const uint64_t out = computeOutput(1000, 1000, 30, in);
  const uint64_t expected = static_cast<uint64_t>(
      static_cast<unsigned __int128>(out) * S / in);
  ASSERT_EQ(computeEffectivePrice(1000, 1000, 30, in), expected);
}

TEST(ActiveRouterComputeEffectivePrice, DecreasesWithInput)
{
  //  Constant-product pools have monotonically decreasing
  //  effective price. Two inputs, larger one has lower price.
  const uint64_t p_small = computeEffectivePrice(1000, 1000, 30, 10);
  const uint64_t p_large = computeEffectivePrice(1000, 1000, 30, 100);
  ASSERT_GT(p_small, p_large);
}

// =================================================================
//  maxInputWithinLimit
// =================================================================

TEST(ActiveRouterMaxInput, NulloptOnZeroReserveIn)
{
  ASSERT_FALSE(maxInputWithinLimit(0, 1000, 30, priceAsScaled(1, 1)).has_value());
}

TEST(ActiveRouterMaxInput, NulloptOnZeroReserveOut)
{
  ASSERT_FALSE(maxInputWithinLimit(1000, 0, 30, priceAsScaled(1, 1)).has_value());
}

TEST(ActiveRouterMaxInput, NulloptOnInvalidFee)
{
  ASSERT_FALSE(maxInputWithinLimit(1000, 1000, 10'000, priceAsScaled(1, 1)).has_value());
  ASSERT_FALSE(maxInputWithinLimit(1000, 1000, 20'000, priceAsScaled(1, 1)).has_value());
}

TEST(ActiveRouterMaxInput, NulloptOnZeroLimit)
{
  ASSERT_FALSE(maxInputWithinLimit(1000, 1000, 30, 0).has_value());
}

TEST(ActiveRouterMaxInput, NulloptWhenSpotBeyondLimit)
{
  //  Pool spot: 1000/1000 = 1.0. Order wants >= 2.0. No input
  //  can raise the pool's price; constant-product output price
  //  is monotone decreasing in input. So nullopt.
  ASSERT_FALSE(
      maxInputWithinLimit(1000, 1000, 30, priceAsScaled(2, 1)).has_value());
}

TEST(ActiveRouterMaxInput, NulloptAtExactSpotPrice)
{
  //  Pool spot: 1.0. Order wants >= 1.0. The first infinitesimal
  //  input already prices below 1.0 because of the fee. With a
  //  fee, any positive input produces price < 1.0. So nullopt.
  //
  //  With no fee, the boundary is degenerate: y_net == 0 gives
  //  price == 1.0 exactly, but y_net must be > 0 to be a swap.
  //  The implementation's y_net <= reserve_in guard turns this
  //  into nullopt. Assert it, and document the choice.
  ASSERT_FALSE(
      maxInputWithinLimit(1000, 1000, 30, priceAsScaled(1, 1)).has_value());
}

TEST(ActiveRouterMaxInput, PositiveWhenPoolFavorable)
{
  //  Pool spot: 2.0. Order wants >= 1.0. Comfortably favorable.
  auto max_in = maxInputWithinLimit(1000, 2000, 30, priceAsScaled(1, 1));
  ASSERT_TRUE(max_in.has_value());
  ASSERT_GT(*max_in, 0u);
}

TEST(ActiveRouterMaxInput, ReturnedInputSatisfiesLimit)
{
  //  Pool spot: 2.0, order wants >= 1.0. The returned max input,
  //  when executed, must produce an effective price >= 1.0.
  const uint64_t limit = priceAsScaled(1, 1);
  auto max_in = maxInputWithinLimit(1000, 2000, 30, limit);
  ASSERT_TRUE(max_in.has_value());

  const uint64_t price = computeEffectivePrice(1000, 2000, 30, *max_in);
  ASSERT_GE(price, limit)
      << "maxInputWithinLimit returned " << *max_in
      << " which prices at " << price
      << " (limit " << limit << ")";
}

TEST(ActiveRouterMaxInput, ReturnedInputPlusOneViolatesLimit)
{
  //  The two-sided pin. If max_in is the *maximum* input satisfying
  //  the limit, then max_in + 1 must violate it — unless +1
  //  exceeds the pool's remaining outflow capacity, in which case
  //  the assertion doesn't apply.
  //
  //  With reserves (1000, 2000), the pool can never output more
  //  than 2000, so the input cap is effectively bounded by
  //  whatever produces that. Pick a limit well inside the pool so
  //  max_in is comfortably less than reserve_out.
  const uint64_t limit = priceAsScaled(1, 1);
  auto max_in = maxInputWithinLimit(1000, 2000, 30, limit);
  ASSERT_TRUE(max_in.has_value());

  //  Sanity: with a limit of 1.0 and a spot of 2.0, the max
  //  input is roughly (reserve_out / limit - reserve_in) scaled,
  //  which is ~1000. Confirm it's not absurdly large.
  ASSERT_LT(*max_in, 100'000u)
      << "max_in " << *max_in << " is suspiciously large";

  const uint64_t price_plus_one =
      computeEffectivePrice(1000, 2000, 30, *max_in + 1);
  ASSERT_LT(price_plus_one, limit)
      << "max_in + 1 still satisfies the limit; max_in is not the "
         "maximum";
}

TEST(ActiveRouterMaxInput, HigherLimitYieldsSmallerMaxInput)
{
  //  Two limits on the same pool: 1.0 and 1.5. The 1.5 limit is
  //  more restrictive, so max input should be smaller.
  const uint64_t limit_lo = priceAsScaled(1, 1);
  const uint64_t limit_hi = priceAsScaled(3, 2); // 1.5

  auto max_lo = maxInputWithinLimit(1000, 2000, 30, limit_lo);
  auto max_hi = maxInputWithinLimit(1000, 2000, 30, limit_hi);

  ASSERT_TRUE(max_lo.has_value());
  ASSERT_TRUE(max_hi.has_value());
  ASSERT_LT(*max_hi, *max_lo);
}

TEST(ActiveRouterMaxInput, FeeReducesMaxInput)
{
  //  Higher fee means the same input yields less output, so the
  //  input that stays within the limit is smaller.
  const uint64_t limit = priceAsScaled(1, 1);

  auto max_no_fee = maxInputWithinLimit(1000, 2000, 0, limit);
  auto max_with_fee = maxInputWithinLimit(1000, 2000, 300, limit);

  ASSERT_TRUE(max_no_fee.has_value());
  ASSERT_TRUE(max_with_fee.has_value());
  ASSERT_LT(*max_with_fee, *max_no_fee);
}

TEST(ActiveRouterMaxInput, NulloptAtOverflowingReserves)
{
  //  A pool with reserves near UINT64_MAX and a limit near 1.0.
  //  The u128 intermediates should hold. If the narrowing would
  //  overflow, the function returns nullopt rather than truncate.
  //
  //  We only assert "does not crash and does not return a value
  //  that is obviously wrong." The specific result depends on the
  //  arithmetic; the property we care about is that it doesn't
  //  wrap.
  const uint64_t big = std::numeric_limits<uint64_t>::max() / 2;
  auto result = maxInputWithinLimit(big, big, 30, priceAsScaled(1, 1));
  //  Spot is 1.0, limit is 1.0, fee is 30 bps: any input prices
  //  below 1.0, so no input satisfies the limit.
  ASSERT_FALSE(result.has_value());
}

TEST(ActiveRouterMaxInput, Deterministic)
{
  //  Same inputs, same output, every time. This is the property
  //  the consensus layer depends on.
  const uint64_t limit = priceAsScaled(1, 1);
  const uint64_t a = *maxInputWithinLimit(1000, 2000, 30, limit);
  const uint64_t b = *maxInputWithinLimit(1000, 2000, 30, limit);
  ASSERT_EQ(a, b);
}

// =================================================================
//  Cross-checks against computeOutput
// =================================================================

TEST(ActiveRouterCrossCheck, MaxInputProducesPositiveOutput)
{
  //  Any max input the function returns must actually produce a
  //  positive output when executed. A max input that yields zero
  //  output is not a fill, it's a burn.
  const uint64_t limit = priceAsScaled(1, 1);
  auto max_in = maxInputWithinLimit(1000, 2000, 30, limit);
  ASSERT_TRUE(max_in.has_value());

  const uint64_t out = computeOutput(1000, 2000, 30, *max_in);
  ASSERT_GT(out, 0u);
}

TEST(ActiveRouterCrossCheck, MaxInputLeavesPoolSolvent)
{
  //  The output must not drain the pool. reserve_out must remain
  //  >= 0 after the swap.
  const uint64_t reserve_in = 1000;
  const uint64_t reserve_out = 2000;
  const uint64_t limit = priceAsScaled(1, 1);

  auto max_in = maxInputWithinLimit(reserve_in, reserve_out, 30, limit);
  ASSERT_TRUE(max_in.has_value());

  const uint64_t out = computeOutput(reserve_in, reserve_out, 30, *max_in);
  ASSERT_LT(out, reserve_out);
}