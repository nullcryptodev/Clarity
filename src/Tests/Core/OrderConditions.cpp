// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <limits>

#include "Fixtures.h"
#include "Core/ActiveRouter.h"

using namespace Core;
using namespace Tests;

//  ============================================================================
//  Order condition evaluation tests
//  ============================================================================
//
//  These tests exercise BlockProcessor::evaluateOrderConditions, the
//  per-epoch pass that cancels orders whose conditions have failed
//  and routes Active orders whose conditions hold.
//
//  The tests are grouped by condition type:
//
//    - Price conditions (PriceAbove, PriceBelow)
//    - Volume conditions (VolumeBelow)
//    - Balance conditions (BalanceBelow)
//    - Expiry (ExpiresAtHeight) — for symmetry, though the expiry
//      path itself is exercised by processOrderExpiries, not by the
//      evaluator
//    - Unevaluable conditions (pool missing or empty)
//    - Cancellation behavior (refund, fee, index cleanup, idempotency)
//
//  Then a second group exercises Active-order routing:
//
//    - Route-at-epoch-boundary (conditions hold)
//    - Cancel-at-epoch-boundary (conditions fail)
//    - Partial fill and retry
//    - Pool moves against the order
//    - Pool deleted
//    - Epoch fills root commitment
//    - Route-on-creation through TransactionExecutor (no conditions)
//
//  IMPORTANT: the price-condition semantics are inverted from what the
//  names suggest. See the block comment above the PriceAbove tests.
//
//  One integration test goes through the full applyBlock path to
//  verify the epoch-boundary gating.

namespace
{
  //  Call the evaluator directly, using the fixture's bound write
  //  txn. Writes performed by the evaluator are visible to
  //  subsequent reads through the same StateAccess.
  //
  //  The evaluator produces fills for any Active order it routes.
  //  Fills are appended to `epoch_fills_out`.
  void evaluate(State::StateAccess &state,
                uint64_t height,
                std::vector<Core::Fill> &epoch_fills_out)
  {
    Core::BlockContext ctx;
    ctx.chain_id = EXEC_CHAIN_ID;
    ctx.current_height = height;
    Core::BlockProcessor::evaluateOrderConditions(state, ctx, epoch_fills_out);
  }

  //  Convenience overload for tests that don't care about the fills.
  void evaluate(State::StateAccess &state, uint64_t height)
  {
    std::vector<Core::Fill> discarded;
    evaluate(state, height, discarded);
  }

  //  A condition that always holds, for tests that need the order
  //  to be routed rather than cancelled. PriceAbove fails when
  //  price > param1, so param1 = UINT64_MAX can never be exceeded.
  Core::OrderCondition holdsAlways()
  {
    Core::OrderCondition c;
    c.type = Core::OrderConditionType::PriceAbove;
    c.param1 = std::numeric_limits<uint64_t>::max();
    c.param2 = 1;
    return c;
  }

  //  A condition that always fails, for tests that need the order
  //  to be cancelled. PriceAbove fails when price > param1, so
  //  param1 = 0 fails for any positive price.
  Core::OrderCondition failsAlways()
  {
    Core::OrderCondition c;
    c.type = Core::OrderConditionType::PriceAbove;
    c.param1 = 0;
    c.param2 = 1;
    return c;
  }

  //  Seed a pool with the given reserves in the fixture's state.
  //  Tokens are canonical: token_a < token_b.
  Core::AmmPool seedPool(State::StateAccess &state,
                         Id pool_id,
                         Id token_a,
                         Id token_b,
                         uint64_t reserve_a,
                         uint64_t reserve_b)
  {
    Core::AmmPool pool;
    pool.id = pool_id;
    pool.creator = Crypto::Address{};
    pool.token_a = token_a;
    pool.token_b = token_b;
    pool.reserve_a = reserve_a;
    pool.reserve_b = reserve_b;
    pool.total_liquidity = 1000;
    pool.fee_bps = Core::AMM_DEFAULT_FEE_BPS;
    pool.created_at_height = 1;
    pool.active = true;
    state.putAmmPool(pool);
    return pool;
  }

  //  Seed a Passive order with a given set of conditions.
  Core::Order seedOrder(State::StateAccess &state,
                        Id order_id,
                        const Crypto::Address &owner,
                        Id sell_token,
                        Id buy_token,
                        uint64_t sell_amount,
                        uint64_t order_expires_at_height,
                        const std::vector<Core::OrderCondition> &conds)
  {
    Core::Order o;
    o.id = order_id;
    o.owner = owner;
    o.mode = Core::OrderExecutionMode::Passive;
    o.sell_token = static_cast<uint32_t>(sell_token);
    o.buy_token = static_cast<uint32_t>(buy_token);
    o.sell_amount = sell_amount;
    o.min_buy_amount = 1;
    o.created_at_height = 1;
    o.order_expires_at_height = order_expires_at_height;
    o.filled_amount = 0;
    o.condition_count = static_cast<uint8_t>(conds.size());

    for (size_t i = 0; i < conds.size() && i < Core::ORDER_MAX_CONDITIONS; ++i)
    {
      o.conditions[i] = conds[i];
    }

    state.putOrder(o);

    if (order_expires_at_height != 0)
    {
      state.addOrderExpiry(order_expires_at_height, order_id);
    }

    return o;
  }

  //  Seed an Active order against a pool. The order's sell-token
  //  lock is NOT taken here; the caller does that separately when
  //  the test cares about balance conservation.
  Core::Order seedActiveOrder(State::StateAccess &state,
                              Id order_id,
                              const Crypto::Address &owner,
                              uint32_t pool_id,
                              Id sell_token,
                              Id buy_token,
                              uint64_t sell_amount,
                              uint64_t min_buy_amount,
                              uint64_t order_expires_at_height,
                              const std::vector<Core::OrderCondition> &conds)
  {
    Core::Order o;
    o.id = order_id;
    o.owner = owner;
    o.mode = Core::OrderExecutionMode::Active;
    o.pool_id = pool_id;
    o.sell_token = static_cast<uint32_t>(sell_token);
    o.buy_token = static_cast<uint32_t>(buy_token);
    o.sell_amount = sell_amount;
    o.min_buy_amount = min_buy_amount;
    o.created_at_height = 1;
    o.order_expires_at_height = order_expires_at_height;
    o.filled_amount = 0;
    o.condition_count = static_cast<uint8_t>(conds.size());

    for (size_t i = 0; i < conds.size() && i < Core::ORDER_MAX_CONDITIONS; ++i)
    {
      o.conditions[i] = conds[i];
    }

    state.putOrder(o);

    if (order_expires_at_height != 0)
    {
      state.addOrderExpiry(order_expires_at_height, order_id);
    }

    return o;
  }
} // anonymous namespace

// ============================================================================
//  PriceAbove
// ============================================================================
//
//  A PriceAbove condition is INVALID when the pool's spot price goes
//  ABOVE the threshold. So it holds while the price is below the
//  threshold and fails once the price rises past it.
//
//  This is inverted from what the name suggests. "PriceAbove 1.0"
//  means "cancel me if the price goes above 1.0", not "activate me
//  when the price is above 1.0". Tests that want a condition that
//  holds should use holdsAlways(); tests that want a condition that
//  fails should use failsAlways().

TEST_F(Core_ExecutorFixture, PriceAboveHoldsWhenPoolPriceIsLow)
{
  //  Pool: 1000 CLRTY vs 500 T42 → price = 500/1000 = 0.5 T42 per CLRTY
  //  Threshold: 1.0 (scaled) → price is below → condition holds.
  seedPool(*state_, /*pool_id=*/1, /*token_a=*/0, /*token_b=*/42,
           /*reserve_a=*/1000, /*reserve_b=*/500);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::PriceAbove;
  c.param1 = 1ULL * PRICE_SCALE; // 1.0
  c.param2 = 1;                  // pool_id

  seedOrder(*state_, /*order_id=*/1, alice_.publicKey,
            /*sell_token=*/0, /*buy_token=*/42,
            /*sell_amount=*/100, /*expires=*/0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got))
      << "order should not be cancelled while price is below threshold";
}

TEST_F(Core_ExecutorFixture, PriceAboveFailsWhenPoolPriceIsHigh)
{
  //  Pool: 1000 CLRTY vs 2000 T42 → price = 2000/1000 = 2.0 T42 per CLRTY
  //  Threshold: 1.0 → price is above → condition fails, order cancelled.
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::PriceAbove;
  c.param1 = 1ULL * PRICE_SCALE;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got))
      << "order should be cancelled once price exceeds threshold";
}

// ============================================================================
//  PriceBelow
// ============================================================================

TEST_F(Core_ExecutorFixture, PriceBelowHoldsWhenPoolPriceIsHigh)
{
  //  Pool price = 2.0, threshold 1.0 → condition holds.
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::PriceBelow;
  c.param1 = 1ULL * PRICE_SCALE;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got));
}

TEST_F(Core_ExecutorFixture, PriceBelowFailsWhenPoolPriceIsLow)
{
  //  Pool price = 0.5, threshold 1.0 → condition fails.
  seedPool(*state_, 1, 0, 42, 1000, 500);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::PriceBelow;
  c.param1 = 1ULL * PRICE_SCALE;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got));
}

TEST_F(Core_ExecutorFixture, PriceConditionDirectionFlipsWithPoolOrdering)
{
  //  Pool is (token_a=10, token_b=42), reserves (1000, 2000).
  //  The price of token_a in token_b is 2.0.
  //  The price of token_b in token_a is 0.5.
  //
  //  An order selling token_b (42) to buy token_a (10) should see
  //  price 0.5. A PriceBelow at 1.0 should FAIL.
  seedPool(*state_, 1, 10, 42, 1000, 2000);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::PriceBelow;
  c.param1 = 1ULL * PRICE_SCALE;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 42, 10, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got))
      << "PriceBelow should fail when the direction is flipped";
}

// ============================================================================
//  VolumeBelow
// ============================================================================

TEST_F(Core_ExecutorFixture, VolumeBelowFailsOnQuietPool)
{
  seedPool(*state_, 1, 0, 42, 1000, 1000);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::VolumeBelow;
  c.param1 = 1;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got));
}

TEST_F(Core_ExecutorFixture, VolumeBelowHoldsAfterSufficientVolume)
{
  auto pool = seedPool(*state_, 1, 0, 42, 1000, 1000);
  pool.volume_window_height = 50;
  pool.volume_last = 10'000;
  pool.volume_current = 0;
  state_->putAmmPool(pool);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::VolumeBelow;
  c.param1 = 5'000;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got))
      << "condition holds when volume exceeds the threshold";
}

TEST_F(Core_ExecutorFixture, VolumeBelowUsesCurrentWindowWhenWindowHasEnded)
{
  auto pool = seedPool(*state_, 1, 0, 42, 1000, 1000);
  pool.volume_window_height = 10;
  pool.volume_last = 1;
  pool.volume_current = 10'000;
  state_->putAmmPool(pool);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::VolumeBelow;
  c.param1 = 5'000;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got))
      << "reportedVolume should return volume_current once the window has ended";
}

// ============================================================================
//  BalanceBelow
// ============================================================================

TEST_F(Core_ExecutorFixture, BalanceBelowFailsWhenBalanceIsLow)
{
  setBalance(alice_.publicKey, 500);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::BalanceBelow;
  c.param1 = 1000;
  c.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got));
}

TEST_F(Core_ExecutorFixture, BalanceAboveHoldsWhenBalanceIsHigh)
{
  setBalance(alice_.publicKey, 5000);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::BalanceBelow;
  c.param1 = 1000;
  c.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got));
}

TEST_F(Core_ExecutorFixture, BalanceBelowUsesOwnerNotSender)
{
  setBalance(alice_.publicKey, 500);
  setBalance(bob_.publicKey, 1'000'000);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::BalanceBelow;
  c.param1 = 1000;
  c.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got));
}

// ============================================================================
//  ExpiresAtHeight
// ============================================================================

TEST_F(Core_ExecutorFixture, ExpiresAtHeightFailsWhenHeightPasses)
{
  Core::OrderCondition c;
  c.type = Core::OrderConditionType::ExpiresAtHeight;
  c.param1 = 50;
  c.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got));
}

TEST_F(Core_ExecutorFixture, ExpiresAtHeightHoldsBeforeHeight)
{
  Core::OrderCondition c;
  c.type = Core::OrderConditionType::ExpiresAtHeight;
  c.param1 = 200;
  c.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got));
}

// ============================================================================
//  Unevaluable conditions
// ============================================================================

TEST_F(Core_ExecutorFixture, PriceConditionWithMissingPoolDoesNotCancel)
{
  Core::OrderCondition c;
  c.type = Core::OrderConditionType::PriceAbove;
  c.param1 = 1ULL * PRICE_SCALE;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got))
      << "missing pool should not trigger cancellation";
}

TEST_F(Core_ExecutorFixture, PriceConditionWithEmptyPoolDoesNotCancel)
{
  seedPool(*state_, 1, 0, 42, 0, 0);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::PriceAbove;
  c.param1 = 1ULL * PRICE_SCALE;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got))
      << "zero-reserve pool should not trigger cancellation";
}

TEST_F(Core_ExecutorFixture, VolumeConditionWithMissingPoolDoesNotCancel)
{
  Core::OrderCondition c;
  c.type = Core::OrderConditionType::VolumeBelow;
  c.param1 = 1000;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got));
}

// ============================================================================
//  Multiple conditions: ALL must hold
// ============================================================================

TEST_F(Core_ExecutorFixture, AllConditionsMustHold)
{
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  Core::OrderCondition price_ok;
  price_ok.type = Core::OrderConditionType::PriceAbove;
  price_ok.param1 = 1ULL * PRICE_SCALE;
  price_ok.param2 = 1;

  Core::OrderCondition balance_bad;
  balance_bad.type = Core::OrderConditionType::BalanceBelow;
  balance_bad.param1 = 1000;
  balance_bad.param2 = 0;

  setBalance(alice_.publicKey, 500);

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {price_ok, balance_bad});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got))
      << "one failing condition should cancel the order";
}

TEST_F(Core_ExecutorFixture, OrderWithNoConditionsIsNotCancelled)
{
  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got));
}

// ============================================================================
//  Cancellation behavior
// ============================================================================

TEST_F(Core_ExecutorFixture, CancelRefundsMinusFee)
{
  setBalance(alice_.publicKey, 5000);

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 100;
    state_->putAccount(alice_.publicKey, acct);
  }
  ASSERT_EQ(state_->getAccount(alice_.publicKey).balance, 4900u);

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::BalanceBelow;
  failing.param1 = 10'000;
  failing.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {failing});

  evaluate(*state_, 100);

  const uint64_t expected =
      4900 + 100 - Core::ORDER_CANCEL_FEE_ATOMIC;
  EXPECT_EQ(state_->getAccount(alice_.publicKey).balance, expected);
}

TEST_F(Core_ExecutorFixture, CancelRefundsTokenSellAmount)
{
  const Id token = 42;
  setTokenBalance(alice_.publicKey, token, 500);
  setBalance(alice_.publicKey, 0);

  {
    uint64_t bal = state_->getTokenBalance(alice_.publicKey, token);
    state_->putTokenBalance(alice_.publicKey, token, bal - 100);
  }

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::BalanceBelow;
  failing.param1 = 10'000;
  failing.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey,
            /*sell_token=*/token, /*buy_token=*/0,
            100, 0, {failing});

  evaluate(*state_, 100);

  const uint64_t expected =
      400 + 100 - Core::ORDER_CANCEL_FEE_ATOMIC;
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token), expected);
}

TEST_F(Core_ExecutorFixture, CancelRemovesFromOwnerIndex)
{
  setBalance(alice_.publicKey, 5000);

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::BalanceBelow;
  failing.param1 = 10'000;
  failing.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {failing});

  {
    size_t count = 0;
    state_->forEachOrderForOwner(alice_.publicKey,
                                 [&](const Core::Order &)
                                 { ++count; });
    ASSERT_EQ(count, 1u);
  }

  evaluate(*state_, 100);

  size_t count = 0;
  state_->forEachOrderForOwner(alice_.publicKey,
                               [&](const Core::Order &)
                               { ++count; });
  EXPECT_EQ(count, 0u);
}

TEST_F(Core_ExecutorFixture, CancelRemovesFromPoolIndex)
{
  seedPool(*state_, 1, 0, 42, 1000, 500);

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::PriceBelow;
  failing.param1 = 1ULL * PRICE_SCALE;
  failing.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {failing});

  {
    size_t count = 0;
    state_->forEachOrderForPool(1, [&](const Core::Order &)
                                { ++count; });
    ASSERT_EQ(count, 1u);
  }

  evaluate(*state_, 100);

  size_t count = 0;
  state_->forEachOrderForPool(1, [&](const Core::Order &)
                              { ++count; });
  EXPECT_EQ(count, 0u);
}

TEST_F(Core_ExecutorFixture, CancelClearsExpiryIndex)
{
  setBalance(alice_.publicKey, 5000);

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::BalanceBelow;
  failing.param1 = 10'000;
  failing.param2 = 0;

  const uint64_t expires_at = 500;
  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100,
            /*expires=*/expires_at, {failing});

  ASSERT_EQ(state_->getOrdersExpiringAt(expires_at).size(), 1u);

  evaluate(*state_, 100);

  EXPECT_TRUE(state_->getOrdersExpiringAt(expires_at).empty());
}

TEST_F(Core_ExecutorFixture, EvaluatorIsIdempotent)
{
  setBalance(alice_.publicKey, 5000);

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 100;
    state_->putAccount(alice_.publicKey, acct);
  }

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::BalanceBelow;
  failing.param1 = 10'000;
  failing.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {failing});

  evaluate(*state_, 100);
  const uint64_t balance_after_first =
      state_->getAccount(alice_.publicKey).balance;

  evaluate(*state_, 101);
  const uint64_t balance_after_second =
      state_->getAccount(alice_.publicKey).balance;

  EXPECT_EQ(balance_after_first, balance_after_second);
}

TEST_F(Core_ExecutorFixture, EvaluatorCancelsMultipleOrdersInOnePass)
{
  setBalance(alice_.publicKey, 5000);
  setBalance(bob_.publicKey, 5000);

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::BalanceBelow;
  failing.param1 = 10'000;
  failing.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {failing});
  seedOrder(*state_, 2, bob_.publicKey, 0, 42, 100, 0, {failing});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got));
  EXPECT_FALSE(state_->getOrder(2, got));
}

// ============================================================================
//  Active order routing: basics
// ============================================================================
//
//  An Active order has mode == Active, a pool_id, and at least one
//  condition, so the evaluator is the entry point. The condition-
//  less Active path is exercised through TransactionExecutor in the
//  last group of tests.

TEST_F(Core_ExecutorFixture, ActiveOrderRoutesAtEpochBoundary)
{
  //  Pool: 1000 CLRTY (token 0) vs 2000 T42 (token 42). Spot price
  //  of CLRTY in T42 is 2.0. The condition holdsAlways() so the
  //  order routes.
  seedPool(*state_, /*pool_id=*/1, /*token_a=*/0, /*token_b=*/42,
           /*reserve_a=*/1000, /*reserve_b=*/2000);

  const uint64_t alice_t42_before = state_->getTokenBalance(alice_.publicKey, 42);
  ASSERT_EQ(alice_t42_before, 0u);

  //  Alice sells 100 CLRTY, wants >= 100 T42 (limit 1.0).
  seedActiveOrder(*state_, /*order_id=*/1, alice_.publicKey,
                  /*pool_id=*/1,
                  /*sell_token=*/0, /*buy_token=*/42,
                  /*sell_amount=*/100, /*min_buy_amount=*/100,
                  /*expires=*/0, {holdsAlways()});

  //  Lock the sell-token amount, mirroring executeCreateOrder.
  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 100;
    state_->putAccount(alice_.publicKey, acct);
  }

  std::vector<Core::Fill> fills;
  evaluate(*state_, 100, fills);

  ASSERT_FALSE(fills.empty());
  ASSERT_EQ(fills[0].source, Core::FillSource::Amm);
  ASSERT_EQ(fills[0].taker_order_id, 1u);
  ASSERT_EQ(fills[0].pool_id, 1u);

  Core::AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(1, pool));
  EXPECT_GT(pool.reserve_a, 1000u);
  EXPECT_LT(pool.reserve_b, 2000u);

  EXPECT_GT(state_->getTokenBalance(alice_.publicKey, 42), 0u);

  Core::Order got;
  if (state_->getOrder(1, got))
  {
    EXPECT_LT(got.filled_amount, got.sell_amount);
  }
}

TEST_F(Core_ExecutorFixture, ActiveOrderCancelsWhenConditionFails)
{
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  //  failsAlways() — condition fails for any positive price.
  seedActiveOrder(*state_, 1, alice_.publicKey, 1, 0, 42,
                  100, 100, 0, {failsAlways()});

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 100;
    state_->putAccount(alice_.publicKey, acct);
  }

  std::vector<Core::Fill> fills;
  evaluate(*state_, 100, fills);

  EXPECT_TRUE(fills.empty())
      << "a failing condition should cancel, not route";

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got))
      << "order should be cancelled on condition failure";
}

TEST_F(Core_ExecutorFixture, ActiveOrderRestsWhenPoolPriceUnfavorable)
{
  //  Pool: 1000 CLRTY vs 500 T42 → spot price 0.5 T42 per CLRTY.
  //  Order wants >= 1.0 (limit 1.0). The pool cannot fill.
  seedPool(*state_, 1, 0, 42, 1000, 500);

  seedActiveOrder(*state_, 1, alice_.publicKey, 1, 0, 42,
                  100, /*min_buy_amount=*/100, 0, {holdsAlways()});

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 100;
    state_->putAccount(alice_.publicKey, acct);
  }

  std::vector<Core::Fill> fills;
  evaluate(*state_, 100, fills);

  EXPECT_TRUE(fills.empty())
      << "unfavorable pool should produce no fill";

  Core::Order got;
  ASSERT_TRUE(state_->getOrder(1, got))
      << "order should rest and retry, not be cancelled";
  EXPECT_EQ(got.filled_amount, 0u);
}

TEST_F(Core_ExecutorFixture, ActiveOrderCancelsWhenPoolMissing)
{
  //  No pool seeded. The order references pool_id 1.
  seedActiveOrder(*state_, 1, alice_.publicKey, 1, 0, 42,
                  100, 100, 0, {holdsAlways()});

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 100;
    state_->putAccount(alice_.publicKey, acct);
  }

  std::vector<Core::Fill> fills;
  evaluate(*state_, 100, fills);

  EXPECT_TRUE(fills.empty());

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got))
      << "missing pool should cancel the order";
}

TEST_F(Core_ExecutorFixture, ActiveOrderPartialFillLeavesRemainder)
{
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  //  Order sells 10'000 CLRTY. The pool can serve a max input
  //  well below that at the limit; a remainder should rest.
  seedActiveOrder(*state_, 1, alice_.publicKey, 1, 0, 42,
                  10'000, /*min_buy_amount=*/10'000, 0, {holdsAlways()});

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 10'000;
    state_->putAccount(alice_.publicKey, acct);
  }

  std::vector<Core::Fill> fills;
  evaluate(*state_, 100, fills);

  ASSERT_FALSE(fills.empty());

  Core::Order got;
  ASSERT_TRUE(state_->getOrder(1, got))
      << "partial fill should leave the order in state";
  EXPECT_GT(got.filled_amount, 0u);
  EXPECT_LT(got.filled_amount, got.sell_amount);
}

TEST_F(Core_ExecutorFixture, ActiveOrderReevaluatesAtNextEpoch)
{
  //  An order that partially fills at one epoch is re-evaluated
  //  at the next. The outcome depends on how the pool moved:
  //
  //    - If the first fill left the pool's spot price at or above
  //      the order's limit, the second epoch fills more.
  //    - If the first fill pushed the spot price below the limit,
  //      the second epoch rests.
  //
  //  Both are correct. What the test pins is that the order
  //  survives the first epoch and is examined again at the
  //  second, not that it necessarily fills more.
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  seedActiveOrder(*state_, 1, alice_.publicKey, 1, 0, 42,
                  5'000, 5'000, 0, {holdsAlways()});

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 5'000;
    state_->putAccount(alice_.publicKey, acct);
  }

  //  First epoch: expect at least one fill and a remainder.
  std::vector<Core::Fill> fills_first;
  evaluate(*state_, 100, fills_first);
  ASSERT_FALSE(fills_first.empty());

  Core::Order after_first;
  ASSERT_TRUE(state_->getOrder(1, after_first))
      << "the order should have a remainder after a partial fill";
  const uint64_t filled_after_first = after_first.filled_amount;
  ASSERT_GT(filled_after_first, 0u);
  ASSERT_LT(filled_after_first, after_first.sell_amount);

  //  Second epoch. Two acceptable outcomes:
  //    (a) the pool is still favorable → the order fills more
  //    (b) the pool moved below the limit → the order rests
  //
  //  Both leave the order's filled_amount at or above its value
  //  after the first epoch. What must NOT happen is a decrease,
  //  a second fill that exceeds the order's sell_amount, or the
  //  order vanishing without being fully filled.
  std::vector<Core::Fill> fills_second;
  evaluate(*state_, 160, fills_second);

  Core::Order after_second;
  const bool still_present = state_->getOrder(1, after_second);

  if (still_present)
  {
    EXPECT_GE(after_second.filled_amount, filled_after_first)
        << "filled_amount must not decrease across epochs";
    EXPECT_LE(after_second.filled_amount, after_second.sell_amount)
        << "filled_amount must not exceed sell_amount";
  }
  else
  {
    //  The order was fully filled (or cancelled). If fully filled,
    //  the total across both epochs should equal sell_amount.
    //  We can't distinguish fully filled from cancelled here
    //  without checking the fills, so assert the fills we saw sum
    //  to sell_amount.
    const uint64_t total_filled =
        (fills_first.empty() ? 0 : fills_first[0].qty_base) +
        (fills_second.empty() ? 0 : fills_second[0].qty_base);
    EXPECT_EQ(total_filled, 5'000u)
        << "an order that disappeared should have been fully filled";
  }
}

// ============================================================================
//  Active order routing: fill accounting
// ============================================================================

TEST_F(Core_ExecutorFixture, ActiveOrderFillConservesValue)
{
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  setTokenBalance(alice_.publicKey, 42, 1'000);
  setBalance(alice_.publicKey, 10'000);

  seedActiveOrder(*state_, 1, alice_.publicKey, 1, 0, 42,
                  1'000, 1'000, 0, {holdsAlways()});

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 1'000;
    state_->putAccount(alice_.publicKey, acct);
  }

  const uint64_t alice_t42_before = state_->getTokenBalance(alice_.publicKey, 42);
  const uint64_t alice_native_before = state_->getAccount(alice_.publicKey).balance;

  std::vector<Core::Fill> fills;
  evaluate(*state_, 100, fills);

  ASSERT_FALSE(fills.empty());
  const auto &f = fills[0];

  Core::Order got;
  if (state_->getOrder(1, got))
  {
    EXPECT_EQ(got.filled_amount, f.qty_base)
        << "filled_amount is denominated in the order's sell token "
           "(CLRTY), which is the fill's base";
  }

  const uint64_t alice_t42_after = state_->getTokenBalance(alice_.publicKey, 42);
  EXPECT_EQ(alice_t42_after, alice_t42_before + f.qty_quote);

  const uint64_t alice_native_after = state_->getAccount(alice_.publicKey).balance;
  EXPECT_EQ(alice_native_after, alice_native_before)
      << "the fill should not move the sell-token balance a second time";

  Core::AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(1, pool));
  EXPECT_EQ(pool.reserve_a, 1000u + f.qty_base);
  EXPECT_EQ(pool.reserve_b, 2000u - f.qty_quote);
}

TEST_F(Core_ExecutorFixture, ActiveOrderFillIsIndexedForPairAndOrder)
{
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  seedActiveOrder(*state_, 1, alice_.publicKey, 1, 0, 42,
                  100, 100, 0, {holdsAlways()});

  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 100;
    state_->putAccount(alice_.publicKey, acct);
  }

  std::vector<Core::Fill> fills;
  evaluate(*state_, 100, fills);
  ASSERT_FALSE(fills.empty());

  {
    size_t count = 0;
    state_->forEachRecentFillForPair(0, 42, /*max=*/10,
                                     [&](const Core::Fill &, uint64_t, uint32_t)
                                     { ++count; });
    EXPECT_EQ(count, 1u);
  }

  {
    size_t count = 0;
    state_->forEachRecentFillForOrder(1, /*max=*/10,
                                      [&](const Core::Fill &, uint64_t, uint32_t)
                                      { ++count; });
    EXPECT_EQ(count, 1u);
  }
}

// ============================================================================
//  Active order routing: unconditional (no-condition) path
// ============================================================================
//
//  An Active order with no conditions routes on creation, not at
//  the epoch boundary. This exercises the TransactionExecutor path
//  through executeCreateOrder.

TEST_F(Core_ExecutorFixture, ActiveOrderWithoutConditionsRoutesOnCreation)
{
  seedPool(*state_, 1, 0, 42, 1000, 2000);

  ASSERT_EQ(state_->getTokenBalance(alice_.publicKey, 42), 0u);

  const uint64_t alice_before = balanceOf(alice_.publicKey);

  Core::Transaction tx =
      TransactionBuilder()
          .type(TxType::CreateOrder)
          .from(alice_)
          .to(Crypto::Address{})
          .amount(100)
          .fee(1)
          .nonce(0)
          .tokenId(NATIVE_TOKEN_ID)
          .chainId(EXEC_CHAIN_ID)
          .payload(makeCreateOrderPayload(
              /*buy_token=*/42,
              /*min_buy_amount=*/100,
              static_cast<uint8_t>(Core::OrderExecutionMode::Active),
              /*expires_at=*/0,
              /*condition_bytes=*/{},
              /*pool_id=*/1))
          .build();

  Core::Receipt r = run(tx);
  ASSERT_EQ(r.status, ReceiptStatus::Success);

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 100 - 1);
  EXPECT_GT(state_->getTokenBalance(alice_.publicKey, 42), 0u);

  ASSERT_EQ(r.fills.size(), 1u);
  EXPECT_EQ(r.fills[0].source, Core::FillSource::Amm);
  EXPECT_EQ(r.fills[0].pool_id, 1u);

  Core::AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(1, pool));
  EXPECT_GT(pool.reserve_a, 1000u);
  EXPECT_LT(pool.reserve_b, 2000u);
}

TEST_F(Core_ExecutorFixture, ActiveOrderWithoutConditionsUnroutableIsRejected)
{
  //  No pool seeded. The order references pool_id 1.
  Core::Transaction tx =
      TransactionBuilder()
          .type(TxType::CreateOrder)
          .from(alice_)
          .to(Crypto::Address{})
          .amount(100)
          .fee(1)
          .nonce(0)
          .tokenId(NATIVE_TOKEN_ID)
          .chainId(EXEC_CHAIN_ID)
          .payload(makeCreateOrderPayload(
              /*buy_token=*/42,
              /*min_buy_amount=*/100,
              static_cast<uint8_t>(Core::OrderExecutionMode::Active),
              /*expires_at=*/0,
              /*condition_bytes=*/{},
              /*pool_id=*/1))
          .build();

  Core::Receipt r = run(tx);
  EXPECT_EQ(r.status, ReceiptStatus::Failure)
      << "an Active order against a missing pool should be rejected";

  //  Only the fee was charged. The pre-route validation rejects
  //  before taking the sell-token lock, so the 100 CLRTY is still
  //  in Alice's balance.
  EXPECT_EQ(balanceOf(alice_.publicKey), 1'000'000'000ULL - 1);

  //  No order was left behind.
  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got));
}

// ============================================================================
//  Epoch-boundary gating (through applyBlock)
// ============================================================================

TEST_F(Core_BlockProcessorFixture, EvaluatorRunsOnEpochBoundary)
{
  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);

    Core::AmmPool pool;
    pool.id = 1;
    pool.creator = Crypto::Address{};
    pool.token_a = 0;
    pool.token_b = 42;
    pool.reserve_a = 1000;
    pool.reserve_b = 500; // price 0.5
    pool.total_liquidity = 1000;
    pool.fee_bps = Core::AMM_DEFAULT_FEE_BPS;
    pool.created_at_height = 1;
    pool.active = true;
    s.putAmmPool(pool);

    s.commit(0);
    t.commit();
  }

  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);

    Core::Order o;
    o.id = 1;
    o.owner = alice_.publicKey;
    o.mode = Core::OrderExecutionMode::Passive;
    o.sell_token = 0;
    o.buy_token = 42;
    o.sell_amount = 100;
    o.min_buy_amount = 1;
    o.created_at_height = 1;
    o.order_expires_at_height = 0;
    o.filled_amount = 0;
    o.condition_count = 1;
    o.conditions[0].type = Core::OrderConditionType::PriceBelow;
    o.conditions[0].param1 = 1ULL * PRICE_SCALE;
    o.conditions[0].param2 = 1;
    s.putOrder(o);

    s.commit(0);
    t.commit();
  }

  //  Height 58: (58 + 1) % 60 != 0, evaluator does NOT run.
  {
    const uint64_t height = 58;
    Core::Block b = makeProcessableBlock(
        height, genesis_hash_, /*txs=*/{}, /*active_set=*/{1, 2});
    Core::BlockResult r = applyPrebuiltBlock(b);
    ASSERT_TRUE(r.valid) << r.error;
  }

  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);
    Core::Order o;
    EXPECT_TRUE(s.getOrder(1, o))
        << "order should survive a non-boundary block";
    t.abort();
  }

  //  Height 59: (59 + 1) % 60 == 0, evaluator runs.
  {
    const uint64_t height = 59;
    Core::Block b = makeProcessableBlock(
        height, genesis_hash_, /*txs=*/{}, /*active_set=*/{1, 2});
    Core::BlockResult r = applyPrebuiltBlock(b);
    ASSERT_TRUE(r.valid) << r.error;
  }

  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);
    Core::Order o;
    EXPECT_FALSE(s.getOrder(1, o))
        << "order should be cancelled on the epoch boundary";
    t.abort();
  }
}

// ============================================================================
//  Epoch fills root commitment
// ============================================================================

TEST_F(Core_BlockProcessorFixture, EpochFillsRootIsComputedAndVerified)
{
  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);

    Core::AmmPool pool;
    pool.id = 1;
    pool.creator = Crypto::Address{};
    pool.token_a = 0;
    pool.token_b = 42;
    pool.reserve_a = 1000;
    pool.reserve_b = 2000;
    pool.total_liquidity = 1000;
    pool.fee_bps = Core::AMM_DEFAULT_FEE_BPS;
    pool.created_at_height = 1;
    pool.active = true;
    s.putAmmPool(pool);

    Core::Account acct = s.getAccount(alice_.publicKey);
    acct.balance += 10'000;
    s.putAccount(alice_.publicKey, acct);

    Core::Order o;
    o.id = 1;
    o.owner = alice_.publicKey;
    o.mode = Core::OrderExecutionMode::Active;
    o.pool_id = 1;
    o.sell_token = 0;
    o.buy_token = 42;
    o.sell_amount = 100;
    o.min_buy_amount = 100;
    o.created_at_height = 1;
    o.order_expires_at_height = 0;
    o.filled_amount = 0;
    o.condition_count = 1;
    o.conditions[0].type = Core::OrderConditionType::PriceAbove;
    o.conditions[0].param1 = std::numeric_limits<uint64_t>::max();
    o.conditions[0].param2 = 1;

    Core::Account owner_acct = s.getAccount(o.owner);
    owner_acct.balance -= o.sell_amount;
    s.putAccount(o.owner, owner_acct);

    s.putOrder(o);

    s.commit(0);
    t.commit();
  }

  //  Height 59: (59 + 1) % 60 == 0, evaluator runs.
  {
    const uint64_t height = 59;
    Core::Block b = makeProcessableBlock(
        height, genesis_hash_, /*txs=*/{}, /*active_set=*/{1, 2});
    Core::BlockResult r = applyPrebuiltBlock(b);
    ASSERT_TRUE(r.valid) << r.error;
    ASSERT_FALSE(r.epoch_fills.empty())
        << "the epoch boundary should have produced at least one fill";

    EXPECT_FALSE(b.header.epoch_fills_root.isNull());
  }
}

TEST_F(Core_BlockProcessorFixture, EpochFillsRootMismatchIsRejected)
{
  {
    auto t = db_->beginWrite();
    State::StateAccess s(*db_, t, 0);

    Core::AmmPool pool;
    pool.id = 1;
    pool.creator = Crypto::Address{};
    pool.token_a = 0;
    pool.token_b = 42;
    pool.reserve_a = 1000;
    pool.reserve_b = 2000;
    pool.total_liquidity = 1000;
    pool.fee_bps = Core::AMM_DEFAULT_FEE_BPS;
    pool.created_at_height = 1;
    pool.active = true;
    s.putAmmPool(pool);

    Core::Account acct = s.getAccount(alice_.publicKey);
    acct.balance += 10'000;
    s.putAccount(alice_.publicKey, acct);

    Core::Order o;
    o.id = 1;
    o.owner = alice_.publicKey;
    o.mode = Core::OrderExecutionMode::Active;
    o.pool_id = 1;
    o.sell_token = 0;
    o.buy_token = 42;
    o.sell_amount = 100;
    o.min_buy_amount = 100;
    o.created_at_height = 1;
    o.order_expires_at_height = 0;
    o.filled_amount = 0;
    o.condition_count = 1;
    o.conditions[0].type = Core::OrderConditionType::PriceAbove;
    o.conditions[0].param1 = std::numeric_limits<uint64_t>::max();
    o.conditions[0].param2 = 1;

    Core::Account owner_acct = s.getAccount(o.owner);
    owner_acct.balance -= o.sell_amount;
    s.putAccount(o.owner, owner_acct);

    s.putOrder(o);

    s.commit(0);
    t.commit();
  }

  Core::Block b = makeProcessableBlock(
      /*height=*/59, genesis_hash_, /*txs=*/{}, /*active_set=*/{1, 2});

  //  Flip a bit in the root.
  b.header.epoch_fills_root.data[0] ^= 0xFF;

  //  Re-sign, because the epoch_fills_root is part of the hash.
  b.quorum_signatures = makeQuorumForBlock(b, {seed1_, seed2_});

  Core::BlockContext ctx = makeContext(59);
  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
  t.abort();

  EXPECT_FALSE(r.valid);
  EXPECT_NE(r.error.find("epoch_fills_root mismatch"), std::string::npos)
      << "got: " << r.error;
}