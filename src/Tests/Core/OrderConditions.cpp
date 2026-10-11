// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Fixtures.h"

using namespace Core;
using namespace Tests;

//  ============================================================================
//  Order condition evaluation tests
//  ============================================================================
//
//  These tests exercise BlockProcessor::evaluateOrderConditions, the
//  per-epoch pass that cancels orders whose conditions have failed.
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
//  One integration test goes through the full applyBlock path to
//  verify the epoch-boundary gating.

namespace
{
  //  Call the evaluator directly, using the fixture's bound write
  //  txn. Writes performed by the evaluator are visible to
  //  subsequent reads through the same StateAccess.
  void evaluate(State::StateAccess &state, uint64_t height)
  {
    Core::BlockContext ctx;
    ctx.chain_id = EXEC_CHAIN_ID;
    ctx.current_height = height;
    Core::BlockProcessor::evaluateOrderConditions(state, ctx);
  }

  //  Seed a pool with the given reserves in the fixture's state.
  //  Tokens are canonical: token_a < token_b.
  //
  //  The pool is created with id 1 by default; tests that need a
  //  different id pass one.
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

  //  Seed an order with a given set of conditions.
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

    //  Match executeCreateOrder: an order with a non-zero expiry
    //  height must appear in the expiry index, so processOrderExpiries
    //  and cancelOrderByCondition can find it.
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
//  Pool is (token_a, token_b) with token_a = 0 (CLRTY), token_b = 42.
//  Order is selling token_a to buy token_b. The spot price the
//  condition evaluates is (amount of buy_token per unit of sell_token)
//  = reserve_b / reserve_a.

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
  //  This tests the poolSpotPrice direction logic. The pool's
  //  canonical ordering is (token_a < token_b). The order's pair
  //  may be in the opposite direction.
  //
  //  Pool is (token_a=10, token_b=42), reserves (1000, 2000).
  //  So the price of token_a in token_b is 2000/1000 = 2.0.
  //  The price of token_b in token_a is 1000/2000 = 0.5.
  //
  //  An order selling token_b (42) to buy token_a (10) should see
  //  price 0.5. A PriceBelow at 1.0 should FAIL.
  seedPool(*state_, 1, 10, 42, 1000, 2000);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::PriceBelow;
  c.param1 = 1ULL * PRICE_SCALE;
  c.param2 = 1;

  //  sell_token = 42, buy_token = 10 → price is (10 per 42) = 0.5
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
  //  Pool with no swaps: volume_last = 0. Threshold 1 → fails.
  seedPool(*state_, 1, 0, 42, 1000, 1000);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::VolumeBelow;
  c.param1 = 1; // any positive threshold
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_FALSE(state_->getOrder(1, got));
}

TEST_F(Core_ExecutorFixture, VolumeBelowHoldsAfterSufficientVolume)
{
  //  Seed a pool with volume_last already set to a high value.
  //  (Setting it directly bypasses executeSwap, which the
  //  TransactionExecutor tests already cover.)
  auto pool = seedPool(*state_, 1, 0, 42, 1000, 1000);
  pool.volume_window_height = 50;
  pool.volume_last = 10'000;
  pool.volume_current = 0;
  state_->putAmmPool(pool);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::VolumeBelow;
  c.param1 = 5'000; // below volume_last
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  evaluate(*state_, 100);

  Core::Order got;
  EXPECT_TRUE(state_->getOrder(1, got))
      << "condition holds when volume exceeds the threshold";
}

TEST_F(Core_ExecutorFixture, VolumeBelowUsesCurrentWindowWhenWindowHasEnded)
{
  //  When a full epoch has elapsed since volume_window_height, the
  //  in-progress window is now a complete one and reportedVolume
  //  returns volume_current instead of volume_last.
  //
  //  Set window_height so that current_height >= window_height + 60
  //  is true at the evaluation height.
  auto pool = seedPool(*state_, 1, 0, 42, 1000, 1000);
  pool.volume_window_height = 10;
  pool.volume_last = 1;         // stale
  pool.volume_current = 10'000; // this window's total
  state_->putAmmPool(pool);

  Core::OrderCondition c;
  c.type = Core::OrderConditionType::VolumeBelow;
  c.param1 = 5'000;
  c.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  //  Evaluate at height 100, which is > 10 + 60.
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
  //  The condition checks the ORDER'S owner, not whoever submitted
  //  it. Fund Bob and leave Alice broke; the order (owned by Alice)
  //  should fail.
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
  c.param1 = 50; // expires at 50
  c.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {c});

  //  Evaluate at height 100, past the expiry.
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
  //  No pool seeded. The condition references pool_id 1, which
  //  doesn't exist. Per the design spec, unevaluable conditions
  //  hold; the order is NOT cancelled.
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
  //  Pool exists but has zero reserves.
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

  //  First condition holds (price 2.0 >= 1.0), second fails
  //  (balance 500 < 1000). Order should be cancelled.
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
  //  An order with condition_count = 0 has nothing to evaluate; the
  //  evaluator skips it.
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
  //  Alice has 5000. Seed a failing order that locked 100 of her
  //  CLRTY. On cancellation she should get back (100 - fee) where
  //  fee = ORDER_CANCEL_FEE_ATOMIC.
  setBalance(alice_.publicKey, 5000);

  //  Lock the sell amount first — seedOrder doesn't do this (the
  //  executor does it at order creation). We simulate it here.
  {
    Core::Account acct = state_->getAccount(alice_.publicKey);
    acct.balance -= 100;
    state_->putAccount(alice_.publicKey, acct);
  }
  ASSERT_EQ(state_->getAccount(alice_.publicKey).balance, 4900u);

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::BalanceBelow;
  failing.param1 = 10'000; // balance is 4900, below threshold
  failing.param2 = 0;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {failing});

  evaluate(*state_, 100);

  //  4900 + (100 - fee)
  const uint64_t expected =
      4900 + 100 - Core::ORDER_CANCEL_FEE_ATOMIC;
  EXPECT_EQ(state_->getAccount(alice_.publicKey).balance, expected);
}

TEST_F(Core_ExecutorFixture, CancelRefundsTokenSellAmount)
{
  const Id token = 42;
  setTokenBalance(alice_.publicKey, token, 500);
  setBalance(alice_.publicKey, 0);

  //  Lock the sell amount.
  {
    uint64_t bal = state_->getTokenBalance(alice_.publicKey, token);
    state_->putTokenBalance(alice_.publicKey, token, bal - 100);
  }

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::BalanceBelow;
  failing.param1 = 10'000; // CLRTY balance is 0
  failing.param2 = 0;

  //  sell_token = custom token, buy_token = native (0). Both are
  //  different IDs, so seedOrder accepts the pair.
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

  //  Before evaluation: index has one entry.
  {
    size_t count = 0;
    state_->forEachOrderForOwner(alice_.publicKey,
                                 [&](const Core::Order &)
                                 { ++count; });
    ASSERT_EQ(count, 1u);
  }

  evaluate(*state_, 100);

  //  After: index is empty.
  size_t count = 0;
  state_->forEachOrderForOwner(alice_.publicKey,
                               [&](const Core::Order &)
                               { ++count; });
  EXPECT_EQ(count, 0u);
}

TEST_F(Core_ExecutorFixture, CancelRemovesFromPoolIndex)
{
  seedPool(*state_, 1, 0, 42, 1000, 500); // price 0.5

  Core::OrderCondition failing;
  failing.type = Core::OrderConditionType::PriceBelow;
  failing.param1 = 1ULL * PRICE_SCALE; // fails because price < threshold
  failing.param2 = 1;

  seedOrder(*state_, 1, alice_.publicKey, 0, 42, 100, 0, {failing});

  //  Before: pool index has one entry.
  {
    size_t count = 0;
    state_->forEachOrderForPool(1, [&](const Core::Order &)
                                { ++count; });
    ASSERT_EQ(count, 1u);
  }

  evaluate(*state_, 100);

  //  After: pool index is empty.
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

  //  Before: expiry index has one entry at height 500.
  ASSERT_EQ(state_->getOrdersExpiringAt(expires_at).size(), 1u);

  evaluate(*state_, 100);

  //  After: index is cleared.
  EXPECT_TRUE(state_->getOrdersExpiringAt(expires_at).empty());
}

TEST_F(Core_ExecutorFixture, EvaluatorIsIdempotent)
{
  setBalance(alice_.publicKey, 5000);

  //  Lock the sell amount.
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

  //  Second evaluation: nothing to do, no second refund.
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
//  Epoch-boundary gating (through applyBlock)
// ============================================================================
//
//  The tests above call the evaluator directly. This one goes through
//  the full applyBlock path to verify the wiring: the evaluator
//  should run only on the last block of an epoch, i.e. when
//  (current_height + 1) % ROTATION_INTERVAL == 0.
//
//  We use the fixture's makeProcessableBlock / applyPrebuiltBlock
//  helpers to run a full block and check that a failing order was
//  (or was not) cancelled depending on the block height.

TEST_F(Core_BlockProcessorFixture, EvaluatorRunsOnEpochBoundary)
{
  //  Seed a pool that will make a PriceBelow condition fail.
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

  //  Seed a failing order.
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

  //  Apply a block at height 58. (58 + 1) % 60 != 0, so the
  //  evaluator does NOT run. The order should survive.
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

  //  Apply a block at height 59. (59 + 1) % 60 == 0, so the
  //  evaluator runs. The order should be cancelled.
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