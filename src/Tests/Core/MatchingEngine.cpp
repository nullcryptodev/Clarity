// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "Core/MatchingEngine.h"
#include "Core/OrderBook.h"
#include "Crypto/Blake2b.h"
#include "Crypto/Types.h"
#include "State/StateAccess.h"
#include "State/StateDB.h"

#include "Fixtures.h"
#include "Tests/Temp.h"
#include "Tests/Utils.h"

using namespace Core;
using State::StateAccess;
using State::StateDB;
using namespace Tests;

// =================================================================
//  Canonical price math (no fixture needed)
// =================================================================

TEST(Core_OrderBookCanonicalPrice, SellBaseFloors)
{
  //  Sell 100 base, want >= 2500 quote. Price = 2500/100 = 25.
  //  canonicalPrice = floor(min_buy_amount * SCALE / sell_amount)
  //                 = floor(2500 * SCALE / 100)
  //                 = 25 * SCALE.
  Order o;
  o.sell_token = 1; // base
  o.buy_token = 2;  // quote
  o.sell_amount = 100;
  o.min_buy_amount = 2500;

  uint64_t p = 0;
  ASSERT_TRUE(OrderBook::canonicalPrice(o, p));
  ASSERT_EQ(p, 25ULL * OrderBook::BOOK_PRICE_SCALE);
}

TEST(Core_OrderBookCanonicalPrice, SellQuoteCeils)
{
  //  Sell 2500 quote, want >= 100 base. Price = 2500/100 = 25.
  //  canonicalPrice = ceil(sell_amount * SCALE / min_buy_amount)
  //                 = ceil(2500 * SCALE / 100)
  //                 = 25 * SCALE.
  Order o;
  o.sell_token = 2; // quote
  o.buy_token = 1;  // base
  o.sell_amount = 2500;
  o.min_buy_amount = 100;

  uint64_t p = 0;
  ASSERT_TRUE(OrderBook::canonicalPrice(o, p));
  ASSERT_EQ(p, 25ULL * OrderBook::BOOK_PRICE_SCALE);
}

TEST(Core_OrderBookCanonicalPrice, CeilRoundsUp)
{
  //  100 quote for at least 33 base -> 100/33 = 3.0303...
  //  ceil at SCALE=10^10 -> 30303030304.
  Order o;
  o.sell_token = 2;
  o.buy_token = 1;
  o.sell_amount = 100;
  o.min_buy_amount = 33;

  uint64_t p = 0;
  ASSERT_TRUE(OrderBook::canonicalPrice(o, p));
  ASSERT_EQ(p, 30303030304ULL);
}

TEST(Core_OrderBookCrosses, SellerCrossesAtEqualPrice)
{
  ASSERT_TRUE(OrderBook::crosses(100, 100, /*side=*/0));
  ASSERT_TRUE(OrderBook::crosses(100, 200, 0));
  ASSERT_FALSE(OrderBook::crosses(100, 99, 0));
}

TEST(Core_OrderBookCrosses, BuyerCrossesAtEqualPrice)
{
  ASSERT_TRUE(OrderBook::crosses(100, 100, /*side=*/1));
  ASSERT_TRUE(OrderBook::crosses(100, 50, 1));
  ASSERT_FALSE(OrderBook::crosses(100, 101, 1));
}

// =================================================================
//  Book mechanics
// =================================================================

TEST_F(Core_MatchingEngineTest, BookIteratesBestPriceFirst)
{
  //  Three resting sells at ascending prices. The book is
  //  price-sorted best-first for side 0, which means lowest ask
  //  first.
  //
  //  Each order rests 30 token-1, so prices:
  //    cheap: 300/30   = 10 quote/base
  //    mid:   600/30   = 20
  //    rich:  900/30   = 30
  Order cheap = makeOrder(1, bob_, 1, 2, 30, 300); // 10 quote/base
  Order mid = makeOrder(2, carol_, 1, 2, 30, 600); // 20
  Order rich = makeOrder(3, dave_, 1, 2, 30, 900); // 30
  restOrder(cheap);
  restOrder(mid);
  restOrder(rich);

  std::vector<Id> seen;
  state_->forEachBookLevel(
      1, 2, /*side=*/0,
      [&](Id order_id, uint64_t, uint64_t)
      {
        seen.push_back(order_id);
        return true;
      });

  ASSERT_EQ(seen.size(), 3u);
  ASSERT_EQ(seen[0], 1u); // cheapest first
  ASSERT_EQ(seen[1], 2u);
  ASSERT_EQ(seen[2], 3u);
}

TEST_F(Core_MatchingEngineTest, BookTiebreaksBySequence)
{
  //  Two sellers at the same price. The one that entered first
  //  must come out first.
  Order first = makeOrder(1, bob_, 1, 2, 30, 300);
  Order second = makeOrder(2, carol_, 1, 2, 30, 300);
  restOrder(first);
  restOrder(second);

  std::vector<Id> seen;
  state_->forEachBookLevel(
      1, 2, 0,
      [&](Id order_id, uint64_t, uint64_t)
      {
        seen.push_back(order_id);
        return true;
      });

  ASSERT_EQ(seen.size(), 2u);
  ASSERT_EQ(seen[0], 1u);
  ASSERT_EQ(seen[1], 2u);
}

TEST_F(Core_MatchingEngineTest, RemoveFromBookDeletesBothRows)
{
  Order o = makeOrder(1, bob_, 1, 2, 30, 300);
  restOrder(o);

  state_->removeFromOrderBook(o);

  size_t count = 0;
  state_->forEachBookLevel(
      1, 2, 0,
      [&](Id, uint64_t, uint64_t)
      { ++count; return true; });
  ASSERT_EQ(count, 0u);

  //  The order record itself is untouched.
  Order reloaded;
  ASSERT_TRUE(state_->getOrder(1, reloaded));
  ASSERT_EQ(reloaded.id, 1u);
}

// =================================================================
//  Full fill
// =================================================================

TEST_F(Core_MatchingEngineTest, FullFillOneMaker)
{
  //  Bob rests: sell 100 token-1, want >= 2500 token-2.
  //  Price = 2500/100 = 25 quote/base.
  Order maker = makeOrder(1, bob_, 1, 2, 100, 2500);
  lockSellToken(bob_, 1, 100);
  restOrder(maker);

  //  Alice takes: sell 2500 token-2, want >= 100 token-1.
  //  Price = 2500/100 = 25 quote/base. Crosses exactly.
  Order taker = makeOrder(2, alice_, 2, 1, 2500, 100);

  const uint64_t supply_before = totalSupply();

  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, /*height=*/1, /*tx_index_in_block=*/0);

  ASSERT_EQ(outcome.fills.size(), 1u);
  ASSERT_EQ(outcome.fills[0].qty_base, 100u);
  ASSERT_EQ(outcome.fills[0].qty_quote, 2500u);
  ASSERT_EQ(outcome.fills[0].price,
            25ULL * OrderBook::BOOK_PRICE_SCALE);
  ASSERT_FALSE(outcome.taker_rests);
  ASSERT_EQ(outcome.total_base, 100u);
  ASSERT_EQ(outcome.total_quote, 2500u);

  //  Balances moved.
  ASSERT_EQ(state_->getTokenBalance(bob_, 2), 1'000'000u + 2500u);
  ASSERT_EQ(state_->getTokenBalance(alice_, 1), 1'000'000u + 100u);

  //  Both records gone.
  Order gone;
  ASSERT_FALSE(state_->getOrder(1, gone));
  ASSERT_FALSE(state_->getOrder(2, gone));

  //  Book empty.
  size_t count = 0;
  state_->forEachBookLevel(
      1, 2, 0, [&](Id, uint64_t, uint64_t)
      { ++count; return true; });
  ASSERT_EQ(count, 0u);
  count = 0;
  state_->forEachBookLevel(
      1, 2, 1, [&](Id, uint64_t, uint64_t)
      { ++count; return true; });
  ASSERT_EQ(count, 0u);

  ASSERT_EQ(totalSupply(), supply_before);
}

// =================================================================
//  Partial fill, taker rests a remainder
// =================================================================

TEST_F(Core_MatchingEngineTest, PartialFillTakerRests)
{
  //  Bob rests 40 token-1 @ 25 quote/base (1000 token-2 total).
  Order maker = makeOrder(1, bob_, 1, 2, 40, 1000);
  lockSellToken(bob_, 1, 40);
  restOrder(maker);

  //  Alice takes with 2500 token-2, wanting >= 100 token-1
  //  (limit = 25 quote/base). Bob only has 40 base, so Alice
  //  fills 40 for 1000 and rests with the other 1500.
  Order taker = makeOrder(2, alice_, 2, 1, 2500, 100);

  const uint64_t supply_before = totalSupply();

  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, /*height=*/1, /*tx_index_in_block=*/0);

  ASSERT_EQ(outcome.fills.size(), 1u);
  ASSERT_EQ(outcome.fills[0].qty_base, 40u);
  ASSERT_EQ(outcome.fills[0].qty_quote, 1000u);
  ASSERT_TRUE(outcome.taker_rests);
  ASSERT_FALSE(taker.isFullyFilled());

  //  Taker's filled_amount is in token-2, its sell token.
  ASSERT_EQ(taker.filled_amount, 1000u);
  ASSERT_EQ(taker.remainingAmount(), 1500u);

  //  Maker fully filled and gone.
  Order gone;
  ASSERT_FALSE(state_->getOrder(1, gone));

  //  Taker rests on side 1.
  size_t count = 0;
  Id seen_id = 0;
  state_->forEachBookLevel(
      1, 2, 1,
      [&](Id id, uint64_t, uint64_t)
      {
        ++count;
        seen_id = id;
        return true;
      });
  ASSERT_EQ(count, 1u);
  ASSERT_EQ(seen_id, 2u);

  ASSERT_EQ(totalSupply(), supply_before);
}

// =================================================================
//  Partial fill, maker survives
// =================================================================

TEST_F(Core_MatchingEngineTest, PartialFillMakerSurvives)
{
  //  Bob rests 200 token-1 @ 25 quote/base.
  Order maker = makeOrder(1, bob_, 1, 2, 200, 5000);
  lockSellToken(bob_, 1, 200);
  restOrder(maker);

  //  Alice takes: 2500 token-2 in, want >= 100 token-1.
  //  She gets exactly 100 base from Bob.
  Order taker = makeOrder(2, alice_, 2, 1, 2500, 100);

  const uint64_t supply_before = totalSupply();

  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, /*height=*/1, /*tx_index_in_block=*/0);

  ASSERT_EQ(outcome.fills.size(), 1u);
  ASSERT_EQ(outcome.fills[0].qty_base, 100u);
  ASSERT_EQ(outcome.fills[0].qty_quote, 2500u);
  ASSERT_FALSE(outcome.taker_rests);

  Order rest;
  ASSERT_TRUE(state_->getOrder(1, rest));
  ASSERT_EQ(rest.filled_amount, 100u);
  ASSERT_EQ(rest.remainingAmount(), 100u);

  size_t count = 0;
  state_->forEachBookLevel(
      1, 2, 0,
      [&](Id id, uint64_t, uint64_t)
      {
        ++count;
        EXPECT_EQ(id, 1u);
        return true;
      });
  ASSERT_EQ(count, 1u);

  ASSERT_EQ(totalSupply(), supply_before);
}

// =================================================================
//  Multi-level fill
// =================================================================

TEST_F(Core_MatchingEngineTest, MultiLevelFill)
{
  //  Three resting sellers at ascending prices, 30 base each.
  Order cheap = makeOrder(1, bob_, 1, 2, 30, 300); // 10
  Order mid = makeOrder(2, carol_, 1, 2, 30, 600); // 20
  Order rich = makeOrder(3, dave_, 1, 2, 30, 900); // 30
  lockSellToken(bob_, 1, 30);
  lockSellToken(carol_, 1, 30);
  lockSellToken(dave_, 1, 30);
  restOrder(cheap);
  restOrder(mid);
  restOrder(rich);

  //  Alice takes: sell 2500 token-2, want >= 100 token-1.
  //  Limit = 2500/100 = 25 quote/base.
  //    Crosses cheap (10) and mid (20).
  //    Misses rich (30).
  Order taker = makeOrder(4, alice_, 2, 1, 2500, 100);

  const uint64_t supply_before = totalSupply();

  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, /*height=*/1, /*tx_index_in_block=*/0);

  ASSERT_EQ(outcome.fills.size(), 2u);
  ASSERT_EQ(outcome.fills[0].maker_order_id, 1u);
  ASSERT_EQ(outcome.fills[0].qty_base, 30u);
  ASSERT_EQ(outcome.fills[0].qty_quote, 300u);
  ASSERT_EQ(outcome.fills[1].maker_order_id, 2u);
  ASSERT_EQ(outcome.fills[1].qty_base, 30u);
  ASSERT_EQ(outcome.fills[1].qty_quote, 600u);
  ASSERT_EQ(outcome.total_base, 60u);
  ASSERT_EQ(outcome.total_quote, 900u);

  //  Third maker untouched.
  Order reloaded;
  ASSERT_TRUE(state_->getOrder(3, reloaded));
  ASSERT_EQ(reloaded.filled_amount, 0u);

  //  Taker rests. Total spendable at the start was 2500 token-2;
  //  900 was spent on the two fills; 1600 remains locked in the
  //  resting remainder. The taker's sell token is token-2.
  ASSERT_TRUE(outcome.taker_rests);
  ASSERT_EQ(taker.filled_amount, 900u);
  ASSERT_EQ(taker.remainingAmount(), 1600u);

  ASSERT_EQ(totalSupply(), supply_before);
}

// =================================================================
//  Self-trade cancels the resting order
// =================================================================

TEST_F(Core_MatchingEngineTest, SelfTradeCancelsResting)
{
  //  Alice rests a sell: 100 token-1 for >= 2500 token-2.
  //  Price = 2500/100 = 25 quote/base.
  Order rest = makeOrder(1, alice_, 1, 2, 100, 2500);
  lockSellToken(alice_, 1, 100);
  restOrder(rest);

  const uint64_t alice_token1_before = state_->getTokenBalance(alice_, 1);
  const uint64_t supply_before = totalSupply();

  //  Alice takes against her own book.
  Order taker = makeOrder(2, alice_, 2, 1, 2500, 100);
  lockSellToken(alice_, 2, 2500);

  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, /*height=*/1, /*tx_index_in_block=*/0);

  ASSERT_TRUE(outcome.fills.empty());

  //  The resting order is gone.
  Order gone;
  ASSERT_FALSE(state_->getOrder(1, gone));

  //  The refund restores the remaining 100 token-1 minus the
  //  cancel fee (1 atomic). So the net change from before the
  //  resting order was placed is -1.
  ASSERT_EQ(state_->getTokenBalance(alice_, 1),
            alice_token1_before + 100u - Core::ORDER_CANCEL_FEE_ATOMIC);

  //  The taker then rested (its 2500 token-2 was untouched by the
  //  self-trade cancel).
  ASSERT_TRUE(outcome.taker_rests);

  size_t count = 0;
  state_->forEachBookLevel(
      1, 2, 0,
      [&](Id, uint64_t, uint64_t)
      { ++count; return true; });
  ASSERT_EQ(count, 0u); // resting sell is gone

  count = 0;
  state_->forEachBookLevel(
      1, 2, 1,
      [&](Id, uint64_t, uint64_t)
      { ++count; return true; });
  ASSERT_EQ(count, 1u); // taker is now resting

  //  Supply invariant. The cancel fee is debited from Alice's
  //  spendable balance and credited nowhere, so the sum drops by
  //  exactly the fee.
  ASSERT_EQ(totalSupply(),
            supply_before - Core::ORDER_CANCEL_FEE_ATOMIC);
}

// =================================================================
//  Commit and reopen: state survives
// =================================================================

TEST_F(Core_MatchingEngineTest, CommitAndReopenPreservesBook)
{
  Order o = makeOrder(1, bob_, 1, 2, 30, 300);
  lockSellToken(bob_, 1, 30);
  restOrder(o);

  //  Persist the write txn.
  state_->commit(/*version=*/1);
  txn_->commit();

  //  Close the current view.
  state_.reset();
  txn_.reset();

  //  Reopen. A new read-only StateAccess on the same DB must
  //  see the order and the book row.
  StateDB &db = temp_.db();

  {
    auto read_state = std::make_unique<StateAccess>(db, /*version=*/1);

    Order reloaded;
    ASSERT_TRUE(read_state->getOrder(1, reloaded));
    ASSERT_EQ(reloaded.owner, bob_);
    ASSERT_EQ(reloaded.sell_amount, 30u);

    size_t count = 0;
    read_state->forEachBookLevel(
        1, 2, 0,
        [&](Id id, uint64_t, uint64_t)
        {
          ++count;
          EXPECT_EQ(id, 1u);
          return true;
        });
    ASSERT_EQ(count, 1u);

    //  The sequence counter persisted too: the next allocation
    //  must be strictly greater than the sequence the resting
    //  order was given.
    const uint64_t next = read_state->nextOrderSequence();
    ASSERT_GE(next, 2u);
  }
}