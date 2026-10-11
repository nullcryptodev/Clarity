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

TEST(Core_OrderBookCanonicalPrice, SellBaseFloorBoundary)
{
  //  Sell 3 base, want >= 10 quote. Exact price = 10/3 = 3.333...
  //  floor(10 * SCALE / 3), SCALE = 10^10, is 33'333'333'333.
  Order o;
  o.sell_token = 1;
  o.buy_token = 2;
  o.sell_amount = 3;
  o.min_buy_amount = 10;

  uint64_t p = 0;
  ASSERT_TRUE(OrderBook::canonicalPrice(o, p));
  ASSERT_EQ(p, 33'333'333'333ULL);

  //  p is the floor of 10 * SCALE / 3. Two-sided check:
  //    p * 3 <= 10 * SCALE          (p is not above the floor)
  //    (p + 1) * 3 > 10 * SCALE     (p + 1 is above the floor)
  //  Together these pin p to be exactly the floor.
  const unsigned __int128 bound = 10ULL * OrderBook::BOOK_PRICE_SCALE;

  ASSERT_LE(static_cast<unsigned __int128>(p) * 3, bound);
  ASSERT_GT(static_cast<unsigned __int128>(p + 1) * 3, bound);
}

TEST(Core_OrderBookCanonicalPrice, SellQuoteCeilBoundary)
{
  //  Sell 10 quote, want >= 3 base. Canonical frame is quote per
  //  base, computed as ceil(sell * SCALE / min_buy).
  //  ceil(10 * 10^10 / 3) = 33'333'333'334.
  Order o;
  o.sell_token = 2;
  o.buy_token = 1;
  o.sell_amount = 10;
  o.min_buy_amount = 3;

  uint64_t p = 0;
  ASSERT_TRUE(OrderBook::canonicalPrice(o, p));
  ASSERT_EQ(p, 33'333'333'334ULL);

  ASSERT_GE(static_cast<unsigned __int128>(p) * 3,
            10ULL * OrderBook::BOOK_PRICE_SCALE);
  ASSERT_LT(static_cast<unsigned __int128>(p - 1) * 3,
            10ULL * OrderBook::BOOK_PRICE_SCALE);
}

TEST(Core_OrderBookCanonicalPrice, ReciprocalPricesCrossAtBoundary)
{
  //  Sell 100 base for 2500 quote  => canonical price 25 * SCALE.
  Order sell_base;
  sell_base.sell_token = 1;
  sell_base.buy_token = 2;
  sell_base.sell_amount = 100;
  sell_base.min_buy_amount = 2500;

  //  Sell 2500 quote for 100 base  => canonical price 25 * SCALE.
  Order sell_quote;
  sell_quote.sell_token = 2;
  sell_quote.buy_token = 1;
  sell_quote.sell_amount = 2500;
  sell_quote.min_buy_amount = 100;

  uint64_t p_base = 0, p_quote = 0;
  ASSERT_TRUE(OrderBook::canonicalPrice(sell_base, p_base));
  ASSERT_TRUE(OrderBook::canonicalPrice(sell_quote, p_quote));
  ASSERT_EQ(p_base, p_quote);

  //  Side 0 (sell base, a seller) crosses a side-1 maker when the
  //  maker's bid is at or above the seller's floor.
  ASSERT_TRUE(OrderBook::crosses(p_base, p_quote, /*side=*/0));
  ASSERT_TRUE(OrderBook::crosses(p_quote, p_base, /*side=*/1));

  //  A seller who raises their floor is *less* likely to cross:
  //  the maker's bid must now be even higher.
  ASSERT_FALSE(OrderBook::crosses(p_base + 1, p_quote, 0));

  //  A seller who lowers their floor is *more* likely to cross.
  ASSERT_TRUE(OrderBook::crosses(p_base - 1, p_quote, 0));

  //  The buyer's direction is the mirror: raising their limit
  //  crosses more, lowering crosses less.
  ASSERT_TRUE(OrderBook::crosses(p_quote + 1, p_base, 1));
  ASSERT_FALSE(OrderBook::crosses(p_quote - 1, p_base, 1));
}

TEST_F(Core_MatchingEngineTest, BookIteratesBestFirstBuySide)
{
  //  Three resting buyers, bidding different prices for token-1.
  //  Buy-side best-first means highest bid first.
  //
  //  Each order sells 30 token-2 and wants at least:
  //    low:   300 token-1  => 10 quote/base  (worse for the seller)
  //    mid:   600          => 20
  //    high:  900          => 30             (better for the seller)
  //
  //  Wait — a buy-side order sells quote and buys base. Its price
  //  in quote per base is sell_amount / min_buy_amount. So:
  //    low:   300/30 = 10  (bid 10)
  //    mid:   600/30 = 20
  //    high:  900/30 = 30  (best bid)
  Order low = makeOrder(1, bob_, 2, 1, 300, 30);
  Order mid = makeOrder(2, carol_, 2, 1, 600, 30);
  Order high = makeOrder(3, dave_, 2, 1, 900, 30);
  restOrder(low);
  restOrder(mid);
  restOrder(high);

  std::vector<Id> seen;
  state_->forEachBookLevel(
      1, 2, /*side=*/1,
      [&](Id order_id, uint64_t, uint64_t)
      {
        seen.push_back(order_id);
        return true;
      });

  ASSERT_EQ(seen.size(), 3u);
  ASSERT_EQ(seen[0], 3u); // highest bid first
  ASSERT_EQ(seen[1], 2u);
  ASSERT_EQ(seen[2], 1u);
}

TEST_F(Core_MatchingEngineTest, SequenceAssignmentDistinctWithinBlock)
{
  const uint64_t before = state_->nextOrderSequence();

  Order a = makeOrder(1, bob_, 1, 2, 30, 300);
  Order b = makeOrder(2, carol_, 1, 2, 30, 300);

  state_->putOrder(a);
  const uint64_t seq_a = state_->nextOrderSequence();

  state_->putOrder(b);
  const uint64_t seq_b = state_->nextOrderSequence();

  ASSERT_GT(seq_a, before);
  ASSERT_GT(seq_b, seq_a);
  ASSERT_NE(seq_a, seq_b);
}

TEST_F(Core_MatchingEngineTest, NoCrossTakerRests)
{
  //  Bob rests: sell 30 base at 300/30 = 10 quote/base.
  Order maker = makeOrder(1, bob_, 1, 2, 30, 300);
  lockSellToken(bob_, 1, 30);
  restOrder(maker);

  //  Alice takes: sell 2500 quote, want >= 100 base.
  //  Limit = 2500/100 = 25 quote/base. That's *above* Bob's
  //  asking price of 10, so she would cross... so flip it.
  //
  //  Sell 2500 quote, want >= 1000 base. Limit = 2.5 quote/base,
  //  which is below Bob's ask of 10. No cross.
  Order taker = makeOrder(2, alice_, 2, 1, 2500, 1000);

  const uint64_t supply_before = totalSupply();
  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);

  ASSERT_TRUE(outcome.fills.empty());
  ASSERT_TRUE(outcome.taker_rests);
  ASSERT_EQ(taker.filled_amount, 0u);
  ASSERT_EQ(taker.remainingAmount(), 2500u);

  //  Maker untouched.
  Order reloaded;
  ASSERT_TRUE(state_->getOrder(1, reloaded));
  ASSERT_EQ(reloaded.filled_amount, 0u);

  //  Both sides present in the book.
  size_t side0 = 0, side1 = 0;
  state_->forEachBookLevel(1, 2, 0,
                           [&](Id, uint64_t, uint64_t)
                           { ++side0; return true; });
  state_->forEachBookLevel(1, 2, 1,
                           [&](Id, uint64_t, uint64_t)
                           { ++side1; return true; });
  ASSERT_EQ(side0, 1u);
  ASSERT_EQ(side1, 1u);

  ASSERT_EQ(totalSupply(), supply_before);
}

TEST_F(Core_MatchingEngineTest, PriceImprovementFillsAtMakerPrice)
{
  //  Bob rests: sell 30 base at 10 quote/base.
  Order maker = makeOrder(1, bob_, 1, 2, 30, 300);
  lockSellToken(bob_, 1, 30);
  restOrder(maker);

  //  Alice takes: sell 3000 quote, want >= 30 base.
  //  Her limit = 3000/30 = 100 quote/base. She's willing to pay
  //  100, but Bob only asks 10. The fill must be at 10.
  Order taker = makeOrder(2, alice_, 2, 1, 3000, 30);

  const uint64_t supply_before = totalSupply();
  lockSellToken(alice_, 2, 3000);
  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);

  ASSERT_EQ(outcome.fills.size(), 1u);
  ASSERT_EQ(outcome.fills[0].qty_base, 30u);
  ASSERT_EQ(outcome.fills[0].qty_quote, 300u); // 30 * 10, not 30 * 100
  ASSERT_EQ(outcome.fills[0].price,
            10ULL * OrderBook::BOOK_PRICE_SCALE);

  //  Alice paid 300 for what she was willing to pay 3000 for.
  //  She has 2700 quote left, which rests.
  ASSERT_TRUE(outcome.taker_rests);
  ASSERT_EQ(taker.filled_amount, 300u);
  ASSERT_EQ(taker.remainingAmount(), 2700u);

  ASSERT_EQ(totalSupply(), supply_before);
}

TEST_F(Core_MatchingEngineTest, FilledAmountDenominatedInOwnSellToken)
{
  Order maker = makeOrder(1, bob_, 1, 2, 100, 2500);
  Order taker = makeOrder(2, alice_, 2, 1, 2500, 100);

  lockSellToken(bob_, 1, 100);
  lockSellToken(alice_, 2, 2500);
  restOrder(maker);
  state_->putOrder(taker);

  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);
  ASSERT_EQ(outcome.fills.size(), 1u);

  //  Both orders are fully filled and deleted. The denomination
  //  is checked through the balances.
  Order gone;
  ASSERT_FALSE(state_->getOrder(1, gone));
  ASSERT_FALSE(state_->getOrder(2, gone));

  ASSERT_EQ(state_->getTokenBalance(alice_, 1), 1'000'000u + 100u);
  ASSERT_EQ(state_->getTokenBalance(alice_, 2), 1'000'000u - 2500u);
  ASSERT_EQ(state_->getTokenBalance(bob_, 1), 1'000'000u - 100u);
  ASSERT_EQ(state_->getTokenBalance(bob_, 2), 1'000'000u + 2500u);
}

//  Same shape, but the maker survives so we can read
//  filled_amount on both sides and assert the units directly.
TEST_F(Core_MatchingEngineTest, FilledAmountUnitsBothSidesSurvive)
{
  //  Bob sells 200 base at 25 quote/base (5000 quote).
  Order maker = makeOrder(1, bob_, 1, 2, 200, 5000);
  lockSellToken(bob_, 1, 200);
  restOrder(maker);

  //  Alice takes 2500 quote, wants >= 100 base. Fills 100 base
  //  for 2500 quote. Bob survives with 100 base left.
  Order taker = makeOrder(2, alice_, 2, 1, 2500, 100);
  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);

  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);
  ASSERT_EQ(outcome.fills.size(), 1u);

  //  Maker's filled_amount is in token-1.
  Order m;
  ASSERT_TRUE(state_->getOrder(1, m));
  ASSERT_EQ(m.filled_amount, 100u);
  ASSERT_EQ(m.remainingAmount(), 100u);

  //  Taker's filled_amount is in token-2.
  ASSERT_EQ(taker.filled_amount, 2500u);
  ASSERT_EQ(taker.remainingAmount(), 0u);
}

TEST_F(Core_MatchingEngineTest, CancelAfterPartialFillRefundsRemainder)
{
  Order maker = makeOrder(1, bob_, 1, 2, 200, 5000);
  lockSellToken(bob_, 1, 200);
  restOrder(maker);

  Order taker = makeOrder(2, alice_, 2, 1, 2500, 100);
  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);
  ASSERT_EQ(outcome.fills.size(), 1u);
  ASSERT_EQ(outcome.fills[0].qty_base, 100u);

  //  Bob locked 200 base at order creation and received 2500
  //  quote (token-2) from the fill. His token-1 balance is
  //  1'000'000 - 200 = 999'800. The 100 base that moved to Alice
  //  never returns to Bob's token-1 balance — his compensation is
  //  the quote he received.
  const uint64_t bob_before_cancel = state_->getTokenBalance(bob_, 1);
  ASSERT_EQ(bob_before_cancel, 999'800u);

  Order m;
  ASSERT_TRUE(state_->getOrder(1, m));
  ASSERT_EQ(m.remainingAmount(), 100u);

  state_->removeFromOrderBook(m);
  state_->deleteOrder(1);
  const uint64_t refund = m.remainingAmount() - Core::ORDER_CANCEL_FEE_ATOMIC;
  state_->putTokenBalance(bob_, 1, bob_before_cancel + refund);

  ASSERT_EQ(state_->getTokenBalance(bob_, 1),
            bob_before_cancel + 100u - Core::ORDER_CANCEL_FEE_ATOMIC);
  ASSERT_LT(refund, m.sell_amount);
}

TEST_F(Core_MatchingEngineTest, SelfTradeContinuesToNextLevel)
{
  Order alice_rest = makeOrder(1, alice_, 1, 2, 30, 300);
  Order carol_rest = makeOrder(2, carol_, 1, 2, 30, 600);
  lockSellToken(alice_, 1, 30);
  lockSellToken(carol_, 1, 30);
  restOrder(alice_rest);
  restOrder(carol_rest);

  const uint64_t supply_before = totalSupply();
  const uint64_t alice_t1_before = state_->getTokenBalance(alice_, 1);
  //  1'000'000 - 30 = 999'970

  Order taker = makeOrder(3, alice_, 2, 1, 2500, 100);
  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);

  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);

  ASSERT_EQ(outcome.fills.size(), 1u);
  ASSERT_EQ(outcome.fills[0].maker_order_id, 2u);
  ASSERT_EQ(outcome.fills[0].qty_base, 30u);
  ASSERT_EQ(outcome.fills[0].qty_quote, 600u);

  Order gone;
  ASSERT_FALSE(state_->getOrder(1, gone));
  ASSERT_FALSE(state_->getOrder(2, gone));

  //  Alice's token-1 balance: -30 (lock), +29 (self-cancel refund
  //  net of fee), +30 (base bought from Carol). Net +29.
  ASSERT_EQ(state_->getTokenBalance(alice_, 1),
            alice_t1_before + 30u + 30u - Core::ORDER_CANCEL_FEE_ATOMIC);

  ASSERT_EQ(totalSupply(),
            supply_before - Core::ORDER_CANCEL_FEE_ATOMIC);
}

TEST_F(Core_MatchingEngineTest, PartialFillDoesNotMoveMakerBookRow)
{
  Order maker = makeOrder(1, bob_, 1, 2, 200, 5000);
  lockSellToken(bob_, 1, 200);
  restOrder(maker);

  //  Read the counter without advancing it.
  const uint64_t seq_before =
      state_->getGlobalU64("order:next_sequence");

  Order taker = makeOrder(2, alice_, 2, 1, 2500, 100);
  lockSellToken(alice_, 2, 2500);
  state_->putOrder(taker);
  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);
  ASSERT_EQ(outcome.fills.size(), 1u);
  ASSERT_EQ(outcome.fills[0].qty_base, 100u);
  ASSERT_FALSE(outcome.taker_rests); // taker fully filled, does not rest

  size_t count = 0;
  Id seen_id = 0;
  state_->forEachBookLevel(
      1, 2, 0,
      [&](Id id, uint64_t, uint64_t)
      {
        ++count;
        seen_id = id;
        return true;
      });
  ASSERT_EQ(count, 1u);
  ASSERT_EQ(seen_id, 1u);

  //  No new sequence was allocated: the maker's book row is
  //  unchanged and the taker never rested.
  ASSERT_EQ(state_->getGlobalU64("order:next_sequence"), seq_before);
}

TEST_F(Core_MatchingEngineTest, TakerStopsAtMaxBookLevels)
{
  //  Build MAX_BOOK_LEVELS_PER_TAKER + 2 resting makers, each
  //  selling 1 base at a distinct ascending price so the taker
  //  would cross all of them if uncapped.
  //
  //  Use two different owners so a self-trade cancel does not
  //  accidentally eat one of them.
  constexpr size_t N = Core::OrderBook::MAX_BOOK_LEVELS_PER_TAKER + 2;

  std::vector<Id> maker_ids;
  maker_ids.reserve(N);

  for (size_t i = 0; i < N; ++i)
  {
    const uint64_t price = i + 1; // quote per base
    Order m = makeOrder(static_cast<Id>(i + 1),
                        (i % 2 == 0) ? bob_ : carol_,
                        1, 2, /*sell_amount=*/1, /*min_buy_amount=*/price);
    lockSellToken(m.owner, 1, 1);
    restOrder(m);
    maker_ids.push_back(m.id);
  }

  //  Alice takes: sell a lot of quote, willing to buy at a very
  //  high implied price, so she would cross every resting maker.
  Order taker = makeOrder(static_cast<Id>(N + 1), alice_,
                          2, 1, /*sell_amount=*/1'000'000,
                          /*min_buy_amount=*/1);
  lockSellToken(alice_, 2, 1'000'000);
  state_->putOrder(taker);

  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);

  //  Exactly MAX_BOOK_LEVELS_PER_TAKER fills.
  ASSERT_EQ(outcome.fills.size(),
            Core::OrderBook::MAX_BOOK_LEVELS_PER_TAKER);

  //  The taker rests with the remainder.
  ASSERT_TRUE(outcome.taker_rests);

  //  Makers below the cap are gone; makers at and above the cap
  //  are untouched.
  for (size_t i = 0; i < N; ++i)
  {
    Order o;
    const bool present = state_->getOrder(maker_ids[i], o);

    if (i < Core::OrderBook::MAX_BOOK_LEVELS_PER_TAKER)
    {
      ASSERT_FALSE(present)
          << "maker " << i << " should have been fully filled";
    }
    else
    {
      ASSERT_TRUE(present)
          << "maker " << i << " should be untouched (cap hit)";
      ASSERT_EQ(o.filled_amount, 0u);
    }
  }

  //  The taker's remaining amount is what was not crossed.
  //  Each fill was 1 base; the taker sold quote, so its
  //  filled_amount is in quote.
  ASSERT_GT(taker.remainingAmount(), 0u);

  //  Book still has the two uncrossed makers on side 0, plus the
  //  taker on side 1.
  size_t side0 = 0, side1 = 0;
  state_->forEachBookLevel(1, 2, 0,
                           [&](Id, uint64_t, uint64_t)
                           { ++side0; return true; });
  state_->forEachBookLevel(1, 2, 1,
                           [&](Id, uint64_t, uint64_t)
                           { ++side1; return true; });
  ASSERT_EQ(side0, 2u);
  ASSERT_EQ(side1, 1u);
}

TEST(Core_OrderBookCanonicalPrice, RejectsOverflowingSellBase)
{
  //  sell_amount small, min_buy_amount huge. The intermediate
  //  min_buy_amount * SCALE overflows u128.
  Order o;
  o.sell_token = 1; // base, side 0: floor(min_buy * SCALE / sell)
  o.buy_token = 2;
  o.sell_amount = 1;
  o.min_buy_amount = std::numeric_limits<uint64_t>::max();

  uint64_t p = 0;
  ASSERT_FALSE(OrderBook::canonicalPrice(o, p));
}

TEST(Core_OrderBookCanonicalPrice, RejectsOverflowingSellQuote)
{
  //  sell_amount huge, min_buy_amount small. The intermediate
  //  sell_amount * SCALE overflows u128.
  Order o;
  o.sell_token = 2; // quote, side 1: ceil(sell * SCALE / min_buy)
  o.buy_token = 1;
  o.sell_amount = std::numeric_limits<uint64_t>::max();
  o.min_buy_amount = 1;

  uint64_t p = 0;
  ASSERT_FALSE(OrderBook::canonicalPrice(o, p));
}

TEST_F(Core_MatchingEngineTest, UnbookableOrderIsNotAddedToBook)
{
  //  A passive order whose canonical price overflows. The
  //  TransactionExecutor is responsible for not calling
  //  addToOrderBook on it; the matcher's own behaviour is:
  //  an unbookable order is not in the book, so it can neither
  //  cross nor be crossed.
  Order o = makeOrder(1, bob_, 1, 2,
                      /*sell_amount=*/1,
                      /*min_buy_amount=*/std::numeric_limits<uint64_t>::max());

  uint64_t p = 0;
  ASSERT_FALSE(OrderBook::canonicalPrice(o, p));

  //  Do not call addToOrderBook. Put the record, then verify the
  //  book has nothing.
  state_->putOrder(o);

  size_t count = 0;
  state_->forEachBookLevel(1, 2, 0,
                           [&](Id, uint64_t, uint64_t)
                           { ++count; return true; });
  ASSERT_EQ(count, 0u);

  //  And a taker cannot cross it: the matcher iterates the book,
  //  which is empty.
  Order taker = makeOrder(2, alice_, 2, 1, 1'000'000, 1);
  lockSellToken(alice_, 2, 1'000'000);
  state_->putOrder(taker);

  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);
  ASSERT_TRUE(outcome.fills.empty());
}

TEST_F(Core_MatchingEngineTest, SelfTradeCancelsDoNotConsumeCap)
{
  //  Build N self-orders owned by Alice at ascending prices,
  //  followed by one Carol order. The cap is on fills, so Alice's
  //  self-cancels should not count against it, and the taker
  //  should reach Carol.
  constexpr size_t N = 8;

  for (size_t i = 0; i < N; ++i)
  {
    const uint64_t price = 10 + i;
    Order m = makeOrder(static_cast<Id>(i + 1), alice_,
                        1, 2, /*sell=*/1, /*min_buy=*/price);
    lockSellToken(alice_, 1, 1);
    restOrder(m);
  }

  Order carol_maker = makeOrder(static_cast<Id>(N + 1), carol_,
                                1, 2, /*sell=*/1, /*min_buy=*/1'000);
  lockSellToken(carol_, 1, 1);
  restOrder(carol_maker);

  const uint64_t supply_before = totalSupply();

  //  Alice takes. Her own orders at 10..17 are all self-trades
  //  and get cancelled, then she reaches Carol's at 1000 and
  //  fills it.
  Order taker = makeOrder(static_cast<Id>(N + 2), alice_,
                          2, 1, /*sell=*/10'000, /*min_buy=*/1);
  lockSellToken(alice_, 2, 10'000);
  state_->putOrder(taker);

  auto outcome = matchPassiveOrder(*state_, taker, 1, 0);

  //  One fill: Carol's.
  ASSERT_EQ(outcome.fills.size(), 1u);
  ASSERT_EQ(outcome.fills[0].maker_order_id, carol_maker.id);

  //  Alice's own resting orders are all gone.
  for (size_t i = 0; i < N; ++i)
  {
    Order gone;
    ASSERT_FALSE(state_->getOrder(static_cast<Id>(i + 1), gone));
  }

  //  Carol's is gone (fully filled).
  Order gone;
  ASSERT_FALSE(state_->getOrder(carol_maker.id, gone));

  //  Supply drops by exactly N cancel fees.
  ASSERT_EQ(totalSupply(),
            supply_before - N * Core::ORDER_CANCEL_FEE_ATOMIC);
}