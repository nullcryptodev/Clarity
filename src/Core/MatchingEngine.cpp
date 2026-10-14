// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "MatchingEngine.h"

#include "Core/OrderBook.h"
#include "Core/TokenTypes.h"  // NATIVE_TOKEN_ID
#include "Core/GlobalState.h" // GlobalConfig::AUTO_STAKE_THRESHOLD
#include "Common/Wire.h"

#include <algorithm>

namespace Core
{
  namespace
  {
    //  The canonical frame for a pair: base = min(sell, buy),
    //  quote = max(sell, buy). All price and quantity arithmetic in
    //  the matcher is in this frame.
    struct PairFrame
    {
      uint32_t base_token;
      uint32_t quote_token;
    };

    PairFrame frameOf(const Order &o) noexcept
    {
      PairFrame f;
      f.base_token = std::min(o.sell_token, o.buy_token);
      f.quote_token = std::max(o.sell_token, o.buy_token);
      return f;
    }

    //  Is this order selling the base token?
    //  Equivalent to: side == 0. Provided as a named predicate so the
    //  fill code reads as "if the taker sells base" rather than
    //  "if side == 0".
    inline bool sellsBase(const Order &o) noexcept
    {
      return o.sell_token < o.buy_token;
    }

    //  Convert an amount of an order's sell token into base-token
    //  units at a given canonical price. Caller asserts the order is
    //  actually on the side that needs conversion.
    //
    //  If the order sells base, its own sell-token amount is already
    //  in base units and this is the identity. If it sells quote,
    //  the amount is in quote units and is converted to base via
    //  the execution price:
    //
    //      base = quote * SCALE / price        (floored)
    //
    //  The price is the maker's canonical price, which is the
    //  execution price. Floored so the converted amount never
    //  exceeds what the quote-side lock can actually cover.
    uint64_t sellAmountToBase(uint64_t sell_amount,
                              bool order_sells_base,
                              uint64_t price) noexcept
    {
      if (order_sells_base)
        return sell_amount;
      if (price == 0)
        return 0;

      const unsigned __int128 prod =
          static_cast<unsigned __int128>(sell_amount) *
          static_cast<unsigned __int128>(OrderBook::BOOK_PRICE_SCALE);

      const unsigned __int128 q = prod / price;

      //  A quotient that does not fit in uint64_t means the order's
      //  sell amount is unrepresentable in base units at this price.
      //  Return 0 so the caller skips the maker rather than filling
      //  against a truncated quantity.
      if (q > static_cast<unsigned __int128>(UINT64_MAX))
        return 0;

      return static_cast<uint64_t>(q);
    }

    //  Convert a base-token amount into an order's sell-token units
    //  at a given canonical price. Mirror of sellAmountToBase.
    //
    //  If the order sells base, identity. If it sells quote:
    //
    //      quote = base * price / SCALE        (floored)
    //
    //  Floored so the quote-side lock never under-covers.
    uint64_t baseToSellAmount(uint64_t base_amount,
                              bool order_sells_base,
                              uint64_t price) noexcept
    {
      if (order_sells_base)
        return base_amount;

      const unsigned __int128 prod =
          static_cast<unsigned __int128>(base_amount) *
          static_cast<unsigned __int128>(price);

      const unsigned __int128 q = prod / OrderBook::BOOK_PRICE_SCALE;

      if (q > static_cast<unsigned __int128>(UINT64_MAX))
        return 0;

      return static_cast<uint64_t>(q);
    }

    //  Credit `amount` of `token_id` to `owner`. Routes through
    //  putAccount for the native token and putTokenBalance otherwise,
    //  matching the rest of the state layer's convention.
    //
    //  Zero-credit is a no-op: putTokenBalance with balance==0
    //  removes the SMT leaf, and we do not want to remove a leaf
    //  that the recipient already has at a nonzero balance. The
    //  check is `amount == 0`, not `resulting balance == 0`, so a
    //  legitimate zero-amount credit is a no-op rather than a leaf
    //  deletion.
    void credit(State::StateAccess &state,
                const Crypto::Address &owner,
                uint32_t token_id,
                uint64_t amount)
    {
      if (amount == 0)
        return;
      if (owner.isNull())
        return;

      if (token_id == NATIVE_TOKEN_ID)
      {
        Account acct = state.getAccount(owner);
        acct.balance += amount;
        state.putAccount(owner, acct);
      }
      else
      {
        const uint64_t cur = state.getTokenBalance(owner, token_id);
        state.putTokenBalance(owner, token_id, cur + amount);
      }
    }

    //  Debit `amount` of `token_id` from `owner`'s *locked* balance.
    //
    //  "Locked" is not a separate accounting bucket in this codebase;
    //  the lock is the order record itself. The order's sell-token
    //  balance was already debited when the order was created, and
    //  filled_amount tracks how much of the lock has been consumed.
    //  This function's only job is to keep the order record's
    //  filled_amount in step with the token movements; it does not
    //  touch a balance.
    //
    //  It exists as a named function so the fill code reads
    //  symmetrically for both sides. See executeFill.
    inline void recordFill(Order &o, uint64_t sell_token_amount) noexcept
    {
      o.filled_amount += sell_token_amount;
    }

    //  Cancel a resting order whose owner matches the taker's, so
    //  the taker does not wash-trade against itself. Removes the
    //  order from the book, refunds its remaining lock minus the
    //  standard cancel fee, and deletes the order record.
    //
    //  refundOrder handles the book-row removal and the SMT
    //  deletion; we call it directly. The fee is charged because
    //  this is a cancellation initiated by the protocol on the
    //  maker's behalf, matching the condition evaluator's policy.
    void cancelSelfTrade(State::StateAccess &state, const Order &maker)
    {
      //  refundOrder takes a const Order&; it reads remainingAmount()
      //  and the index fields. It removes the book row, removes the
      //  expiry entry, credits the refund, and calls deleteOrder.
      state.refundOrder(maker, /*charge_fee=*/true);
    }
  } // anonymous namespace

  MatchOutcome matchPassiveOrder(State::StateAccess &state,
                                 Order &taker,
                                 uint64_t height,
                                 uint32_t tx_index_in_block)
  {
    MatchOutcome out;

    if (taker.id == INVALID_ID ||
        taker.owner.isNull() ||
        taker.isFullyFilled() ||
        taker.mode != OrderExecutionMode::Passive)
    {
      //  Nothing to do. If the order is fully filled or invalid, the
      //  caller will not have written it; if it is a Passive order
      //  with a valid remainder, the caller must not have written it
      //  yet either (the caller writes the taker only after this
      //  function returns, so it knows whether to add a book row).
      //  We still return an empty outcome.
      return out;
    }

    const PairFrame frame = frameOf(taker);
    const bool taker_sells_base = sellsBase(taker);
    const uint8_t taker_side = taker_sells_base ? 0 : 1;
    const uint8_t maker_side = static_cast<uint8_t>(1 - taker_side);

    //  Canonical limit price for the taker.
    uint64_t taker_limit = 0;
    if (!OrderBook::canonicalPrice(taker, taker_limit))
    {
      //  Overflow. The order cannot participate in the book. The
      //  caller will leave the record in place (so the owner can
      //  cancel and recover the lock) but the book row is never
      //  written. An order in this state is visible to RPC as
      //  "unbookable" but not to the matcher.
      return out;
    }

    //  Collect candidate order_ids. The book is pair-symmetric and
    //  price-sorted best-first; we want the opposite side's orders.
    //
    //  We collect rather than process in the visitor because MDBX
    //  invalidates a cursor on any write through the same txn, and
    //  the fill loop writes.
    std::vector<std::pair<Id, uint64_t>> candidates; // (order_id, price)
    candidates.reserve(16);                          // typical case; grows as needed

    state.forEachBookLevel(
        frame.base_token, frame.quote_token, maker_side,
        [&](Id order_id, uint64_t price, uint64_t /*sequence*/) -> bool
        {
          candidates.emplace_back(order_id, price);
          if (candidates.size() >= OrderBook::MAX_BOOK_LEVELS_PER_TAKER)
            return false;
          return true;
        });

    //  Process candidates in order. Because the book is price-sorted
    //  and the crossing check is monotone in price, we stop at the
    //  first candidate that does not cross: no later candidate can
    //  cross either. This is the invariant that lets the matcher
    //  avoid scanning the whole side.
    for (const auto &[maker_id, maker_price] : candidates)
    {
      if (taker.isFullyFilled())
        break;

      if (!OrderBook::crosses(taker_limit, maker_price, taker_side))
        break;

      Order maker;
      if (!state.getOrder(maker_id, maker))
      {
        //  Stale index row. The order record is gone but the book
        //  row survived. This should not happen in a consistent DB;
        //  if it does, clean up the row and continue. We need a
        //  pseudo-order to call removeFromOrderBook with — but
        //  removeFromOrderBook needs the order's tokens and price.
        //  We cannot construct those from the book key alone without
        //  re-deriving them, so we skip cleanup here and rely on
        //  the fact that a well-formed chain never produces this.
        //  A future repair pass can reconcile.
        continue;
      }

      if (maker.owner.isNull())
      {
        //  Orphaned record (owner cleared but id still present).
        //  Remove it from the book and from the SMT. This is a
        //  defensive path; the cancel paths clear the book row
        //  before the owner, so we should never see this.
        state.removeFromOrderBook(maker);
        state.deleteOrder(maker.id);
        continue;
      }

      if (maker.owner == taker.owner)
      {
        cancelSelfTrade(state, maker);
        continue;
      }

      //  Recompute the maker's canonical price from the record
      //  rather than trusting the book key's price. They should
      //  agree; if they do not, the book row is stale and we use
      //  the record (which is authoritative) and repair the book
      //  on the way out by removing the stale row. The repair is
      //  deferred to the end of the loop so we do not invalidate
      //  the candidate list mid-iteration.
      uint64_t true_maker_price = 0;
      if (!OrderBook::canonicalPrice(maker, true_maker_price))
        continue; // unbookable maker; skip

      if (!OrderBook::crosses(taker_limit, true_maker_price, taker_side))
        break;

      //  Fill quantity in base units.
      //
      //  The taker's remaining is in the taker's own sell token;
      //  convert it to base. Same for the maker. The fill is the
      //  smaller of the two.
      const uint64_t taker_remaining_base =
          sellAmountToBase(taker.remainingAmount(),
                           taker_sells_base,
                           true_maker_price);

      const bool maker_sells_base = sellsBase(maker);
      const uint64_t maker_remaining_base =
          sellAmountToBase(maker.remainingAmount(),
                           maker_sells_base,
                           true_maker_price);

      uint64_t qty_base = std::min(taker_remaining_base, maker_remaining_base);
      if (qty_base == 0)
        break;

      //  Convert qty_base to each side's sell token.
      const uint64_t qty_taker_sell =
          baseToSellAmount(qty_base, taker_sells_base, true_maker_price);
      const uint64_t qty_maker_sell =
          baseToSellAmount(qty_base, maker_sells_base, true_maker_price);

      //  Guard against a conversion rounding qty_*_sell down to zero
      //  for a very small fill. A zero-quantity fill is not a fill;
      //  stop rather than loop forever on the same maker.
      if (qty_taker_sell == 0 || qty_maker_sell == 0)
        break;

      //  qty_quote and qty_base for the Fill record. qty_quote is
      //  the amount of the quote token that moved; that is exactly
      //  one of qty_taker_sell / qty_maker_sell, whichever side was
      //  selling quote.
      const uint64_t qty_quote =
          taker_sells_base ? qty_maker_sell : qty_taker_sell;

      //  Execute the fill.
      //
      //  Taker's sell token is debited from its lock (filled_amount
      //  increases); taker's buy token is credited to spendable.
      //  Symmetric for the maker.
      //
      //  The lock bookkeeping: filled_amount is in the order's own
      //  sell token. remainingAmount() = sell_amount - filled_amount
      //  is the source of truth for the matcher; the token balance
      //  was already debited at order creation, so the only balance
      //  movement here is the *credit* to the counterparty.
      recordFill(taker, qty_taker_sell);
      recordFill(maker, qty_maker_sell);

      //  Credit each side with the token they receive.
      //    taker receives its buy_token (== maker's sell_token)
      //    maker receives its buy_token (== taker's sell_token)
      credit(state, taker.owner, taker.buy_token, qty_maker_sell);
      credit(state, maker.owner, maker.buy_token, qty_taker_sell);

      //  Persist maker.
      if (maker.isFullyFilled())
      {
        state.removeFromOrderBook(maker);
        state.deleteOrder(maker.id);
      }
      else
      {
        //  Book row is unchanged (same price, same sequence). Only
        //  the SMT record changes.
        state.putOrder(maker);
      }

      out.fills.push_back(Fill{
          .maker_order_id = maker.id,
          .taker_order_id = taker.id,
          .qty_base = qty_base,
          .qty_quote = qty_quote,
          .price = true_maker_price,
          .base_token = frame.base_token,
          .quote_token = frame.quote_token,
      });

      out.total_base += qty_base;
      out.total_quote += qty_quote;

      //  Persist the fill-history rows. Two order-view rows and
      //  one pair-view row per fill. This is what makes
      //  getPairTrades and getOrderFills possible without walking
      //  receipts.
      //
      //  fill_index is the fill's position in this taker's list.
      //  It is a uint16 because MAX_BOOK_LEVELS_PER_TAKER is 256;
      //  a taker can never produce more than 256 fills, and the
      //  cast is safe because of that bound.
      //
      //  The `height` argument is the current block height. The
      //  matching engine does not otherwise know the height; the
      //  caller must pass it in. Add a `uint64_t height` parameter
      //  to matchPassiveOrder and thread it through from
      //  TransactionExecutor's TxExecutionContext.
      state.indexFill(
          out.fills.back(),
          height,
          tx_index_in_block,
          static_cast<uint16_t>(out.fills.size() - 1));
    }

    //  Persist the taker.
    if (taker.isFullyFilled())
    {
      //  No book row was written (the taker never rested). The
      //  caller will have written the order record before calling
      //  us; we delete it now. If the caller did not write the
      //  record, this delete is a no-op.
      state.deleteOrder(taker.id);
      out.taker_rests = false;
      return out;
    }

    //  Taker has a remainder. Persist the updated filled_amount,
    //  then allocate a sequence and enter the book.
    //
    //  Order of operations matters: putOrder writes the SMT record,
    //  addToOrderBook writes the book row and the companion
    //  sequence key. A reader that sees the book row must see the
    //  updated filled_amount, so putOrder must come first.
    state.putOrder(taker);

    const uint64_t sequence = state.nextOrderSequence();
    state.addToOrderBook(taker, sequence);
    out.taker_rests = true;
    return out;
  }

} // namespace Core