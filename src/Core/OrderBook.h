// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>

#include "Core/Order.h"
#include "Crypto/Types.h"

namespace Core
{
  //  Canonical book frame
  //
  //  Orders are created directionally: a user says "sell A, buy B,
  //  receive at least M of B for N of A." That gives a rational
  //  limit price M/N in B-per-A. Two orders on opposite sides of
  //  the same pair — one selling A, one selling B — are the same
  //  market, but their limit prices are reciprocals.
  //
  //  The book canonicalizes to a single direction: quote per base,
  //  where base = min(sell_token, buy_token) and quote =
  //  max(sell_token, buy_token). Both sides of the pair then speak
  //  the same price language, and the matching engine's crossing
  //  check is a single comparison with no division in the hot loop.
  //
  //  The canonical price is stored scaled:
  //
  //    canonical_price = floor_or_ceil(limit * BOOK_PRICE_SCALE)
  //
  //  where the floor/ceil direction depends on which side of the
  //  pair the order is on, and is chosen so the scaled price is
  //  never *more* aggressive than the true rational price. See
  //  canonicalPrice() below.
  namespace OrderBook
  {
    //  10^10. Chosen to match PRICE_SCALE (which is used for
    //  condition price comparisons, a different concept) and to
    //  leave 4 digits of headroom above the 5-decimal native CLRTY
    //  granularity, so a pair quoted in CLRTY per tiny-token has
    //  enough resolution to be meaningful.
    //
    //  Do not confuse this with PRICE_SCALE. PRICE_SCALE is the
    //  scale of a condition's param1 as it appears on the wire;
    //  BOOK_PRICE_SCALE is the internal representation of a limit
    //  price in the book index. They happen to share a value today;
    //  they are independent and either may change without the other.
    inline constexpr uint64_t BOOK_PRICE_SCALE = 10'000'000'000ULL;

    //  Maximum number of resting orders a single taker will cross
    //  in one transaction. Bounds block-apply time. When the cap is
    //  hit, the taker's remainder rests; the next block's orders
    //  can continue crossing.
    //
    //  This is a consensus constant: it is part of the state-
    //  transition function and every node must enforce the same
    //  value. Changing it is a hard fork.
    inline constexpr size_t MAX_BOOK_LEVELS_PER_TAKER = 256;

    //  Pair key: Blake2b(min || max) over the two u32 token ids in
    //  little-endian order. Pair-symmetric: the key for (A, B) and
    //  the key for (B, A) are identical.
    Crypto::Hash pairKey(uint32_t sell_token, uint32_t buy_token) noexcept;

    //  Side byte for the book key.
    //    0 = the order sells the pair's min token (so it buys max)
    //    1 = the order sells the pair's max token (so it buys min)
    //
    //  The byte is what makes the two sides of one pair occupy
    //  disjoint key ranges, so a single prefix scan can iterate
    //  "all resting sells" or "all resting buys" without a filter.
    uint8_t sideOf(const Order &order) noexcept;

    //  Canonical price of an order, in quote-per-base, scaled by
    //  BOOK_PRICE_SCALE. Returns false on u128 overflow of the
    //  intermediate product — an order with min_buy_amount or
    //  sell_amount near u64::MAX times BOOK_PRICE_SCALE can exceed
    //  u128's practical range. Such an order cannot be placed in
    //  the book; the caller skips it and leaves it in a state the
    //  RPC surface reports as "unbookable."
    //
    //  Rounding:
    //    sell_token == base  (side 0, a seller):
    //        canonical_price = floor(min_buy_amount * SCALE / sell_amount)
    //      Floor makes the seller's limit look *lower* than the true
    //      rational, so it crosses *less* often. Conservative.
    //    sell_token == quote (side 1, a buyer):
    //        canonical_price = ceil(sell_amount * SCALE / min_buy_amount)
    //      Ceil makes the buyer's limit look *higher* than the true
    //      rational, so it also crosses less often. Conservative.
    //  In both cases the scaled price is on the "harder to cross"
    //  side of the exact rational. This is what makes the rounding
    //  rule safe: a fill that the exact rationals would have permitted
    //  is still permitted; a fill they would not have permitted is
    //  never invented by rounding.
    bool canonicalPrice(const Order &order, uint64_t &out) noexcept;

    //  True if a taker at `taker_canonical_limit` crosses a maker at
    //  `maker_canonical_price`. Direction depends on the taker's side.
    bool crosses(uint64_t taker_canonical_limit,
                 uint64_t maker_canonical_price,
                 uint8_t taker_side) noexcept;

    //  Best canonical price for an order side, used by the RPC
    //  order-book snapshot. For side 0 (sellers), the best is the
    //  highest price; for side 1 (buyers), the lowest.
    //
    //  This is a presentation helper. The matcher does not call it.
    bool isBetterPrice(uint64_t candidate,
                       uint64_t incumbent,
                       uint8_t side) noexcept;
  } // namespace OrderBook

} // namespace Core