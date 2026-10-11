// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>

#include "Core/AmmPool.h"

namespace Core::ActiveRouter
{
  //  Compute the amount of `token_in` that can be swapped into a pool
  //  without making the effective execution price worse than
  //  `limit_price` (quote per base, scaled by BOOK_PRICE_SCALE).
  //
  //  Returns:
  //    std::nullopt   if no positive amount can be swapped at a price
  //                   that satisfies the limit. The caller treats
  //                   this as "the pool's spot price is already
  //                   beyond the limit; wait for the next epoch".
  //    0              if the pool has zero reserves on the relevant
  //                   side; the caller treats this as unroutable.
  //    positive       the maximum input amount that satisfies the
  //                   limit. The caller clamps it to the order's
  //                   remaining amount.
  //
  //  Math:
  //
  //    For a constant-product pool with reserves (a, b), fee f in
  //    basis points, and input y of the `in` side:
  //
  //      y_net  = y * (10000 - f) / 10000
  //      out(y) = b * y_net / (a + y_net)
  //
  //    The pool's execution price (out per input, in the same scale
  //    the caller passes for `limit_price`) is:
  //
  //      price(y) = out(y) / y
  //
  //    price(y) is monotonically decreasing in y for a constant-
  //    product pool. So the maximum y that satisfies
  //    price(y) >= limit is the y where price(y) == limit, computed
  //    in closed form:
  //
  //      price(y) * y = out(y)
  //      limit * y    = b * y_net / (a + y_net)
  //      y_net        = a * limit / (b - limit)    (with limit < b)
  //
  //    where `limit` is expressed in the same units as `b / a` and
  //    `y_net` is the input after the fee is deducted.
  //
  //    The caller converts `y_net` back to `y` by multiplying by
  //    10000 / (10000 - f), ceilings, and clamps to the order's
  //    remaining amount.
  //
  //  The caller passes the pool's reserves in the direction of the
  //  swap (reserve_in is the side being sold into, reserve_out is
  //  the side being received) and `limit_price` in the canonical
  //  scale (quote per base * BOOK_PRICE_SCALE). The math is scale-
  //  free because the limit is expressed in the same scale as the
  //  ratio `reserve_out / reserve_in`.
  //
  //  Fails (returns nullopt) if any of:
  //    - reserve_in == 0 or reserve_out == 0
  //    - the pool fee is >= 10000 bps
  //    - limit_price >= reserve_out * BOOK_PRICE_SCALE / reserve_in
  //      (the pool spot price is already worse than the limit)
  std::optional<uint64_t> maxInputWithinLimit(
      uint64_t reserve_in,
      uint64_t reserve_out,
      uint16_t fee_bps,
      uint64_t limit_price_scaled);

  //  Compute the output of a swap for a given input, using the same
  //  fee schedule as AmmPool::executeSwap. Exact, floored, no
  //  rounding surprises. The caller uses this on the amount
  //  returned by maxInputWithinLimit to compute the final qty_out.
  uint64_t computeOutput(
      uint64_t reserve_in,
      uint64_t reserve_out,
      uint16_t fee_bps,
      uint64_t amount_in);

  //  Compute the effective price of a swap: output per input, scaled
  //  by BOOK_PRICE_SCALE. Used to record the fill's price and to
  //  sanity-check maxInputWithinLimit in tests.
  uint64_t computeEffectivePrice(
      uint64_t reserve_in,
      uint64_t reserve_out,
      uint16_t fee_bps,
      uint64_t amount_in);
} // namespace Core::ActiveRouter