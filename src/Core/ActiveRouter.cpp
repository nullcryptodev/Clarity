// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ActiveRouter.h"

#include "Core/OrderBook.h"

namespace Core::ActiveRouter
{
  std::optional<uint64_t> maxInputWithinLimit(
      uint64_t reserve_in,
      uint64_t reserve_out,
      uint16_t fee_bps,
      uint64_t limit_price_scaled)
  {
    if (reserve_in == 0 || reserve_out == 0)
      return std::nullopt;
    if (fee_bps >= 10'000)
      return std::nullopt;
    if (limit_price_scaled == 0)
      return std::nullopt;

    //  Spot price (out per in, scaled): reserve_out * SCALE / reserve_in.
    //  The pool is unusable for this order if the spot price is
    //  already below the limit.
    //
    //    reserve_out * SCALE / reserve_in < limit
    //    reserve_out * SCALE < limit * reserve_in
    //
    //  Computed in u128 to avoid overflow.
    const unsigned __int128 spot_num =
        static_cast<unsigned __int128>(reserve_out) *
        static_cast<unsigned __int128>(OrderBook::BOOK_PRICE_SCALE);
    const unsigned __int128 limit_den =
        static_cast<unsigned __int128>(limit_price_scaled) *
        static_cast<unsigned __int128>(reserve_in);

    if (spot_num <= limit_den)
      return std::nullopt;

    //  Closed form for the maximum input y that satisfies the
    //  limit in a fee-bearing constant-product pool.
    //
    //  Let:
    //    a    = reserve_in
    //    b    = reserve_out
    //    f    = fee fraction = fee_bps / 10'000
    //    L    = limit price (out per in, in the same scale as b/a)
    //    y    = gross input (what the caller passes to computeOutput)
    //    y_n  = net input after fee = y * (1 - f)
    //
    //  The pool's output for input y_n is:
    //    out(y) = b * y_n / (a + y_n)
    //
    //  The pool's effective execution price (output per gross input)
    //  is:
    //    price(y) = out(y) / y
    //             = b * y_n / (a + y_n) / y
    //             = b * (1 - f) / (a + y * (1 - f))
    //
    //  Solving price(y) = L for y:
    //    L * (a + y * (1 - f)) = b * (1 - f)
    //    L * a + L * y * (1 - f) = b * (1 - f)
    //    L * y * (1 - f) = b * (1 - f) - L * a
    //    y = (b * (1 - f) - L * a) / (L * (1 - f))
    //      = b / L - a / (1 - f)
    //
    //  So the correct closed form is y_max = b / L - a / (1 - f),
    //  NOT b / L - a. The difference matters: a / (1 - f) is larger
    //  than a, so subtracting a directly would leave y too large and
    //  the effective price at that y would dip below L.
    //
    //  In scaled integer arithmetic with L = limit_price_scaled / SCALE:
    //
    //    y_max = reserve_out * SCALE / limit_price_scaled
    //          - reserve_in * 10000 / (10000 - fee_bps)
    //
    //  Both divisions are floored. Flooring the first term makes the
    //  result no larger than the exact value; flooring the second
    //  term makes the subtracted quantity no larger than the exact
    //  value, so the result is no smaller than the exact value. On
    //  balance, the returned y is at most the exact maximum and at
    //  least the exact maximum minus ~1 unit, which combined with
    //  computeOutput's own floor keeps the effective price at or
    //  above L.

    const unsigned __int128 b_scaled =
        static_cast<unsigned __int128>(reserve_out) *
        static_cast<unsigned __int128>(OrderBook::BOOK_PRICE_SCALE) /
        static_cast<unsigned __int128>(limit_price_scaled);

    const unsigned __int128 a_adj =
        static_cast<unsigned __int128>(reserve_in) *
        static_cast<unsigned __int128>(10'000) /
        static_cast<unsigned __int128>(10'000 - fee_bps);

    if (b_scaled <= a_adj)
      return std::nullopt;

    const unsigned __int128 y_full = b_scaled - a_adj;

    if (y_full == 0)
      return std::nullopt;
    if (y_full > static_cast<unsigned __int128>(UINT64_MAX))
      return std::nullopt;

    return static_cast<uint64_t>(y_full);
  }

  uint64_t computeOutput(
      uint64_t reserve_in,
      uint64_t reserve_out,
      uint16_t fee_bps,
      uint64_t amount_in)
  {
    if (reserve_in == 0 || reserve_out == 0 || amount_in == 0)
      return 0;

    const uint64_t amount_in_with_fee =
        amount_in * (10'000 - fee_bps) / 10'000;

    const unsigned __int128 numerator =
        static_cast<unsigned __int128>(reserve_out) * amount_in_with_fee;
    const uint64_t denominator = reserve_in + amount_in_with_fee;

    if (denominator == 0)
      return 0;

    return static_cast<uint64_t>(numerator / denominator);
  }

  uint64_t computeEffectivePrice(
      uint64_t reserve_in,
      uint64_t reserve_out,
      uint16_t fee_bps,
      uint64_t amount_in)
  {
    if (amount_in == 0)
      return 0;

    const uint64_t out = computeOutput(reserve_in, reserve_out, fee_bps, amount_in);
    if (out == 0)
      return 0;

    const unsigned __int128 price =
        static_cast<unsigned __int128>(out) *
        static_cast<unsigned __int128>(OrderBook::BOOK_PRICE_SCALE);

    return static_cast<uint64_t>(price / amount_in);
  }
} // namespace Core::ActiveRouter