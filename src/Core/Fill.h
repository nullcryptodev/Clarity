// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Crypto/Types.h"

namespace Core
{
  //  One execution of a taker order against a maker order.
  //
  //  A single taker transaction can produce several fills — one per
  //  resting order it crosses. The fills are recorded on the
  //  transaction's receipt in the order they executed, and the
  //  execution order is what makes a partial-fill history
  //  reconstructible from receipts alone.
  //
  //  All quantities are in the pair's canonical frame:
  //    base  = min(sell_token, buy_token)
  //    quote = max(sell_token, buy_token)
  //    price = quote per base, scaled by OrderBook::BOOK_PRICE_SCALE
  //    qty_base, qty_quote are in atomic units of the respective token
  //
  //  Storing fills in the canonical frame (rather than each order's
  //  own frame) means an explorer reading fills for a pair does not
  //  have to reconstruct which side each order was on to interpret
  //  the numbers. It also makes the fill history for a pair
  //  monotone in price and quantity, which is what a charting
  //  client expects.
  //
  //  Wire layout (55 bytes):
  //    [8]  maker_order_id (u64 LE)
  //    [8]  taker_order_id (u64 LE)
  //    [8]  qty_base       (u64 LE)
  //    [8]  qty_quote      (u64 LE)
  //    [8]  price          (u64 LE, canonical, scaled)
  //    [4]  base_token     (u32 LE)
  //    [4]  quote_token    (u32 LE)
  //    [7]  reserved (zeros; keeps the struct 8-byte aligned if a
  //         future field is added without breaking old readers,
  //         since the length is stored separately and old readers
  //         reject any trailing byte)
  //
  //  See serializeState / deserializeState for the actual codec.
  struct Fill
  {
    uint64_t maker_order_id{0};
    uint64_t taker_order_id{0};
    uint64_t qty_base{0};
    uint64_t qty_quote{0};
    uint64_t price{0};
    uint32_t base_token{0};
    uint32_t quote_token{0};

    static constexpr size_t STATE_SIZE = 8 + 8 + 8 + 8 + 8 + 4 + 4;

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len, Fill &out);

    bool isValid() const noexcept
    {
      return maker_order_id != 0 &&
             taker_order_id != 0 &&
             maker_order_id != taker_order_id &&
             qty_base != 0 &&
             base_token != quote_token;
    }
  };

} // namespace Core