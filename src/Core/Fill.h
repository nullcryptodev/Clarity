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
  //  What produced a fill.
  //
  //    Limit  a taker crossed a resting maker. `maker_order_id` is
  //           the maker's id; `pool_id` is zero.
  //
  //    Amm    an order routed against an AMM pool. `maker_order_id`
  //           is zero; `pool_id` names the pool.
  //
  //  Exactly one of the two identifiers is nonzero. `isValid()`
  //  enforces this.
  enum class FillSource : uint8_t
  {
    Limit = 0,
    Amm = 1,
  };

  //  One execution.
  //
  //  Quantities are in the canonical frame of the pair:
  //    base  = min(sell_token, buy_token)
  //    quote = max(sell_token, buy_token)
  //    price = quote per base, scaled by OrderBook::BOOK_PRICE_SCALE
  //
  //  State codec layout (all multi-byte little-endian):
  //    [1]  source
  //    [8]  maker_order_id
  //    [8]  taker_order_id
  //    [4]  pool_id
  //    [8]  qty_base
  //    [8]  qty_quote
  //    [8]  price
  //    [4]  base_token
  //    [4]  quote_token
  struct Fill
  {
    FillSource source{FillSource::Limit};
    uint64_t maker_order_id{0};
    uint64_t taker_order_id{0};
    uint32_t pool_id{0};
    uint64_t qty_base{0};
    uint64_t qty_quote{0};
    uint64_t price{0};
    uint32_t base_token{0};
    uint32_t quote_token{0};

    static constexpr size_t STATE_SIZE = 1 + 8 + 8 + 4 + 8 + 8 + 8 + 4 + 4;

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len, Fill &out);

    bool isValid() const noexcept
    {
      if (taker_order_id == 0)
        return false;
      if (qty_base == 0)
        return false;
      if (base_token == quote_token)
        return false;

      switch (source)
      {
      case FillSource::Limit:
        if (maker_order_id == 0)
          return false;
        if (maker_order_id == taker_order_id)
          return false;
        if (pool_id != 0)
          return false;
        break;

      case FillSource::Amm:
        if (maker_order_id != 0)
          return false;
        if (pool_id == 0)
          return false;
        break;
      }

      return true;
    }
  };

} // namespace Core