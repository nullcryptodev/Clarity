// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "OrderBook.h"

#include "Crypto/Blake2b.h"

#include <algorithm>
#include <cstring>

namespace Core
{
  namespace OrderBook
  {
    namespace
    {
      //  u128 intermediate. Every multiply in canonicalPrice that
      //  could overflow u64 goes through here and is checked before
      //  narrowing. We use the compiler's __int128 if available and
      //  fall back to a hand-rolled 128-bit multiply-check otherwise.
      //  GCC and Clang both provide __int128 on 64-bit targets; the
      //  CMake build for this project already targets 64-bit only.

      inline bool mulFitsU64(uint64_t a, uint64_t b, uint64_t &out) noexcept
      {
        if (a == 0 || b == 0)
        {
          out = 0;
          return true;
        }
        const unsigned __int128 prod =
            static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b);
        if (prod > static_cast<unsigned __int128>(UINT64_MAX))
          return false;
        out = static_cast<uint64_t>(prod);
        return true;
      }
    } // anonymous namespace

    Crypto::Hash pairKey(uint32_t sell_token, uint32_t buy_token) noexcept
    {
      const uint32_t lo = std::min(sell_token, buy_token);
      const uint32_t hi = std::max(sell_token, buy_token);

      uint8_t buf[8];
      buf[0] = uint8_t(lo);
      buf[1] = uint8_t(lo >> 8);
      buf[2] = uint8_t(lo >> 16);
      buf[3] = uint8_t(lo >> 24);
      buf[4] = uint8_t(hi);
      buf[5] = uint8_t(hi >> 8);
      buf[6] = uint8_t(hi >> 16);
      buf[7] = uint8_t(hi >> 24);

      uint8_t domain_buf[4 + 8];
      std::memcpy(domain_buf, "obok", 4);
      std::memcpy(domain_buf + 4, buf, 8);

      Crypto::Hash h;
      Crypto::blake2b(domain_buf, sizeof(domain_buf),
                      h.data.data(), h.data.size());
      return h;
    }

    uint8_t sideOf(const Order &order) noexcept
    {
      return (order.sell_token < order.buy_token) ? 0 : 1;
    }

    bool canonicalPrice(const Order &order, uint64_t &out) noexcept
    {
      if (order.sell_amount == 0 || order.min_buy_amount == 0)
        return false;

      const bool sells_base = (order.sell_token < order.buy_token);

      if (sells_base)
      {
        //  floor(min_buy_amount * SCALE / sell_amount)
        uint64_t num = 0;
        if (!mulFitsU64(order.min_buy_amount, BOOK_PRICE_SCALE, num))
          return false;
        out = num / order.sell_amount;
      }
      else
      {
        //  ceil(sell_amount * SCALE / min_buy_amount)
        uint64_t num = 0;
        if (!mulFitsU64(order.sell_amount, BOOK_PRICE_SCALE, num))
          return false;
        const uint64_t den = order.min_buy_amount;
        out = num / den + ((num % den != 0) ? 1 : 0);
      }

      return true;
    }

    bool crosses(uint64_t taker_canonical_limit,
                 uint64_t maker_canonical_price,
                 uint8_t taker_side) noexcept
    {
      if (taker_side == 0)
        return maker_canonical_price >= taker_canonical_limit;
      return maker_canonical_price <= taker_canonical_limit;
    }

    bool isBetterPrice(uint64_t candidate,
                       uint64_t incumbent,
                       uint8_t side) noexcept
    {
      return (side == 0) ? (candidate > incumbent)
                         : (candidate < incumbent);
    }
  } // namespace OrderBook
} // namespace Core