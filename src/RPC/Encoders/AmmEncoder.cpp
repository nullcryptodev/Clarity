// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AmmEncoder.h"
#include "Encoding.h"

#include <cstdio>

namespace Rpc
{

  namespace
  {
    // Format a __uint128_t as "0x..." lowercase hex, no leading zeros.
    std::string encodeU128Hex(__uint128_t v)
    {
      if (v == 0)
        return "0x0";

      static constexpr char HEX_LOWER[] = "0123456789abcdef";
      std::string out;
      out.reserve(34);
      bool started = false;
      for (int shift = 124; shift >= 0; shift -= 4)
      {
        uint8_t nib = uint8_t((v >> shift) & 0xF);
        if (!started)
        {
          if (nib == 0)
            continue;
          started = true;
        }
        out.push_back(HEX_LOWER[nib]);
      }
      return "0x" + out;
    }

    // Approximate price as a decimal string. Purely for human display.
    // Uses double; not for financial math.
    std::string formatApprox(double v)
    {
      char buf[32];
      std::snprintf(buf, sizeof(buf), "%.10g", v);
      return std::string(buf);
    }
  } // anonymous namespace

  Common::Json encodeAmmPool(const Core::AmmPool &pool, const std::string &hrp)
  {
    Common::Json j = Common::Json::object();

    putU64(j, "id", pool.id);
    putAddress(j, "creator", pool.creator, hrp);
    putU64(j, "token_a", pool.token_a);
    putU64(j, "token_b", pool.token_b);
    putU64(j, "reserve_a", pool.reserve_a);
    putU64(j, "reserve_b", pool.reserve_b);
    putU64(j, "total_liquidity", pool.total_liquidity);
    j["fee_bps"] = pool.fee_bps;
    putU64(j, "created_at_height", pool.created_at_height);
    j["active"] = pool.active;

    // k = reserve_a * reserve_b, as 128-bit.
    j["k"] = encodeU128Hex(pool.k());

    // Approximate prices, for display only.
    if (pool.reserve_b != 0)
      j["price_a_per_b"] = formatApprox(
          static_cast<double>(pool.reserve_a) /
          static_cast<double>(pool.reserve_b));
    if (pool.reserve_a != 0)
      j["price_b_per_a"] = formatApprox(
          static_cast<double>(pool.reserve_b) /
          static_cast<double>(pool.reserve_a));

    return j;
  }

  Common::Json encodeAmmPosition(const Core::AmmPosition &position,
                                 const Core::AmmPool *pool,
                                 const std::string &hrp)
  {
    Common::Json j = Common::Json::object();

    putU64(j, "id", position.id);
    putAddress(j, "owner", position.owner, hrp);
    putU64(j, "pool_id", position.pool_id);
    putU64(j, "liquidity", position.liquidity);
    putU64(j, "created_at_height", position.created_at_height);

    if (pool != nullptr && pool->total_liquidity != 0)
    {
      // share_bps = position.liquidity * 10000 / pool.total_liquidity.
      // 128-bit intermediate to avoid overflow.
      __uint128_t share = static_cast<__uint128_t>(position.liquidity) * 10000;
      uint64_t share_bps = static_cast<uint64_t>(
          share / pool->total_liquidity);
      j["share_bps"] = static_cast<uint32_t>(share_bps);
    }

    return j;
  }

} // namespace Rpc