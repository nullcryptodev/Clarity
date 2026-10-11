// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Crypto/Types.h"

namespace Core
{
  //  Order — DEX order with conditional logic
  //
  //  [design spec comment from above goes here verbatim]

  //  How the order executes when conditions are met.
  enum class OrderExecutionMode : uint8_t
  {
    Passive = 0, // limit order in the book, waits for a taker
    Active = 1,  // executes against AMM when triggered
  };

  //  The type of predicate in a condition.
  enum class OrderConditionType : uint8_t
  {
    Invalid = 0x00,
    ExpiresAtHeight = 0x01, // invalid when height >= param1
    PriceAbove = 0x02,      // invalid when pool price > param1
    PriceBelow = 0x03,      // invalid when pool price < param1
    VolumeBelow = 0x04,     // invalid when rolling-epoch volume < param1
    BalanceBelow = 0x05,    // invalid when owner's CLRTY balance < param1
  };

  //  Price scaling. param1 for PriceAbove/PriceBelow is a price
  //  expressed as (amount_of_buy_token_per_unit_of_sell_token) ×
  //  PRICE_SCALE. The scale factor is chosen to preserve the smallest
  //  meaningful price granularity: 5 decimals of CLRTY plus 4 digits
  //  of headroom for tiny prices.
  inline constexpr uint64_t PRICE_SCALE = 10'000'000'000ULL; // 10^10

  //  Cancellation fee, in the sell token's atomic units. Charged when a
  //  condition fails and the order is cancelled by the evaluator. Also
  //  charged on explicit CancelOrder — same fee, one constant.
  inline constexpr uint64_t ORDER_CANCEL_FEE_ATOMIC = 1;

  //  A single condition. All conditions in an order must hold for the
  //  order to remain valid. If any condition becomes false, the order
  //  is cancelled and refunded.
  struct OrderCondition
  {
    OrderConditionType type{OrderConditionType::Invalid};

    //  Primary threshold. Interpretation depends on `type`:
    //    ExpiresAtHeight:  the block height threshold
    //    PriceAbove/Below: price × PRICE_SCALE (amount of buy token per
    //                      unit of sell token)
    //    VolumeBelow:      volume threshold in atomic CLRTY units
    //    BalanceBelow:     balance threshold in atomic CLRTY units
    uint64_t param1{0};

    //  Secondary parameter.
    //    PriceAbove/Below: pool_id
    //    VolumeBelow:      pool_id
    //    Others:           unused (0)
    uint32_t param2{0};

    bool isValid() const noexcept
    {
      if (type == OrderConditionType::Invalid)
        return false;

      //  Price and volume conditions must reference a pool.
      if (type == OrderConditionType::PriceAbove ||
          type == OrderConditionType::PriceBelow ||
          type == OrderConditionType::VolumeBelow)
      {
        if (param2 == 0)
          return false;
      }

      //  Non-pool conditions must not carry a pool id.
      if (type == OrderConditionType::ExpiresAtHeight ||
          type == OrderConditionType::BalanceBelow)
      {
        if (param2 != 0)
          return false;
      }

      //  A threshold of zero would make PriceAbove/Below or BalanceBelow
      //  evaluate as "always invalid" or "always valid" respectively,
      //  which is never what the user means.
      if (type == OrderConditionType::PriceAbove ||
          type == OrderConditionType::PriceBelow ||
          type == OrderConditionType::BalanceBelow)
      {
        if (param1 == 0)
          return false;
      }

      //  ExpiresAtHeight = 0 is a valid sentinel meaning "no expiry".
      //  VolumeBelow = 0 means "always valid", which is legal but useless;
      //  we accept it and let the user sort out their intent.

      return true;
    }

    //  ---- State codec ----
    //
    //  Fixed size on the wire: 1 + 8 + 4 = 13 bytes.
    //
    //  Layout:
    //    [1] type
    //    [8] param1, little-endian
    //    [4] param2, little-endian

    void serializeState(std::vector<uint8_t> &out) const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 size_t &offset, OrderCondition &out);

    static constexpr size_t STATE_SIZE = 1 + 8 + 4;
  };

  //  Maximum number of conditions per order. 8 is generous for anything
  //  realistic; more than that becomes a policy/complexity concern.
  inline constexpr size_t ORDER_MAX_CONDITIONS = 8;

  struct Order
  {
    Id id{INVALID_ID};
    Crypto::Address owner{};
    OrderExecutionMode mode{OrderExecutionMode::Passive};

    //  ---- What is being traded ----
    //
    //  Token IDs are u32 because the wire format stores them as u32
    //  and the pool_id in OrderCondition::param2 is also u32. Keeping
    //  the struct field the same width as the wire eliminates a class
    //  of silent truncation.
    uint32_t sell_token{0};
    uint32_t buy_token{0};

    uint64_t sell_amount{0};    // total amount to sell
    uint64_t min_buy_amount{0}; // minimum acceptable buy amount

    //  ---- Lifecycle ----
    uint64_t created_at_height{0};
    uint64_t order_expires_at_height{0};

    //  ---- Fill state ----
    uint64_t filled_amount{0}; // amount already filled

    //  ---- Conditions ----
    uint8_t condition_count{0};
    OrderCondition conditions[ORDER_MAX_CONDITIONS]{};

    //  ---- Validation ----

    bool isValid() const noexcept
    {
      if (id == INVALID_ID)
        return false;
      if (owner.isNull())
        return false;
      if (sell_token == buy_token)
        return false;
      if (sell_amount == 0)
        return false;
      if (min_buy_amount == 0)
        return false;
      if (filled_amount > sell_amount)
        return false;
      if (condition_count > ORDER_MAX_CONDITIONS)
        return false;
      if (mode != OrderExecutionMode::Passive &&
          mode != OrderExecutionMode::Active)
        return false;

      for (uint8_t i = 0; i < condition_count; ++i)
      {
        if (!conditions[i].isValid())
          return false;
      }

      return true;
    }

    uint64_t remainingAmount() const noexcept
    {
      return sell_amount - filled_amount;
    }

    bool isFullyFilled() const noexcept
    {
      return filled_amount >= sell_amount;
    }

    //  ---- State codec ----
    //
    //  Layout:
    //    [8]  id
    //    [32] owner
    //    [1]  mode
    //    [4]  sell_token
    //    [4]  buy_token
    //    [8]  sell_amount
    //    [8]  min_buy_amount
    //    [8]  created_at_height
    //    [8]  order_expires_at_height
    //    [8]  filled_amount
    //    [1]  condition_count
    //    [N]  conditions (each 13 bytes)
    //
    //  deserializeState rejects trailing bytes: the total length must
    //  equal STATE_SIZE_FIXED + condition_count * OrderCondition::STATE_SIZE.

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len, Order &out);

    static constexpr size_t STATE_SIZE_FIXED =
        8 + 32 + 1 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 1;
    static constexpr size_t STATE_SIZE_MAX =
        STATE_SIZE_FIXED + ORDER_MAX_CONDITIONS * OrderCondition::STATE_SIZE;
  };

} // namespace Core