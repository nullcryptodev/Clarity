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
  //  Order — DEX order
  //
  //  Two execution modes:
  //
  //    Passive   rests in the price-time-priority book and is matched
  //              by MatchingEngine against incoming takers.
  //
  //    Active    routes against an AMM pool. `pool_id` names the pool.
  //              An Active order with no conditions executes on
  //              creation; an Active order with conditions executes at
  //              an epoch boundary when they hold. A partial execution
  //              leaves the order in state and it reattempts at the
  //              next epoch until fully filled.
  //
  //  `pool_id` is meaningful only for Active orders. It must be zero
  //  for Passive orders. `isValid()` enforces this.

  enum class OrderExecutionMode : uint8_t
  {
    Passive = 0,
    Active = 1,
  };

  enum class OrderConditionType : uint8_t
  {
    Invalid = 0x00,
    ExpiresAtHeight = 0x01,
    PriceAbove = 0x02,
    PriceBelow = 0x03,
    VolumeBelow = 0x04,
    BalanceBelow = 0x05,
  };

  inline constexpr uint64_t PRICE_SCALE = 10'000'000'000ULL;
  inline constexpr uint64_t ORDER_CANCEL_FEE_ATOMIC = 1;

  struct OrderCondition
  {
    OrderConditionType type{OrderConditionType::Invalid};
    uint64_t param1{0};
    uint32_t param2{0};

    bool isValid() const noexcept
    {
      if (type == OrderConditionType::Invalid)
        return false;

      if (type == OrderConditionType::PriceAbove ||
          type == OrderConditionType::PriceBelow ||
          type == OrderConditionType::VolumeBelow)
      {
        if (param2 == 0)
          return false;
      }

      if (type == OrderConditionType::ExpiresAtHeight ||
          type == OrderConditionType::BalanceBelow)
      {
        if (param2 != 0)
          return false;
      }

      if (type == OrderConditionType::PriceAbove ||
          type == OrderConditionType::PriceBelow ||
          type == OrderConditionType::BalanceBelow)
      {
        if (param1 == 0)
          return false;
      }

      return true;
    }

    void serializeState(std::vector<uint8_t> &out) const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 size_t &offset, OrderCondition &out);

    static constexpr size_t STATE_SIZE = 1 + 8 + 4;
  };

  inline constexpr size_t ORDER_MAX_CONDITIONS = 8;

  struct Order
  {
    Id id{INVALID_ID};
    Crypto::Address owner{};
    OrderExecutionMode mode{OrderExecutionMode::Passive};

    //  AMM pool targeted by an Active order. Zero for Passive.
    uint32_t pool_id{0};

    uint32_t sell_token{0};
    uint32_t buy_token{0};

    uint64_t sell_amount{0};
    uint64_t min_buy_amount{0};

    uint64_t created_at_height{0};
    uint64_t order_expires_at_height{0};

    uint64_t filled_amount{0};

    uint8_t condition_count{0};
    OrderCondition conditions[ORDER_MAX_CONDITIONS]{};

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

      //  pool_id is meaningful only for Active orders.
      if (mode == OrderExecutionMode::Active)
      {
        if (pool_id == 0)
          return false;
      }
      else
      {
        if (pool_id != 0)
          return false;
      }

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

    //  State codec layout (all multi-byte little-endian):
    //    [8]  id
    //    [32] owner
    //    [1]  mode
    //    [4]  pool_id
    //    [4]  sell_token
    //    [4]  buy_token
    //    [8]  sell_amount
    //    [8]  min_buy_amount
    //    [8]  created_at_height
    //    [8]  order_expires_at_height
    //    [8]  filled_amount
    //    [1]  condition_count
    //    [N]  conditions
    //
    //  deserializeState rejects any length other than the exact
    //  size implied by condition_count.

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len, Order &out);

    static constexpr size_t STATE_SIZE_FIXED =
        8 + 32 + 1 + 4 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 1;
    static constexpr size_t STATE_SIZE_MAX =
        STATE_SIZE_FIXED + ORDER_MAX_CONDITIONS * OrderCondition::STATE_SIZE;
  };

} // namespace Core