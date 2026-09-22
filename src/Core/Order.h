// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Serialization/ISerializer.h"

namespace Core
{
  //  Order — DEX order with conditional logic
  //
  //  Orders are stored in the SMT under key = H("ord " || order_id).
  //
  //  Each order has:
  //    - An owner, a token pair, an amount and a limit price
  //    - An execution mode (passive limit order or active AMM trigger)
  //    - Up to 8 conditions that, if any become false, cancel the order
  //    - An expiry height
  //
  //  Evaluation happens during block processing:
  //    - Every block, evaluate conditions for all orders that could be
  //      affected by this block's state changes
  //    - If any condition becomes false, remove the order and refund

  // How the order executes when conditions are met.
  enum class OrderExecutionMode : uint8_t
  {
    Passive = 0, // limit order in the book, waits for a taker
    Active = 1,  // executes against AMM when triggered
  };

  // The type of predicate in a condition.
  enum class OrderConditionType : uint8_t
  {
    Invalid = 0x00,
    ExpiresAtHeight = 0x01, // invalid when height >= param1
    PriceAbove = 0x02,      // invalid when price > param1 (scaled)
    PriceBelow = 0x03,      // invalid when price < param1 (scaled)
    VolumeBelow = 0x04,     // invalid when 24h volume < param1
    BalanceBelow = 0x05,    // invalid when creator's balance < param1
  };

  // A single condition. All conditions in an order must hold for the order
  // to remain valid. If any condition becomes false, the order is cancelled.
  struct OrderCondition
  {
    OrderConditionType type{OrderConditionType::Invalid};

    // Primary threshold. Interpretation depends on `type`:
    //   ExpiresAtHeight: the block height threshold
    //   PriceAbove/Below: price in atomic units (scaled)
    //   VolumeBelow: volume in atomic units
    //   BalanceBelow: balance in atomic units
    uint64_t param1{0};

    // Secondary parameter:
    //   PriceAbove/Below: the "other token" of the pair (e.g., token A of A/B)
    //   Others: unused (0)
    Id param2{0};

    bool isValid() const noexcept
    {
      return type != OrderConditionType::Invalid;
    }

    // State codec
    void serializeState(std::vector<uint8_t> &out) const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 size_t &offset, OrderCondition &out);
    static constexpr size_t STATE_SIZE = 1 + 8 + 4;
  };

  // Maximum number of conditions per order. 8 is generous for anything
  // realistic; more than that becomes a policy/complexity concern.
  inline constexpr size_t ORDER_MAX_CONDITIONS = 8;

  struct Order
  {
    Id id{INVALID_ID};
    Crypto::Address owner{};
    OrderExecutionMode mode{OrderExecutionMode::Passive};

    // ---- What is being traded ----
    Id sell_token{0};
    Id buy_token{0};
    uint64_t sell_amount{0};    // total amount to sell
    uint64_t min_buy_amount{0}; // minimum acceptable buy amount

    // ---- Lifecycle ----
    uint64_t created_at_height{0};
    uint64_t order_expires_at_height{0};

    // ---- Fill state ----
    uint64_t filled_amount{0}; // amount already filled

    // ---- Conditions ----
    uint8_t condition_count{0};
    OrderCondition conditions[ORDER_MAX_CONDITIONS]{};

    // ---- Validation ----

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

      // Validate each condition.
      for (uint8_t i = 0; i < condition_count; ++i)
      {
        if (!conditions[i].isValid())
          return false;
      }

      return true;
    }

    // Remaining amount still available for fills.
    uint64_t remainingAmount() const noexcept
    {
      return sell_amount - filled_amount;
    }

    bool isFullyFilled() const noexcept
    {
      return filled_amount >= sell_amount;
    }

    // ---- State serialization ----
    //
    // Layout:
    //   [8]  id
    //   [32] owner
    //   [1]  mode
    //   [4]  sell_token
    //   [4]  buy_token
    //   [8]  sell_amount
    //   [8]  min_buy_amount
    //   [8]  created_at_height
    //   [8]  order_expires_at_height
    //   [8]  filled_amount
    //   [1]  condition_count
    //   [N]  conditions (each 13 bytes)

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len, Order &out);

    static constexpr size_t STATE_SIZE_FIXED =
        8 + 32 + 1 + 4 + 4 + 8 + 8 + 8 + 8 + 8 + 1;
    static constexpr size_t STATE_SIZE_MAX =
        STATE_SIZE_FIXED + ORDER_MAX_CONDITIONS * OrderCondition::STATE_SIZE;

    // ---- Framework serialization ----

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core