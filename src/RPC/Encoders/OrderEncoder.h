// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Common/Json.h"
#include "Core/Order.h"

namespace Rpc
{
  //  Order -> JSON
  //
  //  Fields:
  //    id                    (hex)
  //    owner                 (Bech32m)
  //    mode                  (string: "passive" | "active")
  //    mode_code             (number)
  //    sell_token            (hex)
  //    buy_token             (hex)
  //    sell_amount           (hex)
  //    min_buy_amount        (hex)
  //    filled_amount         (hex)
  //    remaining_amount      (hex; derived)
  //    created_at_height     (hex)
  //    order_expires_at_height (hex)
  //    is_fully_filled       (bool; derived)
  //    condition_count       (number)
  //    conditions            (array of condition objects)
  //
  //  Condition objects:
  //    type                  (string)
  //    type_code             (number)
  //    param1                (hex)
  //    param2                (hex)
  //    description           (string; human-readable for common cases)

  Common::Json encodeOrder(const Core::Order &order, const std::string &hrp);
}