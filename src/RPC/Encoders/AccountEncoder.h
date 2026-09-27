// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "Common/Json.h"
#include "Core/Account.h"

namespace Rpc
{
  //  Account -> JSON
  //
  //  Fields:
  //    nonce               (hex)
  //    balance             (hex)
  //    staked              (hex)
  //    pending_rewards     (hex)
  //    last_reward_epoch   (hex)
  //    staker_since_height (hex)
  //    created_at_height   (hex)
  //    staking_opted_out   (bool)
  //    is_empty            (bool; derived)
  //    total_value         (hex; balance + pending_rewards)

  Common::Json encodeAccount(const Core::Account &account);
}