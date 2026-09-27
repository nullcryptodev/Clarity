// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AccountEncoder.h"
#include "Encoding.h"

namespace Rpc
{

  Common::Json encodeAccount(const Core::Account &account)
  {
    Common::Json j = Common::Json::object();

    putU64(j, "nonce", account.nonce);
    putU64(j, "balance", account.balance);
    putU64(j, "staked", account.staked);
    putU64(j, "pending_rewards", account.pending_rewards);
    putU64(j, "last_reward_epoch", account.last_reward_epoch);
    putU64(j, "staker_since_height", account.staker_since_height);
    putU64(j, "created_at_height", account.created_at_height);

    j["staking_opted_out"] = account.staking_opted_out;

    // ---- Derived ----
    j["is_empty"] = account.isEmpty();
    putU64(j, "total_value", account.totalValue());

    return j;
  }

} // namespace Rpc