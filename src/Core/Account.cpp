// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Account.h"

#include "Common/Put.h"
#include "Common/Read.h"

#include <cstring>

namespace Core
{
  //  State serialization (fixed-width, deterministic)

  std::vector<uint8_t> Account::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::putU64(out, nonce);
    Common::putU64(out, balance);
    Common::putU64(out, staked);
    Common::putU64(out, pending_rewards);
    Common::putU64(out, last_reward_epoch);
    Common::putU64(out, staker_since_height);
    Common::putU64(out, created_at_height);
    out.push_back(staking_opted_out ? 1 : 0);

    return out;
  }

  bool Account::deserializeState(const uint8_t *data, size_t len, Account &out)
  {
    if (len < STATE_SIZE)
      return false;

    out.nonce = Common::readU64(data + 0);
    out.balance = Common::readU64(data + 8);
    out.staked = Common::readU64(data + 16);
    out.pending_rewards = Common::readU64(data + 24);
    out.last_reward_epoch = Common::readU64(data + 32);
    out.staker_since_height = Common::readU64(data + 40);
    out.created_at_height = Common::readU64(data + 48);
    out.staking_opted_out = (data[56] != 0);

    return true;
  }

  //  Framework serialization (for API / JSON output)

  void Account::serialize(Serialization::ISerializer &s)
  {
    s(nonce, "nonce");
    s(balance, "balance");
    s(staked, "staked");
    s(pending_rewards, "pending_rewards");
    s(last_reward_epoch, "last_reward_epoch");
    s(staker_since_height, "staker_since_height");
    s(created_at_height, "created_at_height");
    s(staking_opted_out, "staking_opted_out");
  }

  void Account::serialize(Serialization::ISerializer &s) const
  {
    s(nonce, "nonce");
    s(balance, "balance");
    s(staked, "staked");
    s(pending_rewards, "pending_rewards");
    s(last_reward_epoch, "last_reward_epoch");
    s(staker_since_height, "staker_since_height");
    s(created_at_height, "created_at_height");
    s(staking_opted_out, "staking_opted_out");
  }

} // namespace Core