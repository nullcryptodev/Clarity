// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Account.h"

#include "Common/Wire.h"

namespace Core
{
  //  State serialization (fixed-width, deterministic)

  std::vector<uint8_t> Account::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(nonce);
    w.writeU64(balance);
    w.writeU64(staked);
    w.writeU64(pending_rewards);
    w.writeU64(last_reward_epoch);
    w.writeU64(staker_since_height);
    w.writeU64(created_at_height);
    w.writeU8(staking_opted_out ? 1 : 0);

    return out;
  }

  bool Account::deserializeState(const uint8_t *data, size_t len, Account &out)
  {
    //  Exact-length check. A serialized Account is exactly STATE_SIZE
    //  bytes; anything longer means the caller passed a buffer with
    //  trailing bytes, which is a bug on their side, not a valid
    //  encoding we should silently accept.
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    out.nonce = r.readU64();
    out.balance = r.readU64();
    out.staked = r.readU64();
    out.pending_rewards = r.readU64();
    out.last_reward_epoch = r.readU64();
    out.staker_since_height = r.readU64();
    out.created_at_height = r.readU64();
    out.staking_opted_out = (r.readU8() != 0);

    return r.ok();
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