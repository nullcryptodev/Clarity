// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>

#include "Crypto/Types.h"

namespace Core
{
  //  Staking state
  //
  //  Staking is liquid: no lockup, no withdrawal delay. Users can spend
  //  their balance at any time. The "staked" amount is bookkeeping —
  //  it determines reward eligibility, not spendability.
  //
  //  Auto-stake rule: any account with balance >= AUTO_STAKE_THRESHOLD is
  //  automatically enrolled unless opted out. Opt-out is per-account.

  struct StakingInfo
  {
    // Total balance eligible for staking rewards. Equal to the account's
    // CLRTY balance when opted in, 0 when opted out.
    //
    // NOTE: this is a convenience cache. The authoritative balance lives
    // in the Account struct; this field exists so the reward calculator
    // doesn't need to look up every account.
    uint64_t staked{0};

    // Accrued but unclaimed rewards. Accumulated during epoch processing.
    // Cleared (and transferred to balance) on claim.
    uint64_t pending_rewards{0};

    // True if the user has explicitly opted out of auto-staking.
    // Default false (auto-staking is on).
    bool opted_out{false};

    // The epoch in which this account last had rewards applied.
    // Used to detect when an account needs to be caught up.
    uint64_t last_reward_epoch{0};

    // ---- Helpers ----

    // True if this account is currently earning staking rewards.
    bool isEarning() const noexcept
    {
      return !opted_out && staked > 0;
    }

    // Total value including pending rewards.
    uint64_t totalValue() const noexcept
    {
      return staked + pending_rewards;
    }

    void serialize(Serialization::ISerializer &s)
    {
      s(staked, "staked");
      s(pending_rewards, "pending_rewards");
      s(opted_out, "opted_out");
      s(last_reward_epoch, "last_reward_epoch");
    }

    void serialize(Serialization::ISerializer &s) const
    {
      s(staked, "staked");
      s(pending_rewards, "pending_rewards");
      s(opted_out, "opted_out");
      s(last_reward_epoch, "last_reward_epoch");
    }
  };

  //  Global staking state
  //
  //  Aggregated across all stakers. Updated once per epoch.

  struct GlobalStakingState
  {
    // Sum of all accounts' `staked` fields. Recomputed and verified
    // at each epoch boundary.
    uint64_t total_staked{0};

    // Number of accounts currently earning.
    uint64_t staker_count{0};

    // Current pot: excess rewards that couldn't be distributed because
    // total_staked was too low to absorb the full staker pool. Will be
    // released when staking pressure justifies it (via APY_pot_bonus).
    uint64_t pot{0};

    // Last height at which the pot and total_staked were recomputed.
    uint64_t last_update_height{0};

    // Current epoch number.
    uint64_t epoch_number{0};

    void serialize(Serialization::ISerializer &s)
    {
      s(total_staked, "total_staked");
      s(staker_count, "staker_count");
      s(pot, "pot");
      s(last_update_height, "last_update_height");
      s(epoch_number, "epoch_number");
    }

    void serialize(Serialization::ISerializer &s) const
    {
      s(total_staked, "total_staked");
      s(staker_count, "staker_count");
      s(pot, "pot");
      s(last_update_height, "last_update_height");
      s(epoch_number, "epoch_number");
    }
  };

} // namespace Core