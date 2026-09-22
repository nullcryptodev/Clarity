// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Serialization/ISerializer.h"
#include "Crypto/Types.h"

namespace Core
{
  //  Account — the chain-level account
  //
  //  Stored in the SMT under key = H("acct" || address).
  //
  //  This is NOT the wallet account. Wallet accounts hold keypairs; chain
  //  accounts hold balance, nonce, and staking state. They share only the
  //  address.
  //
  //  Field invariants:
  //    - staked == 0 iff (staking_opted_out || balance < AUTO_STAKE_THRESHOLD)
  //    - staked == balance otherwise
  //
  //  These invariants are enforced on every write. See recalculateStaked().

  struct Account
  {
    // ---- Replay protection ----
    // Next expected nonce for transactions from this account.
    uint64_t nonce{0};

    // ---- Native CLRTY balance (atomic units, 5 decimals) ----
    uint64_t balance{0};

    // ---- Staking ----
    // Amount eligible for staking rewards. See invariant above.
    uint64_t staked{0};

    // Accrued, unclaimed staking rewards. Added to on each epoch boundary.
    uint64_t pending_rewards{0};

    // Last epoch for which this account's rewards were distributed.
    uint64_t last_reward_epoch{0};

    // Height at which this account most recently transitioned from
    // non-staker (staked == 0) to staker (staked > 0). Zero means the
    // account is not currently a staker (either opted out, below the
    // auto-stake threshold, or never funded).
    //
    // Used by the epoch boundary to credit partial epochs proportionally:
    // a staker that joined mid-epoch earns a fraction of the epoch's
    // payout equal to the fraction of the epoch they were staked for.
    // Without this, a staker could join immediately before an epoch
    // boundary and receive a full epoch's rewards.
    uint64_t staker_since_height{0};

    // ---- Metadata ----
    uint64_t created_at_height{0};

    // ---- Flags ----
    bool staking_opted_out{false};

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    bool isEmpty() const noexcept
    {
      return nonce == 0 && balance == 0 && staked == 0 &&
             pending_rewards == 0 && !staking_opted_out;
    }

    // Total value owned by this account (spendable balance + unclaimed).
    uint64_t totalValue() const noexcept
    {
      return balance + pending_rewards;
    }

    // Recompute `staked` from current balance + opt-out flag.
    // Called after every balance or opt-out change.
    //
    // Note: this does not touch `staker_since_height`. The caller
    // (StateAccess::putAccount) is responsible for setting or clearing
    // that field when the staker status actually transitions. The
    // recalculate function may be called multiple times within a single
    // transaction and the transition should only be recorded once, at
    // the first putAccount where the account becomes a staker.
    void recalculateStaked(uint64_t auto_stake_threshold) noexcept
    {
      if (staking_opted_out || balance < auto_stake_threshold)
      {
        staked = 0;
      }
      else
      {
        staked = balance;
      }
    }

    // ------------------------------------------------------------------
    //  Serialization
    // ------------------------------------------------------------------
    //
    //  Fixed-width little-endian, in field order. 57 bytes total.
    //  We do NOT use the general ISerializer framework for state — state
    //  is written to disk, and we want predictable byte layouts.

    // Serialize to a fixed 57-byte buffer.
    std::vector<uint8_t> serializeState() const;

    // Deserialize from a buffer. Returns false if the buffer is too short
    // or has unexpected content.
    static bool deserializeState(const uint8_t *data, size_t len,
                                 Account &out);

    // Size of the serialized form (always 57).
    static constexpr size_t STATE_SIZE =
        8 + 8 + 8 + 8 + 8 + 8 + 8 + 1;
    // nonce, balance, staked, pending_rewards,
    // last_reward_epoch, staker_since_height, created_at_height,
    // staking_opted_out

    // ---- Framework integration (for JSON/binary API responses) ----

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core