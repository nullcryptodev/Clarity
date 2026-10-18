// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "BridgeTypes.h"

#include "Crypto/Types.h"
#include "GlobalConfig.h"
#include "Serialization/ISerializer.h"

namespace Core
{
  //  =========================================================================
  //  BridgeWatcherInfo
  //
  //  A registered bridge watcher. Watchers are the bridge's operational
  //  signer set: they attest that a deposit or withdrawal was observed
  //  on a source chain, and their signatures authorize a BridgeMint,
  //  BridgeBurn, or BridgeAckWithdrawal on Clarity.
  //
  //  A watcher is also a validator. The record carries a validator's
  //  id, and the watcher's signing identity is the validator's
  //  consensus key at the height of the attestation. This is deliberate:
  //  the watcher's accountability is the validator's accountability,
  //  and a watcher that lies is slashed the same way an equivocating
  //  validator is slashed. There is no separate "watcher key" to manage.
  //
  //  Two statuses: is_active (in the active set, can sign) and
  //  pending_unbond_height (has requested unregistration, still in the
  //  set until the cooldown elapses, still slashable). The active-set
  //  resolution and the threshold computation both use these fields.
  //
  //  =========================================================================
  struct BridgeWatcherInfo
  {
    //  Unique watcher id. Allocated from a monotonic counter. Watcher
    //  ids and validator ids are separate namespaces; a watcher record
    //  points at a validator by that validator's id.
    Id id{0};

    //  The validator whose consensus key signs this watcher's
    //  attestations. A validator can have at most one active watcher
    //  record per source chain (enforced at registration).
    Id validator_id{0};

    //  The chain this watcher covers. Today there's one (CCX); the
    //  field makes the record extensible to a second bridge without
    //  a schema change.
    uint64_t source_chain_id{0};

    //  Where the watcher's stipend goes, if any. Also the address
    //  that authorizes UnregisterBridgeWatcher. Same address as the
    //  validator's reward address by default; can be different.
    Crypto::Address reward_address{};

    //  Registration and stake.
    uint64_t registered_at_height{0};
    uint64_t stake{0};

    //  ---- Liveness ----
    //
    //  Updated every time the watcher's attestation is seen in a
    //  BridgeMint, BridgeBurn, or BridgeAckWithdrawal. A watcher
    //  unseen for BRIDGE_WATCHER_KICK_BLOCKS is considered offline
    //  and dropped from the active set at the next recomputation.
    uint64_t last_seen_height{0};

    //  ---- Status ----

    bool is_active{false};
    uint64_t became_active_at{0};
    uint64_t last_active_at{0};

    //  Non-zero while the watcher has requested unregistration and
    //  the cooldown has not elapsed. Between the request and the
    //  expiry:
    //    - the watcher is removed from the active set immediately
    //      (so it can't sign fresh attestations);
    //    - but the record and its stake remain present and
    //      slashable until pending_unbond_height;
    //    - attestations it signed *before* the request remain
    //      valid; a mint or burn it authorized doesn't get
    //      retroactively rejected because the watcher later
    //      unregistered.
    uint64_t pending_unbond_height{0};

    //  ---- Slashing history ----
    //
    //  Same shape as a validator's. A watcher that signs an
    //  attestation for a deposit or withdrawal that doesn't exist on
    //  the source chain is slashed; the slashing path reuses the
    //  validator's executeSystemSlash machinery, keyed by validator_id.
    uint16_t infraction_count{0};
    uint64_t last_infraction_height{0};

    //  ---- Convenience ----

    bool isWellFormed() const noexcept
    {
      if (id == 0)
        return false;
      if (validator_id == 0)
        return false;
      if (source_chain_id == 0)
        return false;
      if (reward_address.isNull())
        return false;
      if (stake == 0)
        return false;
      if (pending_unbond_height != 0 &&
          pending_unbond_height <= registered_at_height)
        return false;
      return true;
    }

    bool isUnbonding(uint64_t current_height) const noexcept
    {
      return pending_unbond_height != 0 &&
             current_height < pending_unbond_height;
    }

    bool isUnbondExpired(uint64_t current_height) const noexcept
    {
      return pending_unbond_height != 0 &&
             current_height >= pending_unbond_height;
    }

    //  A watcher is in the active set if it is active, not
    //  unbonding, and has been seen recently.
    bool isInActiveSet(uint64_t current_height) const noexcept
    {
      if (!is_active)
        return false;
      if (pending_unbond_height != 0)
        return false;
      if (last_seen_height == 0)
        return true; // freshly registered, not yet attested
      if (last_seen_height + BRIDGE_WATCHER_KICK_BLOCKS <
          current_height)
        return false;
      return true;
    }

    //  ---- State serialization ----
    //
    //  Layout (little-endian, in field order):
    //    [8]  id
    //    [8]  validator_id
    //    [8]  source_chain_id
    //    [32] reward_address
    //    [8]  registered_at_height
    //    [8]  stake
    //    [8]  last_seen_height
    //    [1]  is_active
    //    [8]  became_active_at
    //    [8]  last_active_at
    //    [8]  pending_unbond_height
    //    [2]  infraction_count
    //    [8]  last_infraction_height
    //
    //  Total: 8+8+8+32+8+8+8+1+8+8+8+2+8 = 115 bytes.

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeWatcherInfo &out);

    static constexpr size_t STATE_SIZE =
        8 + 8 + 8 + 32 + 8 + 8 + 8 + 1 + 8 + 8 + 8 + 2 + 8;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeWatcherInfo::STATE_SIZE == 115,
                "BridgeWatcherInfo state size mismatch");

  //  ---- Outcome enums ----

  enum class BridgeWatcherStatus : uint8_t
  {
    Ok = 0,
    NotAValidator = 1,
    AlreadyRegistered = 2,
    StakeTooLow = 3,
    ChainNotRegistered = 4,
    InsufficientBalance = 5,
    PendingUnbondInFlight = 6,
    NotRegistered = 7,
    AlreadyUnbonding = 8,
    ActiveSetWouldShrink = 9,
  };

  const char *bridgeWatcherStatusName(BridgeWatcherStatus s) noexcept;
}