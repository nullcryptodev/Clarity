// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "Crypto/Types.h"
#include "StakingTypes.h"

#include "State/StateAccess.h"

namespace Core
{
  //  Global State
  //
  //  Chain-wide values stored under H("glob" || name) in the SMT.
  //  Each key stores a fixed-width or self-describing value.
  //
  //  These are read once per block, updated at epoch boundaries, and
  //  committed as part of the state root.

  // Named keys. Each is stored in the SMT under its hashed position.
  // NEVER change the string value of a key once deployed, that would
  // change its SMT position and lose the state.

  inline constexpr std::string_view GLOBAL_TOTAL_STAKED = "total_staked";
  inline constexpr std::string_view GLOBAL_POT = "pot";
  inline constexpr std::string_view GLOBAL_EPOCH_NUMBER = "epoch_number";
  inline constexpr std::string_view GLOBAL_TOTAL_SUPPLY = "total_supply";
  inline constexpr std::string_view GLOBAL_STAKER_COUNT = "staker_count";
  inline constexpr std::string_view GLOBAL_NEXT_TOKEN_ID = "next_token_id";
  inline constexpr std::string_view GLOBAL_NEXT_ORDER_ID = "next_order_id";
  inline constexpr std::string_view GLOBAL_NEXT_VALIDATOR_ID = "next_validator_id";
  inline constexpr std::string_view GLOBAL_ACTIVE_SET_SIZE = "active_set_size";
  inline constexpr std::string_view GLOBAL_LAST_ROTATION_H = "last_rotation_height";
  inline constexpr std::string_view GLOBAL_APY_ACTIVITY_BPS = "apy_activity_bps";
  inline constexpr std::string_view GLOBAL_APY_POT_BPS = "apy_pot_bps";

  //  ---- Bridge ----
  //
  //  Chain-agnostic bridge counters and flags. Per-chain
  //  configuration (wrapped token id, fingerprint, decimals, etc.)
  //  lives in the chain registration, not here. The operational
  //  signer set (active watchers) is resolved from state per
  //  verification and isn't stored as a global.
  //
  //  The governance signer set is the validator set. There is no
  //  GLOBAL_BRIDGE_GOVERNANCE_SET; governance transactions verify
  //  against the active validators directly.

  inline constexpr std::string_view GLOBAL_BRIDGE_PAUSED = "bridge_paused";
  inline constexpr std::string_view GLOBAL_BRIDGE_NEXT_WITHDRAWAL_ID = "bridge_next_withdrawal_id";
  inline constexpr std::string_view GLOBAL_BRIDGE_WITHDRAWALS_PENDING = "bridge_withdrawals_pending";
  inline constexpr std::string_view GLOBAL_BRIDGE_CONSUMED_COUNT = "bridge_consumed_count";
  inline constexpr std::string_view GLOBAL_BRIDGE_NEXT_WATCHER_ID = "bridge_next_watcher_id";

  // ---- Value encoders / decoders ----
  //
  //  Global state values are stored as raw bytes. Each type has a
  //  deterministic encoding.

  // Encode a uint64 as 8-byte little-endian.
  std::vector<uint8_t> encodeGlobalU64(uint64_t v);

  // Decode 8-byte little-endian uint64. Returns false if len != 8.
  bool decodeGlobalU64(const uint8_t *data, size_t len, uint64_t &out);

  //  GlobalStateReader / Writer
  //
  //  These are thin helpers over StateAccess. They exist so the code
  //  reads naturally: reader.totalStaked(), writer.setPot(x).
  //
  //  The actual SMT plumbing lives in StateAccess.

  class GlobalStateReader
  {
  public:
    explicit GlobalStateReader(const State::StateAccess &access) : access_(access) {}

    uint64_t totalStaked() const;
    uint64_t pot() const;
    uint64_t epochNumber() const;
    uint64_t totalSupply() const;
    uint64_t stakerCount() const;
    uint32_t nextTokenId() const;
    uint64_t nextOrderId() const;
    uint64_t nextValidatorId() const;
    uint32_t activeSetSize() const;
    uint64_t lastRotationHeight() const;
    uint16_t apyActivityBps() const;
    uint16_t apyPotBps() const;

    //  ---- Bridge ----

    bool bridgePaused() const;
    uint64_t bridgeNextWithdrawalId() const;
    uint64_t bridgeWithdrawalsPending() const;
    uint64_t bridgeConsumedCount() const;
    uint64_t bridgeNextWatcherId() const;

  private:
    const State::StateAccess &access_;
  };

  class GlobalStateWriter
  {
  public:
    explicit GlobalStateWriter(State::StateAccess &access) : access_(access) {}

    void setTotalStaked(uint64_t v);
    void setPot(uint64_t v);
    void setEpochNumber(uint64_t v);
    void setTotalSupply(uint64_t v);
    void setStakerCount(uint64_t v);
    void setNextTokenId(uint32_t v);
    void setNextOrderId(uint64_t v);
    void setNextValidatorId(uint64_t v);
    void setActiveSetSize(uint32_t v);
    void setLastRotationHeight(uint64_t v);
    void setApyActivityBps(uint16_t v);
    void setApyPotBps(uint16_t v);

    //  ---- Bridge ----

    void setBridgePaused(bool v);
    void setBridgeNextWithdrawalId(uint64_t v);
    void setBridgeWithdrawalsPending(uint64_t v);
    void setBridgeConsumedCount(uint64_t v);
    void setBridgeNextWatcherId(uint64_t v);

  private:
    State::StateAccess &access_;
  };

} // namespace Core