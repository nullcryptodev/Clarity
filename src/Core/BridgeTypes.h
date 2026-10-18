// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "GlobalConfig.h"
#include "RewardTypes.h"
#include "Crypto/Types.h"
#include "Serialization/ISerializer.h"

namespace Core
{
  //  =========================================================================
  //  Bridge
  //
  //  Chain-agnostic core with per-chain adapters. The core knows that
  //  it is bridging *some* source chain to Clarity; it does not know
  //  which one. Everything chain-specific (source chain id, decimal
  //  scale, destination encoding, wrapped-token fingerprint, watcher
  //  adapter) lives in a per-chain adapter that registers itself with
  //  the core through a governance transaction.
  //
  //  The operational signer set is NOT here. It is the active bridge
  //  watcher set for a given source chain, resolved from state at
  //  every verification (see BridgeWatcherTypes.h). There is no
  //  per-set key bundle to store.
  //  =========================================================================

  inline constexpr size_t BRIDGE_MAX_WATCHERS = 100;
  inline constexpr size_t BRIDGE_DESTINATION_MIN_BYTES = 64;
  inline constexpr size_t BRIDGE_DESTINATION_MAX_BYTES = 256;

  //  Bridge source-chain registration
  //
  //  The CCX chain id as the bridge sees it. Same across all
  //  networks; the CCX chain itself is one chain.
  inline constexpr uint64_t BRIDGE_CCX_CHAIN_ID = 0x43435831ULL;

  //  A watcher's minimum stake. Locked, slashable, refundable only
  //  at unbonding expiry. Set equal to VALIDATOR_MIN_STAKE for v1;
  //  raise once the bridge holds value worth slashing more of.
  inline constexpr Amount BRIDGE_WATCHER_MIN_STAKE = GlobalConfig::VALIDATOR_MIN_STAKE;

  //  Blocks a watcher's unbonding lasts. Matches the validator
  //  unbonding period: long enough that a pending mint can't be
  //  sabotaged by a departing watcher racing to leave, short
  //  enough that a legitimate departure isn't stranded.
  inline constexpr uint64_t BRIDGE_WATCHER_UNBONDING_PERIOD =
      2 * ROTATION_INTERVAL;

  //  Blocks a watcher can be unseen before it's considered offline
  //  and dropped from the active set at the next recomputation.
  //  Matches the validator offline window.
  inline constexpr uint64_t BRIDGE_WATCHER_KICK_BLOCKS =
      OFFLINE_KICK_BLOCKS;

  //  Fraction of a watcher's stake slashed per attributable
  //  infraction (a witness attestation for a deposit or withdrawal
  //  that doesn't exist on the source chain). Same as the
  //  validator's equivocation penalty: 5% of current stake, plus
  //  the multiplier penalty.
  inline constexpr Bps BRIDGE_WATCHER_SLASH_AMOUNT_BPS =
      SLASH_AMOUNT_BPS;

  //  A watcher's minimum active-set size, per chain. If the active
  //  set drops below this, the bridge halts for that chain (no
  //  mint, no burn, no ack) until it grows. The halt is loud; a
  //  1-of-1 bridge is a bridge with a single point of failure.
  //
  //  This is per-chain because different source chains can require
  //  different minimums. CCX uses 2. The value is written into the
  //  BridgeChainRegistration at registration time (governance) so
  //  the check is part of the chain's configuration, not a global.
  inline constexpr uint32_t BRIDGE_CCX_ACTIVE_WATCHER_MIN = 2;

  using BridgeChainId = uint64_t;
  using BridgeWithdrawalId = uint64_t;

  //  A withdrawal record. Chain-agnostic; the destination is an
  //  opaque blob whose format is defined by the per-chain adapter.
  struct BridgeWithdrawal
  {
    BridgeWithdrawalId id{0};
    BridgeChainId source_chain_id{0};
    Id wrapped_token_id{0};
    Crypto::Address burner{};
    uint64_t amount{0};
    std::vector<uint8_t> destination_blob;
    uint64_t created_at_height{0};

    bool isWellFormed() const noexcept
    {
      if (id == 0)
        return false;
      if (source_chain_id == 0)
        return false;
      if (wrapped_token_id == 0)
        return false;
      if (burner.isNull())
        return false;
      if (amount == 0)
        return false;
      if (destination_blob.size() < BRIDGE_DESTINATION_MIN_BYTES)
        return false;
      if (destination_blob.size() > BRIDGE_DESTINATION_MAX_BYTES)
        return false;
      if (created_at_height == 0)
        return false;
      return true;
    }

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeWithdrawal &out);
    static constexpr size_t PREFIX_SIZE = 69;
    static constexpr size_t MAX_STATE_SIZE = PREFIX_SIZE + 256;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeWithdrawal::PREFIX_SIZE ==
                    8 + 8 + 4 + 32 + 8 + 8 + 1,
                "BridgeWithdrawal prefix size mismatch");

  //  Per-chain registry descriptor. Written by governance
  //  (BridgeRegisterChain), read by the executor and the watcher.
  struct BridgeChainRegistration
  {
    BridgeChainId source_chain_id{0};
    uint32_t wrapped_token_id{0};
    Crypto::Hash fingerprint{};
    uint8_t source_decimals{0};
    uint8_t clarity_decimals{0};
    uint16_t confirmation_depth{0};
    uint8_t destination_blob_min_len{0};
    uint8_t destination_blob_max_len{0};
    bool enabled{false};
    uint32_t active_watcher_min{0};

    bool isWellFormed() const noexcept
    {
      if (source_chain_id == 0)
        return false;
      if (wrapped_token_id == 0)
        return false;
      if (fingerprint.isNull())
        return false;
      if (destination_blob_min_len < BRIDGE_DESTINATION_MIN_BYTES)
        return false;
      if (destination_blob_max_len < destination_blob_min_len)
        return false;
      if (destination_blob_max_len > BRIDGE_DESTINATION_MAX_BYTES)
        return false;
      if (source_decimals > 18)
        return false;
      if (clarity_decimals > 18)
        return false;
      if (active_watcher_min < 1)
        return false;
      if (active_watcher_min > BRIDGE_MAX_WATCHERS)
        return false;
      return true;
    }

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeChainRegistration &out);
    static constexpr size_t STATE_SIZE =
        8 + 4 + 32 + 1 + 1 + 2 + 1 + 1 + 1 + 4; // == 55

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeChainRegistration::STATE_SIZE == 55,
                "BridgeChainRegistration state size mismatch");

  //  A single watcher's attestation over a bridge deposit.
  //
  //  Produced on-chain by a BridgeAttest transaction and stored in
  //  TBL_BRIDGE_ATTESTATIONS keyed by (source_chain_id,
  //  source_tx_hash, source_output_index, validator_id). A BridgeMint
  //  is valid iff a quorum of distinct active watchers has attested
  //  to the same (destination, amount) pair for the same deposit.
  //
  //  The `destination` and `amount` are stored in the record because
  //  the deposit does not exist as a first-class record until the
  //  mint happens. Attestations are the only pre-mint record of what
  //  watchers agreed the deposit was. The assembler validates that
  //  all attestations for a single deposit agree on these two fields
  //  before producing the mint's signature block; conflicting
  //  attestations are a federation split and must not be silently
  //  resolved.
  struct BridgeAttestation
  {
    //  The watcher's position in the sorted active watcher set at
    //  the height of the attestation. This is what goes into the
    //  BridgeMint's signature block; it is captured here so the
    //  block assembly is a pure function of what's in state.
    uint16_t signer_index{0};

    //  The watcher's signature over the canonical mint message
    //  (see Bridge::Signing::EncodeBridgeMintMessage).
    Crypto::Signature signature{};

    //  The deposit's destination and amount, as the watcher
    //  understood them.
    Crypto::Address destination{};
    uint64_t amount{0};

    //  The height of the BridgeAttest transaction that created
    //  this record. Used for the eventual slash path (a watcher
    //  that attested to a nonexistent deposit is slashed) and
    //  for the RPC response.
    uint64_t attested_at_height{0};

    bool isWellFormed() const noexcept
    {
      if (destination.isNull())
        return false;
      if (amount == 0)
        return false;
      if (signature.isNull())
        return false;
      if (attested_at_height == 0)
        return false;
      return true;
    }

    //  Layout (little-endian):
    //    [2]  signer_index
    //    [64] signature
    //    [32] destination
    //    [8]  amount
    //    [8]  attested_at_height
    //
    //  Total: 2 + 64 + 32 + 8 + 8 = 114 bytes.
    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeAttestation &out);
    static constexpr size_t STATE_SIZE = 2 + 64 + 32 + 8 + 8;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeAttestation::STATE_SIZE == 114,
                "BridgeAttestation state size mismatch");

  //  ---- Outcome enums ----
  //
  //  These describe what went wrong on a specific bridge operation.
  //  The signer-set-specific entries are gone; the watcher-set
  //  entries are new and describe the state of the watcher set at
  //  the height the transaction is checked.

  enum class BridgeMintStatus : uint8_t
  {
    Ok = 0,
    Paused = 1,
    ChainDisabled = 2,
    ChainNotRegistered = 3,
    TokenNotFound = 4,
    TokenFingerprintMismatch = 5,
    //  Active watcher set for this chain has fewer than the
    //  registration's active_watcher_min members, or the
    //  attestation block doesn't have enough valid signatures.
    WatcherSetTooSmall = 6,
    BelowWatcherThreshold = 7,
    BadWatcherSignature = 8,
    Replay = 9,
  };

  enum class BridgeBurnStatus : uint8_t
  {
    Ok = 0,
    Paused = 1,
    ChainDisabled = 2,
    ChainNotRegistered = 3,
    TokenNotFound = 4,
    TokenFingerprintMismatch = 5,
    InsufficientBalance = 6,
    DestinationTooShort = 7,
    DestinationTooLong = 8,
  };

  enum class BridgeAttestStatus : uint8_t
  {
    Ok = 0,
    Paused = 1,
    ChainNotRegistered = 2,
    ChainDisabled = 3,
    PayloadMalformed = 4,
    DepositAlreadyConsumed = 5,
    SignerIndexOutOfRange = 6,
    SignerNotActiveWatcher = 7,
    BadSignature = 8,
    AlreadyAttested = 9,
    ConflictingAttestation = 10,
  };

  const char *bridgeAttestStatusName(BridgeAttestStatus s) noexcept;

  enum class BridgeAckStatus : uint8_t
  {
    Ok = 0,
    Paused = 1,
    ChainNotRegistered = 3,
    WithdrawalNotFound = 13,
    WatcherSetTooSmall = 6,
    BelowWatcherThreshold = 7,
    BadWatcherSignature = 8,
  };

  const char *bridgeMintStatusName(BridgeMintStatus s) noexcept;
  const char *bridgeBurnStatusName(BridgeBurnStatus s) noexcept;
  const char *bridgeAckStatusName(BridgeAckStatus s) noexcept;
}