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
  //  scale, destination encoding, wrapped-token fingerprint) lives in
  //  a per-chain adapter that registers itself with the core through
  //  a governance transaction.
  //
  //  The operational signer set is the active validator set. A
  //  validator IS a bridge watcher: there is no separate watcher
  //  role, no separate stake, no per-chain registration. Attestation
  //  quorums are computed against the active validator set at the
  //  height of the operation, using bftQuorum(active_validators).
  //
  //  A validator that does not run a node for a given source chain
  //  simply does not submit attestations for that chain; if enough
  //  other validators do, quorum is reached without them. If not,
  //  the bridge for that chain stalls until the shortfall is
  //  corrected. This is a deliberate design choice: validators are
  //  the bridge's witness set, and the set's size determines the
  //  chain's liveness.
  //  =========================================================================

  inline constexpr size_t BRIDGE_MAX_WATCHERS = 100;
  inline constexpr size_t BRIDGE_DESTINATION_MIN_BYTES = 1;
  inline constexpr size_t BRIDGE_DESTINATION_MAX_BYTES = 255;

  //  ---- Deposit-destination registry bounds ----
  //
  //  A single rclrty1... authority may register at most
  //  MAX_BRIDGE_DEPOSITS_PER_AUTHORITY destinations per source
  //  chain. A bridge with 8 destinations per user is enough for
  //  main + a handful of merchant/cold-storage addresses; beyond
  //  that, the user creates a fresh Clarity account.
  //
  //  A single source chain may hold at most
  //  MAX_BRIDGE_DEPOSITS_PER_CHAIN destinations in total. The
  //  watcher's CCX scanner derives and checks one subaddress per
  //  registered index (see commit 6.4), and the derivation +
  //  matching cost is O(number of registered indices). Capping
  //  at 100,000 keeps that cost bounded: 100k subaddress
  //  derivations is a startup cache; 1M is a scanner that never
  //  finishes a poll.
  //
  //  Both caps are consensus constants. Changing either is a hard
  //  fork; they are per-chain, so raising one chain's cap does
  //  not require touching another's.
  inline constexpr uint64_t MAX_BRIDGE_DEPOSITS_PER_AUTHORITY = 8;
  inline constexpr uint64_t MAX_BRIDGE_DEPOSITS_PER_CHAIN = 100'000;

  //  The CCX chain id as the bridge sees it. Same across all
  //  networks; the CCX chain itself is one chain.
  inline constexpr uint64_t BRIDGE_CCX_CHAIN_ID = 0x43435831ULL;

  //  A watcher's minimum stake is now the validator's stake; this
  //  constant is retained only for wire-format compatibility with
  //  pre-existing registrations. It is not consulted anywhere.
  inline constexpr Amount BRIDGE_WATCHER_MIN_STAKE = GlobalConfig::VALIDATOR_MIN_STAKE;

  using BridgeChainId = uint64_t;
  using BridgeWithdrawalId = uint64_t;

  //  =========================================================================
  //  BridgeDepositRecord
  //
  //  A per-authority deposit destination for a bridge source
  //  chain. Created by BridgeRegisterDeposit; the executor assigns
  //  the index from a per-chain counter. The watcher resolves a
  //  CCX subaddress from the index using the bridge's custody
  //  keys (see commit 6.2/6.4) — the deposit to that subaddress
  //  mints to `destination`.
  //
  //  Bitcoin does not use this table: the OP_RETURN on the
  //  deposit carries the destination directly and there is
  //  nothing to register. The record is chain-agnostic even
  //  though only CCX currently consults it, because the shape is
  //  useful for any chain whose deposit format cannot carry a
  //  32-byte destination inline.
  //
  //  Lifecycle: created by BridgeRegisterDeposit, never modified,
  //  never deleted. A re-registration from the same authority
  //  creates a new record at a new index; the old one remains and
  //  continues to mint deposits to its destination. This is the
  //  correct behavior — a user who rotates their destination
  //  wants deposits to the old subaddress to keep landing at the
  //  old address, and new deposits to land at the new one.
  struct BridgeDepositRecord
  {
    BridgeChainId source_chain_id{0};
    uint64_t index{0};
    Crypto::Address destination{};
    Crypto::Address authority{};
    uint64_t registered_at_height{0};

    bool isWellFormed() const noexcept
    {
      if (source_chain_id == 0)
        return false;
      if (index == 0)
        return false;
      if (destination.isNull())
        return false;
      if (authority.isNull())
        return false;
      if (registered_at_height == 0)
        return false;
      return true;
    }

    //  Layout (little-endian):
    //    [8]  source_chain_id
    //    [8]  index
    //    [32] destination
    //    [32] authority
    //    [8]  registered_at_height
    //
    //  Total: 8 + 8 + 32 + 32 + 8 = 88 bytes.
    static constexpr size_t STATE_SIZE = 88;

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeDepositRecord &out);

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeDepositRecord::STATE_SIZE == 88,
                "BridgeDepositRecord state size mismatch");

  //  A withdrawal record. Chain-agnostic; the destination is an
  //  opaque blob whose format is defined by the per-chain adapter.
  //
  //  (rest unchanged)
  struct BridgeWithdrawal
  {
    BridgeWithdrawalId id{0};
    BridgeChainId source_chain_id{0};
    Id wrapped_token_id{0};
    Crypto::Address burner{};
    uint64_t amount{0};

    std::vector<uint8_t> destination_blob;
    std::string destination_address;

    uint64_t created_at_height{0};
    Crypto::Hash release_tx_hash{};
    uint64_t release_height{0};
    uint64_t released_at_height{0};
    Id released_by_validator_id{0};

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
      if (destination_blob.empty())
        return false;
      if (destination_blob.size() > BRIDGE_DESTINATION_MAX_BYTES)
        return false;
      if (destination_address.empty())
        return false;
      if (created_at_height == 0)
        return false;

      const bool released = !release_tx_hash.isNull();
      if (released)
      {
        if (release_height == 0)
          return false;
        if (released_at_height == 0)
          return false;
        if (released_by_validator_id == 0)
          return false;
      }
      else
      {
        if (release_height != 0)
          return false;
        if (released_at_height != 0)
          return false;
        if (released_by_validator_id != 0)
          return false;
      }
      return true;
    }

    bool isReleased() const noexcept
    {
      return !release_tx_hash.isNull();
    }

    static constexpr size_t PREFIX_SIZE = 69;
    static constexpr size_t MAX_ADDRESS_BYTES = 256;
    static constexpr size_t RELEASE_TRAILER_SIZE = 32 + 8 + 8 + 8;
    static constexpr size_t MAX_STATE_SIZE =
        PREFIX_SIZE + BRIDGE_DESTINATION_MAX_BYTES +
        1 + MAX_ADDRESS_BYTES + RELEASE_TRAILER_SIZE;

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeWithdrawal &out);

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeWithdrawal::PREFIX_SIZE ==
                    8 + 8 + 4 + 32 + 8 + 8 + 1,
                "BridgeWithdrawal prefix size mismatch");

  //  Per-chain registry descriptor. Written by governance
  //  (BridgeRegisterChain), read by the executor.
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
    uint32_t active_validator_min{0};

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
      if (active_validator_min < 1)
        return false;
      if (active_validator_min > BRIDGE_MAX_WATCHERS)
        return false;
      return true;
    }

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeChainRegistration &out);
    static constexpr size_t STATE_SIZE =
        8 + 4 + 32 + 1 + 1 + 2 + 1 + 1 + 1 + 4;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeChainRegistration::STATE_SIZE == 55,
                "BridgeChainRegistration state size mismatch");

  //  A single validator's attestation over a bridge deposit.
  //  (rest unchanged)
  struct BridgeAttestation
  {
    uint16_t signer_index{0};
    Crypto::Signature signature{};
    Crypto::Address destination{};
    uint64_t amount{0};
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

    static constexpr size_t STATE_SIZE = 2 + 64 + 32 + 8 + 8;

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeAttestation &out);

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeAttestation::STATE_SIZE == 114,
                "BridgeAttestation state size mismatch");

  //  A single validator's attestation over a bridge withdrawal.
  //  (rest unchanged)
  struct BridgeAckAttestation
  {
    uint16_t signer_index{0};
    Crypto::Signature signature{};
    uint64_t attested_at_height{0};

    bool isWellFormed() const noexcept
    {
      if (signature.isNull())
        return false;
      if (attested_at_height == 0)
        return false;
      return true;
    }

    static constexpr size_t STATE_SIZE = 2 + 64 + 8;

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeAckAttestation &out);

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeAckAttestation::STATE_SIZE == 74,
                "BridgeAckAttestation state size mismatch");

  //  Aggregate bridge counters, one row per source chain.
  //  (rest unchanged)
  struct BridgeStats
  {
    BridgeChainId source_chain_id{0};
    uint64_t total_minted{0};
    uint64_t total_burned{0};
    uint64_t total_released{0};
    uint64_t deposit_count{0};
    uint64_t withdrawal_count{0};
    uint64_t released_withdrawal_count{0};
    uint64_t last_mint_height{0};
    uint64_t last_burn_height{0};
    uint64_t last_release_height{0};
    uint64_t registered_at_height{0};

    bool isWellFormed() const noexcept
    {
      return source_chain_id != 0;
    }

    static constexpr size_t STATE_SIZE = 88;

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeStats &out);

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeStats::STATE_SIZE == 88,
                "BridgeStats state size mismatch");

  //  A chronological record of one successful bridge operation.
  //  (rest unchanged)
  enum class BridgeEventKind : uint8_t
  {
    Mint = 0,
    Burn = 1,
    AckAttest = 2,
    AckWithdrawal = 3,
  };

  const char *bridgeEventKindName(BridgeEventKind k) noexcept;

  struct BridgeEvent
  {
    BridgeEventKind kind{BridgeEventKind::Mint};
    BridgeChainId source_chain_id{0};
    uint64_t block_height{0};
    uint32_t tx_index_in_block{0};
    bool has_tx_hash{true};
    Crypto::Hash tx_hash{};
    bool has_source_hash{false};
    Crypto::Hash source_tx_hash{};
    uint32_t source_output_index{0};
    BridgeWithdrawalId withdrawal_id{0};
    Crypto::Address actor{};
    uint64_t amount{0};
    uint64_t counterparty{0};

    static constexpr size_t KEY_SIZE = 8 + 8 + 4 + 1;
    static constexpr size_t STATE_SIZE =
        1 + 8 + 8 + 4 + 1 + 32 + 1 + 32 + 4 + 8 + 32 + 8 + 8;

    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeEvent &out);

    static std::array<uint8_t, KEY_SIZE> makeKey(
        BridgeChainId source_chain_id, uint64_t block_height,
        uint32_t tx_index_in_block, BridgeEventKind kind);

    static std::array<uint8_t, 8> chainPrefix(BridgeChainId source_chain_id);
  };

  static_assert(BridgeEvent::STATE_SIZE == 147,
                "BridgeEvent state size mismatch");

  //  ---- Outcome enums ----
  //  (rest unchanged)

  enum class BridgeMintStatus : uint8_t
  {
    Ok = 0,
    Paused = 1,
    ChainDisabled = 2,
    ChainNotRegistered = 3,
    TokenNotFound = 4,
    TokenFingerprintMismatch = 5,
    ValidatorSetTooSmall = 6,
    BelowValidatorThreshold = 7,
    BadValidatorSignature = 8,
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
    SignerNotActiveValidator = 7,
    BadSignature = 8,
    AlreadyAttested = 9,
    ConflictingAttestation = 10,
  };

  enum class BridgeAckAttestStatus : uint8_t
  {
    Ok = 0,
    Paused = 1,
    ChainNotRegistered = 2,
    ChainDisabled = 3,
    PayloadMalformed = 4,
    WithdrawalNotFound = 5,
    WithdrawalAlreadyReleased = 6,
    SignerIndexOutOfRange = 7,
    SignerNotActiveValidator = 8,
    BadSignature = 9,
    AlreadyAttested = 10,
  };

  enum class BridgeAckStatus : uint8_t
  {
    Ok = 0,
    Paused = 1,
    ChainNotRegistered = 3,
    WithdrawalNotFound = 13,
    ValidatorSetTooSmall = 6,
    BelowValidatorThreshold = 7,
    BadValidatorSignature = 8,
  };

  //  Status for a single BridgeRegisterDeposit tx.
  //
  //  Ok: registered.
  //  ChainNotRegistered: the source_chain_id in the payload is not
  //    registered on Clarity via BridgeRegisterChain. Registration
  //    of a destination before the chain is registered would be a
  //    footgun — the destination would be unreachable from the
  //    watcher, which only scans chains that are registered.
  //  ChainDisabled: the chain is registered but currently disabled.
  //  AuthorityLimitReached: the sender already holds
  //    MAX_BRIDGE_DEPOSITS_PER_AUTHORITY destinations on this chain.
  //  ChainLimitReached: MAX_BRIDGE_DEPOSITS_PER_CHAIN destinations
  //    are registered on this chain.
  //  PayloadMalformed: wrong payload length or null destination.
  enum class BridgeRegisterDepositStatus : uint8_t
  {
    Ok = 0,
    ChainNotRegistered = 1,
    ChainDisabled = 2,
    AuthorityLimitReached = 3,
    ChainLimitReached = 4,
    PayloadMalformed = 5,
  };

  const char *bridgeMintStatusName(BridgeMintStatus s) noexcept;
  const char *bridgeBurnStatusName(BridgeBurnStatus s) noexcept;
  const char *bridgeAckStatusName(BridgeAckStatus s) noexcept;
} // namespace Core