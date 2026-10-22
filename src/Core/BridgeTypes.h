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

  //  The CCX chain id as the bridge sees it. Same across all
  //  networks; the CCX chain itself is one chain.
  inline constexpr uint64_t BRIDGE_CCX_CHAIN_ID = 0x43435831ULL;

  //  A watcher's minimum stake is now the validator's stake; this
  //  constant is retained only for wire-format compatibility with
  //  pre-existing registrations. It is not consulted anywhere.
  inline constexpr Amount BRIDGE_WATCHER_MIN_STAKE = GlobalConfig::VALIDATOR_MIN_STAKE;

  using BridgeChainId = uint64_t;
  using BridgeWithdrawalId = uint64_t;

  //  A withdrawal record. Chain-agnostic; the destination is an
  //  opaque blob whose format is defined by the per-chain adapter.
  //
  //  Lifecycle:
  //    - Created by BridgeBurn at the burn height.
  //    - Validators submit BridgeAckAttest txs over the withdrawal
  //      id while it is pending; those live in
  //      TBL_BRIDGE_ACK_ATTESTATIONS.
  //    - Once quorum of acks exists AND the validator has released
  //      the underlying asset on the source chain, one of the
  //      validators submits a BridgeAckWithdrawal tx carrying the
  //      source-chain release tx hash and height. That populates
  //      the release_* fields below and permanently marks the
  //      withdrawal as released.
  //    - The record is never deleted: it is the on-chain audit trail
  //      for the withdrawal, and getPendingWithdrawals filters on
  //      release_tx_hash being null.
  struct BridgeWithdrawal
  {
    BridgeWithdrawalId id{0};
    BridgeChainId source_chain_id{0};
    Id wrapped_token_id{0};
    Crypto::Address burner{};
    uint64_t amount{0};

    //  The destination blob is the 64-byte (spend ‖ view) pubkey
    //  pair. Kept for validation and for any future chain that only
    //  deals in blob form.
    std::vector<uint8_t> destination_blob;

    //  The destination address as a base58 string, exactly as the
    //  user supplied it in the burn payload. This is what
    //  submit_release hands to the CCX wallet RPC — no encoding
    //  needed, since the user already had the address and the burn
    //  carries it verbatim.
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
      //  The destination blob is opaque; per-chain bounds are
      //  enforced by the burn handler against the registration's
      //  destination_blob_min_len / destination_blob_max_len. The
      //  struct-level check only requires that the blob is
      //  non-empty and fits in the wire length prefix.
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

    //  Layout (little-endian):
    //    [8]  id
    //    [8]  source_chain_id
    //    [4]  wrapped_token_id
    //    [32] burner
    //    [8]  amount
    //    [8]  created_at_height
    //    [1]  blob_len
    //    [N]  destination_blob
    //    [1]  addr_len
    //    [M]  destination_address
    //    [32] release_tx_hash
    //    [8]  release_height
    //    [8]  released_at_height
    //    [8]  released_by_validator_id
    //
    //  The fixed portion (prefix) grows by 1 byte (addr_len) plus
    //  the variable address bytes. The MAX_STATE_SIZE accounts for
    //  a 256-byte address in addition to the 256-byte blob.
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
    //  The minimum active validator set size for this chain to
    //  operate. Below this, the bridge for this chain halts: no
    //  mint, no burn, no ack. The halt is loud. The field was
    //  previously `active_watcher_min`; the meaning is unchanged
    //  under the validator-is-watcher model, only the name is
    //  clearer. The wire layout (bytes 51-54 of the 55-byte blob)
    //  is unchanged.
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
        8 + 4 + 32 + 1 + 1 + 2 + 1 + 1 + 1 + 4; // == 55

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeChainRegistration::STATE_SIZE == 55,
                "BridgeChainRegistration state size mismatch");

  //  A single validator's attestation over a bridge deposit.
  //
  //  Produced on-chain by a BridgeAttest transaction and stored in
  //  TBL_BRIDGE_ATTESTATIONS keyed by (source_chain_id,
  //  source_tx_hash, source_output_index, validator_id). A BridgeMint
  //  is valid iff a quorum of distinct active validators has attested
  //  to the same (destination, amount) pair for the same deposit.
  //
  //  The `destination` and `amount` are stored in the record because
  //  the deposit does not exist as a first-class record until the
  //  mint happens. Attestations are the only pre-mint record of what
  //  validators agreed the deposit was. The assembler validates that
  //  all attestations for a single deposit agree on these two fields
  //  before producing the mint's signature block; conflicting
  //  attestations are a federation split and must not be silently
  //  resolved.
  struct BridgeAttestation
  {
    //  The validator's position in the sorted active validator set
    //  at the height of the attestation. This is what goes into the
    //  BridgeMint's signature block; it is captured here so the
    //  block assembly is a pure function of what's in state.
    uint16_t signer_index{0};

    //  The validator's signature over the canonical mint message
    //  (see Bridge::Signing::EncodeBridgeMintMessage).
    Crypto::Signature signature{};

    //  The deposit's destination and amount, as the validator
    //  understood them.
    Crypto::Address destination{};
    uint64_t amount{0};

    //  The height of the BridgeAttest transaction that created
    //  this record. Used for the eventual slash path (a validator
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

  //  A single validator's attestation over a bridge withdrawal.
  //
  //  Produced on-chain by a BridgeAckAttest transaction and stored in
  //  TBL_BRIDGE_ACK_ATTESTATIONS keyed by (withdrawal_id,
  //  validator_id). A BridgeAckWithdrawal is valid iff a quorum of
  //  distinct active validators has attested to the same withdrawal_id.
  //
  //  Unlike BridgeAttestation, this record does NOT carry destination
  //  or amount: those are already in the BridgeWithdrawal record,
  //  created at burn time. The attestation is just a vote that the
  //  validator observed the burn and agrees to release the
  //  underlying. The record is therefore smaller: 74 bytes vs 114.
  struct BridgeAckAttestation
  {
    //  The validator's position in the sorted active validator set
    //  at the height of the attestation. This is what goes into the
    //  BridgeAckWithdrawal's signature block.
    uint16_t signer_index{0};

    //  The validator's signature over the canonical ack message
    //  (see Bridge::Signing::EncodeBridgeAckMessage).
    Crypto::Signature signature{};

    //  The height of the BridgeAckAttest transaction that created
    //  this record.
    uint64_t attested_at_height{0};

    bool isWellFormed() const noexcept
    {
      if (signature.isNull())
        return false;
      if (attested_at_height == 0)
        return false;
      return true;
    }

    //  Layout (little-endian):
    //    [2]  signer_index
    //    [64] signature
    //    [8]  attested_at_height
    //
    //  Total: 2 + 64 + 8 = 74 bytes.
    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeAckAttestation &out);
    static constexpr size_t STATE_SIZE = 2 + 64 + 8;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeAckAttestation::STATE_SIZE == 74,
                "BridgeAckAttestation state size mismatch");

  //  Aggregate bridge counters, one row per source chain.
  //
  //  Updated by executeBridgeMint, executeBridgeBurn, and
  //  executeBridgeAckWithdrawal on every operation. Exposed through
  //  the getBridgeStats RPC so that an auditor, monitoring dashboard,
  //  or operator UI can verify the bridge's economic state without
  //  walking every transaction.
  //
  //  Invariants (checked by a future auditor RPC and by monitoring
  //  alerts):
  //
  //    total_minted - total_burned == wrapped_token.total_supply
  //    total_burned - total_released == outstanding_liability
  //    deposit_count          == number of BridgeMint txs
  //    withdrawal_count       == number of BridgeBurn txs
  //    released_withdrawal_count == number of BridgeAckWithdrawal txs
  //
  //  Note: the three counts are the number of times each operation
  //  succeeded, not the number of unique entities. A reburn is two
  //  withdrawal_count increments, but only one "entity".
  //
  //  The stats record does not live in the SMT under a bridge-specific
  //  key; it's a per-chain row in TBL_BRIDGE_STATS, so it doesn't
  //  affect the state root and doesn't block bridge operations if it
  //  gets out of sync (a monitoring alert would catch that, not a
  //  consensus failure).
  struct BridgeStats
  {
    BridgeChainId source_chain_id{0};

    //  Lifetime totals (in Clarity atomic units, same as withdrawal.amount).
    uint64_t total_minted{0};
    uint64_t total_burned{0};
    uint64_t total_released{0};

    //  Operation counters.
    uint64_t deposit_count{0};
    uint64_t withdrawal_count{0};
    uint64_t released_withdrawal_count{0};

    //  Last-activity heights.
    uint64_t last_mint_height{0};
    uint64_t last_burn_height{0};
    uint64_t last_release_height{0};

    //  Chain registration height (for "bridge has been running N
    //  blocks" reporting).
    uint64_t registered_at_height{0};

    bool isWellFormed() const noexcept
    {
      return source_chain_id != 0;
    }

    //  Layout (little-endian):
    //    [8]  source_chain_id
    //    [8]  total_minted
    //    [8]  total_burned
    //    [8]  total_released
    //    [8]  deposit_count
    //    [8]  withdrawal_count
    //    [8]  released_withdrawal_count
    //    [8]  last_mint_height
    //    [8]  last_burn_height
    //    [8]  last_release_height
    //    [8]  registered_at_height
    //
    //  Total: 88 bytes.
    std::vector<uint8_t> serializeState() const;
    static bool deserializeState(const uint8_t *data, size_t len,
                                 BridgeStats &out);
    static constexpr size_t STATE_SIZE = 88;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  static_assert(BridgeStats::STATE_SIZE == 88,
                "BridgeStats state size mismatch");

  //  A chronological record of one successful bridge operation.
  //
  //  Unlike the other bridge records, this is written to a plain
  //  key-value table (TBL_BRIDGE_EVENTS), not to the SMT. It has
  //  no effect on the state root. Its purpose is audit: every
  //  successful mint, burn, ack-attest, and ack-withdrawal is
  //  logged so that an operator, indexer, or auditor can answer
  //  "what happened on the bridge, and in what order" without
  //  having to join across the other bridge tables.
  //
  //  The event's identity is its key, (source_chain_id,
  //  block_height, tx_index_in_block, kind), so two events with
  //  the same value bytes are distinct if they were emitted at
  //  different heights or by different transactions.
  enum class BridgeEventKind : uint8_t
  {
    Mint = 0,          //  BridgeMint succeeded
    Burn = 1,          //  BridgeBurn succeeded
    AckAttest = 2,     //  BridgeAckAttest recorded
    AckWithdrawal = 3, //  BridgeAckWithdrawal recorded
  };

  const char *bridgeEventKindName(BridgeEventKind k) noexcept;

  struct BridgeEvent
  {
    BridgeEventKind kind{BridgeEventKind::Mint};
    BridgeChainId source_chain_id{0};
    uint64_t block_height{0};
    uint32_t tx_index_in_block{0};

    //  All four kinds set this to true: every bridge event is
    //  emitted by a Bridge tx, so there is always a tx_hash. The
    //  flag exists so a future event kind that isn't associated
    //  with a transaction (e.g. a periodic reconciliation pass)
    //  can emit the same record shape with a null tx_hash, without
    //  a codec change.
    bool has_tx_hash{true};
    Crypto::Hash tx_hash{};

    //  For Mint and AckAttest, the CCX-side deposit identity.
    //  For Burn and AckWithdrawal, has_source_hash is false and
    //  source_tx_hash / source_output_index are zero.
    bool has_source_hash{false};
    Crypto::Hash source_tx_hash{};
    uint32_t source_output_index{0};

    //  For Burn, AckAttest, AckWithdrawal.
    BridgeWithdrawalId withdrawal_id{0};

    //  For Mint and Burn: the burner (tx.from of the mint/burn).
    //  For AckAttest and AckWithdrawal: the signing validator's
    //  reward address (tx.from of the attestation).
    Crypto::Address actor{};

    //  Mint: the minted amount in Clarity atomic units.
    //  Burn: the burned amount in Clarity atomic units.
    //  AckWithdrawal: the released amount in Clarity atomic units.
    //  AckAttest: zero.
    uint64_t amount{0};

    //  AckAttest: the validator_id that signed.
    //  AckWithdrawal: the release_height on the source chain.
    //  Mint and Burn: zero.
    uint64_t counterparty{0};

    //  Key layout, BE for ascending scan = chronological:
    //    [8] source_chain_id || [8] block_height ||
    //    [4] tx_index_in_block || [1] kind
    //
    //  Value layout, fixed 147 bytes:
    //    [1] kind || [8] source_chain_id LE || [8] block_height LE ||
    //    [4] tx_index_in_block LE || [1] has_tx_hash ||
    //    [32] tx_hash || [1] has_source_hash || [32] source_tx_hash ||
    //    [4] source_output_index LE || [8] withdrawal_id LE ||
    //    [32] actor || [8] amount LE || [8] counterparty LE
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

  enum class BridgeMintStatus : uint8_t
  {
    Ok = 0,
    Paused = 1,
    ChainDisabled = 2,
    ChainNotRegistered = 3,
    TokenNotFound = 4,
    TokenFingerprintMismatch = 5,
    //  Active validator set size is below the registration's
    //  active_validator_min, or the attestation block doesn't
    //  have enough valid signatures.
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

  const char *bridgeAttestStatusName(BridgeAttestStatus s) noexcept;

  //  Status for a single BridgeAckAttest tx. Mirrors BridgeAttestStatus
  //  with three differences:
  //
  //    - WithdrawalAlreadyReleased: the withdrawal has already been
  //      released on-chain; attesting to it is pointless.
  //    - No ConflictingAttestation: since the record carries no
  //      destination/amount, there is nothing to conflict on. All
  //      validators attest to the same withdrawal_id or not at all.
  //    - DepositAlreadyConsumed is renamed to WithdrawalAlreadyReleased.
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

  const char *bridgeAckAttestStatusName(BridgeAckAttestStatus s) noexcept;

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

  const char *bridgeMintStatusName(BridgeMintStatus s) noexcept;
  const char *bridgeBurnStatusName(BridgeBurnStatus s) noexcept;
  const char *bridgeAckStatusName(BridgeAckStatus s) noexcept;
}