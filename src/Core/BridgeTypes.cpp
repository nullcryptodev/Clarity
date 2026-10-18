// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BridgeTypes.h"

#include "Common/Wire.h"

namespace Core
{
  //  =========================================================================
  //  BridgeWithdrawal
  //  =========================================================================

  std::vector<uint8_t> BridgeWithdrawal::serializeState() const
  {
    if (!isWellFormed())
      return {};

    std::vector<uint8_t> out;
    out.reserve(PREFIX_SIZE + destination_blob.size());

    Common::Writer w(out);
    w.writeU64(id);
    w.writeU64(source_chain_id);
    w.writeU32(wrapped_token_id);
    w.writeBytes(burner.data.data(), burner.data.size());
    w.writeU64(amount);
    w.writeU64(created_at_height);
    w.writeU8(static_cast<uint8_t>(destination_blob.size()));
    w.writeBytes(destination_blob.data(), destination_blob.size());

    return out;
  }

  bool BridgeWithdrawal::deserializeState(const uint8_t *data, size_t len,
                                          BridgeWithdrawal &out)
  {
    if (len < PREFIX_SIZE)
      return false;

    Common::Reader r(data, len);

    BridgeWithdrawal w;
    w.id = r.readU64();
    w.source_chain_id = r.readU64();
    w.wrapped_token_id = r.readU32();
    r.readBytes(w.burner.data.data(), w.burner.data.size());
    w.amount = r.readU64();
    w.created_at_height = r.readU64();

    const uint8_t blob_len = r.readU8();
    if (!r.ok())
      return false;

    if (r.remaining() != blob_len)
      return false;

    w.destination_blob.resize(blob_len);
    if (blob_len > 0)
      r.readBytes(w.destination_blob.data(), blob_len);
    if (!r.ok())
      return false;

    if (!w.isWellFormed())
      return false;

    out = std::move(w);
    return true;
  }

  void BridgeWithdrawal::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(source_chain_id, "source_chain_id");
    s(wrapped_token_id, "wrapped_token_id");
    s(burner, "burner");
    s(amount, "amount");
    s(created_at_height, "created_at_height");
  }

  void BridgeWithdrawal::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(source_chain_id, "source_chain_id");
    s(wrapped_token_id, "wrapped_token_id");
    s(burner, "burner");
    s(amount, "amount");
    s(created_at_height, "created_at_height");
  }

  //  =========================================================================
  //  BridgeChainRegistration
  //  =========================================================================

  std::vector<uint8_t> BridgeChainRegistration::serializeState() const
  {
    if (!isWellFormed())
      return {};

    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(source_chain_id);
    w.writeU32(wrapped_token_id);
    w.writeBytes(fingerprint.data.data(), fingerprint.data.size());
    w.writeU8(source_decimals);
    w.writeU8(clarity_decimals);
    w.writeU16(confirmation_depth);
    w.writeU8(destination_blob_min_len);
    w.writeU8(destination_blob_max_len);
    w.writeU8(enabled ? 1 : 0);
    w.writeU32(active_watcher_min);

    return out;
  }

  bool BridgeChainRegistration::deserializeState(const uint8_t *data,
                                                 size_t len,
                                                 BridgeChainRegistration &out)
  {
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    BridgeChainRegistration reg;
    reg.source_chain_id = r.readU64();
    reg.wrapped_token_id = r.readU32();
    r.readBytes(reg.fingerprint.data.data(), reg.fingerprint.data.size());
    reg.source_decimals = r.readU8();
    reg.clarity_decimals = r.readU8();
    reg.confirmation_depth = r.readU16();
    reg.destination_blob_min_len = r.readU8();
    reg.destination_blob_max_len = r.readU8();
    reg.enabled = (r.readU8() != 0);
    reg.active_watcher_min = r.readU32();

    if (!r.ok())
      return false;
    if (!reg.isWellFormed())
      return false;

    out = std::move(reg);
    return true;
  }

  void BridgeChainRegistration::serialize(Serialization::ISerializer &s)
  {
    s(source_chain_id, "source_chain_id");
    s(wrapped_token_id, "wrapped_token_id");
    s(fingerprint, "fingerprint");
    s(source_decimals, "source_decimals");
    s(clarity_decimals, "clarity_decimals");
    s(confirmation_depth, "confirmation_depth");
    s(destination_blob_min_len, "destination_blob_min_len");
    s(destination_blob_max_len, "destination_blob_max_len");
    s(enabled, "enabled");
    s(active_watcher_min, "active_watcher_min");
  }

  void BridgeChainRegistration::serialize(Serialization::ISerializer &s) const
  {
    s(source_chain_id, "source_chain_id");
    s(wrapped_token_id, "wrapped_token_id");
    s(fingerprint, "fingerprint");
    s(source_decimals, "source_decimals");
    s(clarity_decimals, "clarity_decimals");
    s(confirmation_depth, "confirmation_depth");
    s(destination_blob_min_len, "destination_blob_min_len");
    s(destination_blob_max_len, "destination_blob_max_len");
    s(enabled, "enabled");
    s(active_watcher_min, "active_watcher_min");
  }

  //  =========================================================================
  //  Status names
  //  =========================================================================

  const char *bridgeMintStatusName(BridgeMintStatus s) noexcept
  {
    switch (s)
    {
    case BridgeMintStatus::Ok:
      return "ok";
    case BridgeMintStatus::Paused:
      return "paused";
    case BridgeMintStatus::ChainDisabled:
      return "chain_disabled";
    case BridgeMintStatus::ChainNotRegistered:
      return "chain_not_registered";
    case BridgeMintStatus::TokenNotFound:
      return "token_not_found";
    case BridgeMintStatus::TokenFingerprintMismatch:
      return "token_fingerprint_mismatch";
    case BridgeMintStatus::WatcherSetTooSmall:
      return "watcher_set_too_small";
    case BridgeMintStatus::BelowWatcherThreshold:
      return "below_watcher_threshold";
    case BridgeMintStatus::BadWatcherSignature:
      return "bad_watcher_signature";
    case BridgeMintStatus::Replay:
      return "replay";
    }
    return "unknown";
  }

  const char *bridgeBurnStatusName(BridgeBurnStatus s) noexcept
  {
    switch (s)
    {
    case BridgeBurnStatus::Ok:
      return "ok";
    case BridgeBurnStatus::Paused:
      return "paused";
    case BridgeBurnStatus::ChainDisabled:
      return "chain_disabled";
    case BridgeBurnStatus::ChainNotRegistered:
      return "chain_not_registered";
    case BridgeBurnStatus::TokenNotFound:
      return "token_not_found";
    case BridgeBurnStatus::TokenFingerprintMismatch:
      return "token_fingerprint_mismatch";
    case BridgeBurnStatus::InsufficientBalance:
      return "insufficient_balance";
    case BridgeBurnStatus::DestinationTooShort:
      return "destination_too_short";
    case BridgeBurnStatus::DestinationTooLong:
      return "destination_too_long";
    }
    return "unknown";
  }

  const char *bridgeAckStatusName(BridgeAckStatus s) noexcept
  {
    switch (s)
    {
    case BridgeAckStatus::Ok:
      return "ok";
    case BridgeAckStatus::Paused:
      return "paused";
    case BridgeAckStatus::ChainNotRegistered:
      return "chain_not_registered";
    case BridgeAckStatus::WatcherSetTooSmall:
      return "watcher_set_too_small";
    case BridgeAckStatus::BelowWatcherThreshold:
      return "below_watcher_threshold";
    case BridgeAckStatus::BadWatcherSignature:
      return "bad_watcher_signature";
    case BridgeAckStatus::WithdrawalNotFound:
      return "withdrawal_not_found";
    }
    return "unknown";
  }

  std::vector<uint8_t> BridgeAttestation::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    out.push_back(uint8_t(signer_index));
    out.push_back(uint8_t(signer_index >> 8));
    out.insert(out.end(), signature.data.begin(), signature.data.end());
    out.insert(out.end(), destination.data.begin(), destination.data.end());
    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(amount >> (i * 8)));
    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(attested_at_height >> (i * 8)));

    return out;
  }

  bool BridgeAttestation::deserializeState(const uint8_t *data, size_t len,
                                           BridgeAttestation &out)
  {
    if (len != STATE_SIZE)
      return false;

    size_t off = 0;
    out.signer_index = uint16_t(data[off]) | (uint16_t(data[off + 1]) << 8);
    off += 2;

    std::memcpy(out.signature.data.data(), data + off, 64);
    off += 64;

    std::memcpy(out.destination.data.data(), data + off, 32);
    off += 32;

    out.amount = 0;
    for (int i = 0; i < 8; ++i)
      out.amount |= uint64_t(data[off + i]) << (i * 8);
    off += 8;

    out.attested_at_height = 0;
    for (int i = 0; i < 8; ++i)
      out.attested_at_height |= uint64_t(data[off + i]) << (i * 8);

    return true;
  }

  void BridgeAttestation::serialize(Serialization::ISerializer &s)
  {
    s(signer_index, "signer_index");
    s(signature, "signature");
    s(destination, "destination");
    s(amount, "amount");
    s(attested_at_height, "attested_at_height");
  }

  void BridgeAttestation::serialize(Serialization::ISerializer &s) const
  {
    s(signer_index, "signer_index");
    s(signature, "signature");
    s(destination, "destination");
    s(amount, "amount");
    s(attested_at_height, "attested_at_height");
  }

  const char *bridgeAttestStatusName(BridgeAttestStatus s) noexcept
  {
    switch (s)
    {
    case BridgeAttestStatus::Ok:
      return "Ok";
    case BridgeAttestStatus::Paused:
      return "Paused";
    case BridgeAttestStatus::ChainNotRegistered:
      return "ChainNotRegistered";
    case BridgeAttestStatus::ChainDisabled:
      return "ChainDisabled";
    case BridgeAttestStatus::PayloadMalformed:
      return "PayloadMalformed";
    case BridgeAttestStatus::DepositAlreadyConsumed:
      return "DepositAlreadyConsumed";
    case BridgeAttestStatus::SignerIndexOutOfRange:
      return "SignerIndexOutOfRange";
    case BridgeAttestStatus::SignerNotActiveWatcher:
      return "SignerNotActiveWatcher";
    case BridgeAttestStatus::BadSignature:
      return "BadSignature";
    case BridgeAttestStatus::AlreadyAttested:
      return "AlreadyAttested";
    case BridgeAttestStatus::ConflictingAttestation:
      return "ConflictingAttestation";
    }
    return "Unknown";
  }
}