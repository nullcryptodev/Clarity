// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BridgeTypes.h"

#include "Common/Wire.h"

namespace Core
{
  //  =========================================================================
  //  BridgeDepositRecord
  //  =========================================================================

  std::vector<uint8_t> BridgeDepositRecord::serializeState() const
  {
    if (!isWellFormed())
      return {};

    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(source_chain_id);
    w.writeU64(index);
    w.writeBytes(destination.data.data(), destination.data.size());
    w.writeBytes(authority.data.data(), authority.data.size());
    w.writeU64(registered_at_height);

    return out;
  }

  bool BridgeDepositRecord::deserializeState(const uint8_t *data, size_t len,
                                             BridgeDepositRecord &out)
  {
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    BridgeDepositRecord rec;
    rec.source_chain_id = r.readU64();
    rec.index = r.readU64();
    r.readBytes(rec.destination.data.data(), rec.destination.data.size());
    r.readBytes(rec.authority.data.data(), rec.authority.data.size());
    rec.registered_at_height = r.readU64();

    if (!r.ok())
      return false;
    if (!rec.isWellFormed())
      return false;

    out = std::move(rec);
    return true;
  }

  void BridgeDepositRecord::serialize(Serialization::ISerializer &s)
  {
    s(source_chain_id, "source_chain_id");
    s(index, "index");
    s(destination, "destination");
    s(authority, "authority");
    s(registered_at_height, "registered_at_height");
  }

  void BridgeDepositRecord::serialize(Serialization::ISerializer &s) const
  {
    s(source_chain_id, "source_chain_id");
    s(index, "index");
    s(destination, "destination");
    s(authority, "authority");
    s(registered_at_height, "registered_at_height");
  }

  //  =========================================================================
  //  BridgeWithdrawal
  //  =========================================================================

  std::vector<uint8_t> BridgeWithdrawal::serializeState() const
  {
    if (!isWellFormed())
      return {};

    std::vector<uint8_t> out;
    out.reserve(PREFIX_SIZE + destination_blob.size() +
                1 + destination_address.size() + RELEASE_TRAILER_SIZE);

    Common::Writer w(out);
    w.writeU64(id);
    w.writeU64(source_chain_id);
    w.writeU32(wrapped_token_id);
    w.writeBytes(burner.data.data(), burner.data.size());
    w.writeU64(amount);
    w.writeU64(created_at_height);
    w.writeU8(static_cast<uint8_t>(destination_blob.size()));
    w.writeBytes(destination_blob.data(), destination_blob.size());
    w.writeU8(static_cast<uint8_t>(destination_address.size()));
    w.writeString(destination_address);

    w.writeBytes(release_tx_hash.data.data(), release_tx_hash.data.size());
    w.writeU64(release_height);
    w.writeU64(released_at_height);
    w.writeU64(released_by_validator_id);

    return out;
  }

  bool BridgeWithdrawal::deserializeState(const uint8_t *data, size_t len,
                                          BridgeWithdrawal &out)
  {
    if (len < PREFIX_SIZE + 1 + RELEASE_TRAILER_SIZE)
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
    if (r.remaining() < blob_len + 1 + RELEASE_TRAILER_SIZE)
      return false;

    w.destination_blob.resize(blob_len);
    if (blob_len > 0)
      r.readBytes(w.destination_blob.data(), blob_len);

    const uint8_t addr_len = r.readU8();
    if (!r.ok())
      return false;
    if (r.remaining() != addr_len + RELEASE_TRAILER_SIZE)
      return false;

    w.destination_address = r.readString(addr_len);

    r.readBytes(w.release_tx_hash.data.data(), w.release_tx_hash.data.size());
    w.release_height = r.readU64();
    w.released_at_height = r.readU64();
    w.released_by_validator_id = r.readU64();

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
    s(destination_address, "destination_address");
    s(release_tx_hash, "release_tx_hash");
    s(release_height, "release_height");
    s(released_at_height, "released_at_height");
    s(released_by_validator_id, "released_by_validator_id");
  }

  void BridgeWithdrawal::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(source_chain_id, "source_chain_id");
    s(wrapped_token_id, "wrapped_token_id");
    s(burner, "burner");
    s(amount, "amount");
    s(created_at_height, "created_at_height");
    s(destination_address, "destination_address");
    s(release_tx_hash, "release_tx_hash");
    s(release_height, "release_height");
    s(released_at_height, "released_at_height");
    s(released_by_validator_id, "released_by_validator_id");
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
    w.writeU32(active_validator_min);

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
    reg.active_validator_min = r.readU32();

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
    s(active_validator_min, "active_validator_min");
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
    s(active_validator_min, "active_validator_min");
  }

  //  =========================================================================
  //  BridgeAttestation
  //  =========================================================================

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

  //  =========================================================================
  //  BridgeAckAttestation
  //  =========================================================================

  std::vector<uint8_t> BridgeAckAttestation::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    out.push_back(uint8_t(signer_index));
    out.push_back(uint8_t(signer_index >> 8));
    out.insert(out.end(), signature.data.begin(), signature.data.end());
    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(attested_at_height >> (i * 8)));

    return out;
  }

  bool BridgeAckAttestation::deserializeState(const uint8_t *data, size_t len,
                                              BridgeAckAttestation &out)
  {
    if (len != STATE_SIZE)
      return false;

    size_t off = 0;
    out.signer_index = uint16_t(data[off]) | (uint16_t(data[off + 1]) << 8);
    off += 2;

    std::memcpy(out.signature.data.data(), data + off, 64);
    off += 64;

    out.attested_at_height = 0;
    for (int i = 0; i < 8; ++i)
      out.attested_at_height |= uint64_t(data[off + i]) << (i * 8);

    return true;
  }

  void BridgeAckAttestation::serialize(Serialization::ISerializer &s)
  {
    s(signer_index, "signer_index");
    s(signature, "signature");
    s(attested_at_height, "attested_at_height");
  }

  void BridgeAckAttestation::serialize(Serialization::ISerializer &s) const
  {
    s(signer_index, "signer_index");
    s(signature, "signature");
    s(attested_at_height, "attested_at_height");
  }

  //  =========================================================================
  //  BridgeStats
  //  =========================================================================

  std::vector<uint8_t> BridgeStats::serializeState() const
  {
    if (!isWellFormed())
      return {};

    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);

    Common::Writer w(out);
    w.writeU64(source_chain_id);
    w.writeU64(total_minted);
    w.writeU64(total_burned);
    w.writeU64(total_released);
    w.writeU64(deposit_count);
    w.writeU64(withdrawal_count);
    w.writeU64(released_withdrawal_count);
    w.writeU64(last_mint_height);
    w.writeU64(last_burn_height);
    w.writeU64(last_release_height);
    w.writeU64(registered_at_height);

    return out;
  }

  bool BridgeStats::deserializeState(const uint8_t *data, size_t len,
                                     BridgeStats &out)
  {
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    BridgeStats s;
    s.source_chain_id = r.readU64();
    s.total_minted = r.readU64();
    s.total_burned = r.readU64();
    s.total_released = r.readU64();
    s.deposit_count = r.readU64();
    s.withdrawal_count = r.readU64();
    s.released_withdrawal_count = r.readU64();
    s.last_mint_height = r.readU64();
    s.last_burn_height = r.readU64();
    s.last_release_height = r.readU64();
    s.registered_at_height = r.readU64();

    if (!r.ok())
      return false;
    if (!s.isWellFormed())
      return false;

    out = std::move(s);
    return true;
  }

  void BridgeStats::serialize(Serialization::ISerializer &s)
  {
    s(source_chain_id, "source_chain_id");
    s(total_minted, "total_minted");
    s(total_burned, "total_burned");
    s(total_released, "total_released");
    s(deposit_count, "deposit_count");
    s(withdrawal_count, "withdrawal_count");
    s(released_withdrawal_count, "released_withdrawal_count");
    s(last_mint_height, "last_mint_height");
    s(last_burn_height, "last_burn_height");
    s(last_release_height, "last_release_height");
    s(registered_at_height, "registered_at_height");
  }

  void BridgeStats::serialize(Serialization::ISerializer &s) const
  {
    s(source_chain_id, "source_chain_id");
    s(total_minted, "total_minted");
    s(total_burned, "total_burned");
    s(total_released, "total_released");
    s(deposit_count, "deposit_count");
    s(withdrawal_count, "withdrawal_count");
    s(released_withdrawal_count, "released_withdrawal_count");
    s(last_mint_height, "last_mint_height");
    s(last_burn_height, "last_burn_height");
    s(last_release_height, "last_release_height");
    s(registered_at_height, "registered_at_height");
  }

  //  =========================================================================
  //  BridgeEvent
  //  =========================================================================

  const char *bridgeEventKindName(BridgeEventKind k) noexcept
  {
    switch (k)
    {
    case BridgeEventKind::Mint:
      return "mint";
    case BridgeEventKind::Burn:
      return "burn";
    case BridgeEventKind::AckAttest:
      return "ack_attest";
    case BridgeEventKind::AckWithdrawal:
      return "ack_withdrawal";
    }
    return "unknown";
  }

  std::array<uint8_t, BridgeEvent::KEY_SIZE> BridgeEvent::makeKey(
      BridgeChainId source_chain_id, uint64_t block_height,
      uint32_t tx_index_in_block, BridgeEventKind kind)
  {
    std::array<uint8_t, KEY_SIZE> key{};
    for (int i = 0; i < 8; ++i)
      key[i] = uint8_t(source_chain_id >> ((7 - i) * 8));
    for (int i = 0; i < 8; ++i)
      key[8 + i] = uint8_t(block_height >> ((7 - i) * 8));
    for (int i = 0; i < 4; ++i)
      key[16 + i] = uint8_t(tx_index_in_block >> ((7 - i) * 8));
    key[20] = static_cast<uint8_t>(kind);
    return key;
  }

  std::array<uint8_t, 8> BridgeEvent::chainPrefix(BridgeChainId source_chain_id)
  {
    std::array<uint8_t, 8> prefix{};
    for (int i = 0; i < 8; ++i)
      prefix[i] = uint8_t(source_chain_id >> ((7 - i) * 8));
    return prefix;
  }

  std::vector<uint8_t> BridgeEvent::serializeState() const
  {
    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE);
    Common::Writer w(out);

    w.writeU8(static_cast<uint8_t>(kind));
    w.writeU64(source_chain_id);
    w.writeU64(block_height);
    w.writeU32(tx_index_in_block);
    w.writeU8(has_tx_hash ? 1 : 0);
    w.writeBytes(tx_hash.data.data(), 32);
    w.writeU8(has_source_hash ? 1 : 0);
    w.writeBytes(source_tx_hash.data.data(), 32);
    w.writeU32(source_output_index);
    w.writeU64(withdrawal_id);
    w.writeBytes(actor.data.data(), 32);
    w.writeU64(amount);
    w.writeU64(counterparty);

    return out;
  }

  bool BridgeEvent::deserializeState(const uint8_t *data, size_t len,
                                     BridgeEvent &out)
  {
    if (len != STATE_SIZE)
      return false;

    Common::Reader r(data, len);

    BridgeEvent e;
    e.kind = static_cast<BridgeEventKind>(r.readU8());
    e.source_chain_id = r.readU64();
    e.block_height = r.readU64();
    e.tx_index_in_block = r.readU32();
    e.has_tx_hash = (r.readU8() != 0);
    r.readBytes(e.tx_hash.data.data(), 32);
    e.has_source_hash = (r.readU8() != 0);
    r.readBytes(e.source_tx_hash.data.data(), 32);
    e.source_output_index = r.readU32();
    e.withdrawal_id = r.readU64();
    r.readBytes(e.actor.data.data(), 32);
    e.amount = r.readU64();
    e.counterparty = r.readU64();

    if (!r.ok())
      return false;

    out = std::move(e);
    return true;
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
    case BridgeMintStatus::ValidatorSetTooSmall:
      return "validator_set_too_small";
    case BridgeMintStatus::BelowValidatorThreshold:
      return "below_validator_threshold";
    case BridgeMintStatus::BadValidatorSignature:
      return "bad_validator_signature";
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
    case BridgeAckStatus::ValidatorSetTooSmall:
      return "validator_set_too_small";
    case BridgeAckStatus::BelowValidatorThreshold:
      return "below_validator_threshold";
    case BridgeAckStatus::BadValidatorSignature:
      return "bad_validator_signature";
    case BridgeAckStatus::WithdrawalNotFound:
      return "withdrawal_not_found";
    }
    return "unknown";
  }
} // namespace Core