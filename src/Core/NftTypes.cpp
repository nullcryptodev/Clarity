// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "NftTypes.h"

#include "Common/Wire.h"

#include <cstring>

namespace Core
{
  // =================================================================
  //  NftInfo codec
  // =================================================================

  std::vector<uint8_t> NftInfo::serializeState() const
  {
    const uint16_t uri_len = static_cast<uint16_t>(
        metadata_uri.size() > NFT_URI_MAX ? NFT_URI_MAX : metadata_uri.size());

    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE_FIXED + uri_len);

    Common::Writer w(out);

    w.writeU64(id);
    w.writeBytes(owner.data.data(), owner.data.size());
    w.writeBytes(creator.data.data(), creator.data.size());
    w.writeU32(shadow_token_id);
    w.writeU32(underlying_token_id);
    w.writeU64(wrapped_amount);
    w.writeU64(collection_id);

    //  Metadata hash: 32 bytes always, with a 1-byte flag. The hash
    //  field is written even when absent, so the layout is fixed.
    const bool has_hash = !metadata_hash.isNull();
    w.writeBytes(metadata_hash.data.data(), metadata_hash.data.size());
    w.writeU8(has_hash ? 1 : 0);

    //  URI: u16 length then bytes.
    w.writeU16(uri_len);
    w.writeBytes(reinterpret_cast<const uint8_t *>(metadata_uri.data()),
                 uri_len);

    w.writeU8(frozen ? 1 : 0);
    w.writeU64(last_accrual_height);
    w.writeU64(accrued_owed);
    w.writeU64(created_at_height);

    return out;
  }

  bool NftInfo::deserializeState(const uint8_t *data, size_t len, NftInfo &out)
  {
    Common::Reader r(data, len);

    out.id = r.readU64();
    r.readBytes(out.owner.data.data(), out.owner.data.size());
    r.readBytes(out.creator.data.data(), out.creator.data.size());
    out.shadow_token_id = r.readU32();
    out.underlying_token_id = r.readU32();
    out.wrapped_amount = r.readU64();
    out.collection_id = r.readU64();

    r.readBytes(out.metadata_hash.data.data(), out.metadata_hash.data.size());
    const uint8_t has_hash = r.readU8();

    if (!r.ok())
      return false;

    //  The hash field is written unconditionally; the flag says
    //  whether it is meaningful. A zero flag with a non-zero hash
    //  is a codec bug on the encode side; reject rather than
    //  silently accept.
    if (has_hash == 0)
    {
      if (!out.metadata_hash.isNull())
        return false;
    }
    else if (has_hash != 1)
    {
      return false;
    }

    const uint16_t uri_len = r.readU16();
    if (!r.ok() || uri_len > NFT_URI_MAX)
      return false;

    out.metadata_uri = r.readString(uri_len);

    const uint8_t frozen_byte = r.readU8();
    if (!r.ok() || frozen_byte > 1)
      return false;
    out.frozen = (frozen_byte == 1);

    out.last_accrual_height = r.readU64();
    out.accrued_owed = r.readU64();
    out.created_at_height = r.readU64();

    if (!r.ok())
      return false;

    //  No trailing bytes. An NftInfo is self-contained.
    if (r.remaining() != 0)
      return false;

    return out.isValid();
  }

  void NftInfo::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(owner, "owner");
    s(creator, "creator");
    s(shadow_token_id, "shadow_token_id");
    s(underlying_token_id, "underlying_token_id");
    s(wrapped_amount, "wrapped_amount");
    s(collection_id, "collection_id");

    const bool has_hash = !metadata_hash.isNull();
    s(has_hash, "has_metadata_hash");
    if (has_hash)
      s(metadata_hash, "metadata_hash");

    s(metadata_uri, "metadata_uri");
    s(frozen, "frozen");
    s(last_accrual_height, "last_accrual_height");
    s(accrued_owed, "accrued_owed");
    s(created_at_height, "created_at_height");
  }

  void NftInfo::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(owner, "owner");
    s(creator, "creator");
    s(shadow_token_id, "shadow_token_id");
    s(underlying_token_id, "underlying_token_id");
    s(wrapped_amount, "wrapped_amount");
    s(collection_id, "collection_id");

    const bool has_hash = !metadata_hash.isNull();
    s(has_hash, "has_metadata_hash");
    if (has_hash)
      s(metadata_hash, "metadata_hash");

    s(metadata_uri, "metadata_uri");
    s(frozen, "frozen");
    s(last_accrual_height, "last_accrual_height");
    s(accrued_owed, "accrued_owed");
    s(created_at_height, "created_at_height");
  }

  // =================================================================
  //  NftCollection codec
  // =================================================================

  std::vector<uint8_t> NftCollection::serializeState() const
  {
    const uint8_t name_len = static_cast<uint8_t>(
        name.size() > NFT_COLLECTION_NAME_MAX
            ? NFT_COLLECTION_NAME_MAX
            : name.size());

    const uint8_t sym_len = static_cast<uint8_t>(
        symbol.size() > NFT_COLLECTION_SYMBOL_MAX
            ? NFT_COLLECTION_SYMBOL_MAX
            : symbol.size());

    const uint16_t uri_len = static_cast<uint16_t>(
        base_uri.size() > NFT_URI_MAX ? NFT_URI_MAX : base_uri.size());

    std::vector<uint8_t> out;
    out.reserve(STATE_SIZE_FIXED + name_len + sym_len + uri_len);

    Common::Writer w(out);

    w.writeU64(id);
    w.writeBytes(creator.data.data(), creator.data.size());

    w.writeU8(name_len);
    w.writeBytes(reinterpret_cast<const uint8_t *>(name.data()), name_len);

    w.writeU8(sym_len);
    w.writeBytes(reinterpret_cast<const uint8_t *>(symbol.data()), sym_len);

    w.writeU16(uri_len);
    w.writeBytes(reinterpret_cast<const uint8_t *>(base_uri.data()), uri_len);

    w.writeU32(reward_token_id);
    w.writeU64(reward_rate_per_epoch);
    w.writeU64(reward_escrow_remaining);
    w.writeU8(reward_paused ? 1 : 0);
    w.writeU64(created_at_height);
    w.writeU64(minted_count);

    return out;
  }

  bool NftCollection::deserializeState(const uint8_t *data, size_t len,
                                       NftCollection &out)
  {
    Common::Reader r(data, len);

    out.id = r.readU64();
    r.readBytes(out.creator.data.data(), out.creator.data.size());

    const uint8_t name_len = r.readU8();
    if (!r.ok() || name_len > NFT_COLLECTION_NAME_MAX)
      return false;
    out.name = r.readString(name_len);

    const uint8_t sym_len = r.readU8();
    if (!r.ok() || sym_len > NFT_COLLECTION_SYMBOL_MAX)
      return false;
    out.symbol = r.readString(sym_len);

    const uint16_t uri_len = r.readU16();
    if (!r.ok() || uri_len > NFT_URI_MAX)
      return false;
    out.base_uri = r.readString(uri_len);

    out.reward_token_id = r.readU32();
    out.reward_rate_per_epoch = r.readU64();
    out.reward_escrow_remaining = r.readU64();

    const uint8_t paused_byte = r.readU8();
    if (!r.ok() || paused_byte > 1)
      return false;
    out.reward_paused = (paused_byte == 1);

    out.created_at_height = r.readU64();
    out.minted_count = r.readU64();

    if (!r.ok())
      return false;

    if (r.remaining() != 0)
      return false;

    return out.isValid();
  }

  void NftCollection::serialize(Serialization::ISerializer &s)
  {
    s(id, "id");
    s(creator, "creator");
    s(name, "name");
    s(symbol, "symbol");
    s(base_uri, "base_uri");
    s(reward_token_id, "reward_token_id");
    s(reward_rate_per_epoch, "reward_rate_per_epoch");
    s(reward_escrow_remaining, "reward_escrow_remaining");
    s(reward_paused, "reward_paused");
    s(created_at_height, "created_at_height");
    s(minted_count, "minted_count");
  }

  void NftCollection::serialize(Serialization::ISerializer &s) const
  {
    s(id, "id");
    s(creator, "creator");
    s(name, "name");
    s(symbol, "symbol");
    s(base_uri, "base_uri");
    s(reward_token_id, "reward_token_id");
    s(reward_rate_per_epoch, "reward_rate_per_epoch");
    s(reward_escrow_remaining, "reward_escrow_remaining");
    s(reward_paused, "reward_paused");
    s(created_at_height, "created_at_height");
    s(minted_count, "minted_count");
  }

} // namespace Core