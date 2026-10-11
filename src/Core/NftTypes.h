// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Serialization/ISerializer.h"
#include "TokenTypes.h"

namespace Core
{
  //  Non-fungible tokens on Clarity
  //
  //  Every NFT is two things:
  //
  //    1. A TokenInfo record with maxSupply = 1 and decimals = 0.
  //       This is the "shadow token" — the thing the DEX, AMM, and
  //       reward layer see. Every existing token mechanism works on
  //       it without special-casing.
  //
  //    2. An NftInfo record (this file) that carries the metadata,
  //       the collection reference, and — for wrapped NFTs — a
  //       reference to an underlying token whose balance is held at
  //       the NFT's virtual address.
  //
  //  The virtual address is derived from the NFT id:
  //
  //    Keys::nftAddress(nft_id) = Blake2b("nfa " || BE(nft_id))
  //
  //  The balance table already supports arbitrary addresses, so the
  //  wrapped underlying is just a token balance at that address. A
  //  refill is a Transfer to the address. A burn releases the
  //  balance back to the owner.
  //
  //  Collections group NFTs and (optionally) carry a reward schedule.
  //  The schedule is per-collection, not per-NFT, because a 10,000-
  //  NFT collection with the same rate for every NFT is 100× cheaper
  //  to track as one schedule than 10,000.

  //  Metadata URI cap. Long enough for ipfs:// and https:// URIs
  //  with a hash fragment; short enough that a full metadata
  //  payload doesn't bloat the SMT. The hash is the authoritative
  //  commitment; the URI is a fetch hint.
  inline constexpr size_t NFT_URI_MAX = 512;

  //  Collection name and symbol caps, matching TOKEN_NAME_MAX and
  //  TOKEN_SYMBOL_MAX so a collection and its shadow token agree.
  inline constexpr size_t NFT_COLLECTION_NAME_MAX = TOKEN_NAME_MAX;
  inline constexpr size_t NFT_COLLECTION_SYMBOL_MAX = TOKEN_SYMBOL_MAX;

  struct NftInfo
  {
    uint64_t id{INVALID_ID};

    Crypto::Address owner{};
    Crypto::Address creator{};

    //  The NFT's own tradeable token id. Equal to the NFT's id by
    //  construction. Stored as a separate field so the derivation
    //  is explicit and can change without touching the token table.
    Id shadow_token_id{0};

    //  Underlying token for a wrapped NFT. Zero for a standalone
    //  NFT, which is not backed by anything. The wrapped amount
    //  lives at Keys::nftAddress(id) in the token-balance table.
    Id underlying_token_id{0};
    uint64_t wrapped_amount{0};

    //  Collection membership. Zero means "no collection". A
    //  standalone NFT with no collection is the throwaway case:
    //  one record, one metadata blob, no reward schedule.
    uint64_t collection_id{0};

    //  Metadata. Either or both may be set. A client that finds a
    //  hash prefers to verify what it fetches from the URI against
    //  the hash; a client that finds only a URI trusts the URI.
    Crypto::Hash metadata_hash{};
    std::string metadata_uri;

    //  One-way metadata lock. Once set, UpdateNftMetadata rejects.
    //  Burning and transferring are unaffected — the lock is on the
    //  metadata, not on the NFT.
    bool frozen{false};

    //  Reward accrual state. Populated on every mint; meaningful
    //  only when collection_id != 0 and the collection has an
    //  active reward schedule.
    //
    //  last_accrual_height is the last height at which this NFT's
    //  reward was settled to its owner. accrued_owed is the total
    //  reward owed but not yet claimed — decremented at claim time,
    //  never touched by the epoch boundary (which only decrements
    //  the collection's escrow).
    uint64_t last_accrual_height{0};
    uint64_t accrued_owed{0};

    uint64_t created_at_height{0};

    bool isStandalone() const noexcept
    {
      return underlying_token_id == 0;
    }

    bool isWrapped() const noexcept
    {
      return underlying_token_id != 0;
    }

    bool isValid() const noexcept
    {
      if (id == INVALID_ID)
        return false;
      if (owner.isNull())
        return false;
      if (creator.isNull())
        return false;
      if (shadow_token_id == 0)
        return false;

      //  A wrapped NFT must have both an underlying token and a
      //  positive amount. A standalone NFT must have neither.
      if (underlying_token_id == 0 && wrapped_amount != 0)
        return false;
      if (underlying_token_id != 0 && wrapped_amount == 0)
        return false;

      //  An NFT cannot wrap itself or its own shadow token.
      if (underlying_token_id == shadow_token_id)
        return false;

      if (metadata_uri.size() > NFT_URI_MAX)
        return false;

      return true;
    }

    //  State codec. Layout (all multi-byte little-endian):
    //    [8]   id
    //    [32]  owner
    //    [32]  creator
    //    [4]   shadow_token_id
    //    [4]   underlying_token_id
    //    [8]   wrapped_amount
    //    [8]   collection_id
    //    [32]  metadata_hash
    //    [1]   has_hash (0 or 1; if 0, the 32 bytes above are zero
    //                   and are still written, so the layout is
    //                   fixed)
    //    [2]   uri_len (LE)
    //    [N]   uri
    //    [1]   frozen
    //    [8]   last_accrual_height
    //    [8]   accrued_owed
    //    [8]   created_at_height

    std::vector<uint8_t> serializeState() const;

    static bool deserializeState(const uint8_t *data, size_t len,
                                 NftInfo &out);

    static constexpr size_t STATE_SIZE_FIXED =
        8 + 32 + 32 + 4 + 4 + 8 + 8 + 32 + 1 + 2 + 1 + 8 + 8 + 8;
    static constexpr size_t STATE_SIZE_MAX =
        STATE_SIZE_FIXED + NFT_URI_MAX;

    //  Framework serialization, for RPC responses.
    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  struct NftCollection
  {
    uint64_t id{INVALID_ID};
    Crypto::Address creator{};

    std::string name;
    std::string symbol;

    //  Base URI for the collection. An NFT with an empty
    //  metadata_uri inherits the collection's base URI, with the
    //  NFT's id appended. Empty base_uri means no inheritance.
    std::string base_uri;

    //  Reward schedule. If reward_token_id == 0, the collection has
    //  no schedule and no escrow; the remaining fields are unused.
    //
    //  If reward_rate_per_epoch > 0 and reward_escrow_remaining > 0,
    //  the collection pays out reward_rate_per_epoch tokens per
    //  minted NFT per epoch, drawn from the escrow at
    //  Keys::nftCollectionAddress(id). When the escrow is
    //  exhausted, reward_paused becomes true and the schedule
    //  stops paying until the creator refills.
    Id reward_token_id{0};
    uint64_t reward_rate_per_epoch{0};
    uint64_t reward_escrow_remaining{0};
    bool reward_paused{false};

    uint64_t created_at_height{0};
    uint64_t minted_count{0};

    bool hasReward() const noexcept
    {
      return reward_token_id != 0 && reward_rate_per_epoch > 0;
    }

    bool isActive() const noexcept
    {
      return hasReward() && !reward_paused && reward_escrow_remaining > 0;
    }

    bool isValid() const noexcept
    {
      if (id == INVALID_ID)
        return false;
      if (creator.isNull())
        return false;
      if (name.empty() || name.size() > NFT_COLLECTION_NAME_MAX)
        return false;
      if (symbol.size() < TOKEN_SYMBOL_MIN ||
          symbol.size() > NFT_COLLECTION_SYMBOL_MAX)
        return false;
      if (base_uri.size() > NFT_URI_MAX)
        return false;

      //  A reward schedule requires a token id and a positive rate.
      //  If a token id is set, the rate must be positive; if no
      //  token id is set, no escrow may exist.
      if (reward_token_id == 0)
      {
        if (reward_rate_per_epoch != 0)
          return false;
        if (reward_escrow_remaining != 0)
          return false;
      }
      else
      {
        if (reward_rate_per_epoch == 0)
          return false;
      }

      return true;
    }

    //  State codec. Layout:
    //    [8]   id
    //    [32]  creator
    //    [1]   name_len
    //    [N]   name
    //    [1]   symbol_len
    //    [M]   symbol
    //    [2]   base_uri_len (LE)
    //    [K]   base_uri
    //    [4]   reward_token_id
    //    [8]   reward_rate_per_epoch
    //    [8]   reward_escrow_remaining
    //    [1]   reward_paused
    //    [8]   created_at_height
    //    [8]   minted_count

    std::vector<uint8_t> serializeState() const;

    static bool deserializeState(const uint8_t *data, size_t len,
                                 NftCollection &out);

    static constexpr size_t STATE_SIZE_FIXED =
        8 + 32 + 1 + 1 + 2 + 4 + 8 + 8 + 1 + 8 + 8;
    static constexpr size_t STATE_SIZE_MAX =
        STATE_SIZE_FIXED + NFT_COLLECTION_NAME_MAX +
        NFT_COLLECTION_SYMBOL_MAX + NFT_URI_MAX;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

} // namespace Core