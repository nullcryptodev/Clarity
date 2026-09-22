// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Serialization/SerializationTools.h"
#include "TransactionTypes.h"
#include "GlobalConfig.h"

namespace Core
{
  inline constexpr uint32_t TX_MAX_PAYLOAD_SIZE = 64 * 1024;

  struct Transaction
  {
    // Versioning
    uint16_t version{GlobalConfig::CURRENT_TRANSACTION_VERSION};
    uint64_t chain_id{0};

    // Identity
    TxType tx_type{TxType::Invalid};
    uint64_t nonce{0};
    uint64_t valid_until_height{0};

    // Participants
    Crypto::Address from{};
    Crypto::Address to{};

    // Value
    Id token_id{0};
    Amount amount{0};
    Amount fee{0};

    // Payload
    std::vector<uint8_t> payload;

    // Authorization
    Crypto::Signature signature;

    // Methods
    bool isWellFormed() const noexcept;

    // The signing hash excludes the signature field. Recomputed on every
    // call — we used to cache this, but the cache was copied along with
    // the Transaction, which caused stale hashes after mutations.
    //
    // If profiling shows this is a hot path, cache it explicitly with
    // an `invalidateSigningHash()` method that callers must invoke on
    // every mutation. Do not silently cache without invalidation.
    Crypto::Hash signingHash() const;
    Crypto::Hash txid() const { return signingHash(); }

    std::vector<uint8_t> serialize() const;
    std::vector<uint8_t> serializeForSigning() const;
    static bool deserialize(const uint8_t *data, size_t len, Transaction &out);

    size_t serializedSize() const noexcept;
    std::string toString() const;

    void serialize(Serialization::ISerializer &s);
    void serialize(Serialization::ISerializer &s) const;
  };

  // Free serialize functions for ADL.
  template <typename Ar>
  inline bool serialize(Transaction &tx, std::string_view, Ar &ar)
  {
    auto bytes = tx.serialize();
    return ar.binary(bytes.data(), bytes.size(), "transaction");
  }

  template <typename Ar>
  inline bool serialize(const Transaction &tx, std::string_view, Ar &ar)
  {
    auto bytes = tx.serialize();
    return ar.binary(const_cast<uint8_t *>(bytes.data()), bytes.size(), "transaction");
  }

} // namespace Core