// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Transaction.h"

#include "Crypto/Blake2b.h"
#include "Crypto/SecureZero.h"

#include "Common/Put.h"
#include "Common/Reader.h"

#include <cstring>
#include <sstream>
#include <stdexcept>

namespace Core
{
  namespace
  {
    // Domain separation tag. Prevents a signature over a transaction from
    // being reused as a signature over any other structure.
    constexpr const char *TX_DOMAIN = "CLRTY_TX_V1";
  } // anonymous namespace

  //  Validation

  bool Transaction::isWellFormed() const noexcept
  {
    // Version must be exactly current for now. Future: allow a range.
    if (version != GlobalConfig::CURRENT_TRANSACTION_VERSION)
      return false;

    // Chain ID must be non-zero. A zero chain ID is a misconfiguration.
    if (chain_id == 0)
      return false;

    // tx_type must be valid.
    if (tx_type == TxType::Invalid)
      return false;

    // `from` must be a non-null address (must have a signer).
    if (from.isNull())
      return false;

    // Payload size limit.
    if (payload.size() > TX_MAX_PAYLOAD_SIZE)
      return false;

    // A transaction must do *something*: either transfer value or pay a fee.
    // (A zero-amount, zero-fee tx with an empty payload is meaningless.)
    if (amount == 0 && fee == 0 && payload.empty())
      return false;

    return true;
  }

  //  Hashing

  Crypto::Hash Transaction::signingHash() const
  {
    // Serialize without the signature.
    auto body = serializeForSigning();

    // Prepend domain tag.
    std::vector<uint8_t> to_hash;
    to_hash.reserve(std::strlen(TX_DOMAIN) + body.size());
    to_hash.insert(to_hash.end(),
                   reinterpret_cast<const uint8_t *>(TX_DOMAIN),
                   reinterpret_cast<const uint8_t *>(TX_DOMAIN) + std::strlen(TX_DOMAIN));
    to_hash.insert(to_hash.end(), body.begin(), body.end());

    Crypto::Hash h;
    Crypto::blake2b(to_hash.data(), to_hash.size(), h.data.data(), 32);
    return h;
  }

  //  Serialization — full (with signature)

  std::vector<uint8_t> Transaction::serialize() const
  {
    auto out = serializeForSigning();
    Common::putBytes(out, signature.data.data(), signature.data.size());
    return out;
  }

  //  Serialization — for signing (without signature)

  std::vector<uint8_t> Transaction::serializeForSigning() const
  {
    std::vector<uint8_t> out;
    out.reserve(179 + payload.size());

    Common::putU16(out, version);
    Common::putU64(out, chain_id);
    out.push_back(static_cast<uint8_t>(tx_type));
    Common::putU64(out, nonce);
    Common::putU64(out, valid_until_height);
    Common::putBytes(out, from.data.data(), from.data.size());
    Common::putBytes(out, to.data.data(), to.data.size());
    Common::putU32(out, token_id);
    Common::putU64(out, amount);
    Common::putU64(out, fee);

    Common::putU32(out, static_cast<uint32_t>(payload.size()));
    Common::putBytes(out, payload.data(), payload.size());

    return out;
  }

  //  Deserialization

  bool Transaction::deserialize(const uint8_t *data, size_t len, Transaction &out)
  {
    Common::Reader r(data, len);

    out.version = r.readU16();
    out.chain_id = r.readU64();
    out.tx_type = static_cast<TxType>(r.readU8());
    out.nonce = r.readU64();
    out.valid_until_height = r.readU64();

    r.readBytes(out.from.data.data(), out.from.data.size());
    r.readBytes(out.to.data.data(), out.to.data.size());

    out.token_id = r.readU32();
    out.amount = r.readU64();
    out.fee = r.readU64();

    uint32_t payload_size = r.readU32();
    if (payload_size > TX_MAX_PAYLOAD_SIZE)
    {
      return false;
    }

    out.payload = r.readVector(payload_size);

    r.readBytes(out.signature.data.data(), out.signature.data.size());

    if (!r.ok())
      return false;

    return out.isWellFormed();
  }

  //  Convenience

  size_t Transaction::serializedSize() const noexcept
  {
    // version(2) + chain_id(8) + tx_type(1) + nonce(8) + valid_until(8)
    // + from(32) + to(32) + token_id(4) + amount(8) + fee(8)
    // + payload_size(4) + payload(N) + signature(64)
    return 2 + 8 + 1 + 8 + 8 + 32 + 32 + 4 + 8 + 8 + 4 + payload.size() + 64;
  }

  std::string Transaction::toString() const
  {
    std::ostringstream ss;
    ss << "Tx("
       << txTypeName(tx_type)
       << " from=" << from.toString().substr(0, 16)
       << " to=" << to.toString().substr(0, 16)
       << " amount=" << amount
       << " fee=" << fee
       << " nonce=" << nonce
       << ")";
    return ss.str();
  }

  //  Serialization framework integration

  void Transaction::serialize(Serialization::ISerializer &s)
  {
    auto bytes = serialize();
    s.binary(bytes.data(), bytes.size(), "transaction");
  }

  void Transaction::serialize(Serialization::ISerializer &s) const
  {
    auto bytes = serialize();
    s.binary(const_cast<uint8_t *>(bytes.data()), bytes.size(), "transaction");
  }

} // namespace Core