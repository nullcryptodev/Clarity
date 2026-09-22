// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "SecureZero.h"
#include "GlobalConfig.h"

#include "Serialization/ISerializer.h"
#include "Serialization/SerializationTools.h"

namespace Crypto
{
  //  ByteArray — fixed-size byte container. Base for all crypto types.

  template <size_t N>
  struct ByteArray
  {
    std::array<uint8_t, N> data{};

    ByteArray() noexcept = default;

    explicit ByteArray(const uint8_t *raw) noexcept
    {
      std::memcpy(data.data(), raw, N);
    }

    bool isNull() const noexcept
    {
      for (auto b : data)
        if (b != 0)
          return false;
      return true;
    }

    bool operator==(const ByteArray &o) const noexcept { return data == o.data; }
    bool operator!=(const ByteArray &o) const noexcept { return data != o.data; }
    bool operator<(const ByteArray &o) const noexcept { return data < o.data; }
    bool operator>(const ByteArray &o) const noexcept { return data > o.data; }

    uint8_t *getData() noexcept { return data.data(); }
    const uint8_t *getData() const noexcept { return data.data(); }

    std::string toString() const
    {
      static constexpr char hex[] = "0123456789abcdef";
      std::string out;
      out.reserve(N * 2);
      for (uint8_t b : data)
      {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
      }
      return out;
    }

    void serialize(Serialization::ISerializer &s)
    {
      s.binary(data.data(), N, "bytes");
    }
    void serialize(Serialization::ISerializer &s) const
    {
      s.binary(const_cast<uint8_t *>(data.data()), N, "bytes");
    }
  };

  //  Cryptographic primitives

  struct EllipticCurveScalar : ByteArray<32>
  {
    using ByteArray::ByteArray;
    EllipticCurveScalar() = default;
  };

  struct EllipticCurvePoint : ByteArray<32>
  {
    using ByteArray::ByteArray;
    EllipticCurvePoint() = default;
  };

  struct Hash : EllipticCurvePoint
  {
    using EllipticCurvePoint::EllipticCurvePoint;
    Hash() = default;
  };

  struct PublicKey : EllipticCurvePoint
  {
    using EllipticCurvePoint::EllipticCurvePoint;
    PublicKey() = default;
  };

  struct SecretKey : EllipticCurveScalar
  {
    using EllipticCurveScalar::EllipticCurveScalar;
    SecretKey() = default;
  };

  struct Signature : ByteArray<64>
  {
    using ByteArray::ByteArray;
    Signature() = default;
  };

  struct Hash160 : ByteArray<20>
  {
    using ByteArray::ByteArray;
    Hash160() = default;
  };

  //  Account / Address types

  using Address = PublicKey;

  // Helper: parse a hex string into an address.
  inline constexpr Address addrFromHex(const char *hex)
  {
    Address a;
    for (size_t i = 0; i < 32; ++i)
    {
      auto nib = [](char c) -> uint8_t
      {
        if (c >= '0' && c <= '9')
          return uint8_t(c - '0');
        if (c >= 'a' && c <= 'f')
          return uint8_t(c - 'a' + 10);
        if (c >= 'A' && c <= 'F')
          return uint8_t(c - 'A' + 10);
        return 0;
      };
      a.data[i] = uint8_t((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    }
    return a;
  }

  inline constexpr PublicKey pubkeyFromHex(const char *hex)
  {
    PublicKey k;
    for (size_t i = 0; i < 32; ++i)
    {
      auto nib = [](char c) -> uint8_t
      {
        if (c >= '0' && c <= '9')
          return uint8_t(c - '0');
        if (c >= 'a' && c <= 'f')
          return uint8_t(c - 'a' + 10);
        if (c >= 'A' && c <= 'F')
          return uint8_t(c - 'A' + 10);
        return 0;
      };
      k.data[i] = uint8_t((nib(hex[i * 2]) << 4) | nib(hex[i * 2 + 1]));
    }
    return k;
  }

  //  BFT wire types
  //
  //  IMPORTANT: these are WIRE types used inside BFT messages. They are
  //  distinct from the chain-level `Id` (which is uint64_t
  //  and never leaves the state layer).
  //
  //  Index is a compact 16-bit index into the current
  //  active validator set. It's valid only within a specific block's
  //  quorum signature vector. It is NOT the same as Id.
  //
  //  If you need the persistent chain-level validator ID, use
  //  Id.

  // One validator's signature over a block hash.
  // The `signer_index` refers to the position in the active set, not
  // the persistent validator ID.
  struct ValidatorSignature
  {
    Index signer_index{INVALID_INDEX};
    Signature signature{};

    bool isNull() const noexcept
    {
      return signer_index == INVALID_INDEX || signature.isNull();
    }

    void serialize(Serialization::ISerializer &s)
    {
      s(signer_index, "signer_index");
      s(signature, "signature");
    }
    void serialize(Serialization::ISerializer &s) const
    {
      s(signer_index, "signer_index");
      s(signature, "signature");
    }
  };

  // A quorum of validator signatures over a block header.
  struct QuorumSignature
  {
    std::vector<ValidatorSignature> signatures;

    bool hasQuorum(size_t threshold) const noexcept
    {
      return signatures.size() >= threshold;
    }

    void serialize(Serialization::ISerializer &s)
    {
      s(signatures, "signatures");
    }
    void serialize(Serialization::ISerializer &s) const
    {
      s(signatures, "signatures");
    }
  };

  //  KeyPair

  struct KeyPair
  {
    PublicKey publicKey{};
    SecretKey secretKey{};

    KeyPair() = default;
    KeyPair(const PublicKey &pub, const SecretKey &sec)
        : publicKey(pub), secretKey(sec) {}

    bool isNull() const noexcept
    {
      return publicKey.isNull() && secretKey.isNull();
    }

    void serialize(Serialization::ISerializer &s)
    {
      s(publicKey, "public_key");
      s(secretKey, "secret_key");
    }
    void serialize(Serialization::ISerializer &s) const
    {
      s(publicKey, "public_key");
      s(secretKey, "secret_key");
    }
  };

  //  Null sentinels

  inline const Hash NULL_HASH{};
  inline const PublicKey NULL_PUBLIC_KEY{};
  inline const SecretKey NULL_SECRET_KEY{};
  inline const Signature NULL_SIGNATURE{};

  inline bool isNullHash(const Hash &h) noexcept { return h.isNull(); }
  inline bool isNullPublicKey(const PublicKey &k) noexcept { return k.isNull(); }
  inline bool isNullSecretKey(const SecretKey &k) noexcept { return k.isNull(); }
  inline bool isNullSignature(const Signature &s) noexcept { return s.isNull(); }
  inline bool isNullAddress(const Address &a) noexcept { return a.isNull(); }

  inline bool operator<(const Hash &a, const Hash &b) noexcept { return a.data < b.data; }
  inline bool operator>(const Hash &a, const Hash &b) noexcept { return a.data > b.data; }
  inline bool operator<=(const Hash &a, const Hash &b) noexcept { return !(b < a); }
  inline bool operator>=(const Hash &a, const Hash &b) noexcept { return !(a < b); }

} // namespace Crypto

// ============================================================================
//  std::hash specializations
// ============================================================================

namespace std
{
  namespace detail
  {
    inline size_t fnv1a_32(const uint8_t *p) noexcept
    {
      constexpr size_t FNV_OFFSET = 1469598103934665603ULL;
      constexpr size_t FNV_PRIME = 1099511628211ULL;
      size_t h = FNV_OFFSET;
      for (size_t i = 0; i < 32; ++i)
      {
        h ^= p[i];
        h *= FNV_PRIME;
      }
      return h;
    }
  } // namespace detail

  template <>
  struct hash<Crypto::Hash>
  {
    size_t operator()(const Crypto::Hash &h) const noexcept
    {
      return detail::fnv1a_32(h.data.data());
    }
  };

  template <>
  struct hash<Crypto::PublicKey>
  {
    size_t operator()(const Crypto::PublicKey &k) const noexcept
    {
      return detail::fnv1a_32(k.data.data());
    }
  };

  template <>
  struct hash<Crypto::Signature>
  {
    size_t operator()(const Crypto::Signature &s) const noexcept
    {
      return detail::fnv1a_32(s.data.data()) ^
             detail::fnv1a_32(s.data.data() + 32);
    }
  };

} // namespace std