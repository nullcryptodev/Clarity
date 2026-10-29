// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BitcoinBip32Private.h"

#include "Common/Base.h"

#include "Crypto/Hmac.h"

#include <secp256k1.h>

#include <cstring>

namespace Crypto
{
  namespace
  {
    constexpr uint32_t HARDENED = 0x80000000u;
    constexpr uint32_t XPRV_MAINNET = 0x0488ADE4u;
    constexpr uint32_t XPRV_TESTNET = 0x04358394u;

    secp256k1_context *context()
    {
      //  The same process-wide context BitcoinBip32 uses. We
      //  create it lazily; whichever module runs first pays the
      //  cost. Both modules only touch sign/verify sub-APIs, so
      //  the flags are identical.
      static secp256k1_context *ctx = []
      {
        return secp256k1_context_create(
            SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
      }();
      return ctx;
    }

    uint32_t readBE32(const uint8_t *p)
    {
      return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
             (uint32_t(p[2]) << 8) | uint32_t(p[3]);
    }

    void writeBE32(uint8_t *p, uint32_t v)
    {
      p[0] = uint8_t(v >> 24);
      p[1] = uint8_t(v >> 16);
      p[2] = uint8_t(v >> 8);
      p[3] = uint8_t(v);
    }

    uint32_t versionFor(BitcoinNetwork network)
    {
      return network == BitcoinNetwork::Mainnet
                 ? XPRV_MAINNET
                 : XPRV_TESTNET;
    }

    bool secretIsValid(const uint8_t *k)
    {
      return secp256k1_ec_seckey_verify(context(), k) == 1;
    }

    //  BIP32 child records carry the parent's fingerprint, which is
    //  RIPEMD160(SHA256(compressed_pubkey(parent)))[0..4]. The
    //  public module already exposes keyFingerprint for a 33-byte
    //  compressed pubkey; here we need it from an xprv (private
    //  key), so we derive the pubkey and delegate.
    //
    //  Defined here (above deriveChildPriv, which is the only
    //  caller) so no forward declaration is needed. It is internal
    //  to this translation unit; not part of the public API.
    uint32_t keyFingerprintFromXprv(const ExtendedPrivKey &prv)
    {
      secp256k1_pubkey pub;
      if (secp256k1_ec_pubkey_create(context(), &pub, prv.key.data()) != 1)
        return 0;

      std::array<uint8_t, 33> compressed{};
      size_t len = compressed.size();
      if (secp256k1_ec_pubkey_serialize(context(), compressed.data(), &len,
                                        &pub,
                                        SECP256K1_EC_COMPRESSED) != 1 ||
          len != 33)
        return 0;

      return keyFingerprint(compressed);
    }
  } // anonymous namespace

  //  ---------------------------------------------------------------------
  //  Parse / serialize
  //  ---------------------------------------------------------------------

  std::optional<ExtendedPrivKey>
  parseExtendedPrivKey(const std::string &encoded,
                       BitcoinNetwork network,
                       std::string *error_out)
  {
    auto payload = Common::decodeBase58Check(encoded);
    if (!payload.has_value())
    {
      if (error_out)
        *error_out = "not valid base58check";
      return std::nullopt;
    }

    if (payload->size() != 78)
    {
      if (error_out)
        *error_out = "payload is " + std::to_string(payload->size()) +
                     " bytes, expected 78";
      return std::nullopt;
    }

    const uint8_t *p = payload->data();

    if (readBE32(p) != versionFor(network))
    {
      if (error_out)
        *error_out = "version bytes do not match the configured network";
      return std::nullopt;
    }

    if (p[45] != 0x00)
    {
      if (error_out)
        *error_out = "extended private key prefix byte is not 0x00";
      return std::nullopt;
    }

    ExtendedPrivKey key;
    key.depth = p[4];
    key.parent_fingerprint = readBE32(p + 5);
    key.child_number = readBE32(p + 9);
    std::memcpy(key.chaincode.data(), p + 13, 32);
    std::memcpy(key.key.data(), p + 46, 32);

    if (!secretIsValid(key.key.data()))
    {
      if (error_out)
        *error_out = "embedded key is not a valid secp256k1 scalar";
      return std::nullopt;
    }

    return key;
  }

  std::string encodeExtendedPrivKey(const ExtendedPrivKey &key,
                                    BitcoinNetwork network)
  {
    std::vector<uint8_t> payload(78, 0);
    uint8_t *p = payload.data();

    writeBE32(p, versionFor(network));
    p[4] = uint8_t(key.depth);
    writeBE32(p + 5, key.parent_fingerprint);
    writeBE32(p + 9, key.child_number);
    std::memcpy(p + 13, key.chaincode.data(), 32);
    p[45] = 0x00;
    std::memcpy(p + 46, key.key.data(), 32);

    return Common::encodeBase58Check(payload);
  }

  //  ---------------------------------------------------------------------
  //  Master from seed
  //  ---------------------------------------------------------------------

  std::optional<ExtendedPrivKey>
  masterFromSeed(const std::vector<uint8_t> &seed,
                 std::string *error_out)
  {
    //  BIP32: I = HMAC-SHA512(key="Bitcoin seed", data=seed).
    static const uint8_t HMAC_KEY[] = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ',
                                       's', 'e', 'e', 'd'};
    uint8_t I[64];
    hmacSha512(HMAC_KEY, sizeof(HMAC_KEY),
               seed.data(), seed.size(), I);

    ExtendedPrivKey master;
    std::memcpy(master.key.data(), I, 32);
    std::memcpy(master.chaincode.data(), I + 32, 32);
    master.depth = 0;
    master.parent_fingerprint = 0;
    master.child_number = 0;

    //  Zero the intermediate buffer; hmacSha512 does not own it.
    std::memset(I, 0, sizeof(I));

    if (!secretIsValid(master.key.data()))
    {
      if (error_out)
        *error_out = "master key is not a valid secp256k1 scalar "
                     "(retry with a different seed; probability ~2^-127)";
      return std::nullopt;
    }

    return master;
  }

  //  ---------------------------------------------------------------------
  //  Private child derivation
  //  ---------------------------------------------------------------------

  std::optional<ExtendedPrivKey>
  deriveChildPriv(const ExtendedPrivKey &parent,
                  uint32_t index,
                  std::string *error_out)
  {
    if (!secretIsValid(parent.key.data()))
    {
      if (error_out)
        *error_out = "parent key is not a valid secp256k1 scalar";
      return std::nullopt;
    }

    const bool hardened = (index >= HARDENED);

    //  HMAC data: hardened uses 0x00 || k_par || ser32(index);
    //  non-hardened uses serP(K_par) || ser32(index).
    uint8_t data[33 + 4];

    if (hardened)
    {
      data[0] = 0x00;
      std::memcpy(data + 1, parent.key.data(), 32);
    }
    else
    {
      secp256k1_pubkey parent_pub;
      if (secp256k1_ec_pubkey_create(context(), &parent_pub,
                                     parent.key.data()) != 1)
      {
        if (error_out)
          *error_out = "could not derive parent public key";
        return std::nullopt;
      }
      size_t len = 33;
      if (secp256k1_ec_pubkey_serialize(context(), data, &len,
                                        &parent_pub,
                                        SECP256K1_EC_COMPRESSED) != 1 ||
          len != 33)
      {
        if (error_out)
          *error_out = "could not serialize parent public key";
        return std::nullopt;
      }
    }
    writeBE32(data + 33, index);

    uint8_t I[64];
    hmacSha512(parent.chaincode.data(), 32,
               data, sizeof(data), I);

    ExtendedPrivKey child;
    std::memcpy(child.chaincode.data(), I + 32, 32);

    //  child.key = (I[0..32] + k_par) mod n.
    //  We use secp256k1_ec_seckey_tweak_add, which does exactly
    //  this arithmetic and rejects invalid results (I[0..32] >= n,
    //  or sum == 0).
    std::memcpy(child.key.data(), parent.key.data(), 32);
    if (secp256k1_ec_seckey_tweak_add(context(), child.key.data(), I) != 1)
    {
      std::memset(I, 0, sizeof(I));
      if (error_out)
        *error_out = "IL is not a valid tweak (IL >= n or result == 0)";
      return std::nullopt;
    }
    std::memset(I, 0, sizeof(I));

    child.depth = parent.depth + 1;
    child.parent_fingerprint = keyFingerprintFromXprv(parent);
    child.child_number = index;

    return child;
  }

  //  ---------------------------------------------------------------------
  //  Path derivation
  //  ---------------------------------------------------------------------

  std::optional<ExtendedPrivKey>
  derivePathPriv(const ExtendedPrivKey &parent,
                 const std::vector<uint32_t> &path,
                 std::string *error_out)
  {
    ExtendedPrivKey cur = parent;
    for (uint32_t idx : path)
    {
      auto next = deriveChildPriv(cur, idx, error_out);
      if (!next.has_value())
        return std::nullopt;
      cur = *next;
    }
    return cur;
  }

  //  ---------------------------------------------------------------------
  //  Public key extraction
  //  ---------------------------------------------------------------------

  std::optional<ExtendedPubKey>
  toXpub(const ExtendedPrivKey &prv,
         std::string *error_out)
  {
    secp256k1_pubkey pub;
    if (secp256k1_ec_pubkey_create(context(), &pub, prv.key.data()) != 1)
    {
      if (error_out)
        *error_out = "could not derive public key from private key";
      return std::nullopt;
    }

    ExtendedPubKey xpub;
    xpub.depth = prv.depth;
    xpub.parent_fingerprint = prv.parent_fingerprint;
    xpub.child_number = prv.child_number;
    std::memcpy(xpub.chaincode.data(), prv.chaincode.data(), 32);

    size_t len = 33;
    if (secp256k1_ec_pubkey_serialize(context(), xpub.pubkey.data(), &len,
                                      &pub,
                                      SECP256K1_EC_COMPRESSED) != 1 ||
        len != 33)
    {
      if (error_out)
        *error_out = "could not serialize public key";
      return std::nullopt;
    }

    return xpub;
  }

  //  ---------------------------------------------------------------------
  //  Convenience: BIP84 account xpub
  //  ---------------------------------------------------------------------

  std::optional<ExtendedPubKey>
  bip84AccountXpub(const std::vector<uint8_t> &seed,
                   BitcoinNetwork network,
                   std::string *error_out)
  {
    auto master = masterFromSeed(seed, error_out);
    if (!master.has_value())
      return std::nullopt;

    const uint32_t coin =
        (network == BitcoinNetwork::Mainnet) ? 0u : 1u;
    const std::vector<uint32_t> path = {
        84u | HARDENED,
        coin | HARDENED,
        0u | HARDENED,
    };

    auto account = derivePathPriv(*master, path, error_out);
    if (!account.has_value())
      return std::nullopt;

    return toXpub(*account, error_out);
  }

  //  ---------------------------------------------------------------------
  //  Full-path text parsing (accepts hardened)
  //  ---------------------------------------------------------------------

  std::optional<std::vector<uint32_t>>
  parseFullPath(const std::string &path, std::string *error_out)
  {
    std::vector<uint32_t> out;
    if (path.empty() || path == "m" || path == "M")
      return out;

    size_t i = 0;
    if (path[0] == 'm' || path[0] == 'M')
    {
      if (path.size() == 1)
        return out;
      if (path[1] != '/')
      {
        if (error_out)
          *error_out = "expected '/' after 'm'";
        return std::nullopt;
      }
      i = 2;
    }

    while (i < path.size())
    {
      size_t slash = path.find('/', i);
      const std::string part =
          (slash == std::string::npos) ? path.substr(i)
                                       : path.substr(i, slash - i);
      if (part.empty())
      {
        if (error_out)
          *error_out = "empty path component";
        return std::nullopt;
      }

      const bool hardened =
          part.back() == '\'' || part.back() == 'h' ||
          part.back() == 'H';
      const std::string digits =
          hardened ? part.substr(0, part.size() - 1) : part;

      if (digits.empty() || digits.size() > 10)
      {
        if (error_out)
          *error_out = "bad path component '" + part + "'";
        return std::nullopt;
      }

      uint64_t v = 0;
      for (char c : digits)
      {
        if (c < '0' || c > '9')
        {
          if (error_out)
            *error_out = "non-digit in path component '" + part + "'";
          return std::nullopt;
        }
        v = v * 10 + uint64_t(c - '0');
      }

      if (v >= HARDENED)
      {
        if (error_out)
          *error_out = "path component out of range: " + part;
        return std::nullopt;
      }

      out.push_back(hardened
                        ? static_cast<uint32_t>(v) | HARDENED
                        : static_cast<uint32_t>(v));

      if (slash == std::string::npos)
        break;
      i = slash + 1;
    }

    return out;
  }
} // namespace Crypto