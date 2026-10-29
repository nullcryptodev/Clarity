// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BitcoinBip32.h"

#include "Common/Base.h"

#include "Crypto/Bech32.h"
#include "Crypto/Hmac.h"
#include "Crypto/Ripemd160.h"
#include "Crypto/Sha256.h"

#include <secp256k1.h>

#include <cstring>
#include <mutex>

namespace Crypto
{
  namespace
  {
    constexpr uint32_t HARDENED = 0x80000000u;
    constexpr uint32_t XPUB_MAINNET = 0x0488B21Eu;
    constexpr uint32_t XPUB_TESTNET = 0x043587CFu;

    //  A process-wide secp256k1 context. Signing is not used here
    //  (we only tweak public keys and serialize), but the context
    //  is created with both flags so the same code is correct if
    //  a future caller adds signing. It is created once and never
    //  destroyed; this matches how libsecp256k1 is normally used
    //  and avoids a destructor ordering hazard at process exit.
    secp256k1_context *context()
    {
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
                 ? XPUB_MAINNET
                 : XPUB_TESTNET;
    }

    const char *hrpFor(BitcoinNetwork network)
    {
      switch (network)
      {
      case BitcoinNetwork::Mainnet:
        return "bc";
      case BitcoinNetwork::Testnet:
        return "tb";
      case BitcoinNetwork::Regtest:
        return "bcrt";
      }
      return "bc";
    }

    bool pubkeyParse(const std::array<uint8_t, 33> &pk,
                     secp256k1_pubkey &out)
    {
      return secp256k1_ec_pubkey_parse(
                 context(), &out, pk.data(), pk.size()) == 1;
    }

    bool pubkeySerialize(const secp256k1_pubkey &pk,
                         std::array<uint8_t, 33> &out)
    {
      size_t len = out.size();
      return secp256k1_ec_pubkey_serialize(
                 context(), out.data(), &len, &pk,
                 SECP256K1_EC_COMPRESSED) == 1 &&
             len == out.size();
    }

    void sha256d(const uint8_t *data, size_t len, uint8_t *out)
    {
      uint8_t first[SHA256_OUTPUT_SIZE];
      sha256(data, len, first);
      sha256(first, sizeof(first), out);
    }

    void hash160(const uint8_t *data, size_t len, uint8_t *out20)
    {
      uint8_t sha[SHA256_OUTPUT_SIZE];
      sha256(data, len, sha);
      Ripemd160::hash(sha, sizeof(sha), out20);
    }
  } // anonymous namespace

  //  ---------------------------------------------------------------------
  //  Parse / serialize
  //  ---------------------------------------------------------------------

  std::optional<ExtendedPubKey>
  parseExtendedPubKey(const std::string &encoded,
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

    const uint32_t depth = p[4];
    if (depth > 255)
    {
      //  (depth is a single byte, so this is defence-in-depth.)
      if (error_out)
        *error_out = "invalid depth";
      return std::nullopt;
    }

    ExtendedPubKey key;
    key.depth = depth;
    key.parent_fingerprint = readBE32(p + 5);
    key.child_number = readBE32(p + 9);
    std::memcpy(key.chaincode.data(), p + 13, 32);
    std::memcpy(key.pubkey.data(), p + 45, 33);

    secp256k1_pubkey parsed;
    if (!pubkeyParse(key.pubkey, parsed))
    {
      if (error_out)
        *error_out = "embedded public key is not a valid secp256k1 point";
      return std::nullopt;
    }

    return key;
  }

  std::string encodeExtendedPubKey(const ExtendedPubKey &key,
                                   BitcoinNetwork network)
  {
    std::vector<uint8_t> payload(78, 0);
    uint8_t *p = payload.data();

    writeBE32(p, versionFor(network));
    p[4] = uint8_t(key.depth);
    writeBE32(p + 5, key.parent_fingerprint);
    writeBE32(p + 9, key.child_number);
    std::memcpy(p + 13, key.chaincode.data(), 32);
    std::memcpy(p + 45, key.pubkey.data(), 33);

    return Common::encodeBase58Check(payload);
  }

  //  ---------------------------------------------------------------------
  //  Non-hardened derivation
  //  ---------------------------------------------------------------------

  std::optional<ExtendedPubKey>
  deriveChild(const ExtendedPubKey &parent,
              uint32_t index,
              std::string *error_out)
  {
    if (index >= HARDENED)
    {
      if (error_out)
        *error_out = "hardened derivation is not possible from an xpub";
      return std::nullopt;
    }

    //  HMAC-SHA512(chaincode, ser33(parent_pub) || ser32(index)).
    uint8_t data[33 + 4];
    std::memcpy(data, parent.pubkey.data(), 33);
    writeBE32(data + 33, index);

    uint8_t I[HMAC_SHA512_OUTPUT_SIZE];
    hmacSha512(parent.chaincode.data(), parent.chaincode.size(),
               data, sizeof(data), I);

    //  IL must be < n. With overwhelming probability it is; if
    //  not, BIP32 says to skip this index (the caller may retry
    //  with the next one). We surface the failure rather than
    //  silently skipping, so the caller decides.
    secp256k1_pubkey parent_pk;
    if (!pubkeyParse(parent.pubkey, parent_pk))
    {
      if (error_out)
        *error_out = "parent public key does not parse";
      return std::nullopt;
    }

    secp256k1_pubkey child_pk = parent_pk;
    if (secp256k1_ec_pubkey_tweak_add(context(), &child_pk, I) != 1)
    {
      if (error_out)
        *error_out = "IL is not a valid tweak (IL >= n or "
                     "point at infinity); retry with the next index";
      return std::nullopt;
    }

    ExtendedPubKey child;
    child.depth = parent.depth + 1;
    child.parent_fingerprint = keyFingerprint(parent.pubkey);
    child.child_number = index;
    std::memcpy(child.chaincode.data(), I + 32, 32);
    if (!pubkeySerialize(child_pk, child.pubkey))
    {
      if (error_out)
        *error_out = "could not serialize child public key";
      return std::nullopt;
    }

    return child;
  }

  std::optional<ExtendedPubKey>
  derivePath(const ExtendedPubKey &account,
             const std::vector<uint32_t> &path,
             std::string *error_out)
  {
    ExtendedPubKey cur = account;
    for (uint32_t idx : path)
    {
      if (idx >= HARDENED)
      {
        if (error_out)
          *error_out = "path component " + std::to_string(idx) +
                       " is hardened; not derivable from an xpub";
        return std::nullopt;
      }
      auto next = deriveChild(cur, idx, error_out);
      if (!next.has_value())
        return std::nullopt;
      cur = *next;
    }
    return cur;
  }

  std::optional<std::vector<uint32_t>>
  parseDerivationTail(const std::string &tail,
                      std::string *error_out)
  {
    std::vector<uint32_t> out;
    if (tail.empty() || tail == "m")
      return out;

    size_t i = 0;
    if (tail[0] == 'm' || tail[0] == 'M')
    {
      if (tail.size() == 1)
        return out;
      if (tail[1] != '/')
      {
        if (error_out)
          *error_out = "expected '/' after 'm'";
        return std::nullopt;
      }
      i = 2;
    }

    while (i < tail.size())
    {
      size_t slash = tail.find('/', i);
      const std::string part =
          (slash == std::string::npos) ? tail.substr(i)
                                       : tail.substr(i, slash - i);

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

      if (hardened)
      {
        if (error_out)
          *error_out = "hardened component '" + part +
                       "' cannot be derived from an xpub";
        return std::nullopt;
      }

      out.push_back(static_cast<uint32_t>(v));

      if (slash == std::string::npos)
        break;
      i = slash + 1;
    }

    return out;
  }

  //  ---------------------------------------------------------------------
  //  Script and address
  //  ---------------------------------------------------------------------

  std::array<uint8_t, 22>
  p2wpkhScript(const std::array<uint8_t, 33> &compressed_pubkey)
  {
    std::array<uint8_t, 22> script{};
    script[0] = 0x00; // OP_0 (witness version 0)
    script[1] = 0x14; // push 20 bytes
    hash160(compressed_pubkey.data(), compressed_pubkey.size(),
            script.data() + 2);
    return script;
  }

  std::string p2wpkhAddress(const std::array<uint8_t, 22> &script,
                            BitcoinNetwork network)
  {
    //  Witness program = bytes 2..22 (the 20-byte pubkey hash).
    std::vector<uint8_t> program5;
    if (!convertBitsTo5(script.data() + 2, 20, program5,
                        /*pad=*/true))
      return {};

    //  Prepend witness version 0 as a single 5-bit value. Do NOT
    //  run it through convertBitsTo5 — it is already 5-bit by
    //  definition, and converting it would misalign the stream.
    std::vector<uint8_t> data5;
    data5.reserve(program5.size() + 1);
    data5.push_back(0);
    data5.insert(data5.end(), program5.begin(), program5.end());

    //  Witness v0 uses Bech32 (BIP-173), not Bech32m (BIP-350).
    return bech32Encode5(hrpFor(network), data5,
                         Bech32Encoding::Bech32);
  }

  std::string p2wpkhAddressFromPubkey(
      const std::array<uint8_t, 33> &compressed_pubkey,
      BitcoinNetwork network)
  {
    return p2wpkhAddress(p2wpkhScript(compressed_pubkey), network);
  }

  uint32_t keyFingerprint(const std::array<uint8_t, 33> &compressed_pubkey)
  {
    uint8_t h[20];
    hash160(compressed_pubkey.data(), compressed_pubkey.size(), h);
    return (uint32_t(h[0]) << 24) | (uint32_t(h[1]) << 16) |
           (uint32_t(h[2]) << 8) | uint32_t(h[3]);
  }
} // namespace Crypto