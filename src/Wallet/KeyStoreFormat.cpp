// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "KeyStoreFormat.h"

#include "Common/Json.h"
#include "Crypto/Random.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <system_error>

namespace Wallet
{
  namespace
  {
    //  Hex helpers
    //
    //  Keystore byte fields are encoded as lowercase hex strings, the
    //  convention shared by every JSON keystore format in the wild
    //  (Ethereum, Cosmos, Solana, every browser wallet). This keeps
    //  the file human-readable and lets third-party tools inspect it
    //  without needing to know our exact schema.

    std::string toHex(const std::vector<uint8_t> &v)
    {
      static constexpr char hex[] = "0123456789abcdef";
      std::string out;
      out.reserve(v.size() * 2);
      for (uint8_t b : v)
      {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
      }
      return out;
    }

    // Decode a hex string. Returns std::nullopt on odd length or any
    // non-hex character. Accepts both cases on input.
    std::optional<std::vector<uint8_t>> fromHex(std::string_view s)
    {
      if (s.size() % 2 != 0)
        return std::nullopt;

      auto nib = [](char c) -> int
      {
        if (c >= '0' && c <= '9')
          return c - '0';
        if (c >= 'a' && c <= 'f')
          return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
          return c - 'A' + 10;
        return -1;
      };

      std::vector<uint8_t> out;
      out.reserve(s.size() / 2);
      for (size_t i = 0; i < s.size(); i += 2)
      {
        const int hi = nib(s[i]);
        const int lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0)
          return std::nullopt;
        out.push_back(uint8_t((hi << 4) | lo));
      }
      return out;
    }

    //  JSON accessors
    //
    //  Small helpers that read a required field of a specific type.
    //  Each returns false if the field is missing or the wrong type.
    //  We use these instead of nlohmann::json::at() because we want
    //  a clean WalletStatus error rather than an exception.

    bool getUint(const Common::Json &j, const char *key, uint64_t &out)
    {
      if (!j.contains(key))
        return false;
      const auto &v = j[key];
      if (!v.is_number_unsigned() && !v.is_number_integer())
        return false;
      out = v.get<uint64_t>();
      return true;
    }

    bool getString(const Common::Json &j, const char *key, std::string &out)
    {
      if (!j.contains(key))
        return false;
      const auto &v = j[key];
      if (!v.is_string())
        return false;
      out = v.get<std::string>();
      return true;
    }

    // Read a hex string field into a byte vector.
    bool getHex(const Common::Json &j, const char *key,
                std::vector<uint8_t> &out)
    {
      std::string s;
      if (!getString(j, key, s))
        return false;
      auto decoded = fromHex(s);
      if (!decoded)
        return false;
      out = std::move(*decoded);
      return true;
    }

    //  Json -> struct

    // Parse a crypto.kdfparams sub-object for the given KDF.
    bool parseArgon2Params(const Common::Json &j, Argon2ParamsJson &out,
                           WalletStatus *err)
    {
      if (!j.is_object())
        return false;

      if (!getHex(j, "salt", out.salt))
      {
        if (err)
          *err = WalletStatus::fail(WalletError::KeyStoreCorrupt,
                                    "argon2id: missing or invalid 'salt'");
        return false;
      }

      uint64_t m = 0, t = 0, p = 0;
      if (!getUint(j, "m_cost_kib", m) ||
          !getUint(j, "t_cost", t) ||
          !getUint(j, "p_cost", p))
      {
        if (err)
          *err = WalletStatus::fail(WalletError::KeyStoreCorrupt,
                                    "argon2id: missing cost parameters");
        return false;
      }

      // Cost parameters must fit in uint32_t and be within sane bounds.
      // The exact bounds are re-checked in validateKeyStoreFile; here
      // we only guard against overflow and nonsensical values.
      if (m > 0xFFFFFFFFull || t > 0xFFFFFFFFull || p > 0xFFFFFFFFull)
      {
        if (err)
          *err = WalletStatus::fail(WalletError::KeyStoreCorrupt,
                                    "argon2id: cost parameter overflows uint32");
        return false;
      }

      out.m_cost_kib = uint32_t(m);
      out.t_cost = uint32_t(t);
      out.p_cost = uint32_t(p);
      return true;
    }

    bool parsePbkdf2Params(const Common::Json &j, Pbkdf2ParamsJson &out,
                           WalletStatus *err)
    {
      if (!j.is_object())
        return false;

      if (!getHex(j, "salt", out.salt))
      {
        if (err)
          *err = WalletStatus::fail(WalletError::KeyStoreCorrupt,
                                    "pbkdf2: missing or invalid 'salt'");
        return false;
      }

      uint64_t iters = 0;
      if (!getUint(j, "iterations", iters))
      {
        if (err)
          *err = WalletStatus::fail(WalletError::KeyStoreCorrupt,
                                    "pbkdf2: missing 'iterations'");
        return false;
      }
      if (iters > 0xFFFFFFFFull)
      {
        if (err)
          *err = WalletStatus::fail(WalletError::KeyStoreCorrupt,
                                    "pbkdf2: iterations overflows uint32");
        return false;
      }
      out.iterations = uint32_t(iters);
      return true;
    }

    //  struct -> Json

    Common::Json serializeArgon2Params(const Argon2ParamsJson &p)
    {
      Common::Json j;
      j["salt"] = toHex(p.salt);
      j["m_cost_kib"] = p.m_cost_kib;
      j["t_cost"] = p.t_cost;
      j["p_cost"] = p.p_cost;
      return j;
    }

    Common::Json serializePbkdf2Params(const Pbkdf2ParamsJson &p)
    {
      Common::Json j;
      j["salt"] = toHex(p.salt);
      j["iterations"] = p.iterations;
      return j;
    }

    std::optional<Network> networkFromString(std::string_view s) noexcept
    {
      if (s == "mainnet")
        return Network::Mainnet;
      if (s == "testnet")
        return Network::Testnet;
      if (s == "regtest")
        return Network::Regtest;
      return std::nullopt;
    }

    //  Temp-file-then-rename atomic write
    //
    //  Write to `path + ".tmp"`, fsync, rename over `path`. If we
    //  crash mid-write, the original file is untouched. This is the
    //  standard pattern for durability without a journal.
    bool writeFileAtomically(const std::string &path,
                             const std::string &contents,
                             WalletStatus *error_out)
    {
      const std::string tmp_path = path + ".tmp";

      {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f.is_open())
        {
          if (error_out)
            *error_out = WalletStatus::fail(
                WalletError::Internal,
                "could not open temp file: " + tmp_path);
          return false;
        }
        f.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        f.flush();
        if (!f)
        {
          if (error_out)
            *error_out = WalletStatus::fail(
                WalletError::Internal,
                "write failed: " + tmp_path);
          f.close();
          std::remove(tmp_path.c_str());
          return false;
        }
      } // ofstream destructor closes and flushes

      // Rename over the target. std::rename is atomic on POSIX when
      // src and dst are on the same filesystem.
      if (std::rename(tmp_path.c_str(), path.c_str()) != 0)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::Internal,
              "rename failed: " + tmp_path + " -> " + path);
        std::remove(tmp_path.c_str());
        return false;
      }

      return true;
    }

  } // namespace

  //  Serialize

  std::string serializeKeyStoreFile(const KeyStoreFile &f)
  {
    Common::Json j;

    // Top-level identity.
    j["version"] = f.version;
    j["id"] = f.id;
    j["label"] = f.label;
    j["network"] = f.network;
    j["chain_id"] = f.chain_id;
    j["address"] = f.address;
    j["pubkey"] = toHex(f.pubkey);

    // Crypto section.
    {
      Common::Json c;
      c["cipher"] = f.crypto.cipher;
      c["nonce"] = toHex(f.crypto.nonce);
      c["aad"] = f.crypto.aad;
      c["ciphertext"] = toHex(f.crypto.ciphertext);
      c["mac"] = toHex(f.crypto.mac);
      c["kdf"] = f.crypto.kdf;

      // Exactly one of the two kdfparams sub-objects is present.
      if (f.crypto.kdf == KDF_ARGON2ID && f.crypto.argon2)
      {
        c["kdfparams"] = serializeArgon2Params(*f.crypto.argon2);
      }
      else if (f.crypto.kdf == KDF_PBKDF2_HMAC_SHA512 && f.crypto.pbkdf2)
      {
        c["kdfparams"] = serializePbkdf2Params(*f.crypto.pbkdf2);
      }
      else
      {
        // Malformed input to the serializer. Emit an empty object;
        // validateKeyStoreFile would have caught this earlier.
        c["kdfparams"] = Common::Json::object();
      }

      j["crypto"] = std::move(c);
    }

    // HD section.
    {
      Common::Json h;
      h["seed_fingerprint"] = toHex(f.hd.seed_fingerprint);
      h["default_path"] = f.hd.default_path;
      j["hd"] = std::move(h);
    }

    // Metadata.
    j["created_at_ms"] = f.created_at_ms;

    // Pretty-print with 4-space indent. nlohmann::json::dump does
    // not guarantee key order, but it preserves insertion order for
    // objects by default, which is what we want for readability.
    return j.dump(4);
  }

  //  Parse

  std::optional<KeyStoreFile> parseKeyStoreFile(
      const std::string &json,
      WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<KeyStoreFile>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    Common::Json j;
    try
    {
      j = Common::Json::parse(json);
    }
    catch (const std::exception &e)
    {
      return fail(WalletError::KeyStoreCorrupt,
                  std::string("JSON parse error: ") + e.what());
    }

    if (!j.is_object())
      return fail(WalletError::KeyStoreCorrupt, "root is not an object");

    KeyStoreFile f;

    // Version. Must be present and match what we support. Older
    // versions would need a migration path; v1 is the only one so far.
    {
      uint64_t version = 0;
      if (!getUint(j, "version", version))
        return fail(WalletError::KeyStoreCorrupt, "missing 'version'");
      if (version != KEYSTORE_VERSION)
        return fail(WalletError::KeyStoreUnsupportedVersion,
                    "version " + std::to_string(version) +
                        " not supported (expected " +
                        std::to_string(KEYSTORE_VERSION) + ")");
      f.version = uint32_t(version);
    }

    // Identity fields.
    if (!getString(j, "id", f.id))
      return fail(WalletError::KeyStoreCorrupt, "missing 'id'");
    if (!getString(j, "network", f.network))
      return fail(WalletError::KeyStoreCorrupt, "missing 'network'");
    if (!networkFromString(f.network))
      return fail(WalletError::KeyStoreCorrupt,
                  "unknown network: '" + f.network + "'");

    // chain_id is required.
    {
      uint64_t cid = 0;
      if (!getUint(j, "chain_id", cid))
        return fail(WalletError::KeyStoreCorrupt, "missing 'chain_id'");
      f.chain_id = cid;
    }

    // Optional identity fields with sensible defaults.
    getString(j, "label", f.label);
    getString(j, "address", f.address);

    // pubkey is required.
    if (!getHex(j, "pubkey", f.pubkey))
      return fail(WalletError::KeyStoreCorrupt,
                  "missing or invalid 'pubkey'");

    //  Crypto section.

    if (!j.contains("crypto") || !j["crypto"].is_object())
      return fail(WalletError::KeyStoreCorrupt, "missing 'crypto' object");

    const auto &c = j["crypto"];

    if (!getString(c, "cipher", f.crypto.cipher))
      return fail(WalletError::KeyStoreCorrupt, "missing 'crypto.cipher'");
    if (f.crypto.cipher != CIPHER_XCHACHA20_POLY1305)
      return fail(WalletError::KeyStoreUnsupportedCipher,
                  "unsupported cipher: '" + f.crypto.cipher + "'");

    if (!getHex(c, "nonce", f.crypto.nonce))
      return fail(WalletError::KeyStoreCorrupt, "missing 'crypto.nonce'");
    if (!getString(c, "aad", f.crypto.aad))
      return fail(WalletError::KeyStoreCorrupt, "missing 'crypto.aad'");
    if (!getHex(c, "ciphertext", f.crypto.ciphertext))
      return fail(WalletError::KeyStoreCorrupt, "missing 'crypto.ciphertext'");
    if (!getHex(c, "mac", f.crypto.mac))
      return fail(WalletError::KeyStoreCorrupt, "missing 'crypto.mac'");

    if (!getString(c, "kdf", f.crypto.kdf))
      return fail(WalletError::KeyStoreCorrupt, "missing 'crypto.kdf'");

    if (!c.contains("kdfparams") || !c["kdfparams"].is_object())
      return fail(WalletError::KeyStoreCorrupt,
                  "missing 'crypto.kdfparams' object");

    const auto &kp = c["kdfparams"];

    if (f.crypto.kdf == KDF_ARGON2ID)
    {
      Argon2ParamsJson params;
      if (!parseArgon2Params(kp, params, error_out))
        return std::nullopt;
      f.crypto.argon2 = std::move(params);
    }
    else if (f.crypto.kdf == KDF_PBKDF2_HMAC_SHA512)
    {
      Pbkdf2ParamsJson params;
      if (!parsePbkdf2Params(kp, params, error_out))
        return std::nullopt;
      f.crypto.pbkdf2 = std::move(params);
    }
    else
    {
      return fail(WalletError::KeyStoreUnsupportedKdf,
                  "unsupported kdf: '" + f.crypto.kdf + "'");
    }

    //  HD section.

    if (!j.contains("hd") || !j["hd"].is_object())
      return fail(WalletError::KeyStoreCorrupt, "missing 'hd' object");

    const auto &h = j["hd"];

    if (!getHex(h, "seed_fingerprint", f.hd.seed_fingerprint))
      return fail(WalletError::KeyStoreCorrupt,
                  "missing 'hd.seed_fingerprint'");
    if (!getString(h, "default_path", f.hd.default_path))
      return fail(WalletError::KeyStoreCorrupt,
                  "missing 'hd.default_path'");

    //  Metadata. Optional but recommended.
    {
      uint64_t t = 0;
      if (getUint(j, "created_at_ms", t))
        f.created_at_ms = t;
    }

    // Semantic validation. Parse succeeded; now check lengths and
    // ranges. This is separated out so it can also be called on
    // freshly constructed files before serialization.
    const WalletError ve = validateKeyStoreFile(f);
    if (ve != WalletError::Ok)
      return fail(ve, walletErrorMessage(ve));

    return f;
  }

  //  File I/O

  std::optional<KeyStoreFile> readKeyStoreFile(
      const std::string &path,
      WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<KeyStoreFile>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    std::ifstream f(path, std::ios::binary);
    if (!f.is_open())
    {
      return fail(WalletError::KeyStoreNotFound,
                  "cannot open keystore: " + path);
    }

    std::ostringstream ss;
    ss << f.rdbuf();
    if (!f.good() && !f.eof())
    {
      return fail(WalletError::Internal,
                  "read error on keystore: " + path);
    }

    return parseKeyStoreFile(ss.str(), error_out);
  }

  bool writeKeyStoreFile(const std::string &path,
                         const KeyStoreFile &f,
                         WalletStatus *error_out)
  {
    const std::string contents = serializeKeyStoreFile(f);
    return writeFileAtomically(path, contents, error_out);
  }

  //  Validation

  WalletError validateKeyStoreFile(const KeyStoreFile &f)
  {
    // Version.
    if (f.version != KEYSTORE_VERSION)
      return WalletError::KeyStoreUnsupportedVersion;

    // Identity.
    if (f.id.empty())
      return WalletError::KeyStoreCorrupt;
    if (f.network.empty() || !networkFromString(f.network))
      return WalletError::KeyStoreCorrupt;
    if (f.chain_id == 0)
      return WalletError::KeyStoreCorrupt;
    if (f.pubkey.size() != ADDRESS_PUBKEY_LENGTH)
      return WalletError::KeyStoreCorrupt;

    // Crypto section field lengths.
    if (f.crypto.cipher != CIPHER_XCHACHA20_POLY1305)
      return WalletError::KeyStoreUnsupportedCipher;
    if (f.crypto.nonce.size() != KEYSTORE_NONCE_LENGTH)
      return WalletError::KeyStoreCorrupt;
    if (f.crypto.mac.size() != 16)
      return WalletError::KeyStoreCorrupt;
    if (f.crypto.ciphertext.empty() || f.crypto.ciphertext.size() > 64)
      return WalletError::KeyStoreCorrupt;

    // AAD must match what we expect for this version. This is the
    // downgrade protection: if an attacker changes the version field
    // to a "v2" that uses weaker crypto, the AAD won't match and
    // decryption fails.
    if (f.crypto.aad != KEYSTORE_AAD)
      return WalletError::KeyStoreCorrupt;

    // KDF and its parameters.
    if (f.crypto.kdf == KDF_ARGON2ID)
    {
      if (!f.crypto.argon2)
        return WalletError::KeyStoreCorrupt;
      const auto &p = *f.crypto.argon2;
      if (p.salt.size() != KEYSTORE_SALT_LENGTH)
        return WalletError::KeyStoreCorrupt;
      // Reuse Crypto::Argon2Params::valid() semantics.
      if (p.m_cost_kib < 8)
        return WalletError::KeyStoreCorrupt;
      if (p.t_cost < 1)
        return WalletError::KeyStoreCorrupt;
      if (p.p_cost < 1)
        return WalletError::KeyStoreCorrupt;
      if (p.m_cost_kib < 8u * p.p_cost)
        return WalletError::KeyStoreCorrupt;
      // Upper bound: refuse to allocate absurd memory. 8 GiB is
      // generous; a keystore that requests more is either malicious
      // or corrupt.
      if (p.m_cost_kib > 8u * 1024u * 1024u)
        return WalletError::KeyStoreCorrupt;
    }
    else if (f.crypto.kdf == KDF_PBKDF2_HMAC_SHA512)
    {
      if (!f.crypto.pbkdf2)
        return WalletError::KeyStoreCorrupt;
      const auto &p = *f.crypto.pbkdf2;
      if (p.salt.size() != KEYSTORE_SALT_LENGTH)
        return WalletError::KeyStoreCorrupt;
      // Minimum iterations. Any value below this is insecure and
      // suggests the file has been tampered with.
      if (p.iterations < 100000)
        return WalletError::KeyStoreCorrupt;
    }
    else
    {
      return WalletError::KeyStoreUnsupportedKdf;
    }

    // HD section.
    if (f.hd.seed_fingerprint.size() != 4)
      return WalletError::KeyStoreCorrupt;
    if (f.hd.default_path.empty())
      return WalletError::KeyStoreCorrupt;

    return WalletError::Ok;
  }

  //  UUID-v4 generation
  //
  //  Format: 8-4-4-4-12 lowercase hex, with version and variant bits
  //  set per RFC 4122 §4.4. Used only for identification, not for
  //  security; the entropy source is Crypto::randomBytes.

  std::string generateUuidV4()
  {
    uint8_t b[16];
    Crypto::randomBytes(b, sizeof(b));

    // Version: bits 4-7 of byte 6 = 0100 (4).
    b[6] = uint8_t((b[6] & 0x0F) | 0x40);

    // Variant: bits 6-7 of byte 8 = 10.
    b[8] = uint8_t((b[8] & 0x3F) | 0x80);

    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (int i = 0; i < 16; ++i)
    {
      if (i == 4 || i == 6 || i == 8 || i == 10)
        out.push_back('-');
      out.push_back(hex[b[i] >> 4]);
      out.push_back(hex[b[i] & 0x0F]);
    }
    return out;
  }

  //  Network string <-> enum
  //
  //  Duplicated from WalletTypes.cpp's networkName, but in the
  //  direction we need for JSON. Kept local so this file doesn't
  //  depend on the .cpp for a two-line mapping.

  const char *networkToString(Network n) noexcept
  {
    switch (n)
    {
    case Network::Mainnet:
      return "mainnet";
    case Network::Testnet:
      return "testnet";
    case Network::Regtest:
      return "regtest";
    }
    return "unknown";
  }
} // namespace Wallet