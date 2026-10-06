// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "KeyStoreFormat.h"

#include "Common/Json.h"
#include "Common/StringTools.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <filesystem>
#include <random>

namespace Wallet
{

  namespace
  {
    //  ---- Hex helpers ----
    //
    //  Kept local so the format doesn't depend on Common/Hex.h's
    //  exact API.

    std::string bytesToHex(const std::vector<uint8_t> &v)
    {
      static const char hex[] = "0123456789abcdef";
      std::string out;
      out.reserve(v.size() * 2);
      for (uint8_t b : v)
      {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0F]);
      }
      return out;
    }

    bool hexToBytes(const std::string &hex, std::vector<uint8_t> &out)
    {
      if (hex.size() % 2 != 0)
        return false;

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

      out.clear();
      out.reserve(hex.size() / 2);
      for (size_t i = 0; i < hex.size(); i += 2)
      {
        const int hi = nib(hex[i]);
        const int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0)
          return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
      }
      return true;
    }
  } // anonymous namespace

  // ===========================================================================
  //  Serialize
  // ===========================================================================

  std::string serializeKeyStoreFile(const KeyStoreFile &f)
  {
    Common::Json j = Common::Json::object();

    j["version"] = f.version;
    j["id"] = f.id;
    j["label"] = f.label;
    j["network"] = f.network;
    j["chain_id"] = f.chain_id;
    j["address"] = f.address;
    j["pubkey"] = bytesToHex(f.pubkey);
    j["created_at_ms"] = f.created_at_ms;

    //  ---- crypto ----
    {
      Common::Json c = Common::Json::object();
      c["cipher"] = f.crypto.cipher;
      c["nonce"] = bytesToHex(f.crypto.nonce);
      c["aad"] = f.crypto.aad;
      c["ciphertext"] = bytesToHex(f.crypto.ciphertext);
      c["mac"] = bytesToHex(f.crypto.mac);
      c["kdf"] = f.crypto.kdf;

      Common::Json kp = Common::Json::object();
      if (f.crypto.argon2.has_value())
      {
        kp["salt"] = bytesToHex(f.crypto.argon2->salt);
        kp["m_cost_kib"] = f.crypto.argon2->m_cost_kib;
        kp["t_cost"] = f.crypto.argon2->t_cost;
        kp["p_cost"] = f.crypto.argon2->p_cost;
      }
      else if (f.crypto.pbkdf2.has_value())
      {
        kp["salt"] = bytesToHex(f.crypto.pbkdf2->salt);
        kp["iterations"] = f.crypto.pbkdf2->iterations;
      }
      c["kdfparams"] = std::move(kp);

      j["crypto"] = std::move(c);
    }

    //  ---- hd ----
    {
      Common::Json h = Common::Json::object();
      h["seed_fingerprint"] = bytesToHex(f.hd.seed_fingerprint);
      h["default_path"] = f.hd.default_path;
      //  Only emit validator_path if it's set. Older readers that
      //  don't understand the field will ignore it; newer readers
      //  fall back to the standard path if the field is absent.
      if (!f.hd.validator_path.empty())
        h["validator_path"] = f.hd.validator_path;
      j["hd"] = std::move(h);
    }

    return j.dump(4);
  }

  // ===========================================================================
  //  Parse
  // ===========================================================================

  std::optional<KeyStoreFile> parseKeyStoreFile(
      const std::string &json,
      WalletStatus *error_out)
  {
    Common::Json j;
    try
    {
      j = Common::Json::parse(json);
    }
    catch (const std::exception &e)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreCorrupt,
            std::string("invalid JSON: ") + e.what());
      return std::nullopt;
    }

    if (!j.is_object())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreCorrupt, "top-level JSON is not an object");
      return std::nullopt;
    }

    KeyStoreFile f;

    //  ---- version ----
    if (!j.contains("version") || !j["version"].is_number_unsigned())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreCorrupt, "missing or invalid 'version'");
      return std::nullopt;
    }
    f.version = j["version"].get<uint32_t>();
    if (f.version != KEYSTORE_VERSION)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreUnsupportedVersion,
            "unsupported keystore version");
      return std::nullopt;
    }

    //  ---- top-level scalars ----
    if (!j.contains("id") || !j["id"].is_string() ||
        !j.contains("label") || !j["label"].is_string() ||
        !j.contains("network") || !j["network"].is_string() ||
        !j.contains("chain_id") || !j["chain_id"].is_number_unsigned() ||
        !j.contains("address") || !j["address"].is_string() ||
        !j.contains("pubkey") || !j["pubkey"].is_string() ||
        !j.contains("created_at_ms") || !j["created_at_ms"].is_number_unsigned())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreCorrupt,
            "missing or invalid top-level field");
      return std::nullopt;
    }

    f.id = j["id"].get<std::string>();
    f.label = j["label"].get<std::string>();
    f.network = j["network"].get<std::string>();
    f.chain_id = j["chain_id"].get<uint64_t>();
    f.address = j["address"].get<std::string>();
    f.created_at_ms = j["created_at_ms"].get<uint64_t>();

    if (!hexToBytes(j["pubkey"].get<std::string>(), f.pubkey))
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreCorrupt, "invalid 'pubkey' hex");
      return std::nullopt;
    }

    //  ---- crypto ----
    if (!j.contains("crypto") || !j["crypto"].is_object())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreCorrupt, "missing 'crypto' object");
      return std::nullopt;
    }
    {
      const auto &c = j["crypto"];
      if (!c.contains("cipher") || !c["cipher"].is_string() ||
          !c.contains("nonce") || !c["nonce"].is_string() ||
          !c.contains("aad") || !c["aad"].is_string() ||
          !c.contains("ciphertext") || !c["ciphertext"].is_string() ||
          !c.contains("mac") || !c["mac"].is_string() ||
          !c.contains("kdf") || !c["kdf"].is_string() ||
          !c.contains("kdfparams") || !c["kdfparams"].is_object())
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::KeyStoreCorrupt, "missing crypto field");
        return std::nullopt;
      }

      f.crypto.cipher = c["cipher"].get<std::string>();
      f.crypto.aad = c["aad"].get<std::string>();
      f.crypto.kdf = c["kdf"].get<std::string>();

      if (!hexToBytes(c["nonce"].get<std::string>(), f.crypto.nonce) ||
          !hexToBytes(c["ciphertext"].get<std::string>(), f.crypto.ciphertext) ||
          !hexToBytes(c["mac"].get<std::string>(), f.crypto.mac))
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::KeyStoreCorrupt, "invalid crypto hex field");
        return std::nullopt;
      }

      const auto &kp = c["kdfparams"];
      if (f.crypto.kdf == KDF_ARGON2ID)
      {
        if (!kp.contains("salt") || !kp["salt"].is_string() ||
            !kp.contains("m_cost_kib") || !kp["m_cost_kib"].is_number_unsigned() ||
            !kp.contains("t_cost") || !kp["t_cost"].is_number_unsigned() ||
            !kp.contains("p_cost") || !kp["p_cost"].is_number_unsigned())
        {
          if (error_out)
            *error_out = WalletStatus::fail(
                WalletError::KeyStoreCorrupt, "invalid argon2id params");
          return std::nullopt;
        }

        Argon2ParamsJson a;
        if (!hexToBytes(kp["salt"].get<std::string>(), a.salt))
        {
          if (error_out)
            *error_out = WalletStatus::fail(
                WalletError::KeyStoreCorrupt, "invalid argon2id salt");
          return std::nullopt;
        }
        a.m_cost_kib = kp["m_cost_kib"].get<uint32_t>();
        a.t_cost = kp["t_cost"].get<uint32_t>();
        a.p_cost = kp["p_cost"].get<uint32_t>();
        f.crypto.argon2 = std::move(a);
      }
      else if (f.crypto.kdf == KDF_PBKDF2_HMAC_SHA512)
      {
        if (!kp.contains("salt") || !kp["salt"].is_string() ||
            !kp.contains("iterations") || !kp["iterations"].is_number_unsigned())
        {
          if (error_out)
            *error_out = WalletStatus::fail(
                WalletError::KeyStoreCorrupt, "invalid pbkdf2 params");
          return std::nullopt;
        }

        Pbkdf2ParamsJson p;
        if (!hexToBytes(kp["salt"].get<std::string>(), p.salt))
        {
          if (error_out)
            *error_out = WalletStatus::fail(
                WalletError::KeyStoreCorrupt, "invalid pbkdf2 salt");
          return std::nullopt;
        }
        p.iterations = kp["iterations"].get<uint32_t>();
        f.crypto.pbkdf2 = std::move(p);
      }
      else
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::KeyStoreUnsupportedKdf,
              "unknown KDF: " + f.crypto.kdf);
        return std::nullopt;
      }
    }

    //  ---- hd ----
    if (!j.contains("hd") || !j["hd"].is_object())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreCorrupt, "missing 'hd' object");
      return std::nullopt;
    }
    {
      const auto &h = j["hd"];
      if (!h.contains("seed_fingerprint") || !h["seed_fingerprint"].is_string() ||
          !h.contains("default_path") || !h["default_path"].is_string())
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::KeyStoreCorrupt, "missing hd field");
        return std::nullopt;
      }

      if (!hexToBytes(h["seed_fingerprint"].get<std::string>(),
                      f.hd.seed_fingerprint))
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::KeyStoreCorrupt, "invalid seed_fingerprint");
        return std::nullopt;
      }
      f.hd.default_path = h["default_path"].get<std::string>();

      //  validator_path is optional. Older keystores don't have it.
      //  When absent, leave it empty; the caller (EncryptedKeyStore)
      //  falls back to the standard path.
      if (h.contains("validator_path") && h["validator_path"].is_string())
      {
        f.hd.validator_path = h["validator_path"].get<std::string>();
      }
    }

    //  Run the format's validation rules on the parsed structure.
    //  parseKeyStoreFile is the single choke point for reading a
    //  keystore from JSON — whether that JSON came from disk or from
    //  a caller that constructed it in memory — and every reader of
    //  a keystore file must see the same rejection semantics. Doing
    //  validation here means an invalid field is caught at parse time
    //  with the specific error code the caller expects, rather than
    //  surfacing later as a KDF failure or an authentication failure
    //  with a misleading cause.
    const WalletError verr = validateKeyStoreFile(f);
    if (verr != WalletError::Ok)
    {
      if (error_out)
        *error_out = WalletStatus::fail(verr, walletErrorMessage(verr));
      return std::nullopt;
    }

    return f;
  }

  // ===========================================================================
  //  File I/O
  // ===========================================================================

  std::optional<KeyStoreFile> readKeyStoreFile(
      const std::string &path,
      WalletStatus *error_out)
  {
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreNotFound,
            "cannot open " + path);
      return std::nullopt;
    }

    std::stringstream buf;
    buf << in.rdbuf();
    if (in.bad())
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::Internal,
            "read error on " + path);
      return std::nullopt;
    }

    return parseKeyStoreFile(buf.str(), error_out);
  }

  bool writeKeyStoreFile(const std::string &path,
                         const KeyStoreFile &f,
                         WalletStatus *error_out)
  {
    namespace fs = std::filesystem;

    //  Write to a temporary file in the same directory, then rename.
    //  A crash mid-write leaves the original untouched.
    const fs::path final_path(path);
    const fs::path tmp_path = final_path.string() + ".tmp";

    const std::string json = serializeKeyStoreFile(f);

    {
      std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
      if (!out)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::Internal,
              "cannot create " + tmp_path.string());
        return false;
      }

      out.write(json.data(), json.size());
      out.flush();
      if (!out)
      {
        if (error_out)
          *error_out = WalletStatus::fail(
              WalletError::Internal,
              "write error on " + tmp_path.string());
        std::error_code ec;
        fs::remove(tmp_path, ec);
        return false;
      }
    }

    //  Restrict permissions before the rename. Best-effort.
    std::error_code ec;
    fs::permissions(tmp_path,
                    fs::perms::owner_read | fs::perms::owner_write,
                    fs::perm_options::replace,
                    ec);

    //  Atomic rename.
    fs::rename(tmp_path, final_path, ec);
    if (ec)
    {
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::Internal,
            "cannot rename temp file: " + ec.message());
      std::error_code rm_ec;
      fs::remove(tmp_path, rm_ec);
      return false;
    }

    return true;
  }

  // ===========================================================================
  //  Validation
  // ===========================================================================

  WalletError validateKeyStoreFile(const KeyStoreFile &f)
  {
    if (f.version != KEYSTORE_VERSION)
      return WalletError::KeyStoreUnsupportedVersion;

    // ---- top-level scalar checks ----
    if (f.chain_id == 0)
      return WalletError::KeyStoreCorrupt;

    if (f.network != "mainnet" &&
        f.network != "testnet" &&
        f.network != "regtest")
    {
      return WalletError::KeyStoreCorrupt;
    }

    // ---- crypto structural checks ----
    if (f.crypto.cipher != CIPHER_XCHACHA20_POLY1305)
      return WalletError::KeyStoreUnsupportedCipher;

    if (f.crypto.nonce.size() != KEYSTORE_NONCE_LENGTH)
      return WalletError::KeyStoreCorrupt;

    if (f.crypto.mac.size() != 16)
      return WalletError::KeyStoreCorrupt;

    //  Ciphertext is the encrypted seed, so it's bounded by the seed
    //  length: non-empty, at most 64 bytes. An empty ciphertext would
    //  decrypt to nothing; an oversized one can't be a seed.
    if (f.crypto.ciphertext.empty() || f.crypto.ciphertext.size() > 64)
      return WalletError::KeyStoreCorrupt;

    //  AAD must match the format's fixed string. The AAD binds the
    //  ciphertext to a specific format version; a mismatch is either
    //  tampering or a file from a format we don't recognize.
    if (f.crypto.aad != KEYSTORE_AAD)
      return WalletError::KeyStoreCorrupt;

    // ---- KDF parameters ----
    if (f.crypto.kdf == KDF_ARGON2ID)
    {
      if (!f.crypto.argon2.has_value())
        return WalletError::KeyStoreCorrupt;
      const auto &a = *f.crypto.argon2;
      if (a.salt.size() != KEYSTORE_SALT_LENGTH)
        return WalletError::KeyStoreCorrupt;

      //  Argon2id parameter bounds. RFC 9106 requires m_cost >=
      //  8 * p_cost; a smaller value would be rejected by the KDF
      //  implementation, but we reject it earlier so the failure is
      //  a clean validation error rather than a KDF failure.
      if (a.m_cost_kib < 8)
        return WalletError::KeyStoreCorrupt;
      if (a.t_cost == 0)
        return WalletError::KeyStoreCorrupt;
      if (a.p_cost == 0)
        return WalletError::KeyStoreCorrupt;
      if (a.m_cost_kib < 8 * a.p_cost)
        return WalletError::KeyStoreCorrupt;
      //  Upper bound: 8 GiB. Rejects absurd memory allocations that
      //  would OOM the host rather than produce a key.
      if (a.m_cost_kib > 8 * 1024 * 1024)
        return WalletError::KeyStoreCorrupt;
    }
    else if (f.crypto.kdf == KDF_PBKDF2_HMAC_SHA512)
    {
      if (!f.crypto.pbkdf2.has_value())
        return WalletError::KeyStoreCorrupt;
      const auto &p = *f.crypto.pbkdf2;
      if (p.salt.size() != KEYSTORE_SALT_LENGTH)
        return WalletError::KeyStoreCorrupt;

      //  PBKDF2 iteration floor: 100,000. Below this the derived key
      //  is too weak to be a meaningful barrier, and a keystore that
      //  claims a low count is either corrupt or hostile.
      if (p.iterations < 100'000)
        return WalletError::KeyStoreCorrupt;
    }
    else
    {
      return WalletError::KeyStoreUnsupportedKdf;
    }

    // ---- public key and HD ----
    if (f.pubkey.size() != 32)
      return WalletError::KeyStoreCorrupt;

    if (f.hd.seed_fingerprint.size() != 4)
      return WalletError::KeyStoreCorrupt;

    if (f.hd.default_path.empty())
      return WalletError::KeyStoreCorrupt;

    return WalletError::Ok;
  }

  // ===========================================================================
  //  Helpers
  // ===========================================================================

  std::string generateUuidV4()
  {
    //  Generate 16 random bytes, set the version and variant bits,
    //  format as the canonical "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".
    //
    //  Use std::random_device as a source. Not cryptographically
    //  strong, but adequate for a unique identifier.
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    uint8_t b[16];
    for (auto &x : b)
      x = static_cast<uint8_t>(dist(rd));

    b[6] = (b[6] & 0x0F) | 0x40; // version 4
    b[8] = (b[8] & 0x3F) | 0x80; // variant 10

    static const char hex[] = "0123456789abcdef";
    auto hexbyte = [&](uint8_t v) -> std::pair<char, char>
    {
      return {hex[v >> 4], hex[v & 0x0F]};
    };

    std::string s;
    s.reserve(36);
    const int dash_after[] = {3, 5, 7, 9};
    for (int i = 0; i < 16; ++i)
    {
      if (std::find(std::begin(dash_after), std::end(dash_after), (i * 2) - 1) != std::end(dash_after))
        s.push_back('-');
      auto [hi, lo] = hexbyte(b[i]);
      s.push_back(hi);
      s.push_back(lo);
    }
    // Fix the last dash: it should be after byte 9's second character.
    s.push_back('-');
    auto [hi, lo] = hexbyte(b[10]);
    s.back() = '-'; // already correct
    // Simpler: build it explicitly.
    s.clear();
    s.reserve(36);
    for (int i = 0; i < 16; ++i)
    {
      if (i == 4 || i == 6 || i == 8 || i == 10)
        s.push_back('-');
      auto [h, l] = hexbyte(b[i]);
      s.push_back(h);
      s.push_back(l);
    }
    return s;
  }

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