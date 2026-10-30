// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Custody.h"

#include "Common/Json.h"

#include "Crypto/Argon2id.h"
#include "Crypto/BitcoinBip32Private.h"
#include "Crypto/Chacha20Poly1305.h"
#include "Crypto/Random.h"
#include "Crypto/SecureZero.h"

#include "Wallet/Bip39.h"
#include "Wallet/KeyDerivation.h"
#include "Wallet/WalletError.h"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace Bridge
{
  namespace
  {
    constexpr uint32_t kGapLimit = 20;
    constexpr size_t kSaltBytes = 16;
    constexpr size_t kKeyBytes = Crypto::AEAD_KEY_SIZE;     // 32
    constexpr size_t kNonceBytes = Crypto::AEAD_NONCE_SIZE; // 24
    constexpr size_t kMacBytes = Crypto::AEAD_MAC_SIZE;     // 16
    constexpr int kMnemonicStrength = 256;                  // 24 words

    //  Argon2id parameters for the custody file. The custody file
    //  is unlocked once per daemon start (not per request), so the
    //  cost is paid once. These are the same parameters the wallet
    //  keystore uses by default (m=64 MiB, t=3, p=4), documented in
    //  Argon2id.h.
    Crypto::Argon2Params custodyKdfParams()
    {
      Crypto::Argon2Params p;
      p.m_cost_kib = 65536;
      p.t_cost = 3;
      p.p_cost = 4;
      return p;
    }

    std::string hexOf(const uint8_t *data, size_t len)
    {
      static const char H[] = "0123456789abcdef";
      std::string s;
      s.reserve(len * 2);
      for (size_t i = 0; i < len; ++i)
      {
        s.push_back(H[data[i] >> 4]);
        s.push_back(H[data[i] & 0xF]);
      }
      return s;
    }

    std::string hexOf(const std::vector<uint8_t> &v)
    {
      return hexOf(v.data(), v.size());
    }

    std::optional<std::vector<uint8_t>> hexToBytes(const std::string &hex)
    {
      if (hex.size() % 2 != 0)
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
      out.reserve(hex.size() / 2);
      for (size_t i = 0; i + 1 < hex.size(); i += 2)
      {
        int hi = nib(hex[i]);
        int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0)
          return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
      }
      return out;
    }

    //  Derive the 32-byte file key from the password and salt.
    bool deriveFileKey(const std::string &password,
                       const std::vector<uint8_t> &salt,
                       uint8_t out_key[kKeyBytes],
                       std::string *error_out)
    {
      const Crypto::Argon2Params params = custodyKdfParams();
      if (!Crypto::argon2id(
              reinterpret_cast<const uint8_t *>(password.data()),
              password.size(),
              salt.data(), salt.size(),
              params,
              out_key, kKeyBytes))
      {
        if (error_out)
          *error_out = "Argon2id key derivation failed";
        return false;
      }
      return true;
    }

    //  Encrypt the mnemonic. Ciphertext and MAC are separate
    //  outputs (that is the AEAD module's shape; it does not
    //  concatenate). The salt is used as the AAD so a tampered
    //  salt invalidates the tag.
    bool encryptMnemonic(const std::string &password,
                         const std::string &mnemonic,
                         std::vector<uint8_t> &salt_out,
                         std::vector<uint8_t> &nonce_out,
                         std::vector<uint8_t> &ciphertext_out,
                         std::vector<uint8_t> &mac_out,
                         std::string *error_out)
    {
      salt_out.resize(kSaltBytes);
      if (!Crypto::randomBytes(salt_out.data(), salt_out.size()))
      {
        if (error_out)
          *error_out = "could not generate random salt";
        return false;
      }
      nonce_out.resize(kNonceBytes);
      if (!Crypto::randomBytes(nonce_out.data(), nonce_out.size()))
      {
        if (error_out)
          *error_out = "could not generate random nonce";
        return false;
      }

      uint8_t key[kKeyBytes];
      if (!deriveFileKey(password, salt_out, key, error_out))
        return false;

      ciphertext_out.resize(mnemonic.size());
      mac_out.resize(kMacBytes);

      bool ok = Crypto::aeadEncrypt(
          reinterpret_cast<const uint8_t *>(mnemonic.data()),
          mnemonic.size(),
          salt_out.data(), salt_out.size(),
          key,
          nonce_out.data(),
          ciphertext_out.data(),
          mac_out.data());

      Crypto::secureZero(key, sizeof(key));

      if (!ok)
      {
        if (error_out)
          *error_out = "AEAD encryption failed";
        return false;
      }
      return true;
    }

    bool decryptMnemonic(const std::string &password,
                         const std::vector<uint8_t> &salt,
                         const std::vector<uint8_t> &nonce,
                         const std::vector<uint8_t> &ciphertext,
                         const std::vector<uint8_t> &mac,
                         std::string &mnemonic_out,
                         std::string *error_out)
    {
      if (mac.size() != kMacBytes)
      {
        if (error_out)
          *error_out = "mac has wrong length";
        return false;
      }

      uint8_t key[kKeyBytes];
      if (!deriveFileKey(password, salt, key, error_out))
        return false;

      std::vector<uint8_t> plaintext(ciphertext.size());
      bool ok = Crypto::aeadDecrypt(
          ciphertext.data(), ciphertext.size(),
          salt.data(), salt.size(),
          key,
          nonce.data(),
          mac.data(),
          plaintext.data());

      Crypto::secureZero(key, sizeof(key));

      if (!ok)
      {
        if (error_out)
          *error_out =
              "decryption failed (wrong password or corrupted custody file)";
        return false;
      }

      mnemonic_out.assign(plaintext.begin(), plaintext.end());
      Crypto::secureZero(plaintext.data(), plaintext.size());
      return true;
    }

    bool readJsonFile(const std::filesystem::path &file,
                      Common::Json &out,
                      std::string *error_out)
    {
      std::ifstream in(file);
      if (!in.good())
        return false;
      try
      {
        out = Common::Json::parse(in);
      }
      catch (const std::exception &e)
      {
        if (error_out)
          *error_out = std::string("could not parse ") + file.string() +
                       ": " + e.what();
        return false;
      }
      return true;
    }

    bool writeFileAtomic(const std::filesystem::path &file,
                         const std::string &contents,
                         std::string *error_out)
    {
      const std::filesystem::path tmp = file.string() + ".tmp";
      {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out)
        {
          if (error_out)
            *error_out = "could not open " + tmp.string() + " for writing";
          return false;
        }
        out << contents;
        if (!out)
        {
          if (error_out)
            *error_out = "could not write " + tmp.string();
          return false;
        }
      }
      std::error_code ec;
      std::filesystem::rename(tmp, file, ec);
      if (ec)
      {
        if (error_out)
          *error_out = "could not rename " + tmp.string() + " to " +
                       file.string() + ": " + ec.message();
        return false;
      }
      return true;
    }
  } // anonymous namespace

  BitcoinCustody::~BitcoinCustody()
  {
    if (have_seed_)
    {
      Crypto::secureZero(seed_.data(), seed_.size());
      have_seed_ = false;
    }
  }

  std::unique_ptr<BitcoinCustody>
  BitcoinCustody::create_or_load(const std::string &custody_dir,
                                 Crypto::BitcoinNetwork network,
                                 const std::string &password,
                                 std::string *error_out)
  {
    if (custody_dir.empty())
    {
      if (error_out)
        *error_out = "custody_dir is empty";
      return nullptr;
    }
    if (password.empty())
    {
      if (error_out)
        *error_out = "password is empty; cannot encrypt or decrypt the "
                     "custody file";
      return nullptr;
    }

    const std::filesystem::path dir = custody_dir;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec)
    {
      if (error_out)
        *error_out = "could not create custody dir " + dir.string() +
                     ": " + ec.message();
      return nullptr;
    }

    const std::filesystem::path file = dir / "custody.keystore";

    std::string mnemonic;

    if (std::filesystem::exists(file))
    {
      Common::Json doc;
      std::string read_err;
      if (!readJsonFile(file, doc, &read_err) || !doc.is_object())
      {
        if (error_out)
          *error_out = read_err.empty()
                           ? "custody file " + file.string() +
                                 " is unreadable or malformed"
                           : read_err;
        return nullptr;
      }

      const auto version = doc.value("version", 0);
      if (version != 1)
      {
        if (error_out)
          *error_out = "unsupported custody file version " +
                       std::to_string(version);
        return nullptr;
      }

      auto salt = hexToBytes(doc.value("salt", std::string("")));
      auto nonce = hexToBytes(doc.value("nonce", std::string("")));
      auto ct = hexToBytes(doc.value("ciphertext", std::string("")));
      auto mac = hexToBytes(doc.value("mac", std::string("")));

      if (!salt.has_value() || salt->size() != kSaltBytes ||
          !nonce.has_value() || nonce->size() != kNonceBytes ||
          !ct.has_value() || !mac.has_value() || mac->size() != kMacBytes)
      {
        if (error_out)
          *error_out = "custody file " + file.string() +
                       " has malformed hex fields";
        return nullptr;
      }

      std::string dec_err;
      if (!decryptMnemonic(password, *salt, *nonce, *ct, *mac,
                           mnemonic, &dec_err))
      {
        if (error_out)
          *error_out = "custody file " + file.string() + ": " + dec_err;
        return nullptr;
      }

      std::cerr << "[btc-custody] loaded existing custody file "
                << file.string() << "\n";
    }
    else
    {
      mnemonic = Wallet::generateMnemonic(kMnemonicStrength);
      if (mnemonic.empty())
      {
        if (error_out)
          *error_out = "BIP39 mnemonic generation failed";
        return nullptr;
      }

      const Wallet::WalletError ve = Wallet::validateMnemonic(mnemonic);
      if (ve != Wallet::WalletError::Ok)
      {
        Crypto::secureZero(mnemonic.data(), mnemonic.size());
        if (error_out)
          *error_out = "generated mnemonic failed validation";
        return nullptr;
      }

      std::vector<uint8_t> salt, nonce, ct, mac;
      std::string enc_err;
      if (!encryptMnemonic(password, mnemonic, salt, nonce, ct, mac,
                           &enc_err))
      {
        Crypto::secureZero(mnemonic.data(), mnemonic.size());
        if (error_out)
          *error_out = enc_err;
        return nullptr;
      }

      Common::Json doc = Common::Json::object();
      doc["version"] = 1;
      doc["kdf"] = "argon2id";
      doc["kdf_m"] = 65536;
      doc["kdf_t"] = 3;
      doc["kdf_p"] = 4;
      doc["salt"] = hexOf(salt);
      doc["nonce"] = hexOf(nonce);
      doc["ciphertext"] = hexOf(ct);
      doc["mac"] = hexOf(mac);

      std::string write_err;
      if (!writeFileAtomic(file, doc.dump(2) + "\n", &write_err))
      {
        Crypto::secureZero(mnemonic.data(), mnemonic.size());
        if (error_out)
          *error_out = write_err;
        return nullptr;
      }

      std::cerr << "[btc-custody] generated new custody key, encrypted "
                   "under the session password, at "
                << file.string() << "\n";
    }

    //  ---- mnemonic -> seed -> BIP84 account xpub ----
    //
    //  The seed is retained on the custody object: the release
    //  path needs it to derive the spending key for the deposit
    //  address a UTXO arrived at, and re-running PBKDF2 + Argon2id
    //  per release is both slow and a second place for the
    //  password to leak. Retention is the standard custody-wallet
    //  tradeoff and matches how the CCX adapter keeps
    //  bridge_custody_view_priv for the process lifetime.
    //
    //  The seed is copied into custody->seed_ and the local copy
    //  is zeroed. On every failure path below, custody's
    //  destructor (or an explicit zero here, before returning
    //  nullptr) wipes the retained copy.
    std::array<uint8_t, 64> seed{};
    Wallet::mnemonicToSeed(mnemonic, /*passphrase=*/"", seed.data());
    Crypto::secureZero(mnemonic.data(), mnemonic.size());

    const std::vector<uint8_t> seed_vec(seed.begin(), seed.end());

    std::string xpub_err;
    auto account_xpub =
        Crypto::bip84AccountXpub(seed_vec, network, &xpub_err);
    if (!account_xpub.has_value())
    {
      Crypto::secureZero(seed.data(), seed.size());
      if (error_out)
        *error_out = "could not derive BIP84 account xpub: " + xpub_err;
      return nullptr;
    }

    auto custody = std::unique_ptr<BitcoinCustody>(new BitcoinCustody());
    custody->account_ = *account_xpub;
    custody->source_ = Source::Generated;
    custody->master_fp_ = Crypto::keyFingerprint(account_xpub->pubkey);
    custody->network_ = network;
    custody->seed_ = seed;
    custody->have_seed_ = true;
    Crypto::secureZero(seed.data(), seed.size());

    const std::vector<uint32_t> tail = {0u}; // receive branch
    if (!custody->init_common(network, tail, error_out))
      return nullptr; // custody's destructor wipes seed_

    return custody;
  }

  std::unique_ptr<BitcoinCustody>
  BitcoinCustody::from_xpub(const std::string &account_xpub,
                            Crypto::BitcoinNetwork network,
                            const std::vector<uint32_t> &derivation_tail,
                            std::string *error_out)
  {
    std::string parse_err;
    auto key = Crypto::parseExtendedPubKey(account_xpub, network, &parse_err);
    if (!key.has_value())
    {
      if (error_out)
        *error_out = "xpub parse failed: " + parse_err;
      return nullptr;
    }

    auto custody = std::unique_ptr<BitcoinCustody>(new BitcoinCustody());
    custody->account_ = *key;
    custody->source_ = Source::FromXpub;
    custody->master_fp_ = Crypto::keyFingerprint(key->pubkey);
    custody->network_ = network;

    if (!custody->init_common(network, derivation_tail, error_out))
      return nullptr;

    return custody;
  }

  bool BitcoinCustody::init_common(
      Crypto::BitcoinNetwork network,
      const std::vector<uint32_t> &derivation_tail,
      std::string *error_out)
  {
    network_ = network;
    tail_ = derivation_tail;

    for (uint32_t i = 0; i < kGapLimit; ++i)
    {
      std::string derr;
      if (!deriveInto(i, &derr))
      {
        if (error_out)
          *error_out = "initial window derivation failed at index " +
                       std::to_string(i) + ": " + derr;
        return false;
      }
    }
    have_derived_ = true;

    std::cerr << "[btc-custody] configured: source="
              << (source_ == Source::Generated ? "generated" : "xpub")
              << " network="
              << (network == Crypto::BitcoinNetwork::Mainnet
                      ? "mainnet"
                  : network == Crypto::BitcoinNetwork::Testnet
                      ? "testnet"
                      : "regtest")
              << " master_fp=" << std::hex << master_fp_ << std::dec
              << "\n";
    for (uint64_t i = 0;
         i < std::min<uint64_t>(kGapLimit, 3); ++i)
    {
      auto it = derived_.find(i);
      if (it != derived_.end())
        std::cerr << "[btc-custody]   index " << i << " -> "
                  << it->second.address << "\n";
    }
    return true;
  }

  bool BitcoinCustody::deriveInto(uint64_t index,
                                  std::string *error_out) const
  {
    if (derived_.find(index) != derived_.end())
      return true;

    std::vector<uint32_t> path = tail_;
    path.push_back(static_cast<uint32_t>(index & 0x7FFFFFFF));

    std::string derr;
    auto key = Crypto::derivePath(account_, path, &derr);
    if (!key.has_value())
    {
      if (error_out)
        *error_out = "derivePath failed: " + derr;
      return false;
    }

    DerivedScript ds;
    ds.index = index;
    ds.script = Crypto::p2wpkhScript(key->pubkey);
    ds.address = Crypto::p2wpkhAddress(ds.script, network_);

    derived_.emplace(index, ds);
    by_script_[ds.script] = ds;
    if (!have_derived_ || index > highest_derived_)
    {
      highest_derived_ = index;
      have_derived_ = true;
    }
    return true;
  }

  std::optional<DerivedScript> BitcoinCustody::deriveScript(
      uint64_t index, std::string *error_out) const
  {
    auto it = derived_.find(index);
    if (it != derived_.end())
      return it->second;

    std::string derr;
    if (!deriveInto(index, &derr))
    {
      if (error_out)
        *error_out = derr;
      return std::nullopt;
    }
    return derived_.at(index);
  }

  std::optional<std::string> BitcoinCustody::deriveAddress(
      uint64_t index, std::string *error_out) const
  {
    auto ds = deriveScript(index, error_out);
    if (!ds.has_value())
      return std::nullopt;
    return ds->address;
  }

  const std::map<std::array<uint8_t, 22>, DerivedScript> &
  BitcoinCustody::scriptsInWindow() const noexcept
  {
    return by_script_;
  }

  void BitcoinCustody::onDepositSeen(uint64_t index)
  {
    if (!have_used_ || index > highest_used_)
    {
      highest_used_ = index;
      have_used_ = true;
    }

    const uint64_t target = highest_used_ + kGapLimit;
    for (uint64_t i = highest_derived_ + 1; i < target; ++i)
    {
      std::string derr;
      if (!deriveInto(i, &derr))
      {
        std::cerr << "[btc-custody] onDepositSeen(" << index
                  << "): failed to extend window at index " << i
                  << ": " << derr << "\n";
        return;
      }
    }
  }

  bool BitcoinCustody::ensureIndexInWindow(uint64_t index)
  {
    for (uint64_t i = 0; i <= index; ++i)
    {
      std::string derr;
      if (!deriveInto(i, &derr))
      {
        std::cerr << "[btc-custody] ensureIndexInWindow(" << index
                  << "): failed at index " << i << ": " << derr << "\n";
        return false;
      }
    }
    return true;
  }

  std::string BitcoinCustody::accountXpubDisplay() const
  {
    return Crypto::encodeExtendedPubKey(account_, network_);
  }

  std::optional<Crypto::ExtendedPrivKey>
  BitcoinCustody::derivePrivateKeyAt(
      uint64_t index,
      std::string *error_out) const
  {
    if (source_ != Source::Generated || !have_seed_)
    {
      if (error_out)
        *error_out =
            "BitcoinCustody: cannot derive a private key in "
            "watch-only (FromXpub) mode; the seed was never "
            "loaded, so spending from this custody is impossible "
            "by construction";
      return std::nullopt;
    }

    //  Walk the same path deriveInto does: the account tail
    //  (receive branch, 0) followed by the index. Use
    //  derivePathPriv (which accepts non-hardened indices and
    //  does the secp256k1 scalar arithmetic) rather than the
    //  public-only derivePath.
    std::vector<uint32_t> path = tail_;
    path.push_back(static_cast<uint32_t>(index & 0x7FFFFFFF));

    std::string master_err;
    auto master = Crypto::masterFromSeed(
        std::vector<uint8_t>(seed_.begin(), seed_.end()), &master_err);
    if (!master.has_value())
    {
      if (error_out)
        *error_out = "masterFromSeed failed: " + master_err;
      return std::nullopt;
    }

    //  Hardened account path m/84'/<coin>'/0' must be
    //  re-walked first, because masterFromSeed gives us the
    //  BIP32 master and derivePathPriv only descends from
    //  whatever node it's handed. The account_ xpub in this
    //  object is already at that path, but xpub → privkey is
    //  not possible; we have to redo the hardened walk.
    const uint32_t coin =
        (network_ == Crypto::BitcoinNetwork::Mainnet) ? 0u : 1u;
    const std::vector<uint32_t> account_path = {
        84u | 0x80000000u,
        coin | 0x80000000u,
        0u | 0x80000000u,
    };

    std::string path_err;
    auto account = Crypto::derivePathPriv(*master, account_path, &path_err);
    if (!account.has_value())
    {
      if (error_out)
        *error_out = "derivePathPriv (account) failed: " + path_err;
      return std::nullopt;
    }

    std::string child_err;
    auto child = Crypto::derivePathPriv(*account, path, &child_err);
    if (!child.has_value())
    {
      if (error_out)
        *error_out = "derivePathPriv (child) failed: " + child_err;
      return std::nullopt;
    }

    return child;
  }
} // namespace Bridge