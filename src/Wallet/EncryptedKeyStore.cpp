// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "EncryptedKeyStore.h"

#include "AddressCodec.h"
#include "Bip39.h"
#include "KeyStoreFormat.h"
#include "Crypto/Argon2id.h"
#include "Crypto/Chacha20Poly1305.h"
#include "Crypto/Ed25519.h"
#include "Crypto/Pbkdf2.h"
#include "Crypto/Random.h"
#include "Crypto/SecureZero.h"

#include <chrono>
#include <cstring>

namespace Wallet
{
  namespace
  {
    // KEK length. Matches AEAD_KEY_SIZE (32).
    constexpr size_t KEK_SIZE = Crypto::AEAD_KEY_SIZE;

    // Current wall-clock time in milliseconds since the Unix epoch.
    uint64_t nowMs()
    {
      using namespace std::chrono;
      return static_cast<uint64_t>(
          duration_cast<milliseconds>(
              system_clock::now().time_since_epoch())
              .count());
    }

    // Map the network string in the file to a Network enum. The parser
    // already validated the string, so a missing value here is a bug.
    Network networkFromFile(const std::string &s)
    {
      if (s == "mainnet")
        return Network::Mainnet;
      if (s == "testnet")
        return Network::Testnet;
      if (s == "regtest")
        return Network::Regtest;
      return Network::Mainnet;
    }
  } // namespace

  //  Factories

  std::optional<std::unique_ptr<EncryptedKeyStore>>
  EncryptedKeyStore::create(const std::string &path,
                            std::string_view password,
                            Network network,
                            uint32_t strength_bits,
                            std::string &out_mnemonic,
                            std::string_view kdf,
                            WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<std::unique_ptr<EncryptedKeyStore>>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    if (password.empty())
      return fail(WalletError::BadArgument, "password must not be empty");

    if (kdf != KDF_ARGON2ID && kdf != KDF_PBKDF2_HMAC_SHA512)
      return fail(WalletError::KeyStoreUnsupportedKdf,
                  "unsupported kdf: '" + std::string(kdf) + "'");

    // Generate mnemonic.
    const std::string mnemonic =
        generateMnemonic(static_cast<int>(strength_bits));
    if (mnemonic.empty())
      return fail(WalletError::Internal, "mnemonic generation failed");

    // Derive seed material. Empty passphrase (the mnemonic itself is
    // the secret; an additional passphrase is opt-in at the wallet
    // layer, not the keystore layer).
    WalletStatus status;
    auto material = SeedMaterial::fromMnemonic(mnemonic, "", &status);
    if (!material)
      return fail(status.code, std::move(status.detail));

    auto ks = std::unique_ptr<EncryptedKeyStore>(new EncryptedKeyStore());
    ks->path_ = path;
    ks->network_ = network;

    ks->file_.version = KEYSTORE_VERSION;
    ks->file_.id = generateUuidV4();
    if (ks->file_.id.empty())
      return fail(WalletError::Internal,
                  "RNG failure generating keystore id");
    ks->file_.label = "";
    ks->file_.network = networkToString(network);
    ks->file_.chain_id = chainIdForNetwork(network);
    ks->file_.created_at_ms = nowMs();

    ks->file_.crypto.cipher = CIPHER_XCHACHA20_POLY1305;
    ks->file_.crypto.aad = KEYSTORE_AAD;
    ks->file_.crypto.kdf = std::string(kdf);

    // Set KDF parameters.
    if (kdf == KDF_ARGON2ID)
    {
      Argon2ParamsJson params;
      params.salt.assign(KEYSTORE_SALT_LENGTH, 0);
      if (!Crypto::randomBytes(params.salt.data(), params.salt.size()))
        return fail(WalletError::Internal, "RNG failure generating salt");
      params.m_cost_kib = KEYSTORE_ARGON2_M_COST_KIB;
      params.t_cost = KEYSTORE_ARGON2_T_COST;
      params.p_cost = KEYSTORE_ARGON2_P_COST;
      ks->file_.crypto.argon2 = std::move(params);
    }
    else
    {
      Pbkdf2ParamsJson params;
      params.salt.assign(KEYSTORE_SALT_LENGTH, 0);
      if (!Crypto::randomBytes(params.salt.data(), params.salt.size()))
        return fail(WalletError::Internal, "RNG failure generating salt");
      params.iterations = KEYSTORE_PBKDF2_ITERATIONS;
      ks->file_.crypto.pbkdf2 = std::move(params);
    }

    // Derive the default account's public key. Used to fill in
    // `file_.address` and `file_.pubkey` for identification, and the
    // HD section's default path.
    const HdPath default_path = clrtyPath(0, 0, 0);
    auto key = material->deriveKey(default_path, &status);
    if (!key)
      return fail(status.code, std::move(status.detail));

    ks->file_.pubkey.assign(key->pubkey.data.begin(),
                            key->pubkey.data.end());
    ks->file_.address = encodeAddress(key->pubkey, network);
    if (ks->file_.address.empty())
      return fail(WalletError::Internal, "address encoding failed");

    // Wipe the secret half of the derived key. We only needed the pubkey.
    Crypto::secureZero(key->secret.data.data(), 32);

    // Fingerprint and default path.
    ks->fingerprint_ = material->fingerprint();
    ks->file_.hd.seed_fingerprint.assign(
        ks->fingerprint_.bytes,
        ks->fingerprint_.bytes + 4);
    ks->file_.hd.default_path = default_path.toString();

    // Derive the KEK and encrypt the seed.
    auto kek = ks->deriveKek(password);
    if (!kek)
      return fail(WalletError::Internal, "KEK derivation failed");

    const WalletError ee = ks->encryptSeed(material->seed(), *kek);
    Crypto::secureZero(kek->data(), kek->size());
    if (ee != WalletError::Ok)
      return fail(ee, walletErrorMessage(ee));

    // Persist.
    WalletStatus save_status;
    if (!writeKeyStoreFile(path, ks->file_, &save_status))
      return fail(save_status.code, std::move(save_status.detail));

    // Move the material in so the returned keystore is unlocked.
    ks->material_ = std::move(*material);

    out_mnemonic = mnemonic;
    return ks;
  }

  std::optional<std::unique_ptr<EncryptedKeyStore>>
  EncryptedKeyStore::open(const std::string &path,
                          WalletStatus *error_out)
  {
    auto fail = [&](WalletError code, std::string detail)
        -> std::optional<std::unique_ptr<EncryptedKeyStore>>
    {
      if (error_out)
        *error_out = WalletStatus::fail(code, std::move(detail));
      return std::nullopt;
    };

    if (error_out)
      *error_out = WalletStatus::success();

    auto file = readKeyStoreFile(path, error_out);
    if (!file)
      return std::nullopt;

    auto ks = std::unique_ptr<EncryptedKeyStore>(new EncryptedKeyStore());
    ks->path_ = path;
    ks->file_ = std::move(*file);
    ks->network_ = networkFromFile(ks->file_.network);

    if (ks->file_.hd.seed_fingerprint.size() == 4)
    {
      std::memcpy(ks->fingerprint_.bytes,
                  ks->file_.hd.seed_fingerprint.data(), 4);
    }

    // Locked on open. Caller must call unlock().
    return ks;
  }

  EncryptedKeyStore::~EncryptedKeyStore()
  {
    lock();
  }

  //  Lock state

  WalletError EncryptedKeyStore::unlock(std::string_view password)
  {
    if (material_)
      return WalletError::Ok; // already unlocked

    if (password.empty())
      return WalletError::BadArgument;

    auto kek = deriveKek(password);
    if (!kek)
      return WalletError::Internal;

    auto seed = decryptSeed(*kek);
    Crypto::secureZero(kek->data(), kek->size());

    if (!seed)
      return WalletError::WrongPassword;

    WalletStatus status;
    auto material = SeedMaterial::fromSeed(*seed, &status);
    Crypto::secureZero(seed->data(), seed->size());

    if (!material)
      return status.code;

    // Verify the fingerprint matches the file's. If a user has
    // accidentally swapped the seed (e.g. wrong mnemonic restored
    // into an existing file), this catches it immediately rather
    // than after the first failed signature.
    if (material->fingerprint() != fingerprint_)
    {
      return WalletError::DerivationSeedFingerprintMismatch;
    }

    material_ = std::move(*material);
    return WalletError::Ok;
  }

  void EncryptedKeyStore::lock() noexcept
  {
    // SeedMaterial's destructor wipes the seed and master node.
    material_.reset();
  }

  WalletError EncryptedKeyStore::save()
  {
    if (!material_)
      return WalletError::KeyStoreLocked;

    WalletStatus status;
    if (!writeKeyStoreFile(path_, file_, &status))
      return status.code;

    return WalletError::Ok;
  }

  WalletError EncryptedKeyStore::changePassword(std::string_view new_password)
  {
    if (!material_)
      return WalletError::KeyStoreLocked;
    if (new_password.empty())
      return WalletError::BadArgument;

    // Regenerate the KDF salt. This ensures a password change
    // produces a completely different derived key, even if the new
    // password happens to equal the old one.
    if (regenerateSalt() != WalletError::Ok)
      return WalletError::Internal;

    auto kek = deriveKek(new_password);
    if (!kek)
      return WalletError::Internal;

    const WalletError ee = encryptSeed(material_->seed(), *kek);
    Crypto::secureZero(kek->data(), kek->size());
    if (ee != WalletError::Ok)
      return ee;

    WalletStatus status;
    if (!writeKeyStoreFile(path_, file_, &status))
      return status.code;

    return WalletError::Ok;
  }

  //  Derivation

  std::optional<DerivedKey> EncryptedKeyStore::derive(
      const HdPath &path,
      WalletStatus *error_out) const
  {
    if (!material_)
    {
      if (error_out)
        *error_out = WalletStatus::fail(WalletError::KeyStoreLocked,
                                        "keystore is locked");
      return std::nullopt;
    }
    return material_->deriveKey(path, error_out);
  }

  //  KEK derivation

  std::optional<std::vector<uint8_t>>
  EncryptedKeyStore::deriveKek(std::string_view password) const
  {
    std::vector<uint8_t> kek(KEK_SIZE);

    if (file_.crypto.kdf == KDF_ARGON2ID && file_.crypto.argon2)
    {
      const auto &p = *file_.crypto.argon2;
      Crypto::Argon2Params params;
      params.m_cost_kib = p.m_cost_kib;
      params.t_cost = p.t_cost;
      params.p_cost = p.p_cost;
      if (!params.valid())
        return std::nullopt;

      if (!Crypto::argon2id(
              reinterpret_cast<const uint8_t *>(password.data()),
              password.size(),
              p.salt.data(), p.salt.size(),
              params,
              kek.data(), kek.size()))
      {
        Crypto::secureZero(kek.data(), kek.size());
        return std::nullopt;
      }
    }
    else if (file_.crypto.kdf == KDF_PBKDF2_HMAC_SHA512 &&
             file_.crypto.pbkdf2)
    {
      const auto &p = *file_.crypto.pbkdf2;
      Crypto::pbkdf2HmacSha512(
          reinterpret_cast<const uint8_t *>(password.data()),
          password.size(),
          p.salt.data(), p.salt.size(),
          p.iterations,
          kek.data(), kek.size());
    }
    else
    {
      return std::nullopt;
    }

    return kek;
  }

  //  Seed encryption / decryption

  WalletError EncryptedKeyStore::encryptSeed(
      const std::vector<uint8_t> &seed,
      const std::vector<uint8_t> &kek)
  {
    // Fresh random nonce. XChaCha's 24-byte nonce means random
    // generation is safe: collision probability is 2^-96, and
    // re-encrypting the same plaintext under a different nonce is
    // the intended usage.
    file_.crypto.nonce.assign(KEYSTORE_NONCE_LENGTH, 0);
    if (!Crypto::randomBytes(file_.crypto.nonce.data(),
                             file_.crypto.nonce.size()))
    {
      return WalletError::Internal;
    }

    // Output buffers.
    file_.crypto.ciphertext.assign(seed.size(), 0);
    file_.crypto.mac.assign(Crypto::AEAD_MAC_SIZE, 0);

    // AAD is the fixed string from the format. It binds the
    // ciphertext to a specific format version; an attacker who
    // rewrites the version field to a weaker one also has to
    // produce a valid MAC for the new AAD, which they can't.
    const auto *aad =
        reinterpret_cast<const uint8_t *>(file_.crypto.aad.data());
    const size_t aad_len = file_.crypto.aad.size();

    if (!Crypto::aeadEncrypt(
            seed.data(), seed.size(),
            aad, aad_len,
            kek.data(),
            file_.crypto.nonce.data(),
            file_.crypto.ciphertext.data(),
            file_.crypto.mac.data()))
    {
      return WalletError::Internal;
    }

    return WalletError::Ok;
  }
  std::optional<std::vector<uint8_t>>
  EncryptedKeyStore::decryptSeed(const std::vector<uint8_t> &kek) const
  {
    std::vector<uint8_t> plaintext(file_.crypto.ciphertext.size());

    const auto *aad =
        reinterpret_cast<const uint8_t *>(file_.crypto.aad.data());
    const size_t aad_len = file_.crypto.aad.size();

    if (!Crypto::aeadDecrypt(
            file_.crypto.ciphertext.data(),
            file_.crypto.ciphertext.size(),
            aad, aad_len,
            kek.data(),
            file_.crypto.nonce.data(),
            file_.crypto.mac.data(),
            plaintext.data()))
    {
      Crypto::secureZero(plaintext.data(), plaintext.size());
      return std::nullopt;
    }

    return plaintext;
  }

  //  Salt regeneration

  WalletError EncryptedKeyStore::regenerateSalt()
  {
    if (file_.crypto.kdf == KDF_ARGON2ID && file_.crypto.argon2)
    {
      auto &p = *file_.crypto.argon2;
      p.salt.assign(KEYSTORE_SALT_LENGTH, 0);
      if (!Crypto::randomBytes(p.salt.data(), p.salt.size()))
        return WalletError::Internal;
      return WalletError::Ok;
    }
    if (file_.crypto.kdf == KDF_PBKDF2_HMAC_SHA512 &&
        file_.crypto.pbkdf2)
    {
      auto &p = *file_.crypto.pbkdf2;
      p.salt.assign(KEYSTORE_SALT_LENGTH, 0);
      if (!Crypto::randomBytes(p.salt.data(), p.salt.size()))
        return WalletError::Internal;
      return WalletError::Ok;
    }
    return WalletError::KeyStoreUnsupportedKdf;
  }

  //  Label

  WalletError EncryptedKeyStore::setLabel(std::string_view label)
  {
    file_.label.assign(label.data(), label.size());
    return save();
  }

  //  Free-function factories declared in KeyStore.h

  std::optional<std::unique_ptr<KeyStore>> createEncryptedKeyStore(
      const std::string &path,
      std::string_view password,
      Network network,
      uint32_t strength_bits,
      std::string &out_mnemonic,
      WalletStatus *error_out)
  {
    return EncryptedKeyStore::create(path, password, network,
                                     strength_bits, out_mnemonic,
                                     KDF_ARGON2ID, error_out);
  }

  std::optional<std::unique_ptr<KeyStore>> openEncryptedKeyStore(
      const std::string &path,
      WalletStatus *error_out)
  {
    return EncryptedKeyStore::open(path, error_out);
  }

} // namespace Wallet