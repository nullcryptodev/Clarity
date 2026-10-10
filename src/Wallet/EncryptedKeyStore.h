// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "Crypto/Types.h"
#include "KeyDerivation.h"
#include "KeyStore.h"
#include "KeyStoreFormat.h"
#include "WalletError.h"
#include "WalletTypes.h"

namespace Wallet
{
  //  EncryptedKeyStore
  //
  //  The default KeyStore implementation: a JSON file on disk holding
  //  a BIP-39 seed encrypted under a password-derived key.
  //
  //  Lifecycle:
  //
  //    1. createEncryptedKeyStore(path, password, ...) -> fresh keystore
  //    2. openEncryptedKeyStore(path) -> locked keystore
  //    3. ks->unlock(password) -> decrypts the seed into memory
  //    4. ks->derive(path) -> derive keys on demand
  //    5. ks->lock() -> wipes the in-memory seed
  //
  //  While locked, only metadata is accessible: name, network,
  //  chainId, fingerprint. While unlocked, derive() works.
  //
  //  Concurrency: not thread-safe by itself. If you need to share a
  //  single keystore across threads, wrap it in a mutex. The wallet
  //  is designed so that each thread has its own unlocked copy, or
  //  a single mutex serializes access.

  class EncryptedKeyStore : public KeyStore
  {
  public:
    // Create a new keystore on disk from a fresh mnemonic.
    //
    // On success returns the open (unlocked) keystore and, via
    // `out_mnemonic`, the mnemonic the user must back up. The caller
    // must display and then wipe the mnemonic.
    //
    // `strength_bits` is passed to generateMnemonic; 256 (24 words)
    // is the default and recommended value.
    //
    // `kdf` selects the KDF. Defaults to Argon2id; PBKDF2-HMAC-SHA512
    // is the fallback for environments where Argon2 is unavailable
    // or undesired.
    static std::optional<std::unique_ptr<EncryptedKeyStore>> create(
        const std::string &path,
        std::string_view password,
        Network network,
        uint32_t strength_bits,
        std::string &out_mnemonic,
        std::string_view kdf = KDF_ARGON2ID,
        WalletStatus *error_out = nullptr);

    // Create a new keystore on disk from an existing mnemonic.
    //
    // Equivalent to create() except the mnemonic is supplied by the
    // caller rather than generated. Used by the "import" flow in the
    // wallet CLI and by any tool that needs to materialize a keystore
    // from a backup phrase.
    //
    // The mnemonic is validated before use. If it fails validation,
    // the function returns nullopt and error_out is populated with
    // the specific validation error (InvalidWordCount, InvalidWord,
    // or InvalidChecksum).
    //
    // `passphrase` is the BIP-39 passphrase, the optional "25th word".
    // Most users leave it empty; the API requires it explicitly so
    // callers can't accidentally omit it.
    //
    // The `kdf` argument selects the KDF used to encrypt the seed.
    // Defaults to Argon2id, same as create().
    static std::optional<std::unique_ptr<EncryptedKeyStore>> createFromMnemonic(
        const std::string &path,
        std::string_view password,
        Network network,
        std::string_view mnemonic,
        std::string_view passphrase,
        std::string_view kdf = KDF_ARGON2ID,
        WalletStatus *error_out = nullptr);

    // Open an existing keystore from disk. The returned keystore is
    // locked; call unlock() before deriving.
    static std::optional<std::unique_ptr<EncryptedKeyStore>> open(
        const std::string &path,
        WalletStatus *error_out = nullptr);

    ~EncryptedKeyStore() override;

    EncryptedKeyStore(const EncryptedKeyStore &) = delete;
    EncryptedKeyStore &operator=(const EncryptedKeyStore &) = delete;

    // ---- KeyStore interface ----

    std::string name() const override { return path_; }
    Network network() const override { return network_; }
    uint64_t chainId() const override { return file_.chain_id; }
    SeedFingerprint fingerprint() const override { return fingerprint_; }

    bool isUnlocked() const override { return material_.has_value(); }

    WalletError unlock(std::string_view password) override;
    void lock() noexcept override;
    WalletError save() override;

    std::optional<DerivedKey> derive(
        const HdPath &path,
        WalletStatus *error_out = nullptr) const override;

    WalletError changePassword(std::string_view new_password) override;

    std::string address() const override { return file_.address; }

    //  Metadata for callers that don't want to reach into the file.
    const std::string &label() const noexcept { return file_.label; }
    const std::string &id() const noexcept { return file_.id; }

    //  Set a new label and persist. Returns the WalletError from save.
    WalletError setLabel(std::string_view label);

    //  Change the network label of this keystore.
    //
    //  The mnemonic, the derived keys, the ciphertext, and the MAC
    //  are all network-independent and are not modified. Only three
    //  fields change: the network string, the chain ID, and the
    //  bech32m encoding of the default account's address. The
    //  underlying pubkey is the same; only its HRP-prefixed encoding
    //  changes.
    //
    //  Does not require the keystore to be unlocked. The network
    //  field is not part of the AEAD's additional authenticated data
    //  (the AAD is the fixed string KEYSTORE_AAD), so changing it
    //  does not invalidate the MAC.
    //
    //  Returns WalletError::Ok on success. Returns
    //  WalletError::BadArgument if new_network is not one of the
    //  three known networks. Returns WalletError::KeyStoreCorrupt
    //  if the existing address field can't be decoded, which would
    //  mean the file was modified outside this tool.
    WalletError convertNetwork(Network new_network);

private:
    EncryptedKeyStore() = default;

    // Derive the KEK (key-encryption key) from a password, given the
    // file's KDF parameters. Returns 32 bytes or std::nullopt on
    // failure (invalid params, KDF failure, RNG failure).
    std::optional<std::vector<uint8_t>> deriveKek(
        std::string_view password) const;

    // Encrypt `seed` under `kek` and populate `file_.crypto`. Uses
    // the file's existing KDF parameters and generates a fresh
    // nonce. Returns WalletError::Ok on success.
    WalletError encryptSeed(const std::vector<uint8_t> &seed,
                            const std::vector<uint8_t> &kek);

    // Decrypt `file_.crypto.ciphertext` under `kek`. Returns the
    // plaintext seed or std::nullopt on authentication failure.
    std::optional<std::vector<uint8_t>> decryptSeed(
        const std::vector<uint8_t> &kek) const;

    // Regenerate the crypto section's KDF salt. Called on create and
    // on password change. Uses the file's current KDF kind.
    WalletError regenerateSalt();

    std::string path_;
    KeyStoreFile file_;
    Network network_{Network::Mainnet};
    SeedFingerprint fingerprint_{};

    // The decrypted seed material. Present iff unlocked. Wiped by
    // lock() and by the destructor.
    std::optional<SeedMaterial> material_;
  };

} // namespace Wallet