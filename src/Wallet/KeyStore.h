// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "Crypto/Types.h"
#include "HdPath.h"
#include "KeyDerivation.h"
#include "WalletError.h"
#include "WalletTypes.h"

namespace Wallet
{
  //  KeyStore — abstract key storage
  //
  //  A KeyStore holds the seed material for a single wallet and can
  //  produce derived keypairs on demand. It is the layer between "the
  //  secret exists in memory" and "the secret is stored somewhere
  //  durable."
  //
  //  Two concrete implementations are planned:
  //
  //    EncryptedKeyStore  — password-protected, on-disk, JSON.
  //                         The default. Encrypts the seed at rest
  //                         with XChaCha20-Poly1305, key derived
  //                         from the password via Argon2id (or
  //                         PBKDF2-HMAC-SHA512 as a fallback).
  //
  //    PlainKeyStore      — in-memory only, no encryption. For tests
  //                         and for transient wallets that never touch
  //                         disk. Will be added if a concrete need
  //                         arises; not part of Phase 1.
  //
  //  The interface is deliberately small. Everything a caller needs
  //  to sign transactions comes from three methods: unlock, derive,
  //  and lock. Persistence is a concern of the concrete type, not
  //  the interface.

  class KeyStore
  {
  public:
    virtual ~KeyStore() = default;

    KeyStore(const KeyStore &) = delete;
    KeyStore &operator=(const KeyStore &) = delete;

    // ---- Identity ----

    // Human-readable identifier, e.g. the keystore file path or a
    // user-assigned label. For diagnostics only.
    virtual std::string name() const = 0;

    // Network this keystore is bound to. Encoded in the file, checked
    // on load. Prevents a user from accidentally using a mainnet
    // keystore to sign a testnet transaction.
    virtual Network network() const = 0;

    // Chain ID this keystore is bound to. Same rationale as network:
    // the chain_id goes into the signed transaction, and we don't
    // want to sign for the wrong chain.
    virtual uint64_t chainId() const = 0;

    // Fingerprint of the seed. Safe to display. Used to verify a
    // restore matched the original wallet without decrypting.
    virtual SeedFingerprint fingerprint() const = 0;

    // ---- Lock state ----

    // True after successful unlock() and before lock(). While locked,
    // derive() returns std::nullopt.
    virtual bool isUnlocked() const = 0;

    // ---- Lifecycle ----

    // Load from disk and attempt to decrypt with the given password.
    // Returns WalletError::Ok on success. Failure modes:
    //   - KeyStoreNotFound       (file doesn't exist)
    //   - KeyStoreCorrupt        (file exists but is malformed)
    //   - KeyStoreUnsupportedVersion
    //   - WrongPassword
    //   - Internal               (I/O error, allocation failure)
    virtual WalletError unlock(std::string_view password) = 0;

    // Drop the decrypted seed. The keystore remains loadable; a
    // subsequent unlock() with the correct password restores it.
    virtual void lock() noexcept = 0;

    // Persist the keystore to disk. If the keystore is already
    // unlocked, this re-encrypts with the currently active password.
    // If locked, it's a no-op.
    virtual WalletError save() = 0;

    // ---- Derivation ----

    // Derive a keypair at the given path. Requires unlock().
    //
    // On success, returns a DerivedKey whose `secret` must be wiped
    // by the caller after use (Crypto::secureZero on the data).
    virtual std::optional<DerivedKey> derive(
        const HdPath &path,
        WalletStatus *error_out = nullptr) const = 0;

    // Convenience: derive the CLRTY account key at (account, change,
    // index). Equivalent to derive(clrtyPath(...)).
    std::optional<DerivedKey> deriveClrty(
        uint32_t account, uint32_t change, uint32_t index,
        WalletStatus *error_out = nullptr) const
    {
      return derive(clrtyPath(account, change, index), error_out);
    }

    //  Derive the public key at a path without exposing the secret.
    //
    //  Watch-only wallets need this: they hold public keys but not
    //  the seed. EncryptedKeyStore cannot serve this while locked
    //  (it needs the seed to derive), but a future
    //  WatchOnlyKeyStore could.
    //
    //  Default implementation returns std::nullopt; concrete stores
    //  override when they can answer without unlocking.
    virtual std::optional<Crypto::PublicKey> publicKeyAt(
        const HdPath &path,
        WalletStatus *error_out = nullptr) const
    {
      (void)path;
      if (error_out)
        *error_out = WalletStatus::fail(
            WalletError::KeyStoreLocked,
            "publicKeyAt not supported by this key store");
      return std::nullopt;
    }

    // ---- Change password ----
    //
    // Re-encrypts the seed under a new password. Requires the keystore
    // to be unlocked (we need the plaintext to re-wrap it).
    //
    // Concrete stores may return WalletError::Internal if the file
    // is read-only.
    virtual WalletError changePassword(std::string_view new_password) = 0;

  protected:
    KeyStore() = default;
  };

  //  Factory: create a new encrypted keystore on disk.
  //
  //  Generates a fresh BIP-39 mnemonic, derives the seed, encrypts it
  //  with the given password, and writes the keystore to `path`.
  //
  //  On success returns the open (unlocked) key store and, via
  //  `out_mnemonic`, the mnemonic the user must back up. The caller
  //  is responsible for displaying the mnemonic to the user and then
  //  wiping it.
  //
  //  This function is declared here but implemented in
  //  EncryptedKeyStore.cpp. It exists on the abstract interface so
  //  the rest of the wallet code never needs to know which concrete
  //  type it's using.

  std::optional<std::unique_ptr<KeyStore>> createEncryptedKeyStore(
      const std::string &path,
      std::string_view password,
      Network network,
      uint32_t strength_bits,
      std::string &out_mnemonic,
      WalletStatus *error_out = nullptr);

  //  Factory: open an existing encrypted keystore.
  //
  //  Reads the file, parses it, and returns the (still-locked)
  //  key store. The caller must call unlock() with the correct
  //  password before deriving any keys.
  std::optional<std::unique_ptr<KeyStore>> openEncryptedKeyStore(
      const std::string &path,
      WalletStatus *error_out = nullptr);

} // namespace Wallet