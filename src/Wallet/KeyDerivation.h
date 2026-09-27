// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "Bip39.h"
#include "Crypto/Types.h"
#include "HdPath.h"
#include "Slip10.h"
#include "WalletError.h"
#include "WalletTypes.h"

namespace Wallet
{
  //  KeyDerivation — mnemonic -> seed -> HD tree -> keypair
  //
  //  The pipeline is:
  //
  //    mnemonic (words)  ──BIP-39 PBKDF2──▶  seed (64 bytes)
  //    seed              ──SLIP-0010─────▶  master node
  //    master node       ──SLIP-0010─────▶  account node
  //    account node      ──Ed25519───────▶  keypair
  //
  //  Everything is deterministic. The same mnemonic and passphrase
  //  always produce the same keypairs, at every path, on every
  //  machine, forever. That is the property that makes mnemonic
  //  backup sufficient.
  //
  //  This module does not store anything. It is pure computation.
  //  Persistence is the KeyStore's job; see KeyStore.h.

  //  The 4-byte fingerprint of a seed, per BIP-32 §"Extended Keys".
  //
  //  It's the first 4 bytes of HASH160(compressed pubkey of the master
  //  key). For Ed25519 there is no "compressed pubkey" in the
  //  secp256k1 sense, so we use the natural 32-byte Ed25519 public key
  //  of the master node, hashed with Blake2b-160.
  //
  //  The fingerprint is not secret. It is safe to display and safe to
  //  store in plaintext. Its purpose is to let a user verify that a
  //  restored mnemonic matches the one they originally backed up,
  //  without having to derive every key.
  struct SeedFingerprint
  {
    uint8_t bytes[4]{0, 0, 0, 0};

    bool operator==(const SeedFingerprint &o) const noexcept
    {
      return bytes[0] == o.bytes[0] && bytes[1] == o.bytes[1] &&
             bytes[2] == o.bytes[2] && bytes[3] == o.bytes[3];
    }
    bool operator!=(const SeedFingerprint &o) const noexcept
    {
      return !(*this == o);
    }

    // Hex form, e.g. "a1b2c3d4". Lowercase.
    std::string toHex() const;
  };

  //  A derived keypair plus the path that produced it.
  //
  //  The path is included so callers can log/track which key they're
  //  using. It is not secret.

  struct DerivedKey
  {
    Crypto::PublicKey pubkey{};
    Crypto::SecretKey secret{}; // sensitive; wipe after use
    HdPath path{};

    bool isNull() const noexcept
    {
      return pubkey.isNull() && secret.isNull();
    }
  };

  //  The in-memory representation of a "seed" for a wallet. Holds the
  //  64-byte BIP-39 seed and the derived master node. This is the
  //  secret that the keystore encrypts.
  //
  //  Design: we don't store the mnemonic in memory after deriving the
  //  seed. The mnemonic is a weaker secret than the seed (it's
  //  human-transcribable, often shown on screen, may be photographed).
  //  Once the seed exists, only the seed is needed, and only the seed
  //  is worth protecting. Wiping the mnemonic string immediately
  //  after seed derivation is best practice.
  //
  //  The seed and master node are kept together because reconstructing
  //  the master from the seed is a single HMAC. If you ever decide to
  //  store only one, store the seed — it's the canonical input.

  class SeedMaterial
  {
  public:
    // Construct from a mnemonic. Validates the mnemonic first; returns
    // std::nullopt and fills error_out on any validation failure.
    //
    // The passphrase may be empty. Non-empty passphrases change the
    // seed entirely (see BIP-39 §"From mnemonic to seed").
    static std::optional<SeedMaterial> fromMnemonic(
        std::string_view mnemonic,
        std::string_view passphrase,
        WalletStatus *error_out = nullptr);

    // Construct from raw seed bytes. For tests, for restoring from a
    // keystore that already holds the seed, and for advanced callers
    // who manage their own entropy.
    //
    // `seed` must be 16-64 bytes (SLIP-0010 constraint).
    static std::optional<SeedMaterial> fromSeed(
        const std::vector<uint8_t> &seed,
        WalletStatus *error_out = nullptr);

    // Move-only. Contains secret material; we don't want accidental
    // copies lying around.
    SeedMaterial() = default;
    SeedMaterial(const SeedMaterial &) = delete;
    SeedMaterial &operator=(const SeedMaterial &) = delete;
    SeedMaterial(SeedMaterial &&o) noexcept;
    SeedMaterial &operator=(SeedMaterial &&o) noexcept;
    ~SeedMaterial();

    // The 64-byte seed. Wiped on destruction.
    const std::vector<uint8_t> &seed() const noexcept { return seed_; }

    // The master SLIP-0010 node derived from the seed.
    const Slip10Node &master() const noexcept { return master_; }

    // Fingerprint of the master public key. Cached at construction.
    const SeedFingerprint &fingerprint() const noexcept
    {
      return fingerprint_;
    }

    //  Derive a key at a specific path. All components must be
    //  hardened. Returns std::nullopt on failure.
    //
    //  The returned DerivedKey owns a copy of the secret; the caller
    //  is responsible for wiping it (call Crypto::secureZero on
    //  `key.secret.data.data()`) after use. Alternatively, keep the
    //  DerivedKey short-lived.
    std::optional<DerivedKey> deriveKey(
        const HdPath &path,
        WalletStatus *error_out = nullptr) const;

    //  Convenience for the common case: derive the CLRTY account key
    //  at (account, change, index).
    std::optional<DerivedKey> deriveClrtyKey(
        uint32_t account, uint32_t change, uint32_t index,
        WalletStatus *error_out = nullptr) const
    {
      return deriveKey(clrtyPath(account, change, index), error_out);
    }

  private:
    void computeFingerprint() noexcept;

    std::vector<uint8_t> seed_;
    Slip10Node master_{};
    SeedFingerprint fingerprint_{};
  };

  //  Fingerprint from a master node, standalone.
  //
  //  Rarely needed directly; SeedMaterial computes and caches it.
  SeedFingerprint fingerprintForMaster(const Slip10Node &master) noexcept;

  //  Hash160 of a public key, used as input to the fingerprint and
  //  potentially as an address-form alternative in a future revision.
  //
  //  Uses Blake2b-160 (the 20-byte variant of Blake2b). Exposed
  //  because it is also useful for other wallet-layer identifiers.
  Crypto::Hash160 pubkeyHash160(const Crypto::PublicKey &pk) noexcept;

} // namespace Wallet