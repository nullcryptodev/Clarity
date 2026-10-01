// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "WalletError.h"
#include "WalletTypes.h"

namespace Wallet
{
  //  Keystore on-disk format (v1)
  //
  //  A JSON document with a fixed top-level schema. The seed is
  //  encrypted with XChaCha20-Poly1305; the key (KEK) is derived from
  //  the user's password via Argon2id (default) or PBKDF2-HMAC-SHA512
  //  (fallback).
  //
  //  Example (with the ciphertext elided):
  //
  //    {
  //      "version": 1,
  //      "id": "8e4f...uuid-v4",
  //      "label": "main",
  //      "network": "mainnet",
  //      "chain_id": 1128357460,
  //      "address": "clrty1...",
  //      "pubkey": "hex-32-bytes",
  //      "crypto": {
  //        "cipher": "xchacha20-poly1305",
  //        "nonce": "hex-24-bytes",
  //        "aad": "clrty-keystore-v1",
  //        "ciphertext": "hex",
  //        "mac": "hex-16-bytes",
  //        "kdf": "argon2id",
  //        "kdfparams": {
  //          "salt": "hex-16-bytes",
  //          "m_cost_kib": 65536,
  //          "t_cost": 3,
  //          "p_cost": 4
  //        }
  //      },
  //      "hd": {
  //        "seed_fingerprint": "hex-4-bytes",
  //        "default_path": "m/44'/9000'/0'/0'/0'",
  //        "validator_path": "m/44'/9000'/0'/2'/0'"
  //      },
  //      "created_at_ms": 1767225600000
  //    }
  //
  //  Field notes:
  //
  //    version          Always present. Reader dispatches on it.
  //
  //    id               UUID-v4, assigned at creation.
  //
  //    label            User-assigned name. Free-form. Not secret.
  //
  //    network          "mainnet" / "testnet" / "regtest". Must
  //                     match the HRP of `address` when present.
  //
  //    chain_id         The chain ID at creation time. Read at load
  //                     and compared against the current chain.
  //
  //    address          The bech32m address of the default account.
  //
  //    pubkey           Raw hex of the default account's public key.
  //
  //    hd.default_path  The path used for the default account's
  //                     receive address. Informational; the wallet
  //                     doesn't depend on this being a specific value.
  //
  //    hd.validator_path  The path used for the validator consensus
  //                       key. Optional. If absent, the standard
  //                       m/44'/9000'/0'/2'/0' is used. Keystores
  //                       created before the merge between Address
  //                       and ValidatorKeyGen won't have this field,
  //                       and the reader falls back to the default.

  // KDF identifiers, matching the `crypto.kdf` string in JSON.
  inline constexpr const char *KDF_ARGON2ID = "argon2id";
  inline constexpr const char *KDF_PBKDF2_HMAC_SHA512 = "pbkdf2-hmac-sha512";

  // Cipher identifier.
  inline constexpr const char *CIPHER_XCHACHA20_POLY1305 = "xchacha20-poly1305";

  //  Argon2id parameters as they appear in the JSON.
  struct Argon2ParamsJson
  {
    std::vector<uint8_t> salt; // 16 bytes
    uint32_t m_cost_kib{65536};
    uint32_t t_cost{3};
    uint32_t p_cost{4};
  };

  //  PBKDF2 parameters as they appear in the JSON.
  struct Pbkdf2ParamsJson
  {
    std::vector<uint8_t> salt; // 16 bytes
    uint32_t iterations{600000};
  };

  //  The crypto sub-object.
  struct CryptoSection
  {
    std::string cipher;              // CIPHER_XCHACHA20_POLY1305
    std::vector<uint8_t> nonce;      // 24 bytes
    std::string aad;                 // KEYSTORE_AAD
    std::vector<uint8_t> ciphertext; // encrypted seed
    std::vector<uint8_t> mac;        // 16 bytes

    std::string kdf; // KDF_ARGON2ID | KDF_PBKDF2_HMAC_SHA512
    std::optional<Argon2ParamsJson> argon2;
    std::optional<Pbkdf2ParamsJson> pbkdf2;
  };

  //  The hd sub-object.
  struct HdSection
  {
    std::vector<uint8_t> seed_fingerprint; // 4 bytes
    std::string default_path;              // "m/44'/9000'/0'/0'/0'"
    std::string validator_path;            // "m/44'/9000'/0'/2'/0'"
  };

  //  The complete parsed keystore.
  struct KeyStoreFile
  {
    uint32_t version{KEYSTORE_VERSION};
    std::string id;      // UUID-v4
    std::string label;   // user-assigned
    std::string network; // "mainnet" / "testnet" / "regtest"
    uint64_t chain_id{0};
    std::string address;         // bech32m of default account
    std::vector<uint8_t> pubkey; // 32 bytes

    CryptoSection crypto;
    HdSection hd;

    uint64_t created_at_ms{0};
  };

  //  Serialization

  std::string serializeKeyStoreFile(const KeyStoreFile &f);

  std::optional<KeyStoreFile> parseKeyStoreFile(
      const std::string &json,
      WalletStatus *error_out = nullptr);

  //  File I/O

  std::optional<KeyStoreFile> readKeyStoreFile(
      const std::string &path,
      WalletStatus *error_out = nullptr);

  bool writeKeyStoreFile(const std::string &path,
                         const KeyStoreFile &f,
                         WalletStatus *error_out = nullptr);

  //  Parameter validation

  WalletError validateKeyStoreFile(const KeyStoreFile &f);

  std::string generateUuidV4();
  const char *networkToString(Network n) noexcept;

} // namespace Wallet