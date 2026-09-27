// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string_view>
#include <optional>

#include "GlobalConfig.h"

namespace Wallet
{
  //  Network
  //
  //  Duplicated from Node::Network on purpose. The wallet module must
  //  compile without pulling in Node, so it carries its own copy of the
  //  enum. The two values must stay in lockstep; the conversion helpers
  //  in NetworkBridge.h are the only place they meet.
  //
  //  If you ever decide to unify them, move Network to Common/ and make
  //  both Node::Network and Wallet::Network aliases. Until then, this
  //  duplication is intentional and documented.

  enum class Network : uint8_t
  {
    Mainnet = 0,
    Testnet = 1,
    Regtest = 2,
  };

  const char *networkName(Network n) noexcept;

  // Chain ID for a network, sourced from GlobalConfig.
  constexpr uint64_t chainIdForNetwork(Network n) noexcept
  {
    switch (n)
    {
    case Network::Mainnet:
      return GlobalConfig::CHAIN_ID;
    case Network::Testnet:
      return GlobalConfig::TESTNET_CHAIN_ID;
    case Network::Regtest:
      return GlobalConfig::REGNET_CHAIN_ID;
    }
    return GlobalConfig::CHAIN_ID;
  }

  //  Address encoding (Bech32m, BIP-350)
  //
  //  Addresses are encoded as bech32m(HRP, witness_version=0x00, pubkey32).
  //  The HRP comes from GlobalConfig, one per network. See
  //  AddressCodec.h for the encode/decode entry points.
  //
  //  Witness version 0 is used for all CLRTY addresses. Future address
  //  types (script hashes, threshold commitments) would bump this.

  inline constexpr uint8_t ADDRESS_WITNESS_VERSION = 0x00;
  inline constexpr size_t ADDRESS_PUBKEY_LENGTH = 32;

  constexpr std::string_view hrpForNetwork(Network n) noexcept
  {
    switch (n)
    {
    case Network::Mainnet:
      return GlobalConfig::MAINNET_HRP;
    case Network::Testnet:
      return GlobalConfig::TESTNET_HRP;
    case Network::Regtest:
      return GlobalConfig::REGTEST_HRP;
    }
    return GlobalConfig::MAINNET_HRP;
  }

  //  HD derivation (SLIP-0010 / BIP-44 convention)
  //
  //  Path: m / 44' / COIN_TYPE_CLRTY' / account' / change' / index'
  //
  //  All components are hardened. SLIP-0010 for Ed25519 requires
  //  hardened-only derivation; non-hardened is mathematically
  //  unavailable because Ed25519 has no public-key tweak operation.
  //
  //  COIN_TYPE_CLRTY is a placeholder. 9000 is currently unregistered
  //  with SLIP-0044. If you register a different number later and
  //  change this constant, every mnemonic-derived wallet in the field
  //  becomes orphaned. Decide before shipping.

  inline constexpr uint32_t BIP44_PURPOSE = 44;
  inline constexpr uint32_t COIN_TYPE_CLRTY = 9000;
  inline constexpr uint32_t HD_EXTERNAL_CHAIN = 0; // receive addresses
  inline constexpr uint32_t HD_INTERNAL_CHAIN = 1; // change addresses

  //  Currency
  //
  //  Mirrors GlobalConfig, exposed here for wallet-internal convenience
  //  so wallet code doesn't reach into GlobalConfig for every amount.

  inline constexpr uint8_t DECIMALS = GlobalConfig::DECIMALS;
  inline constexpr uint64_t ATOMIC_UNITS_PER_COIN =
      GlobalConfig::ATOMIC_UNITS_PER_COIN;

  //  Keystore
  //
  //  Format version for the on-disk JSON. Bump this when the schema
  //  changes; the reader dispatches on the version field.
  //
  //  v1: current. ChaCha20-Poly1305 + Argon2id (default) or
  //      PBKDF2-HMAC-SHA512 (fallback). See KeyStoreFormat.h.

  inline constexpr uint32_t KEYSTORE_VERSION = 1;

  // Default Argon2id parameters. Tuned for ~200-400ms on a desktop CPU.
  // The keystore file records the actual parameters used at creation
  // time; these are only the defaults for new keystores.
  inline constexpr uint32_t KEYSTORE_ARGON2_M_COST_KIB = 65536; // 64 MiB
  inline constexpr uint32_t KEYSTORE_ARGON2_T_COST = 3;
  inline constexpr uint32_t KEYSTORE_ARGON2_P_COST = 4;

  // Default PBKDF2 iteration count, if the fallback KDF is selected.
  // BIP-39 uses 2048 for mnemonic -> seed; that's separate and fixed.
  // This constant is only for the keystore KEK.
  inline constexpr uint32_t KEYSTORE_PBKDF2_ITERATIONS = 600000;

  // KEK and cipher key length in bytes. ChaCha20-Poly1305 uses a
  // 32-byte key; the KEK is also 32 bytes.
  inline constexpr size_t KEYSTORE_KEY_LENGTH = 32;

  // ChaCha20-Poly1305 nonce length (IETF variant, 96 bits).
  inline constexpr size_t KEYSTORE_NONCE_LENGTH = 24;

  // Salt length for both KDFs. 16 bytes = 128 bits.
  inline constexpr size_t KEYSTORE_SALT_LENGTH = 16;

  // Additional authenticated data binding the ciphertext to the
  // keystore format version. Prevents a downgrade attack where an
  // attacker rewrites the version field to a weaker format.
  inline constexpr const char *KEYSTORE_AAD = "clrty-keystore-v1";

  //  BIP-39

  // Allowed mnemonic word counts. BIP-39 specifies 12, 15, 18, 21, 24.
  // We default to 24 (256 bits of entropy).
  inline constexpr int BIP39_DEFAULT_WORD_COUNT = 24;
  inline constexpr int BIP39_MIN_WORD_COUNT = 12;
  inline constexpr int BIP39_MAX_WORD_COUNT = 24;

  //  Display

  // Format an atomic amount as a human-readable string with DECIMALS
  // decimal places. e.g. 1234567 atomic -> "12.34567".
  //
  // Returns "-" for null-ish inputs (out of range).
  std::string formatAmount(uint64_t atomic);

  // Parse a human-readable amount string into atomic units.
  // Accepts "12.34567", "12", "0.00001". Rejects negative, empty,
  // more than DECIMALS fractional digits, and any non-digit content
  // other than a single '.'.
  //
  // Returns std::nullopt on failure.
  std::optional<uint64_t> parseAmount(std::string_view s);

} // namespace Wallet