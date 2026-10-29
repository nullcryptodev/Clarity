// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace Crypto
{
  //  =========================================================================
  //  Bitcoin BIP32 / BIP84
  //
  //  Public-only (xpub) derivation, plus P2WPKH script and address
  //  encoding. This is what the bridge needs to hand a depositor a
  //  fresh address per registration without ever holding a private
  //  key on the daemon.
  //
  //  We deliberately do NOT implement:
  //
  //    - hardened derivation (needs the private key, which the
  //      daemon must not hold),
  //    - xprv parsing or private child derivation (same reason),
  //    - BIP49 / BIP86 / Taproot (out of scope; P2WPKH is the
  //      universal-compatibility choice for deposits),
  //    - mnemonic / seed handling (the bridge receives an xpub,
  //      not a seed).
  //
  //  The functions here are pure: no global state, no I/O, no
  //  logging. Callers validate, log, and cache.
  //  =========================================================================

  enum class BitcoinNetwork : uint8_t
  {
    Mainnet, // xpub version 0x0488B21E, HRP "bc"
    Testnet, // tpub version 0x043587CF, HRP "tb"
    Regtest, // tpub version 0x043587CF, HRP "bcrt"
  };

  //  A BIP32 extended public key: the 33-byte compressed pubkey,
  //  the 32-byte chain code, and the bookkeeping fields that BIP32
  //  serializes alongside them.
  struct ExtendedPubKey
  {
    std::array<uint8_t, 33> pubkey{};
    std::array<uint8_t, 32> chaincode{};
    uint32_t depth{0};
    uint32_t parent_fingerprint{0};
    uint32_t child_number{0};

    bool isNull() const noexcept
    {
      for (auto b : pubkey)
        if (b != 0)
          return false;
      return true;
    }
  };

  //  Parse a base58check xpub/tpub. Validates:
  //    - base58check checksum,
  //    - 78-byte payload,
  //    - version bytes match `network`,
  //    - depth < 256,
  //    - the embedded pubkey is a valid secp256k1 point
  //      (this last one is the important one: a syntactically valid
  //      xpub whose pubkey is off-curve would otherwise be accepted
  //      at config time and fail silently at first deposit).
  //
  //  On any failure returns nullopt and, if error_out is non-null,
  //  fills it with a human-readable reason.
  std::optional<ExtendedPubKey>
  parseExtendedPubKey(const std::string &encoded,
                      BitcoinNetwork network,
                      std::string *error_out = nullptr);

  //  Serialize back to base58check xpub/tpub. Round-trips with
  //  parseExtendedPubKey.
  std::string encodeExtendedPubKey(const ExtendedPubKey &key,
                                   BitcoinNetwork network);

  //  Derive one non-hardened child. `index` must be < 0x80000000
  //  (i.e. not hardened). Returns nullopt on:
  //    - hardened index (we have no private key),
  //    - IL >= n (BIP32's "invalid child" case, ~2^-127
  //      probability, but must be handled),
  //    - the resulting point at infinity.
  //
  //  Deterministic: same input, same output, always.
  std::optional<ExtendedPubKey>
  deriveChild(const ExtendedPubKey &parent,
              uint32_t index,
              std::string *error_out = nullptr);

  //  Derive a path of non-hardened children. Empty path returns
  //  `account` unchanged. Any component >= 0x80000000 is rejected.
  std::optional<ExtendedPubKey>
  derivePath(const ExtendedPubKey &account,
             const std::vector<uint32_t> &path,
             std::string *error_out = nullptr);

  //  Parse a textual derivation prefix like "m/84'/0'/0'" and
  //  return the components after the account level, i.e. the
  //  non-hardened tail. The bridge's xpub is the *account* xpub,
  //  so the prefix consumed here is everything the operator wrote
  //  after it. Rejects any hardened component in the tail (that
  //  would require the private key).
  //
  //  Example: for a config with
  //    derivation_prefix = "m/84'/0'/0'"
  //    xpub = <account xpub at m/84'/0'/0'>
  //  the adapter calls derivePath(account, {0, index}) to get the
  //  receiving address at m/84'/0'/0'/0/index.
  std::optional<std::vector<uint32_t>>
  parseDerivationTail(const std::string &tail,
                      std::string *error_out = nullptr);

  //  P2WPKH scriptPubKey for a compressed pubkey:
  //    OP_0 PUSH20 RIPEMD160(SHA256(pubkey))
  //  which is exactly 22 bytes: 0x00 0x14 <20 bytes>.
  std::array<uint8_t, 22>
  p2wpkhScript(const std::array<uint8_t, 33> &compressed_pubkey);

  //  Encode a P2WPKH scriptPubKey as a bech32 (v0) address.
  //
  //  IMPORTANT: witness version 0 uses bech32, NOT bech32m. The
  //  bech32m variant is for witness v1+ (Taproot, BIP350). Using
  //  bech32m here produces a string that looks right and is
  //  rejected by every wallet. This distinction is the single
  //  most common source of wrong Bitcoin address bugs.
  std::string p2wpkhAddress(const std::array<uint8_t, 22> &script,
                            BitcoinNetwork network);

  //  Convenience: compressed pubkey -> P2WPKH address. The single
  //  call the bridge adapter makes per deposit index.
  std::string p2wpkhAddressFromPubkey(
      const std::array<uint8_t, 33> &compressed_pubkey,
      BitcoinNetwork network);

  //  BIP32 key fingerprint: first 4 bytes of
  //  RIPEMD160(SHA256(compressed_pubkey)), big-endian.
  uint32_t keyFingerprint(const std::array<uint8_t, 33> &compressed_pubkey);
} // namespace Crypto