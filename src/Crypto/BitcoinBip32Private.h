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

#include "BitcoinBip32.h"

namespace Crypto
{
  //  =========================================================================
  //  Bitcoin BIP32 private derivation
  //
  //  The counterpart to BitcoinBip32.h. That module does public-only
  //  (xpub) non-hardened derivation, which is what the bridge's
  //  scanner and RPC need. This module does private-key derivation,
  //  which is what the custody-key generator needs to walk the
  //  hardened account path m/84'/<coin>'/0' from a BIP39 seed.
  //
  //  Both modules share the ExtendedPubKey type; this one adds
  //  ExtendedPrivKey and the three functions that convert between
  //  the two worlds:
  //
  //    masterFromSeed(seed)         -> ExtendedPrivKey
  //    deriveChildPriv(parent, i)   -> ExtendedPrivKey  (hard or non-hard)
  //    toXpub(prv)                  -> ExtendedPubKey
  //
  //  Once we have the account xpub (at the end of the hardened
  //  path), everything below it is non-hardened and derives through
  //  BitcoinBip32's existing derivePath/deriveChild. This module is
  //  used exactly once per chain, at custody-key setup.
  //
  //  Deliberately NOT in scope:
  //
  //    - signing with the derived private keys (that is a future
  //      release path; the custody keys are generated but unused
  //      for spending in v1),
  //    - xprv storage in a plaintext-friendly form (BitcoinCustody
  //      persists the BIP39 mnemonic under EncryptedKeyStore, not
  //      the xprv),
  //    - BIP49 / BIP86 path helpers (the bridge uses BIP84 P2WPKH;
  //      other paths would be a new function, not a new module).
  //
  //  Verified against BIP32 test vectors 1 and 2, including every
  //  intermediate node, and cross-checked against the public module:
  //  for every non-hardened index, deriveChildPriv(parent, i) and
  //  deriveChild(toXpub(parent), i) must produce the same child
  //  pubkey.
  //  =========================================================================

  //  BIP32 extended private key. Same bookkeeping fields as
  //  ExtendedPubKey; the key material is the 32-byte secret.
  struct ExtendedPrivKey
  {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 32> chaincode{};
    uint32_t depth{0};
    uint32_t parent_fingerprint{0};
    uint32_t child_number{0};

    bool isNull() const noexcept
    {
      for (auto b : key)
        if (b != 0)
          return false;
      return true;
    }
  };

  //  Parse a base58check xprv/tprv. Validates:
  //    - base58check checksum,
  //    - 78-byte payload,
  //    - version bytes match `network`,
  //    - depth < 256,
  //    - the embedded secret is a valid secp256k1 scalar
  //      (secp256k1_ec_seckey_verify).
  std::optional<ExtendedPrivKey>
  parseExtendedPrivKey(const std::string &encoded,
                       BitcoinNetwork network,
                       std::string *error_out = nullptr);

  //  Serialize back to base58check xprv/tprv. Round-trips with
  //  parseExtendedPrivKey.
  std::string encodeExtendedPrivKey(const ExtendedPrivKey &key,
                                    BitcoinNetwork network);

  //  Derive the BIP32 master node from a seed. `seed` is the
  //  standard 16-64 byte BIP39 seed (the output of PBKDF2-HMAC-SHA512,
  //  not the mnemonic). I = HMAC-SHA512("Bitcoin seed", seed);
  //  key = I[0..32], chaincode = I[32..64]. The key must be a valid
  //  secp256k1 scalar; if it is not, the function returns nullopt
  //  (probability ~2^-127, but handled per BIP32).
  std::optional<ExtendedPrivKey>
  masterFromSeed(const std::vector<uint8_t> &seed,
                 std::string *error_out = nullptr);

  //  Derive one child. Handles both hardened and non-hardened
  //  indices; the parent may be the master or any descendant.
  //
  //  Hardened (index >= 0x80000000):
  //    I = HMAC-SHA512(chaincode, 0x00 || k_par || ser32(index))
  //  Non-hardened (index < 0x80000000):
  //    I = HMAC-SHA512(chaincode, serP(K_par) || ser32(index))
  //
  //  In both cases: child.key = (I[0..32] + k_par) mod n,
  //  child.chaincode = I[32..64]. Returns nullopt on:
  //    - I[0..32] >= n (BIP32's invalid-child case),
  //    - child.key == 0.
  std::optional<ExtendedPrivKey>
  deriveChildPriv(const ExtendedPrivKey &parent,
                  uint32_t index,
                  std::string *error_out = nullptr);

  //  Derive a path of children. Accepts hardened and non-hardened
  //  components; the textual form "m/84'/0'/0'" parses to
  //  {0x80000054, 0x80000000, 0x80000000}. Use the helpers in
  //  BitcoinBip32.h (parseDerivationTail / path helpers) for text
  //  parsing that rejects hardened; here we accept hardened by
  //  design because the account path is hardened.
  std::optional<ExtendedPrivKey>
  derivePathPriv(const ExtendedPrivKey &parent,
                 const std::vector<uint32_t> &path,
                 std::string *error_out = nullptr);

  //  Convert a private node to its public counterpart. Used exactly
  //  once per chain: after walking m/84'/<coin>'/0', produce the
  //  account xpub, then hand it to BitcoinBip32::derivePath for
  //  every receive-branch derivation below it.
  std::optional<ExtendedPubKey>
  toXpub(const ExtendedPrivKey &prv,
         std::string *error_out = nullptr);

  //  Convenience: given a BIP39 seed and a BIP84 account path,
  //  return the account xpub. One call replaces
  //  masterFromSeed + derivePathPriv + toXpub.
  std::optional<ExtendedPubKey>
  bip84AccountXpub(const std::vector<uint8_t> &seed,
                   BitcoinNetwork network,
                   std::string *error_out = nullptr);

  //  Text helper: parse a path like "m/84'/0'/0'" into 32-bit
  //  components (hardened flag encoded in the high bit). Unlike
  //  BitcoinBip32's parseDerivationTail, this accepts hardened
  //  components, because the account path has them.
  std::optional<std::vector<uint32_t>>
  parseFullPath(const std::string &path, std::string *error_out = nullptr);
} // namespace Crypto