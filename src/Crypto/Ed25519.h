// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "Types.h"

namespace Crypto
{
  inline constexpr size_t ED25519_PUBLIC_KEY_SIZE = 32;
  inline constexpr size_t ED25519_SECRET_KEY_SIZE = 32;
  inline constexpr size_t ED25519_SIGNATURE_SIZE = 64;

  KeyPair generateKeyPair();
  KeyPair generateKeyPairFromSeed(const SecretKey &seed) noexcept;
  PublicKey derivePublicKey(const SecretKey &sk) noexcept;

  void sign(const Hash &msg, const SecretKey &sk, Signature &out) noexcept;
  void sign(const uint8_t *msg, size_t msgLen,
            const SecretKey &sk, Signature &out) noexcept;

  Signature sign(const Hash &msg, const SecretKey &sk) noexcept;
  Signature sign(const uint8_t *msg, size_t msgLen,
                 const SecretKey &sk) noexcept;

  bool verify(const Hash &msg,
              const PublicKey &pk,
              const Signature &sig) noexcept;

  bool verify(const uint8_t *msg, size_t msgLen,
              const PublicKey &pk,
              const Signature &sig) noexcept;

  bool verifyBatch(const Hash &msg,
                   const std::vector<PublicKey> &pks,
                   const std::vector<Signature> &sigs) noexcept;

  //  =====================================================================
  //  CryptoNote output-key derivation
  //
  //  These two primitives are what the bridge needs to identify which
  //  vout of a scanned CCX deposit transaction pays to the custody
  //  address. They are byte-for-byte compatible with conceald's
  //  crypto::generate_key_derivation / crypto::derive_public_key,
  //  including the Conceal-specific ge_mul8 cofactor step and the
  //  exact "KeyDerivation || varint(index)" hash input.
  //
  //  The implementation is a thin adapter over the vendored ref10
  //  curve arithmetic (extern/cryptonote-ref10/crypto-ops.{c,h}) and
  //  the vendored keccak-1600 (extern/cryptonote-ref10/hash-ops.c,
  //  keccak.c). No other CCX code is required.
  //
  //  Why vendored rather than reimplemented: the derivation is a
  //  silent-failure primitive. A wrong ge_mul8 (or a missing one),
  //  a wrong varint layout, or a wrong hash produces a well-formed
  //  32-byte key that never matches the on-chain output — i.e. "no
  //  deposit found" for a real deposit. The vendored code is the
  //  same code that produced the on-chain outputs, so byte-for-byte
  //  parity is guaranteed by construction.
  //  =====================================================================

  struct KeyDerivation : ByteArray<32>
  {
    using ByteArray::ByteArray;
    KeyDerivation() = default;
  };

  bool generateKeyDerivation(const PublicKey &txPubKey,
                             const SecretKey &viewSecretKey,
                             KeyDerivation &out) noexcept;

  bool derivePublicKey(const KeyDerivation &derivation,
                       size_t outputIndex,
                       const PublicKey &spendPubKey,
                       PublicKey &out) noexcept;

} // namespace Crypto