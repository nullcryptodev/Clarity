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

  //  Original Keccak-256 (padding 0x01, not SHA3's 0x06), 32-byte
  //  output. This is CCX's cn_fast_hash — the hash used in
  //  CryptoNote's key derivations, address checksums, and
  //  subaddress derivations. Byte-for-byte compatible with
  //  conceald's crypto::cn_fast_hash.
  //
  //  Exposed here rather than kept internal to Ed25519.cpp because
  //  the bridge's subaddress derivation (see
  //  Core/Bridge/ConcealCCX.h) needs the same primitive, and
  //  duplicating the "which padding?" gotcha across two files is
  //  exactly the class of bug this function exists to prevent.
  //  The known-answer test in Tests/Crypto/Ed25519Derivation.cpp
  //  pins the padding: cn_fast_hash("") must equal c5d24601...,
  //  not the SHA3-256 digest a7ffc6f8....
  void cnFastHash(const void *data, size_t len,
                  uint8_t out[32]) noexcept;

  //  =====================================================================
  //  Subaddress matching
  //
  //  A CCX watcher's scanner is given an on-chain output pubkey P and a
  //  per-transaction key derivation D (from generateKeyDerivation), and
  //  must decide in O(1) whether P was paid to any known subaddress A.
  //
  //  The naive check — for each known A, compute
  //  derivePublicKey(D, i, A) and compare to P — is O(n_known) per
  //  vout. At chain scale (n_known up to the deposit registry cap,
  //  100,000) that is infeasible during initial catch-up.
  //
  //  The reverse is O(1) per vout:
  //
  //    s  = Hs(D, i)          # the derivation_to_scalar used by
  //                           # derivePublicKey internally
  //    A' = P - 8*s*G         # reverse the ge_mul8 cofactor step and
  //                           # the point addition
  //
  //  A' is the spend pubkey of the subaddress that paid P, or a
  //  point that matches no known subaddress (A' is a valid point in
  //  either case; the caller does the set membership test).
  //
  //  The ×8 is critical. Conceal's generateKeyDerivation applies
  //  ge_mul8 (a cofactor step) to the derivation before returning it,
  //  so derivePublicKey effectively computes A + 8*s*G, not A + s*G.
  //  A reverse that forgot the ×8 would compute P - s*G, which is a
  //  different point and would match nothing. The known-answer test
  //  in Tests/Crypto/Ed25519Derivation.cpp pins this: for any
  //  (spend, view) pair, derivePublicKey(reverse_derivation_of(X))
  //  must equal X.
  //  =====================================================================

  //  Return P = scalar * G. Thin wrapper over ref10's
  //  ge_scalarmult_base, used by reverseDeriveCandidate and by any
  //  future code that needs a scalar × base multiplication without a
  //  full KeyDerivation round-trip.
  PublicKey scalarMultBase(const SecretKey &scalar) noexcept;

  //  Return A - B, in the same 32-byte compressed encoding as both
  //  inputs. Thin wrapper over ref10's ge_sub.
  PublicKey pointSubtract(const PublicKey &a,
                          const PublicKey &b) noexcept;

  //  Reverse-derive the spend pubkey that would pay to P under
  //  (derivation, outputIndex). Returns false if any input is not a
  //  valid curve point/scalar, or if the subtraction yields a point
  //  that can't be compressed (which should not happen for any
  //  well-formed inputs; the check exists so a bug here is caught
  //  rather than silently producing a wrong candidate).
  //
  //  On true, candidate_out holds the candidate spend pubkey. The
  //  caller is expected to look it up in a set of known subaddress
  //  spend pubkeys; if it's not present, P was paid to an address the
  //  watcher doesn't know about (a non-bridge CCX deposit to the
  //  custody wallet, or a deposit to a subaddress registered after
  //  the watcher's cache was built).
  bool reverseDeriveCandidate(const PublicKey &P,
                              const KeyDerivation &derivation,
                              size_t outputIndex,
                              PublicKey &candidate_out) noexcept;

  //  Return a (scalar, public-key) pair in the CryptoNote model:
  //  `secretKey` is a canonical scalar mod ℓ (passes sc_check),
  //  and `publicKey = secretKey * G`.
  //
  //  This is NOT an ed25519 signing keypair. The scalar is not
  //  derived by clamping (which would put it in [2^254, 2^255),
  //  almost always > ℓ and therefore rejected by sc_check). It is
  //  derived by hashing the seed and reducing mod ℓ. The public
  //  key is the corresponding group element.
  //
  //  Use this for CryptoNote / Conceal key derivation, where the
  //  "secret key" is used as a raw scalar multiplier (not as a
  //  signing key). For ed25519 signing, use
  //  generateKeyPairFromSeed.
  KeyPair generateScalarKeyPairFromSeed(const SecretKey &seed) noexcept;

  //  True iff `sk` is a canonical scalar mod the ed25519 group
  //  order ℓ (i.e. sc_check returns 0). Distinct from "is a valid
  //  ed25519 secret" — an ed25519 seed is 32 arbitrary bytes and
  //  almost never passes this check. Use this to validate raw
  //  scalars (CryptoNote view keys, subaddress derivation inputs),
  //  not seeds.
  bool isValidScalar(const SecretKey &sk) noexcept;
} // namespace Crypto