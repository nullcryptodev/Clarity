// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "BitcoinBip32Private.h"
#include "Types.h"

namespace Crypto
{
  //  =========================================================================
  //  Bitcoin ECDSA signing
  //
  //  The small surface the bridge's release path needs: sign a
  //  32-byte hash with a BIP32 private key, DER-encode the
  //  signature, and produce the exact witness-stack item a
  //  P2WPKH input needs (DER signature || SIGHASH byte).
  //
  //  Deliberately narrow:
  //
  //    - secp256k1 only (Bitcoin's curve). No other curve.
  //    - ECDSA only. No Schnorr (BIP340) — the custody keys are
  //      BIP84 P2WPKH, which is ECDSA.
  //    - Deterministic nonces: secp256k1_ecdsa_sign uses RFC 6979
  //      internally, which is what Bitcoin Core and every modern
  //      wallet use. No caller-supplied nonce, no way to pass one.
  //    - Low-S normalization (BIP62) is applied unconditionally.
  //      A high-S signature is rejected by Bitcoin consensus (the
  //      malleability fix), so there is no use case for returning
  //      one. secp256k1_ecdsa_signature_normalize does the
  //      s -> n-s transform; secp256k1_ecdsa_sign already produces
  //      low-S in practice, but normalizing is cheap and makes the
  //      property unconditional rather than "true in practice".
  //
  //  secp256k1 v0.8.0 is vendored at external/secp256k1/, core
  //  module only. The three functions used here
  //  (ecdsa_sign, ecdsa_signature_normalize,
  //  ecdsa_signature_serialize_der) are all core-module.
  //  =========================================================================

  //  Sign a 32-byte hash with a BIP32 extended private key.
  //
  //  Returns the 64-byte compact (r || s) signature, low-S
  //  normalized. This is the form used internally by
  //  secp256k1 and by DER encoding; the witness stack wants the
  //  DER form (see signDerWithHashType), not this.
  //
  //  On failure (null key, null hash, secp256k1 sign failure —
  //  which for a valid scalar and any 32-byte hash cannot
  //  happen, but is checked), returns nullopt and fills
  //  error_out if provided.
  std::optional<Signature> signHash(
      const ExtendedPrivKey &key,
      const Hash &hash,
      std::string *error_out = nullptr);

  //  DER-encode a 64-byte (r || s) signature into Bitcoin's
  //  variable-length DER form. Returns the minimal DER encoding
  //  (secp256k1_ecdsa_signature_serialize_der emits the
  //  canonical minimal form, per DER's leading-zero rules).
  //
  //  On failure (the 64 bytes are not a valid (r, s) pair — e.g.
  //  r or s is >= the curve order), returns an empty vector. A
  //  caller with a signature produced by signHash never sees the
  //  failure path; it exists so the function has a defined
  //  behavior for arbitrary input rather than UB.
  std::vector<uint8_t> derEncode(const Signature &sig);

  //  Sign + DER-encode + append the SIGHASH byte. This is the
  //  exact witness-stack item a P2WPKH input carries:
  //
  //    [ DER-encoded signature || 0x01 ]
  //
  //  where 0x01 is SIGHASH_ALL. The witness stack has a second
  //  item, the 33-byte compressed public key, which is not
  //  produced here — the caller gets it from the same
  //  ExtendedPrivKey via toXpub() + serialization, or (simpler)
  //  from custody->deriveScript(index).script's 20-byte hash
  //  after a pubkey recovery step that the caller already has
  //  the key for.
  //
  //  `hash_type` must be 0x01. Every other value returns nullopt.
  //  This mirrors sighashBip143's restriction: the bridge only
  //  ever signs SIGHASH_ALL, and a signature with a different
  //  sighash byte would commit to a different preimage than the
  //  one signHash was called with (the hash_type is part of the
  //  BIP143 preimage), so allowing other values here would be a
  //  silent footgun.
  //
  //  On failure, returns nullopt and fills error_out if provided.
  std::optional<std::vector<uint8_t>> signDerWithHashType(
      const ExtendedPrivKey &key,
      const Hash &hash,
      uint32_t hash_type = 0x01,
      std::string *error_out = nullptr);

} // namespace Crypto