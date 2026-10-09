// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace Crypto
{
  inline constexpr size_t X25519_KEY_SIZE = 32;

  // An ephemeral X25519 keypair. Used by the P2P layer's session
  // encryption handshake (see P2P-ENCRYPTION.md). Not persisted, not
  // derivable, not related to a validator's identity keys. Lives only
  // for the duration of a single P2P session.
  struct X25519KeyPair
  {
    std::array<uint8_t, X25519_KEY_SIZE> secretKey{};
    std::array<uint8_t, X25519_KEY_SIZE> publicKey{};
  };

  // Generate a fresh X25519 keypair. The secret key is 32 bytes of
  // CSPRNG output; the public key is derived from it via
  // crypto_x25519_public_key (which clamps the scalar internally, per
  // Monocypher 4.x semantics).
  //
  // Throws std::runtime_error if the CSPRNG is unavailable. This
  // matches Crypto::Ed25519::generateKeyPair's behavior on the same
  // condition — a missing CSPRNG is a program error, not a peer error.
  X25519KeyPair generateX25519KeyPair();

  // Derive the public key from a secret. Deterministic. The secret is
  // clamped internally by Monocypher, so callers can pass raw CSPRNG
  // output without pre-clamping. noexcept because the operation is a
  // pure function of its inputs and cannot fail.
  void x25519PublicKey(const uint8_t secretKey[X25519_KEY_SIZE],
                       uint8_t publicKey[X25519_KEY_SIZE]) noexcept;

  // Scalar multiplication: out = X25519(secretKey, peerPublicKey).
  //
  // Returns true on success. Returns false if the peer's public key is
  // a low-order point (the raw shared secret is all zeros), in which
  // case `out` is zeroed and must not be used. The caller MUST treat a
  // false return as a handshake failure — a zero shared secret means
  // the peer is either broken or actively attacking the exchange.
  //
  // Monocypher 4.x's crypto_x25519 does not return a status code; the
  // all-zero check is the caller's responsibility. We do it here, in
  // constant time, using crypto_verify32.
  bool x25519(const uint8_t secretKey[X25519_KEY_SIZE],
              const uint8_t peerPublicKey[X25519_KEY_SIZE],
              uint8_t out[X25519_KEY_SIZE]) noexcept;

} // namespace Crypto