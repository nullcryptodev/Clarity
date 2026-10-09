// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "Crypto/X25519.h"

namespace Crypto
{
  inline constexpr size_t SESSION_KEY_SIZE = 32;

  // Directional session keys derived from a completed X25519 handshake.
  //
  // Three keys:
  //
  //   sessionKey      — the master key. Retained for diagnostics and
  //                     for deriving additional directional keys if the
  //                     protocol ever gains a second channel. NOT used
  //                     directly for encryption.
  //
  //   lowerNonceKey   — used by the side with the lower network nonce
  //                     (the "A" side) to send, and by the "B" side to
  //                     receive.
  //
  //   higherNonceKey  — used by the "B" side to send, and by the "A"
  //                     side to receive.
  //
  // The two directional keys are independent: knowing one does not
  // reveal the other, and a ciphertext produced under one will not
  // verify under the other. This is what makes the two directions
  // cryptographically distinct and prevents reflection attacks.
  struct DerivedSessionKeys
  {
    std::array<uint8_t, SESSION_KEY_SIZE> sessionKey{};
    std::array<uint8_t, SESSION_KEY_SIZE> lowerNonceKey{};
    std::array<uint8_t, SESSION_KEY_SIZE> higherNonceKey{};

    // Select the key this peer uses to SEND. `weAreLowerNonce` is true
    // if this peer's network nonce is the lower of the two involved in
    // the handshake. Both peers compute the same A/B ordering, so both
    // arrive at the same pair of keys; each picks the one matching its
    // role.
    const uint8_t *forSend(bool weAreLowerNonce) const noexcept
    {
      return weAreLowerNonce ? lowerNonceKey.data() : higherNonceKey.data();
    }

    // Select the key this peer uses to RECEIVE.
    const uint8_t *forReceive(bool weAreLowerNonce) const noexcept
    {
      return weAreLowerNonce ? higherNonceKey.data() : lowerNonceKey.data();
    }
  };

  // Derive the three session keys from a completed X25519 handshake.
  //
  // Inputs:
  //
  //   sharedSecret      — X25519(our_ephemeral_secret, their_ephemeral_pub).
  //                       Must NOT be all-zeros; the caller is expected
  //                       to have already rejected that case via
  //                       Crypto::x25519's bool return.
  //
  //   ourEphemeralPub   — our X25519 ephemeral public key.
  //   theirEphemeralPub — the peer's X25519 ephemeral public key.
  //
  //   ourIdentityPub    — our Ed25519 identity public key (the one that
  //                       authenticated via the Auth exchange).
  //   theirIdentityPub  — the peer's Ed25519 identity public key.
  //
  //   ourNonce          — our network nonce (from our Version message).
  //   theirNonce        — the peer's network nonce (from their Version).
  //
  //   weAreLowerNonce   — true if ourNonce < theirNonce. Must be the
  //                       logical inverse of the peer's own flag; if
  //                       both sides compute the same value, they have
  //                       disagreed about which is which and the
  //                       derived keys will not match. This is caught
  //                       by the AuthReady key-confirmation step, but
  //                       the inputs here are what make that check
  //                       meaningful.
  //
  // Returns a struct with all three keys. The function cannot fail: all
  // inputs are fixed-size byte arrays, and Blake2b is total. Zeroing of
  // internal temporaries is handled inside.
  //
  // Domain separation: the KDF input is prefixed with the literal ASCII
  // string "CLRTY-P2P-ENC-v1". This is not a length-prefixed field, it
  // is a fixed 16-byte prefix. The prefix ensures the same Blake2b
  // construction used elsewhere in the codebase cannot produce a
  // colliding value for a different purpose.
  DerivedSessionKeys deriveSessionKeys(
      const uint8_t sharedSecret[X25519_KEY_SIZE],
      const uint8_t ourEphemeralPub[X25519_KEY_SIZE],
      const uint8_t theirEphemeralPub[X25519_KEY_SIZE],
      const uint8_t ourIdentityPub[32],
      const uint8_t theirIdentityPub[32],
      uint64_t ourNonce,
      uint64_t theirNonce,
      bool weAreLowerNonce) noexcept;

} // namespace Crypto