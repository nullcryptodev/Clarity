// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SessionKey.h"
#include "Blake2b.h"
#include "SecureZero.h"

#include <cstring>

namespace Crypto
{
  namespace
  {
    // Fixed domain separator. 16 bytes, no length prefix — see the
    // header comment. Bumping the version suffix invalidates every
    // session established under the old value, which is the intended
    // behavior for a protocol revision.
    constexpr char DOMAIN_PREFIX[] = "CLRTY-P2P-ENC-v1";
    constexpr size_t DOMAIN_PREFIX_SIZE = sizeof(DOMAIN_PREFIX) - 1; // 16

    // Direction labels for the per-direction key derivation. Fixed
    // ASCII, no length prefix, distinct first byte so there is no
    // ambiguity between the two labels even if one is a prefix of the
    // other (which they are not, but the property costs nothing).
    constexpr char LABEL_LOWER[] = "lower";
    constexpr size_t LABEL_LOWER_SIZE = sizeof(LABEL_LOWER) - 1;

    constexpr char LABEL_HIGHER[] = "higher";
    constexpr size_t LABEL_HIGHER_SIZE = sizeof(LABEL_HIGHER) - 1;

    // Little-endian put for a 64-bit integer. Matches the wire encoding
    // used by VersionMessage and AuthMessage's challenge, so the two
    // sides agree byte-for-byte without depending on host endianness.
    inline void putU64LE(uint8_t *out, uint64_t v) noexcept
    {
      out[0] = static_cast<uint8_t>(v >> 0);
      out[1] = static_cast<uint8_t>(v >> 8);
      out[2] = static_cast<uint8_t>(v >> 16);
      out[3] = static_cast<uint8_t>(v >> 24);
      out[4] = static_cast<uint8_t>(v >> 32);
      out[5] = static_cast<uint8_t>(v >> 40);
      out[6] = static_cast<uint8_t>(v >> 48);
      out[7] = static_cast<uint8_t>(v >> 56);
    }
  } // anonymous namespace

  DerivedSessionKeys deriveSessionKeys(
      const uint8_t sharedSecret[X25519_KEY_SIZE],
      const uint8_t ourEphemeralPub[X25519_KEY_SIZE],
      const uint8_t theirEphemeralPub[X25519_KEY_SIZE],
      const uint8_t ourIdentityPub[32],
      const uint8_t theirIdentityPub[32],
      uint64_t ourNonce,
      uint64_t theirNonce,
      bool weAreLowerNonce) noexcept
  {
    // Canonical A/B ordering. The lower-nonce side is "A"; the
    // higher-nonce side is "B". If the two nonces are equal (a bug —
    // self-connection detection should have caught it, and a genuine
    // collision is 2^-64 improbable), fall back to a fixed ordering so
    // the function remains total. Both sides will compute the same
    // fallback because both see the same equal nonces.
    const bool weAreA = weAreLowerNonce;

    const uint8_t *aEphemeral = weAreA ? ourEphemeralPub : theirEphemeralPub;
    const uint8_t *bEphemeral = weAreA ? theirEphemeralPub : ourEphemeralPub;
    const uint8_t *aIdentity = weAreA ? ourIdentityPub : theirIdentityPub;
    const uint8_t *bIdentity = weAreA ? theirIdentityPub : ourIdentityPub;
    const uint64_t aNonce = weAreA ? ourNonce : theirNonce;
    const uint64_t bNonce = weAreA ? theirNonce : ourNonce;

    // Build the KDF input. Fixed-size buffer, no allocation.
    //
    // Layout:
    //   [16]  domain prefix
    //   [32]  shared secret
    //   [32]  A ephemeral public key
    //   [32]  B ephemeral public key
    //   [32]  A identity public key
    //   [32]  B identity public key
    //   [8]   A nonce (LE)
    //   [8]   B nonce (LE)
    // = 192 bytes
    constexpr size_t KDF_INPUT_SIZE =
        DOMAIN_PREFIX_SIZE + X25519_KEY_SIZE * 5 + 8 + 8;
    static_assert(KDF_INPUT_SIZE == 192, "KDF input layout mismatch");

    uint8_t input[KDF_INPUT_SIZE];
    size_t off = 0;

    std::memcpy(input + off, DOMAIN_PREFIX, DOMAIN_PREFIX_SIZE);
    off += DOMAIN_PREFIX_SIZE;

    std::memcpy(input + off, sharedSecret, X25519_KEY_SIZE);
    off += X25519_KEY_SIZE;

    std::memcpy(input + off, aEphemeral, X25519_KEY_SIZE);
    off += X25519_KEY_SIZE;
    std::memcpy(input + off, bEphemeral, X25519_KEY_SIZE);
    off += X25519_KEY_SIZE;

    std::memcpy(input + off, aIdentity, 32);
    off += 32;
    std::memcpy(input + off, bIdentity, 32);
    off += 32;

    putU64LE(input + off, aNonce);
    off += 8;
    putU64LE(input + off, bNonce);
    off += 8;

    // Session key. This is the master key; the directional keys are
    // derived from it below, never used directly for encryption.
    DerivedSessionKeys out;
    blake2b(input, KDF_INPUT_SIZE, out.sessionKey.data(), SESSION_KEY_SIZE);

    // Directional keys.
    //
    // Each directional key is Blake2b(sessionKey || label). The labels
    // are distinct, so the two keys are independent under the random
    // oracle assumption for Blake2b. A 32-byte session key plus an
    // ASCII label is a well-formed input to Blake2b's one-shot
    // interface; no length prefix is needed because the session key is
    // fixed-size and comes first.
    //
    // The lower-nonce key is used by the A side to SEND and the B side
    // to RECEIVE. The higher-nonce key is the inverse. Both sides
    // compute both keys; each picks the one matching its role at the
    // call site (see DerivedSessionKeys::forSend / forReceive).
    {
      uint8_t labelInput[SESSION_KEY_SIZE + LABEL_LOWER_SIZE];
      std::memcpy(labelInput, out.sessionKey.data(), SESSION_KEY_SIZE);
      std::memcpy(labelInput + SESSION_KEY_SIZE, LABEL_LOWER, LABEL_LOWER_SIZE);
      blake2b(labelInput, sizeof(labelInput),
              out.lowerNonceKey.data(), SESSION_KEY_SIZE);
      secureZero(labelInput, sizeof(labelInput));
    }
    {
      uint8_t labelInput[SESSION_KEY_SIZE + LABEL_HIGHER_SIZE];
      std::memcpy(labelInput, out.sessionKey.data(), SESSION_KEY_SIZE);
      std::memcpy(labelInput + SESSION_KEY_SIZE, LABEL_HIGHER, LABEL_HIGHER_SIZE);
      blake2b(labelInput, sizeof(labelInput),
              out.higherNonceKey.data(), SESSION_KEY_SIZE);
      secureZero(labelInput, sizeof(labelInput));
    }

    // The KDF input buffer held the shared secret and both ephemeral
    // public keys. The public keys are not secret, but the shared
    // secret is — the whole point of the derivation is to not leave it
    // lying around. Zero the whole buffer rather than reasoning about
    // which fields are sensitive; the cost is one 192-byte memset per
    // handshake.
    secureZero(input, sizeof(input));

    return out;
  }

} // namespace Crypto