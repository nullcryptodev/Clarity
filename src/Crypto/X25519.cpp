// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "X25519.h"
#include "Random.h"
#include "SecureZero.h"

#include <cstring>
#include <stdexcept>

extern "C"
{
#include "monocypher.h"
}

namespace Crypto
{

  //  Key generation

  X25519KeyPair generateX25519KeyPair()
  {
    X25519KeyPair kp;

    if (!randomBytes(kp.secretKey.data(), kp.secretKey.size()))
    {
      throw std::runtime_error("X25519: CSPRNG unavailable");
    }

    crypto_x25519_public_key(kp.publicKey.data(), kp.secretKey.data());

    return kp;
  }

  //  Public key derivation

  void x25519PublicKey(const uint8_t secretKey[X25519_KEY_SIZE],
                       uint8_t publicKey[X25519_KEY_SIZE]) noexcept
  {
    crypto_x25519_public_key(publicKey, secretKey);
  }

  //  Scalar multiplication

  bool x25519(const uint8_t secretKey[X25519_KEY_SIZE],
              const uint8_t peerPublicKey[X25519_KEY_SIZE],
              uint8_t out[X25519_KEY_SIZE]) noexcept
  {
    // Monocypher 4.x's crypto_x25519 writes the raw shared secret
    // unconditionally and returns void. The all-zero case is the
    // low-order-point failure: a peer that sends a low-order public
    // key (e.g. the identity point, or one of the other small-order
    // points) forces the output to zero regardless of the secret.
    // The peer learns nothing useful, but the caller must not treat
    // the zero result as a valid shared secret — deriving a session
    // key from it would produce a key known to the peer.
    //
    // crypto_verify32 is constant-time (returns 0 on match, -1 on
    // mismatch), so this check does not leak timing information about
    // the secret. Comparing against a stack zero buffer avoids
    // introducing a data-dependent branch on the result bytes.
    uint8_t raw[X25519_KEY_SIZE];
    crypto_x25519(raw, secretKey, peerPublicKey);

    static const uint8_t zero[X25519_KEY_SIZE] = {0};
    const bool ok = (crypto_verify32(raw, zero) != 0);

    if (ok)
    {
      std::memcpy(out, raw, X25519_KEY_SIZE);
    }
    else
    {
      // Zero the output so a caller that ignores the return value
      // cannot accidentally use uninitialized or partial data. The
      // raw shared secret is zeroed below regardless of the path.
      std::memset(out, 0, X25519_KEY_SIZE);
    }

    secureZero(raw, sizeof(raw));
    return ok;
  }

} // namespace Crypto