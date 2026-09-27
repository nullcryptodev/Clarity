// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Crypto/Ed25519.h"

namespace P2P
{
  enum class PeerDirection : uint8_t;

  // Authentication exchange, sent after Verack and before Established.
  //
  // Both sides send an Auth message. Each carries the sender's public
  // key and an Ed25519 signature over a challenge that binds the
  // signature to this specific session:
  //
  //     challenge = Blake2b( localNonce || remoteNonce || pubkey )
  //
  // localNonce is the sender's networkNonce from its Version message;
  // remoteNonce is the peer's networkNonce. Including both binds the
  // signature to the session, so a captured Auth message cannot be
  // replayed against a different connection. Including the pubkey
  // binds the signature to the claimed key, so an attacker cannot
  // substitute a different pubkey and replay a signature.
  //
  // The nonces are already exchanged in VersionMessage, so no new
  // fields are needed there. This message is purely additive.
  struct AuthMessage
  {
    Crypto::PublicKey pubkey{};
    Crypto::Signature signature{};
  };

  struct AuthNonces
  {
    uint64_t initiator; // the nonce of the peer that dialed (Outbound)
    uint64_t responder; // the nonce of the peer that accepted (Inbound)
  };

  std::vector<uint8_t> serializeAuth(const AuthMessage &m);
  bool deserializeAuth(const uint8_t *data, size_t len, AuthMessage &out);

  // Compute the challenge hash. Both nonces are in host byte order;
  // the hash is computed over their little-endian byte representation
  // (matching VersionMessage's wire encoding) so the two sides agree.
  Crypto::Hash computeAuthChallenge(uint64_t localNonce,
                                    uint64_t remoteNonce,
                                    const Crypto::PublicKey &pubkey);

  AuthNonces orderNonces(PeerDirection my_direction,
                         uint64_t my_nonce,
                         uint64_t their_nonce);

  Crypto::Hash computeAuthChallenge(const AuthNonces &n,
                                    const Crypto::PublicKey &pubkey);

} // namespace P2P