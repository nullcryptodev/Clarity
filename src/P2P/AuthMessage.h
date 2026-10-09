// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Crypto/Ed25519.h"
#include "Crypto/X25519.h"

namespace P2P
{
  enum class PeerDirection : uint8_t;

  // Authentication exchange, sent after Verack and before AuthReady.
  //
  // Both sides send an Auth message. Each carries the sender's Ed25519
  // identity public key, an X25519 ephemeral public key for session
  // key agreement, and an Ed25519 signature binding them to this
  // specific session:
  //
  //     challenge = Blake2b( localNonce || remoteNonce
  //                          || identity_pubkey || ephemeral_pubkey )
  //
  // localNonce is the sender's networkNonce from its Version message;
  // remoteNonce is the peer's networkNonce. Including both binds the
  // signature to the session, so a captured Auth message cannot be
  // replayed against a different connection. Including both public
  // keys binds the signature to the claimed identity AND to the
  // ephemeral key — a MITM cannot substitute a different ephemeral key
  // without invalidating the signature.
  //
  // The nonces are already exchanged in VersionMessage, so no new
  // fields are needed there. The ephemeral key is new; it is the only
  // addition to the message since the pre-encryption protocol.
  //
  // Wire format (fixed 128 bytes):
  //
  //     [32] identity_pubkey    Ed25519 public key
  //     [32] ephemeral_pubkey   X25519 public key
  //     [64] signature          Ed25519 over the challenge above
  //
  // Fixed-size, no framing, no type tag. A 96-byte message is the old
  // (pre-encryption) format and is rejected by the size check; a
  // 128-byte message is this format. The protocol version bump (see
  // P2P-ENCRYPTION.md §9) ensures old peers are rejected at
  // handleVersion before any Auth message is sent.
  struct AuthMessage
  {
    Crypto::PublicKey pubkey{};          // Ed25519 identity key
    Crypto::PublicKey ephemeralPubkey{}; // raw X25519, 32 bytes
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
  //
  // The challenge covers four fields: both nonces, the identity public
  // key, and the ephemeral public key. See the struct comment for the
  // reasoning.
  Crypto::Hash computeAuthChallenge(uint64_t localNonce,
                                    uint64_t remoteNonce,
                                    const Crypto::PublicKey &pubkey,
                                    const Crypto::PublicKey &ephemeralPubkey);

  AuthNonces orderNonces(PeerDirection my_direction,
                         uint64_t my_nonce,
                         uint64_t their_nonce);

  Crypto::Hash computeAuthChallenge(const AuthNonces &n,
                                    const Crypto::PublicKey &pubkey,
                                    const Crypto::PublicKey &ephemeralPubkey);

} // namespace P2P