// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AuthMessage.h"
#include "Peer.h"

#include "Common/Wire.h"

#include "Crypto/Blake2b.h"

#include <cstring>

namespace P2P
{
  namespace
  {
    // Wire sizes. The identity and ephemeral public keys are both 32
    // bytes (Ed25519 and X25519 respectively have the same
    // representation size). The signature is 64 bytes.
    constexpr size_t IDENTITY_PUBKEY_SIZE = 32;
    constexpr size_t EPHEMERAL_PUBKEY_SIZE = 32;
    constexpr size_t SIGNATURE_SIZE = 64;
    constexpr size_t AUTH_WIRE_SIZE =
        IDENTITY_PUBKEY_SIZE + EPHEMERAL_PUBKEY_SIZE + SIGNATURE_SIZE;
  } // anonymous namespace

  std::vector<uint8_t> serializeAuth(const AuthMessage &m)
  {
    std::vector<uint8_t> out;
    out.reserve(AUTH_WIRE_SIZE);

    Common::Writer w(out);
    w.writeBytes(m.pubkey.data.data(), m.pubkey.data.size());
    w.writeBytes(m.ephemeralPubkey.data.data(), m.ephemeralPubkey.data.size());
    w.writeBytes(m.signature.data.data(), m.signature.data.size());

    return out;
  }

  bool deserializeAuth(const uint8_t *data, size_t len, AuthMessage &out)
  {
    // Fixed-size message: 128 bytes. Anything else is malformed. This
    // deliberately rejects the old 96-byte format — see the struct
    // comment for the reasoning.
    //
    // Null data with a non-zero length is also rejected here, not
    // deeper in the Reader. The Reader's contract is "data points to
    // at least len valid bytes"; a caller that passes null has
    // already violated the contract, and the right place to catch
    // that is the entry point, before the Reader is constructed.
    if (data == nullptr || len != AUTH_WIRE_SIZE)
      return false;

    Common::Reader r(data, len);
    r.readBytes(out.pubkey.data.data(), out.pubkey.data.size());
    r.readBytes(out.ephemeralPubkey.data.data(), out.ephemeralPubkey.data.size());
    r.readBytes(out.signature.data.data(), out.signature.data.size());
    return r.ok();
  }

  Crypto::Hash computeAuthChallenge(uint64_t localNonce,
                                    uint64_t remoteNonce,
                                    const Crypto::PublicKey &pubkey,
                                    const Crypto::PublicKey &ephemeralPubkey)
  {
    std::vector<uint8_t> buf;
    buf.reserve(8 + 8 + 32 + 32);

    Common::putU64(buf, localNonce);
    Common::putU64(buf, remoteNonce);
    Common::putBytes(buf, pubkey.data.data(), pubkey.data.size());
    Common::putBytes(buf, ephemeralPubkey.data.data(), ephemeralPubkey.data.size());

    Crypto::Hash h;
    Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
    return h;
  }

  AuthNonces orderNonces(PeerDirection my_direction,
                         uint64_t my_nonce,
                         uint64_t their_nonce)
  {
    if (my_direction == PeerDirection::Outbound)
      return {my_nonce, their_nonce}; // I'm the initiator
    return {their_nonce, my_nonce};   // they're the initiator
  }

  Crypto::Hash computeAuthChallenge(const AuthNonces &n,
                                    const Crypto::PublicKey &pubkey,
                                    const Crypto::PublicKey &ephemeralPubkey)
  {
    std::vector<uint8_t> buf;
    buf.reserve(8 + 8 + 32 + 32);

    Common::putU64(buf, n.initiator);
    Common::putU64(buf, n.responder);
    Common::putBytes(buf, pubkey.data.data(), pubkey.data.size());
    Common::putBytes(buf, ephemeralPubkey.data.data(), ephemeralPubkey.data.size());

    Crypto::Hash h;
    Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
    return h;
  }
} // namespace P2P