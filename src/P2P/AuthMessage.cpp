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
  std::vector<uint8_t> serializeAuth(const AuthMessage &m)
  {
    std::vector<uint8_t> out;
    out.reserve(32 + 64);

    Common::Writer w(out);
    w.writeBytes(m.pubkey.data.data(), m.pubkey.data.size());
    w.writeBytes(m.signature.data.data(), m.signature.data.size());

    return out;
  }

  bool deserializeAuth(const uint8_t *data, size_t len, AuthMessage &out)
  {
    // Fixed-size message: 32 + 64. Anything else is malformed.
    constexpr size_t AUTH_WIRE_SIZE = 32 + 64;
    if (len != AUTH_WIRE_SIZE)
      return false;

    Common::Reader r(data, len);
    r.readBytes(out.pubkey.data.data(), out.pubkey.data.size());
    r.readBytes(out.signature.data.data(), out.signature.data.size());
    return r.ok();
  }

  Crypto::Hash computeAuthChallenge(uint64_t localNonce,
                                    uint64_t remoteNonce,
                                    const Crypto::PublicKey &pubkey)
  {
    std::vector<uint8_t> buf;
    buf.reserve(8 + 8 + 32);

    Common::putU64(buf, localNonce);
    Common::putU64(buf, remoteNonce);
    Common::putBytes(buf, pubkey.data.data(), pubkey.data.size());

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
                                    const Crypto::PublicKey &pubkey)
  {
    std::vector<uint8_t> buf;
    buf.reserve(8 + 8 + 32);

    Common::putU64(buf, n.initiator);
    Common::putU64(buf, n.responder);
    Common::putBytes(buf, pubkey.data.data(), pubkey.data.size());

    Crypto::Hash h;
    Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
    return h;
  }
} // namespace P2P