// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AuthMessage.h"
#include "Peer.h"

#include "Common/Reader.h"
#include "Crypto/Blake2b.h"

#include <cstring>

namespace P2P
{
  namespace
  {
    inline void appendBytes(std::vector<uint8_t> &out,
                            const uint8_t *p, size_t n)
    {
      out.insert(out.end(), p, p + n);
    }

    inline void appendU64(std::vector<uint8_t> &out, uint64_t v)
    {
      for (int i = 0; i < 8; ++i)
        out.push_back(uint8_t(v >> (i * 8)));
    }
  } // anonymous namespace

  std::vector<uint8_t> serializeAuth(const AuthMessage &m)
  {
    std::vector<uint8_t> out;
    out.reserve(32 + 64);
    appendBytes(out, m.pubkey.data.data(), 32);
    appendBytes(out, m.signature.data.data(), 64);
    return out;
  }

  bool deserializeAuth(const uint8_t *data, size_t len, AuthMessage &out)
  {
    // Fixed-size message: 32 + 64. Anything else is malformed.
    if (len != 32 + 64)
      return false;

    std::memcpy(out.pubkey.data.data(), data, 32);
    std::memcpy(out.signature.data.data(), data + 32, 64);
    return true;
  }

  Crypto::Hash computeAuthChallenge(uint64_t localNonce,
                                    uint64_t remoteNonce,
                                    const Crypto::PublicKey &pubkey)
  {
    std::vector<uint8_t> buf;
    buf.reserve(8 + 8 + 32);
    appendU64(buf, localNonce);
    appendU64(buf, remoteNonce);
    appendBytes(buf, pubkey.data.data(), 32);

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
    appendU64(buf, n.initiator);
    appendU64(buf, n.responder);
    appendBytes(buf, pubkey.data.data(), 32);

    Crypto::Hash h;
    Crypto::blake2b(buf.data(), buf.size(), h.data.data(), 32);
    return h;
  }
} // namespace P2P