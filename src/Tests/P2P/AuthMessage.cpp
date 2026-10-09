// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "P2P/AuthMessage.h"
#include "P2P/Peer.h"

#include "Crypto/Ed25519.h"
#include "Crypto/X25519.h"

#include <array>
#include <cstring>

using namespace P2P;

// ---------------------------------------------------------------------------
//  Wire format
// ---------------------------------------------------------------------------

TEST(P2P_AuthMessage, SerializeIsFixed128Bytes)
{
  AuthMessage m;
  const auto wire = serializeAuth(m);
  EXPECT_EQ(wire.size(), 128u);
}

TEST(P2P_AuthMessage, RoundTripPreservesAllFields)
{
  AuthMessage in;

  // Fill with distinguishable values.
  for (size_t i = 0; i < 32; ++i)
  {
    in.pubkey.data[i] = static_cast<uint8_t>(0x10 + i);
    in.ephemeralPubkey.data[i] = static_cast<uint8_t>(0x40 + i);
  }
  for (size_t i = 0; i < 64; ++i)
    in.signature.data[i] = static_cast<uint8_t>(0x80 + i);

  const auto wire = serializeAuth(in);
  AuthMessage out;
  ASSERT_TRUE(deserializeAuth(wire.data(), wire.size(), out));

  EXPECT_EQ(std::memcmp(in.pubkey.data.data(),
                        out.pubkey.data.data(), 32),
            0);
  EXPECT_EQ(std::memcmp(in.ephemeralPubkey.data.data(),
                        out.ephemeralPubkey.data.data(), 32),
            0);
  EXPECT_EQ(std::memcmp(in.signature.data.data(),
                        out.signature.data.data(), 64),
            0);
}

TEST(P2P_AuthMessage, RejectsOld96ByteFormat)
{
  // The pre-encryption wire format was 96 bytes. The new format is
  // 128. A 96-byte message must be rejected — this is the mechanism
  // that makes old peers fail cleanly rather than being misinterpreted.
  std::vector<uint8_t> old(96, 0);
  AuthMessage out;
  EXPECT_FALSE(deserializeAuth(old.data(), old.size(), out));
}

TEST(P2P_AuthMessage, RejectsTruncatedAndOversize)
{
  std::vector<uint8_t> buf(128, 0);
  AuthMessage out;

  EXPECT_FALSE(deserializeAuth(buf.data(), 127, out)); // one short
  EXPECT_FALSE(deserializeAuth(buf.data(), 129, out)); // one long
  EXPECT_FALSE(deserializeAuth(buf.data(), 0, out));
  EXPECT_FALSE(deserializeAuth(nullptr, 128, out));
}

// ---------------------------------------------------------------------------
//  Challenge construction
// ---------------------------------------------------------------------------

TEST(P2P_AuthMessage, ChallengeCoversPubkey)
{
  Crypto::PublicKey id1{};
  Crypto::PublicKey id2{};
  Crypto::PublicKey eph{};

  id1.data[0] = 0x01;
  id2.data[0] = 0x02;

  const auto h1 = computeAuthChallenge(1, 2, id1, eph);
  const auto h2 = computeAuthChallenge(1, 2, id2, eph);

  EXPECT_NE(std::memcmp(h1.data.data(), h2.data.data(), 32), 0);
}

TEST(P2P_AuthMessage, ChallengeCoversEphemeralPubkey)
{
  Crypto::PublicKey id{};
  Crypto::PublicKey eph1{};
  Crypto::PublicKey eph2{};

  eph1.data[0] = 0x01;
  eph2.data[0] = 0x02;

  const auto h1 = computeAuthChallenge(1, 2, id, eph1);
  const auto h2 = computeAuthChallenge(1, 2, id, eph2);

  EXPECT_NE(std::memcmp(h1.data.data(), h2.data.data(), 32), 0);
}

TEST(P2P_AuthMessage, ChallengeCoversBothNonces)
{
  Crypto::PublicKey id{};
  Crypto::PublicKey eph{};

  const auto base = computeAuthChallenge(1, 2, id, eph);
  const auto changedLocal = computeAuthChallenge(3, 2, id, eph);
  const auto changedRemote = computeAuthChallenge(1, 3, id, eph);

  EXPECT_NE(std::memcmp(base.data.data(), changedLocal.data.data(), 32), 0);
  EXPECT_NE(std::memcmp(base.data.data(), changedRemote.data.data(), 32), 0);
}

TEST(P2P_AuthMessage, ChallengeDoesNotCommuteNonces)
{
  // Swapping local and remote nonces must change the challenge. If it
  // didn't, a message signed by one side could be replayed by the
  // other, which would defeat the session-binding property.
  Crypto::PublicKey id{};
  Crypto::PublicKey eph{};

  const auto ab = computeAuthChallenge(1, 2, id, eph);
  const auto ba = computeAuthChallenge(2, 1, id, eph);

  EXPECT_NE(std::memcmp(ab.data.data(), ba.data.data(), 32), 0);
}

TEST(P2P_AuthMessage, OverloadsProduceSameResultForSameInputs)
{
  // The two overloads (raw nonces vs AuthNonces) must agree when
  // given the same values in the same order.
  Crypto::PublicKey id{};
  Crypto::PublicKey eph{};
  id.data[0] = 0xAA;
  eph.data[0] = 0xBB;

  const auto raw = computeAuthChallenge(0x1234, 0x5678, id, eph);

  AuthNonces n;
  n.initiator = 0x1234;
  n.responder = 0x5678;
  const auto packed = computeAuthChallenge(n, id, eph);

  EXPECT_EQ(std::memcmp(raw.data.data(), packed.data.data(), 32), 0);
}

// ---------------------------------------------------------------------------
//  Nonce ordering
// ---------------------------------------------------------------------------

TEST(P2P_AuthMessage, OrderNoncesOutboundIsInitiator)
{
  const auto n = orderNonces(PeerDirection::Outbound, 0xAAAA, 0xBBBB);
  EXPECT_EQ(n.initiator, 0xAAAAu);
  EXPECT_EQ(n.responder, 0xBBBBu);
}

TEST(P2P_AuthMessage, OrderNoncesInboundIsResponder)
{
  const auto n = orderNonces(PeerDirection::Inbound, 0xBBBB, 0xAAAA);
  EXPECT_EQ(n.initiator, 0xAAAAu);
  EXPECT_EQ(n.responder, 0xBBBBu);
}

TEST(P2P_AuthMessage, OrderNoncesIsConsistentFromBothSides)
{
  // Outbound and inbound sides must agree on which nonce is the
  // initiator's, even though each sees a different (local, remote)
  // ordering.
  const auto outbound = orderNonces(PeerDirection::Outbound, 0xAAAA, 0xBBBB);
  const auto inbound = orderNonces(PeerDirection::Inbound, 0xBBBB, 0xAAAA);

  EXPECT_EQ(outbound.initiator, inbound.initiator);
  EXPECT_EQ(outbound.responder, inbound.responder);
}