// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <vector>

#include "P2P/AuthMessage.h"
#include "P2P/Peer.h"

#include "Crypto/Ed25519.h"

using namespace P2P;

namespace
{
  // Deterministic keypair for tests. Avoids the randomness of
  // generateKeyPair() so failures are reproducible.
  Crypto::KeyPair deterministicKey(uint8_t seed)
  {
    Crypto::SecretKey sk;
    for (size_t i = 0; i < sk.data.size(); ++i)
      sk.data[i] = uint8_t(seed + i);
    Crypto::KeyPair kp;
    kp.secretKey = sk;
    kp.publicKey = Crypto::derivePublicKey(sk);
    return kp;
  }

  AuthMessage makeAuth(uint8_t seed, uint64_t localNonce, uint64_t remoteNonce)
  {
    auto kp = deterministicKey(seed);
    AuthMessage a;
    a.pubkey = kp.publicKey;
    auto challenge = P2P::computeAuthChallenge(localNonce, remoteNonce, kp.publicKey);
    a.signature = Crypto::sign(challenge, kp.secretKey);
    return a;
  }
} // anonymous namespace

// ============================================================================
//  Wire format
// ============================================================================

TEST(Node_AuthMessage, SerializeRoundTrip)
{
  auto kp = deterministicKey(0x42);
  AuthMessage in;
  in.pubkey = kp.publicKey;
  for (size_t i = 0; i < in.signature.data.size(); ++i)
    in.signature.data[i] = uint8_t(i);

  auto bytes = P2P::serializeAuth(in);
  ASSERT_EQ(bytes.size(), 96u)
      << "AuthMessage wire size is fixed: 32-byte pubkey + 64-byte sig";

  AuthMessage out;
  ASSERT_TRUE(P2P::deserializeAuth(bytes.data(), bytes.size(), out));

  EXPECT_EQ(out.pubkey, in.pubkey);
  EXPECT_EQ(out.signature, in.signature);
}

TEST(Node_AuthMessage, DeserializeRejectsShortInput)
{
  AuthMessage out;
  std::vector<uint8_t> short_buf(95, 0);
  EXPECT_FALSE(P2P::deserializeAuth(short_buf.data(), short_buf.size(), out));
}

TEST(Node_AuthMessage, DeserializeRejectsLongInput)
{
  AuthMessage out;
  std::vector<uint8_t> long_buf(97, 0);
  EXPECT_FALSE(P2P::deserializeAuth(long_buf.data(), long_buf.size(), out));
}

TEST(Node_AuthMessage, DeserializeRejectsEmptyInput)
{
  AuthMessage out;
  EXPECT_FALSE(P2P::deserializeAuth(nullptr, 0, out));
}

// ============================================================================
//  Challenge
// ============================================================================

TEST(Node_AuthChallenge, Deterministic)
{
  auto kp = deterministicKey(0x01);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey);
  auto b = P2P::computeAuthChallenge(111, 222, kp.publicKey);
  EXPECT_EQ(a, b);
}

TEST(Node_AuthChallenge, DependsOnLocalNonce)
{
  auto kp = deterministicKey(0x01);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey);
  auto b = P2P::computeAuthChallenge(112, 222, kp.publicKey);
  EXPECT_NE(a, b) << "challenge must change when localNonce changes";
}

TEST(Node_AuthChallenge, DependsOnRemoteNonce)
{
  auto kp = deterministicKey(0x01);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey);
  auto b = P2P::computeAuthChallenge(111, 223, kp.publicKey);
  EXPECT_NE(a, b) << "challenge must change when remoteNonce changes";
}

TEST(Node_AuthChallenge, DependsOnPubkey)
{
  auto kp1 = deterministicKey(0x01);
  auto kp2 = deterministicKey(0x02);
  auto a = P2P::computeAuthChallenge(111, 222, kp1.publicKey);
  auto b = P2P::computeAuthChallenge(111, 222, kp2.publicKey);
  EXPECT_NE(a, b) << "challenge must change when pubkey changes";
}

TEST(Node_AuthChallenge, SwappedNoncesProduceDifferentChallenge)
{
  // localNonce and remoteNonce are not symmetric — the order matters.
  // If they were symmetric, a signature produced in one direction
  // would verify in the other, which is a replay vector.
  auto kp = deterministicKey(0x01);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey);
  auto b = P2P::computeAuthChallenge(222, 111, kp.publicKey);
  EXPECT_NE(a, b) << "challenge must not be symmetric in the two nonces";
}

// ============================================================================
//  Signature verification
// ============================================================================

TEST(Node_AuthSignature, ValidSignatureVerifies)
{
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, localNonce, remoteNonce);
  auto challenge = P2P::computeAuthChallenge(localNonce, remoteNonce, a.pubkey);

  EXPECT_TRUE(Crypto::verify(challenge, a.pubkey, a.signature));
}

TEST(Node_AuthSignature, WrongLocalNonceFailsVerification)
{
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, localNonce, remoteNonce);

  // Attacker replays the signature with a different local nonce — as
  // would happen if this Auth message were captured from an earlier
  // session and replayed against a new one.
  auto wrongChallenge =
      P2P::computeAuthChallenge(localNonce + 1, remoteNonce, a.pubkey);

  EXPECT_FALSE(Crypto::verify(wrongChallenge, a.pubkey, a.signature));
}

TEST(Node_AuthSignature, WrongRemoteNonceFailsVerification)
{
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, localNonce, remoteNonce);

  auto wrongChallenge =
      P2P::computeAuthChallenge(localNonce, remoteNonce + 1, a.pubkey);

  EXPECT_FALSE(Crypto::verify(wrongChallenge, a.pubkey, a.signature));
}

TEST(Node_AuthSignature, WrongPubkeyFailsVerification)
{
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, localNonce, remoteNonce);
  auto other = deterministicKey(0x20);

  auto challenge = P2P::computeAuthChallenge(localNonce, remoteNonce, other.publicKey);
  EXPECT_FALSE(Crypto::verify(challenge, other.publicKey, a.signature));
}

TEST(AuthSignature, NullPubkeyRejectedByVerify)
{
  // Crypto::verify now rejects null inputs directly. Before this,
  // the primitive returned true for (non-zero msg, null pk, null
  // sig) — the curve equation is trivially satisfied for the
  // identity element. Node::verifyPeerAuth guarded against this
  // with an explicit isNull() check; the primitive-level fix makes
  // that guard redundant (but it stays as defense in depth).
  Crypto::PublicKey null_pk{};
  Crypto::Signature null_sig{};

  auto challenge = P2P::computeAuthChallenge(1, 2, null_pk);

  EXPECT_FALSE(Crypto::verify(challenge, null_pk, null_sig))
      << "Crypto::verify must reject null pubkey";
}

TEST(AuthChallenge, BothSidesComputeSameChallenge)
{
  // The challenge must be identical from the initiator's perspective
  // and the responder's perspective. If it isn't, the signature
  // made by one side won't verify on the other — which is exactly
  // what happens when each side uses its own "localNonce" without
  // a canonical ordering.

  const uint64_t initiator_nonce = 0x1111111111111111ULL;
  const uint64_t responder_nonce = 0x2222222222222222ULL;

  auto kp = deterministicKey(0x42);

  // Initiator's view: my nonce is initiator_nonce, theirs is responder_nonce.
  auto from_initiator = P2P::orderNonces(
      PeerDirection::Outbound,
      /*my_nonce=*/initiator_nonce,
      /*their_nonce=*/responder_nonce);
  auto challenge_i = P2P::computeAuthChallenge(from_initiator, kp.publicKey);

  // Responder's view: my nonce is responder_nonce, theirs is initiator_nonce.
  auto from_responder = P2P::orderNonces(
      PeerDirection::Inbound,
      /*my_nonce=*/responder_nonce,
      /*their_nonce=*/initiator_nonce);
  auto challenge_r = P2P::computeAuthChallenge(from_responder, kp.publicKey);

  EXPECT_EQ(challenge_i, challenge_r)
      << "challenge must be identical from both sides' perspectives; "
         "if this fails, a signature made by one side won't verify on "
         "the other, and every auth exchange will fail";

  // Sanity: the challenge must actually depend on both nonces.
  auto wrong_order = P2P::AuthNonces{responder_nonce, initiator_nonce};
  auto challenge_wrong = P2P::computeAuthChallenge(wrong_order, kp.publicKey);
  EXPECT_NE(challenge_i, challenge_wrong)
      << "swapping initiator and responder must change the challenge; "
         "otherwise a signature from the initiator could be replayed "
         "by the responder";
}