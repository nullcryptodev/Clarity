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
#include "Crypto/X25519.h"

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

  // A deterministic-looking ephemeral public key. Not a real X25519
  // point (no scalar multiplication involved), but the codec and
  // challenge tests don't care — they exercise the byte-level
  // handling, not the curve. Session-key tests that need a real
  // ephemeral key use Crypto::generateX25519KeyPair() directly.
  Crypto::PublicKey deterministicEphemeral(uint8_t seed)
  {
    Crypto::PublicKey pk;
    for (size_t i = 0; i < pk.data.size(); ++i)
      pk.data[i] = uint8_t(seed + i);
    return pk;
  }

  AuthMessage makeAuth(uint8_t seed,
                       uint8_t ephSeed,
                       uint64_t localNonce,
                       uint64_t remoteNonce)
  {
    auto kp = deterministicKey(seed);
    auto eph = deterministicEphemeral(ephSeed);
    AuthMessage a;
    a.pubkey = kp.publicKey;
    a.ephemeralPubkey = eph;
    auto challenge = P2P::computeAuthChallenge(localNonce, remoteNonce,
                                               kp.publicKey, eph);
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
  auto eph = deterministicEphemeral(0x99);

  AuthMessage in;
  in.pubkey = kp.publicKey;
  in.ephemeralPubkey = eph;
  for (size_t i = 0; i < in.signature.data.size(); ++i)
    in.signature.data[i] = uint8_t(i);

  auto bytes = P2P::serializeAuth(in);
  ASSERT_EQ(bytes.size(), 128u)
      << "AuthMessage wire size is fixed: 32-byte pubkey + 32-byte "
         "ephemeral pubkey + 64-byte sig";

  AuthMessage out;
  ASSERT_TRUE(P2P::deserializeAuth(bytes.data(), bytes.size(), out));

  EXPECT_EQ(out.pubkey, in.pubkey);
  EXPECT_EQ(out.ephemeralPubkey, in.ephemeralPubkey);
  EXPECT_EQ(out.signature, in.signature);
}

TEST(Node_AuthMessage, DeserializeRejectsOld96ByteFormat)
{
  // The pre-encryption format. A peer running the old code would send
  // 96 bytes; we must reject it. This is part of the hard cutover
  // described in P2P-ENCRYPTION.md §9.
  AuthMessage out;
  std::vector<uint8_t> old(96, 0);
  EXPECT_FALSE(P2P::deserializeAuth(old.data(), old.size(), out));
}

TEST(Node_AuthMessage, DeserializeRejectsShortInput)
{
  AuthMessage out;
  std::vector<uint8_t> short_buf(127, 0);
  EXPECT_FALSE(P2P::deserializeAuth(short_buf.data(), short_buf.size(), out));
}

TEST(Node_AuthMessage, DeserializeRejectsLongInput)
{
  AuthMessage out;
  std::vector<uint8_t> long_buf(129, 0);
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
  auto eph = deterministicEphemeral(0x02);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey, eph);
  auto b = P2P::computeAuthChallenge(111, 222, kp.publicKey, eph);
  EXPECT_EQ(a, b);
}

TEST(Node_AuthChallenge, DependsOnLocalNonce)
{
  auto kp = deterministicKey(0x01);
  auto eph = deterministicEphemeral(0x02);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey, eph);
  auto b = P2P::computeAuthChallenge(112, 222, kp.publicKey, eph);
  EXPECT_NE(a, b) << "challenge must change when localNonce changes";
}

TEST(Node_AuthChallenge, DependsOnRemoteNonce)
{
  auto kp = deterministicKey(0x01);
  auto eph = deterministicEphemeral(0x02);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey, eph);
  auto b = P2P::computeAuthChallenge(111, 223, kp.publicKey, eph);
  EXPECT_NE(a, b) << "challenge must change when remoteNonce changes";
}

TEST(Node_AuthChallenge, DependsOnIdentityPubkey)
{
  auto kp1 = deterministicKey(0x01);
  auto kp2 = deterministicKey(0x03);
  auto eph = deterministicEphemeral(0x02);
  auto a = P2P::computeAuthChallenge(111, 222, kp1.publicKey, eph);
  auto b = P2P::computeAuthChallenge(111, 222, kp2.publicKey, eph);
  EXPECT_NE(a, b) << "challenge must change when identity pubkey changes";
}

TEST(Node_AuthChallenge, DependsOnEphemeralPubkey)
{
  // The whole point of extending the challenge in step 3: a MITM
  // cannot substitute the ephemeral key without invalidating the
  // signature.
  auto kp = deterministicKey(0x01);
  auto eph1 = deterministicEphemeral(0x02);
  auto eph2 = deterministicEphemeral(0x04);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey, eph1);
  auto b = P2P::computeAuthChallenge(111, 222, kp.publicKey, eph2);
  EXPECT_NE(a, b) << "challenge must change when ephemeral pubkey changes";
}

TEST(Node_AuthChallenge, SwappedNoncesProduceDifferentChallenge)
{
  auto kp = deterministicKey(0x01);
  auto eph = deterministicEphemeral(0x02);
  auto a = P2P::computeAuthChallenge(111, 222, kp.publicKey, eph);
  auto b = P2P::computeAuthChallenge(222, 111, kp.publicKey, eph);
  EXPECT_NE(a, b) << "challenge must not be symmetric in the two nonces";
}

// ============================================================================
//  Signature verification
// ============================================================================

TEST(Node_AuthSignature, ValidSignatureVerifies)
{
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, 0x20, localNonce, remoteNonce);
  auto challenge = P2P::computeAuthChallenge(localNonce, remoteNonce,
                                             a.pubkey, a.ephemeralPubkey);

  EXPECT_TRUE(Crypto::verify(challenge, a.pubkey, a.signature));
}

TEST(Node_AuthSignature, WrongLocalNonceFailsVerification)
{
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, 0x20, localNonce, remoteNonce);

  auto wrongChallenge = P2P::computeAuthChallenge(
      localNonce + 1, remoteNonce, a.pubkey, a.ephemeralPubkey);

  EXPECT_FALSE(Crypto::verify(wrongChallenge, a.pubkey, a.signature));
}

TEST(Node_AuthSignature, WrongRemoteNonceFailsVerification)
{
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, 0x20, localNonce, remoteNonce);

  auto wrongChallenge = P2P::computeAuthChallenge(
      localNonce, remoteNonce + 1, a.pubkey, a.ephemeralPubkey);

  EXPECT_FALSE(Crypto::verify(wrongChallenge, a.pubkey, a.signature));
}

TEST(Node_AuthSignature, WrongEphemeralPubkeyFailsVerification)
{
  // The MITM case: swap the ephemeral key, keep the signature. The
  // signature was made over the original ephemeral key, so it fails.
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, 0x20, localNonce, remoteNonce);
  auto substitutedEphemeral = deterministicEphemeral(0xFF);

  auto wrongChallenge = P2P::computeAuthChallenge(
      localNonce, remoteNonce, a.pubkey, substitutedEphemeral);

  EXPECT_FALSE(Crypto::verify(wrongChallenge, a.pubkey, a.signature));
}

TEST(Node_AuthSignature, WrongPubkeyFailsVerification)
{
  const uint64_t localNonce = 0xAABBCCDD11223344ULL;
  const uint64_t remoteNonce = 0x1122334455667788ULL;

  auto a = makeAuth(0x10, 0x20, localNonce, remoteNonce);
  auto other = deterministicKey(0x20);

  auto challenge = P2P::computeAuthChallenge(
      localNonce, remoteNonce, other.publicKey, a.ephemeralPubkey);
  EXPECT_FALSE(Crypto::verify(challenge, other.publicKey, a.signature));
}

TEST(Node_AuthSignature, NullPubkeyRejectedByVerify)
{
  Crypto::PublicKey null_pk{};
  Crypto::PublicKey null_eph{};
  Crypto::Signature null_sig{};

  auto challenge = P2P::computeAuthChallenge(1, 2, null_pk, null_eph);

  EXPECT_FALSE(Crypto::verify(challenge, null_pk, null_sig))
      << "Crypto::verify must reject null pubkey";
}

// ============================================================================
//  Both-sides agreement
// ============================================================================

TEST(Node_AuthChallenge, BothSidesComputeSameChallenge)
{
  const uint64_t initiator_nonce = 0x1111111111111111ULL;
  const uint64_t responder_nonce = 0x2222222222222222ULL;

  auto kp = deterministicKey(0x42);
  auto eph = deterministicEphemeral(0x99);

  // Initiator's view.
  auto from_initiator = P2P::orderNonces(
      PeerDirection::Outbound,
      /*my_nonce=*/initiator_nonce,
      /*their_nonce=*/responder_nonce);
  auto challenge_i = P2P::computeAuthChallenge(from_initiator,
                                               kp.publicKey, eph);

  // Responder's view.
  auto from_responder = P2P::orderNonces(
      PeerDirection::Inbound,
      /*my_nonce=*/responder_nonce,
      /*their_nonce=*/initiator_nonce);
  auto challenge_r = P2P::computeAuthChallenge(from_responder,
                                               kp.publicKey, eph);

  EXPECT_EQ(challenge_i, challenge_r)
      << "challenge must be identical from both sides' perspectives";

  // Sanity: swapping the roles must change the challenge.
  auto wrong_order = P2P::AuthNonces{responder_nonce, initiator_nonce};
  auto challenge_wrong = P2P::computeAuthChallenge(wrong_order,
                                                   kp.publicKey, eph);
  EXPECT_NE(challenge_i, challenge_wrong);
}