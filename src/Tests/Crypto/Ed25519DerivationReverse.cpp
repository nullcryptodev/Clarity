// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"

#include <cstring>
#include <vector>

namespace
{
  //  Build a keypair whose secret half is the *scalar* (not the
  //  seed). Functions that feed their secret-half input to
  //  sc_check (generateKeyDerivation, deriveSubaddress) require
  //  this form. generateKeyPairFromSeed produces the seed form,
  //  which those functions correctly reject.
  Crypto::KeyPair makeScalarKeypairFromBytes(
      const std::vector<uint8_t> &bytes)
  {
    Crypto::SecretKey seed;
    std::memcpy(seed.data.data(), bytes.data(), 32);
    return Crypto::generateScalarKeyPairFromSeed(seed);
  }

  //  Build a keypair via the seed form (secretKey == seed). Suitable
  //  for callers that only use publicKey; not suitable for
  //  generateKeyDerivation's viewSecretKey or deriveSubaddress's
  //  view_priv, both of which check sc_check on the secret half.
  Crypto::KeyPair makeSeedKeypairFromBytes(
      const std::vector<uint8_t> &bytes)
  {
    Crypto::SecretKey seed;
    std::memcpy(seed.data.data(), bytes.data(), 32);
    return Crypto::generateKeyPairFromSeed(seed);
  }
} // anonymous namespace

TEST(CryptoReverseDerivation, RoundTripsThroughDerivePublicKey)
{
  //  Build (spend, view) and a tx pubkey.
  //
  //    spend_pub: only its publicKey is used (as the point A in
  //               derivePublicKey's "A + 8*s*G"); seed form is
  //               fine.
  //    view_priv: its secretKey is passed to generateKeyDerivation,
  //               which calls sc_check. Must be the scalar form.
  //    tx_pub:    only its publicKey is used; seed form is fine.
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);
  const std::vector<uint8_t> tx_seed(32, 0x30);

  auto spend_kp = makeSeedKeypairFromBytes(spend_seed);
  auto view_kp = makeScalarKeypairFromBytes(view_seed);
  auto tx_kp = makeSeedKeypairFromBytes(tx_seed);

  Crypto::KeyDerivation derivation;
  ASSERT_TRUE(Crypto::generateKeyDerivation(
      tx_kp.publicKey, view_kp.secretKey, derivation));

  for (size_t index = 0; index < 8; ++index)
  {
    Crypto::PublicKey expected;
    ASSERT_TRUE(Crypto::derivePublicKey(
        derivation, index, spend_kp.publicKey, expected));

    Crypto::PublicKey candidate;
    ASSERT_TRUE(Crypto::reverseDeriveCandidate(
        expected, derivation, index, candidate));

    EXPECT_EQ(candidate, spend_kp.publicKey)
        << "index " << index << ": reverse of derived pubkey "
        << "did not return the original spend_pub";
  }
}

TEST(CryptoReverseDerivation, NullCurvePointProducesNonMatchingCandidate)
{
  //  A null P (all zeros) is a valid curve point in ref10's
  //  encoding — it decodes to a specific curve point, not to "the
  //  invalid input". So reverseDeriveCandidate correctly accepts
  //  it and computes a candidate.
  //
  //  The property that matters for the scanner is not "reject null
  //  P" (that would be the scanner's job, and null P is not a
  //  well-formed on-chain output anyway), but "a garbage P cannot
  //  cause the scanner to match a real subaddress." That is
  //  guaranteed by the arithmetic: the candidate is
  //  null_P - 8*s*G, which for null_P = a specific low-order
  //  point and a nondeterministic s is essentially never equal to
  //  any real spend pubkey.
  //
  //  We test: the function accepts the input, the candidate is
  //  deterministic, and it is not null (a real curve point, not
  //  the identity encoded as all-zeros).
  Crypto::KeyDerivation derivation;
  std::memset(derivation.data.data(), 0xAB, 32);

  Crypto::PublicKey null_P{};
  Crypto::PublicKey candidate;
  EXPECT_TRUE(Crypto::reverseDeriveCandidate(
      null_P, derivation, 0, candidate));

  Crypto::PublicKey candidate2;
  EXPECT_TRUE(Crypto::reverseDeriveCandidate(
      null_P, derivation, 0, candidate2));
  EXPECT_EQ(candidate, candidate2);

  EXPECT_FALSE(candidate.isNull());
}

TEST(CryptoReverseDerivation, WrongIndexProducesDifferentCandidate)
{
  //  Reversing with the wrong index must not return the original
  //  spend_pub. Otherwise, a bug in the scanner's index bookkeeping
  //  would silently match deposits to the wrong subaddress.
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);
  const std::vector<uint8_t> tx_seed(32, 0x30);

  auto spend_kp = makeSeedKeypairFromBytes(spend_seed);
  auto view_kp = makeScalarKeypairFromBytes(view_seed);
  auto tx_kp = makeSeedKeypairFromBytes(tx_seed);

  Crypto::KeyDerivation derivation;
  ASSERT_TRUE(Crypto::generateKeyDerivation(
      tx_kp.publicKey, view_kp.secretKey, derivation));

  Crypto::PublicKey expected;
  ASSERT_TRUE(Crypto::derivePublicKey(
      derivation, 3, spend_kp.publicKey, expected));

  Crypto::PublicKey wrong_candidate;
  ASSERT_TRUE(Crypto::reverseDeriveCandidate(
      expected, derivation, 4, wrong_candidate));

  EXPECT_NE(wrong_candidate, spend_kp.publicKey);
}

TEST(CryptoReverseDerivation, MatchesAcrossDifferentTxPubkeys)
{
  //  The property the scanner relies on: for each deposit tx's
  //  tx_pubkey, the derivation and P are both different, and the
  //  reverse of P against that tx's derivation gives back the same
  //  spend_pub. This is what makes a single subaddress set
  //  matchable against deposits from many different senders.
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);

  auto spend_kp = makeSeedKeypairFromBytes(spend_seed);
  auto view_kp = makeScalarKeypairFromBytes(view_seed);

  for (uint8_t tx_seed_byte = 1; tx_seed_byte <= 4; ++tx_seed_byte)
  {
    std::vector<uint8_t> tx_seed(32, tx_seed_byte);
    auto tx_kp = makeSeedKeypairFromBytes(tx_seed);

    Crypto::KeyDerivation derivation;
    ASSERT_TRUE(Crypto::generateKeyDerivation(
        tx_kp.publicKey, view_kp.secretKey, derivation));

    Crypto::PublicKey expected;
    ASSERT_TRUE(Crypto::derivePublicKey(
        derivation, 0, spend_kp.publicKey, expected));

    Crypto::PublicKey candidate;
    ASSERT_TRUE(Crypto::reverseDeriveCandidate(
        expected, derivation, 0, candidate));

    EXPECT_EQ(candidate, spend_kp.publicKey)
        << "tx_seed_byte = " << (int)tx_seed_byte;
  }
}

TEST(CryptoReverseDerivation, ScalarMultBaseMatchesDerivePublicKeyAdditive)
{
  //  derivePublicKey(derivation, i, A) computes A + 8*s*G. This
  //  test checks that our scalarMultBase + pointSubtract path
  //  produces the same value as the reverse: candidate equals
  //  the original spend_pub.
  const std::vector<uint8_t> spend_seed(32, 0x10);
  const std::vector<uint8_t> view_seed(32, 0x20);
  const std::vector<uint8_t> tx_seed(32, 0x30);

  auto spend_kp = makeSeedKeypairFromBytes(spend_seed);
  auto view_kp = makeScalarKeypairFromBytes(view_seed);
  auto tx_kp = makeSeedKeypairFromBytes(tx_seed);

  Crypto::KeyDerivation derivation;
  ASSERT_TRUE(Crypto::generateKeyDerivation(
      tx_kp.publicKey, view_kp.secretKey, derivation));

  Crypto::PublicKey expected;
  ASSERT_TRUE(Crypto::derivePublicKey(
      derivation, 7, spend_kp.publicKey, expected));

  Crypto::PublicKey candidate;
  ASSERT_TRUE(Crypto::reverseDeriveCandidate(
      expected, derivation, 7, candidate));

  EXPECT_EQ(candidate, spend_kp.publicKey);
}