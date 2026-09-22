// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Ed25519.h"
#include "Crypto/Types.h"

extern "C"
{
#include "monocypher.h"
#include "monocypher-ed25519.h"
}

using namespace Crypto;
using namespace Tests;

// Raw Monocypher test, bypasses our wrapper entirely.
// If this test FAILS, the bug is in Monocypher (or the wrong version
// is linked). If it PASSES, the bug is in our wrapper.

TEST(Ed25519Raw, RFC8032_Test1_EmptyMessage)
{
  // RFC 8032 Test 1 vectors.
  uint8_t seed[32];
  ASSERT_TRUE(fromHex(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      seed, 32));

  uint8_t expected_pk[32];
  ASSERT_TRUE(fromHex(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      expected_pk, 32));

  uint8_t expected_sig[64];
  ASSERT_TRUE(fromHex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
      expected_sig, 64));

  // Direct Monocypher calls.
  uint8_t expanded_sk[64];
  uint8_t pk[32];
  crypto_ed25519_key_pair(expanded_sk, pk, seed);

  EXPECT_EQ(toHex(pk, 32), toHex(expected_pk, 32))
      << "Monocypher key derivation does not match RFC 8032";

  uint8_t sig[64];
  crypto_ed25519_sign(sig, expanded_sk, nullptr, 0);

  EXPECT_EQ(toHex(sig, 64), toHex(expected_sig, 64))
      << "Monocypher signing does not match RFC 8032";

  // Verify with Monocypher directly.
  int check = crypto_ed25519_check(sig, pk, nullptr, 0);
  EXPECT_EQ(check, 0) << "Monocypher verify rejects its own signature";
}

// RFC 8032 Test Vectors (via our wrapper)

TEST(Ed25519, RFC8032_Test1_EmptyMessage)
{
  SecretKey sk;
  PublicKey pk_expected;
  Signature sig_expected;

  ASSERT_TRUE(fromHex(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      sk.data.data(), 32));
  ASSERT_TRUE(fromHex(
      "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
      pk_expected.data.data(), 32));
  ASSERT_TRUE(fromHex(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
      "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
      sig_expected.data.data(), 64));

  PublicKey pk = derivePublicKey(sk);
  EXPECT_EQ(pk.toString(), pk_expected.toString());

  const uint8_t empty[1] = {0};
  Signature sig;
  sign(empty, 0, sk, sig);
  EXPECT_EQ(sig.toString(), sig_expected.toString());

  EXPECT_TRUE(verify(empty, 0, pk, sig));
}

TEST(Ed25519, RFC8032_Test2_OneByteMessage)
{
  SecretKey sk;
  PublicKey pk_expected;
  Signature sig_expected;

  ASSERT_TRUE(fromHex(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      sk.data.data(), 32));
  ASSERT_TRUE(fromHex(
      "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      pk_expected.data.data(), 32));
  ASSERT_TRUE(fromHex(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
      "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
      sig_expected.data.data(), 64));

  PublicKey pk = derivePublicKey(sk);
  EXPECT_EQ(pk.toString(), pk_expected.toString());

  uint8_t msg[1] = {0x72};
  Signature sig;
  sign(msg, 1, sk, sig);
  EXPECT_EQ(sig.toString(), sig_expected.toString());

  EXPECT_TRUE(verify(msg, 1, pk, sig));
}

TEST(Ed25519, RFC8032_Test3_TwoByteMessage)
{
  SecretKey sk;
  PublicKey pk_expected;
  Signature sig_expected;

  ASSERT_TRUE(fromHex(
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      sk.data.data(), 32));
  ASSERT_TRUE(fromHex(
      "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
      pk_expected.data.data(), 32));
  ASSERT_TRUE(fromHex(
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
      "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
      sig_expected.data.data(), 64));

  PublicKey pk = derivePublicKey(sk);
  EXPECT_EQ(pk.toString(), pk_expected.toString());

  uint8_t msg[2] = {0xaf, 0x82};
  Signature sig;
  sign(msg, 2, sk, sig);
  EXPECT_EQ(sig.toString(), sig_expected.toString());

  EXPECT_TRUE(verify(msg, 2, pk, sig));
}

// Round-trip

TEST(Ed25519, GenerateKeyPairIsValid)
{
  KeyPair kp = generateKeyPair();
  EXPECT_FALSE(kp.publicKey.isNull());
  EXPECT_FALSE(kp.secretKey.isNull());

  PublicKey derived = derivePublicKey(kp.secretKey);
  EXPECT_EQ(derived.toString(), kp.publicKey.toString());
}

TEST(Ed25519, DeterministicFromSeed)
{
  SecretKey seed;
  for (size_t i = 0; i < 32; ++i)
    seed.data[i] = static_cast<uint8_t>(i);

  KeyPair kp1 = generateKeyPairFromSeed(seed);
  KeyPair kp2 = generateKeyPairFromSeed(seed);

  EXPECT_EQ(kp1.publicKey.toString(), kp2.publicKey.toString());
  EXPECT_EQ(kp1.secretKey.toString(), kp2.secretKey.toString());
}

TEST(Ed25519, SignVerifyRoundTrip)
{
  KeyPair kp = generateKeyPair();

  const char *msg = "The quick brown fox jumps over the lazy dog";
  Signature sig = sign(reinterpret_cast<const uint8_t *>(msg),
                       std::strlen(msg), kp.secretKey);

  EXPECT_TRUE(verify(reinterpret_cast<const uint8_t *>(msg),
                     std::strlen(msg), kp.publicKey, sig));
}

TEST(Ed25519, VerifyRejectsTamperedSignature)
{
  KeyPair kp = generateKeyPair();

  const char *msg = "hello";
  Signature sig = sign(reinterpret_cast<const uint8_t *>(msg),
                       std::strlen(msg), kp.secretKey);

  sig.data[0] ^= 0xFF;

  EXPECT_FALSE(verify(reinterpret_cast<const uint8_t *>(msg),
                      std::strlen(msg), kp.publicKey, sig));
}

TEST(Ed25519, VerifyRejectsWrongMessage)
{
  KeyPair kp = generateKeyPair();

  const char *msg1 = "hello";
  const char *msg2 = "world";

  Signature sig = sign(reinterpret_cast<const uint8_t *>(msg1),
                       std::strlen(msg1), kp.secretKey);

  EXPECT_FALSE(verify(reinterpret_cast<const uint8_t *>(msg2),
                      std::strlen(msg2), kp.publicKey, sig));
}

TEST(Ed25519, VerifyRejectsWrongKey)
{
  KeyPair kp1 = generateKeyPair();
  KeyPair kp2 = generateKeyPair();

  const char *msg = "hello";
  Signature sig = sign(reinterpret_cast<const uint8_t *>(msg),
                       std::strlen(msg), kp1.secretKey);

  EXPECT_FALSE(verify(reinterpret_cast<const uint8_t *>(msg),
                      std::strlen(msg), kp2.publicKey, sig));
}