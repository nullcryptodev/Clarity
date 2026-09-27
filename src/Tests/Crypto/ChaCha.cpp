// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Chacha20Poly1305.h"

using namespace Crypto;
using namespace Tests;

//  XChaCha20-Poly1305 AEAD tests.
//
//  Coverage:
//    - basic round-trip with no AAD
//    - tampering rejection (ciphertext, MAC)
//    - nonce uniqueness effect on ciphertext
//    - AAD round-trip (16-byte, 17-byte, and keystore-length 17 bytes)
//    - AAD mismatch rejection
//    - AAD length mismatch rejection
//    - keystore parameter shape (64-byte plaintext, std::vector storage)
//
//  Note: an earlier version of this file contained a test that
//  hardcoded ciphertext bytes captured from a keystore debug run.
//  That test was removed because the values are only valid for one
//  specific random-salt run; they can never match a fresh keystore.

TEST(Crypto_ChaChaPoly1305, RoundTrip)
{
  // Fixed key + nonce for determinism.
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};
  key[0] = 0x42;
  nonce[0] = 0xAB;

  const char *plaintext = "The quick brown fox jumps over the lazy dog";
  size_t len = std::strlen(plaintext);

  uint8_t ciphertext[64];
  uint8_t mac[16];

  // Encrypt.
  EXPECT_TRUE(aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
                          nullptr, 0, key, nonce, ciphertext, mac));

  // Ciphertext should not equal plaintext.
  EXPECT_NE(std::memcmp(ciphertext, plaintext, len), 0);

  // Decrypt.
  uint8_t decrypted[64];
  EXPECT_TRUE(aeadDecrypt(ciphertext, len, nullptr, 0,
                          key, nonce, mac, decrypted));

  // Recovered plaintext should match.
  EXPECT_EQ(std::memcmp(decrypted, plaintext, len), 0);
}

TEST(Crypto_ChaChaPoly1305, TamperedCiphertextRejected)
{
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};

  const char *plaintext = "hello world";
  size_t len = std::strlen(plaintext);

  uint8_t ciphertext[32];
  uint8_t mac[16];
  aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
              nullptr, 0, key, nonce, ciphertext, mac);

  ciphertext[0] ^= 0xFF;

  uint8_t decrypted[32];
  EXPECT_FALSE(aeadDecrypt(ciphertext, len, nullptr, 0,
                           key, nonce, mac, decrypted));
}

TEST(Crypto_ChaChaPoly1305, TamperedMacRejected)
{
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};

  const char *plaintext = "hello world";
  size_t len = std::strlen(plaintext);

  uint8_t ciphertext[32];
  uint8_t mac[16];
  aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
              nullptr, 0, key, nonce, ciphertext, mac);

  mac[0] ^= 0xFF;

  uint8_t decrypted[32];
  EXPECT_FALSE(aeadDecrypt(ciphertext, len, nullptr, 0,
                           key, nonce, mac, decrypted));
}

TEST(Crypto_ChaChaPoly1305, DifferentNonceDifferentCiphertext)
{
  uint8_t key[32] = {0};

  const char *plaintext = "hello world";
  size_t len = std::strlen(plaintext);

  uint8_t nonce1[24] = {0};
  uint8_t nonce2[24] = {0};
  nonce1[0] = 1;
  nonce2[0] = 2;

  uint8_t ct1[32], ct2[32];
  uint8_t mac1[16], mac2[16];

  aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
              nullptr, 0, key, nonce1, ct1, mac1);
  aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
              nullptr, 0, key, nonce2, ct2, mac2);

  EXPECT_NE(std::memcmp(ct1, ct2, len), 0);
}

//  Round trip with non-empty AAD.
//
//  This is the exact shape the EncryptedKeyStore uses. If this
//  fails while the empty-AAD RoundTrip above passes, the bug is
//  in how the implementation handles AAD.

TEST(Crypto_ChaChaPoly1305, RoundTripWithAad)
{
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};
  key[0] = 0x42;
  nonce[0] = 0xAB;

  const char *plaintext = "The quick brown fox jumps over the lazy dog";
  size_t len = std::strlen(plaintext);

  const char *aad = "clrty-keystore-v1";
  size_t aad_len = std::strlen(aad);

  uint8_t ciphertext[64];
  uint8_t mac[16];

  EXPECT_TRUE(aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
                          reinterpret_cast<const uint8_t *>(aad), aad_len,
                          key, nonce, ciphertext, mac));

  uint8_t decrypted[64];
  EXPECT_TRUE(aeadDecrypt(ciphertext, len,
                          reinterpret_cast<const uint8_t *>(aad), aad_len,
                          key, nonce, mac, decrypted));

  EXPECT_EQ(std::memcmp(decrypted, plaintext, len), 0);
}

//  Wrong AAD must fail authentication.

TEST(Crypto_ChaChaPoly1305, WrongAadRejected)
{
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};

  const char *plaintext = "hello world";
  size_t len = std::strlen(plaintext);

  const char *aad_enc = "correct-aad";
  const char *aad_dec = "wrong-aad-xx"; // same length, different content

  uint8_t ciphertext[64];
  uint8_t mac[16];
  aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
              reinterpret_cast<const uint8_t *>(aad_enc), std::strlen(aad_enc),
              key, nonce, ciphertext, mac);

  uint8_t decrypted[64];
  EXPECT_FALSE(aeadDecrypt(ciphertext, len,
                           reinterpret_cast<const uint8_t *>(aad_dec),
                           std::strlen(aad_dec),
                           key, nonce, mac, decrypted));
}

//  AAD length mismatch must also fail.

TEST(Crypto_ChaChaPoly1305, AadLengthMismatchRejected)
{
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};

  const char *plaintext = "hello world";
  size_t len = std::strlen(plaintext);

  const char *aad_enc = "some-aad";
  const char *aad_dec = "some-aad-extra";

  uint8_t ciphertext[64];
  uint8_t mac[16];
  aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
              reinterpret_cast<const uint8_t *>(aad_enc), std::strlen(aad_enc),
              key, nonce, ciphertext, mac);

  uint8_t decrypted[64];
  EXPECT_FALSE(aeadDecrypt(ciphertext, len,
                           reinterpret_cast<const uint8_t *>(aad_dec),
                           std::strlen(aad_dec),
                           key, nonce, mac, decrypted));
}

//  AAD of exactly 16 bytes (single Poly1305 block) round trip.

TEST(Crypto_ChaChaPoly1305, RoundTripAad16Bytes)
{
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};

  const char *plaintext = "hello world";
  size_t len = std::strlen(plaintext);

  uint8_t aad[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

  uint8_t ciphertext[64];
  uint8_t mac[16];
  EXPECT_TRUE(aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
                          aad, 16, key, nonce, ciphertext, mac));

  uint8_t decrypted[64];
  EXPECT_TRUE(aeadDecrypt(ciphertext, len, aad, 16,
                          key, nonce, mac, decrypted));
  EXPECT_EQ(std::memcmp(decrypted, plaintext, len), 0);
}

//  AAD that's NOT a multiple of 16 (Poly1305 padding case).

TEST(Crypto_ChaChaPoly1305, RoundTripAad17Bytes)
{
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};

  const char *plaintext = "hello world";
  size_t len = std::strlen(plaintext);

  uint8_t aad[17] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};

  uint8_t ciphertext[64];
  uint8_t mac[16];
  EXPECT_TRUE(aeadEncrypt(reinterpret_cast<const uint8_t *>(plaintext), len,
                          aad, 17, key, nonce, ciphertext, mac));

  uint8_t decrypted[64];
  EXPECT_TRUE(aeadDecrypt(ciphertext, len, aad, 17,
                          key, nonce, mac, decrypted));
  EXPECT_EQ(std::memcmp(decrypted, plaintext, len), 0);
}

//  Keystore parameter shape with locally-generated key/nonce.
//
//  This does not use hardcoded bytes; it round-trips through a
//  std::vector-based ciphertext buffer with a 64-byte plaintext
//  and a 17-byte AAD, matching EncryptedKeyStore's usage.

TEST(Crypto_ChaChaPoly1305, KeystoreShapeLocalRoundTrip)
{
  uint8_t key[32] = {0};
  uint8_t nonce[24] = {0};
  for (size_t i = 0; i < 32; ++i)
    key[i] = uint8_t(i * 7 + 1);
  for (size_t i = 0; i < 24; ++i)
    nonce[i] = uint8_t(i * 11 + 3);

  const char *aad_str = "clrty-keystore-v1";
  const uint8_t *aad = reinterpret_cast<const uint8_t *>(aad_str);
  const size_t aad_len = std::strlen(aad_str);

  std::vector<uint8_t> plaintext(64);
  for (size_t i = 0; i < 64; ++i)
    plaintext[i] = uint8_t(i);

  std::vector<uint8_t> ciphertext(64);
  std::vector<uint8_t> mac(16);

  EXPECT_TRUE(aeadEncrypt(plaintext.data(), plaintext.size(),
                          aad, aad_len,
                          key, nonce,
                          ciphertext.data(), mac.data()));

  std::vector<uint8_t> decrypted(64);
  EXPECT_TRUE(aeadDecrypt(ciphertext.data(), ciphertext.size(),
                          aad, aad_len,
                          key, nonce,
                          mac.data(), decrypted.data()));

  EXPECT_EQ(decrypted, plaintext);
}