// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <gtest/gtest.h>

#include "Crypto/Chacha20Poly1305.h"

using namespace Crypto;

TEST(ChaChaPoly1305, RoundTrip)
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

TEST(ChaChaPoly1305, TamperedCiphertextRejected)
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

TEST(ChaChaPoly1305, TamperedMacRejected)
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

TEST(ChaChaPoly1305, DifferentNonceDifferentCiphertext)
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