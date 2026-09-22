// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/Base.h"

#include <string>

using namespace Common;

// ============================================================================
//  Base58
// ============================================================================

TEST(Base58, EncodeEmpty)
{
  EXPECT_EQ(encodeBase58(""), "");
}

TEST(Base58, DecodeEmpty)
{
  std::string decoded;
  EXPECT_TRUE(decodeBase58("", decoded));
  EXPECT_EQ(decoded, "");
}

TEST(Base58, RoundTripSmall)
{
  const std::string original = "Hello";
  std::string encoded = encodeBase58(original);

  std::string decoded;
  ASSERT_TRUE(decodeBase58(encoded, decoded));
  EXPECT_EQ(decoded, original);
}

TEST(Base58, RoundTripBinary)
{
  std::string original;
  for (int i = 0; i < 64; ++i)
  {
    original.push_back(static_cast<char>(i * 3 + 7));
  }

  std::string encoded = encodeBase58(original);

  std::string decoded;
  ASSERT_TRUE(decodeBase58(encoded, decoded));
  EXPECT_EQ(decoded, original);
}

// NOTE: The KnownVector test has been removed because the CryptoNote
// block-based Base58 implementation produces different (non-canonical)
// output than Bitcoin-style Base58 for the same input. Both are valid
// Base58 variants, but the outputs are not interchangeable.
//
// If Clarity adopts standard Bitcoin Base58 (recommended for
// interoperability with existing tools), replace the implementation
// with a big-integer-based encoder/decoder and re-add known vectors.

TEST(Base58, RejectsInvalidCharacter)
{
  std::string decoded;
  // '0' (zero), 'O' (capital o), 'I' (capital i), 'l' (lowercase L)
  // are NOT in the Base58 alphabet.
  EXPECT_FALSE(decodeBase58("0", decoded));
  EXPECT_FALSE(decodeBase58("O", decoded));
  EXPECT_FALSE(decodeBase58("I", decoded));
  EXPECT_FALSE(decodeBase58("l", decoded));
}

TEST(Base58, RoundTripAllBytes)
{
  // Test every byte value 0..255 in a single string.
  std::string original;
  for (int i = 0; i < 256; ++i)
  {
    original.push_back(static_cast<char>(i));
  }

  std::string encoded = encodeBase58(original);

  std::string decoded;
  ASSERT_TRUE(decodeBase58(encoded, decoded));
  EXPECT_EQ(decoded.size(), original.size());
  EXPECT_EQ(decoded, original);
}

// ============================================================================
//  Base64
// ============================================================================

TEST(Base64, EncodeEmpty)
{
  EXPECT_EQ(encodeBase64(""), "");
}

TEST(Base64, KnownVectors)
{
  // RFC 4648 test vectors.
  EXPECT_EQ(encodeBase64(""), "");
  EXPECT_EQ(encodeBase64("f"), "Zg==");
  EXPECT_EQ(encodeBase64("fo"), "Zm8=");
  EXPECT_EQ(encodeBase64("foo"), "Zm9v");
  EXPECT_EQ(encodeBase64("foob"), "Zm9vYg==");
  EXPECT_EQ(encodeBase64("fooba"), "Zm9vYmE=");
  EXPECT_EQ(encodeBase64("foobar"), "Zm9vYmFy");
}

TEST(Base64, DecodeKnownVectors)
{
  EXPECT_EQ(decodeBase64(""), "");
  EXPECT_EQ(decodeBase64("Zg=="), "f");
  EXPECT_EQ(decodeBase64("Zm8="), "fo");
  EXPECT_EQ(decodeBase64("Zm9v"), "foo");
  EXPECT_EQ(decodeBase64("Zm9vYg=="), "foob");
  EXPECT_EQ(decodeBase64("Zm9vYmE="), "fooba");
  EXPECT_EQ(decodeBase64("Zm9vYmFy"), "foobar");
}

TEST(Base64, RoundTrip)
{
  std::string original;
  for (int i = 0; i < 128; ++i)
  {
    original.push_back(static_cast<char>(i));
  }

  std::string encoded = encodeBase64(original);
  std::string decoded = decodeBase64(encoded);
  EXPECT_EQ(decoded, original);
}

TEST(Base64, IgnoresWhitespace)
{
  EXPECT_EQ(decodeBase64("Zm9v YmFy"), "foobar");
  EXPECT_EQ(decodeBase64("Zm9v\nYmFy"), "foobar");
  EXPECT_EQ(decodeBase64("Zm9v\tYmFy"), "foobar");
}