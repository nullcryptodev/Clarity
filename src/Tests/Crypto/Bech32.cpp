// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Bech32.h"

using namespace Crypto;
using namespace Tests;

//  Bech32 / Bech32m tests.
//
//  Coverage:
//    - encode/decode round trip
//    - Bech32m vs Bech32 variant distinction
//    - invalid input rejection
//    - mixed case rejection
//    - 5-bit conversion round trip

//  Round trip

TEST(Crypto_Bech32, RoundTripBech32m)
{
  const auto payload = testPayload();
  const std::string encoded = bech32Encode("clrty", payload, Bech32Encoding::Bech32m);
  ASSERT_FALSE(encoded.empty());

  std::vector<uint8_t> decoded;
  std::string hrp;
  Bech32Encoding enc;
  const auto err = bech32Decode(encoded, decoded, hrp, enc);

  EXPECT_EQ(err, Bech32Error::Ok);
  EXPECT_EQ(enc, Bech32Encoding::Bech32m);
  EXPECT_EQ(hrp, "clrty");
  EXPECT_EQ(decoded, payload);
}

TEST(Crypto_Bech32, RoundTripBech32)
{
  const auto payload = testPayload();
  const std::string encoded = bech32Encode("clrty", payload, Bech32Encoding::Bech32);
  ASSERT_FALSE(encoded.empty());

  std::vector<uint8_t> decoded;
  std::string hrp;
  Bech32Encoding enc;
  const auto err = bech32Decode(encoded, decoded, hrp, enc);

  EXPECT_EQ(err, Bech32Error::Ok);
  EXPECT_EQ(enc, Bech32Encoding::Bech32);
  EXPECT_EQ(hrp, "clrty");
  EXPECT_EQ(decoded, payload);
}

//  The two checksum variants must produce distinct strings.

TEST(Crypto_Bech32, Bech32AndBech32mProduceDifferentStrings)
{
  const auto payload = testPayload();

  const std::string m = bech32Encode("clrty", payload, Bech32Encoding::Bech32m);
  const std::string b = bech32Encode("clrty", payload, Bech32Encoding::Bech32);

  ASSERT_FALSE(m.empty());
  ASSERT_FALSE(b.empty());
  EXPECT_NE(m, b);

  // Each decodes to its own variant.
  std::vector<uint8_t> data;
  std::string hrp;
  Bech32Encoding enc;

  ASSERT_EQ(bech32Decode(m, data, hrp, enc), Bech32Error::Ok);
  EXPECT_EQ(enc, Bech32Encoding::Bech32m);

  ASSERT_EQ(bech32Decode(b, data, hrp, enc), Bech32Error::Ok);
  EXPECT_EQ(enc, Bech32Encoding::Bech32);
}

//  Empty payload round trip

TEST(Crypto_Bech32, EmptyPayloadRoundTrip)
{
  const std::vector<uint8_t> empty;

  const std::string encoded = bech32Encode("clrty", empty, Bech32Encoding::Bech32m);
  ASSERT_FALSE(encoded.empty());

  std::vector<uint8_t> decoded;
  std::string hrp;
  Bech32Encoding enc;
  const auto err = bech32Decode(encoded, decoded, hrp, enc);

  EXPECT_EQ(err, Bech32Error::Ok);
  EXPECT_TRUE(decoded.empty());
  EXPECT_EQ(hrp, "clrty");
  EXPECT_EQ(enc, Bech32Encoding::Bech32m);
}

//  Invalid input

TEST(Crypto_Bech32, EmptyInputRejected)
{
  std::vector<uint8_t> data;
  std::string hrp;
  Bech32Encoding enc;
  EXPECT_EQ(bech32Decode("", data, hrp, enc), Bech32Error::Empty);
}

TEST(Crypto_Bech32, NoSeparatorRejected)
{
  std::vector<uint8_t> data;
  std::string hrp;
  Bech32Encoding enc;
  EXPECT_EQ(bech32Decode("no-separator-here", data, hrp, enc),
            Bech32Error::NoSeparator);
}

TEST(Crypto_Bech32, MixedCaseRejected)
{
  // Same string, but with a single character uppercased.
  const auto payload = testPayload();
  const std::string lower = bech32Encode("clrty", payload, Bech32Encoding::Bech32m);
  ASSERT_FALSE(lower.empty());

  // Uppercase one character in the middle.
  std::string mixed = lower;
  mixed[7] = char(std::toupper(static_cast<unsigned char>(mixed[7])));

  std::vector<uint8_t> data;
  std::string hrp;
  Bech32Encoding enc;
  EXPECT_EQ(bech32Decode(mixed, data, hrp, enc), Bech32Error::MixedCase);
}

TEST(Crypto_Bech32, UppercaseInputAccepted)
{
  const auto payload = testPayload();
  const std::string lower = bech32Encode("clrty", payload, Bech32Encoding::Bech32m);
  ASSERT_FALSE(lower.empty());

  std::string upper = lower;
  for (char &c : upper)
    if (c >= 'a' && c <= 'z')
      c = char(c - 'a' + 'A');

  std::vector<uint8_t> decoded_lower, decoded_upper;
  std::string hrp_lower, hrp_upper;
  Bech32Encoding enc_lower, enc_upper;

  ASSERT_EQ(bech32Decode(lower, decoded_lower, hrp_lower, enc_lower),
            Bech32Error::Ok);
  ASSERT_EQ(bech32Decode(upper, decoded_upper, hrp_upper, enc_upper),
            Bech32Error::Ok);

  EXPECT_EQ(decoded_lower, decoded_upper);
  EXPECT_EQ(hrp_lower, hrp_upper);
  EXPECT_EQ(enc_lower, enc_upper);
}

TEST(Crypto_Bech32, TamperedChecksumRejected)
{
  const auto payload = testPayload();
  std::string encoded = bech32Encode("clrty", payload, Bech32Encoding::Bech32m);
  ASSERT_FALSE(encoded.empty());

  // Flip the last character (part of the checksum).
  encoded.back() = (encoded.back() == 'q') ? 'p' : 'q';

  std::vector<uint8_t> data;
  std::string hrp;
  Bech32Encoding enc;
  EXPECT_EQ(bech32Decode(encoded, data, hrp, enc), Bech32Error::ChecksumMismatch);
}

TEST(Crypto_Bech32, TamperedDataRejected)
{
  const auto payload = testPayload();
  std::string encoded = bech32Encode("clrty", payload, Bech32Encoding::Bech32m);
  ASSERT_FALSE(encoded.empty());

  // Flip a data character (before the checksum).
  const size_t sep = encoded.find('1');
  ASSERT_NE(sep, std::string::npos);
  const size_t mid = sep + 3; // inside the data part
  encoded[mid] = (encoded[mid] == 'q') ? 'p' : 'q';

  std::vector<uint8_t> data;
  std::string hrp;
  Bech32Encoding enc;
  EXPECT_EQ(bech32Decode(encoded, data, hrp, enc), Bech32Error::ChecksumMismatch);
}

TEST(Crypto_Bech32, InvalidDataCharacterRejected)
{
  // 'b' is not in the Bech32 charset.
  std::vector<uint8_t> data;
  std::string hrp;
  Bech32Encoding enc;
  EXPECT_EQ(bech32Decode("clrty1bbbbbb", data, hrp, enc),
            Bech32Error::InvalidDataCharacter);
}

//  Encoder validation

TEST(Crypto_Bech32, EncodeRejectsEmptyHrp)
{
  const std::vector<uint8_t> payload = {0x00, 0x01};
  EXPECT_TRUE(bech32Encode("", payload, Bech32Encoding::Bech32m).empty());
}

TEST(Crypto_Bech32, EncodeRejectsOverlongHrp)
{
  const std::string hrp(84, 'a');
  const std::vector<uint8_t> payload = {0x00, 0x01};
  EXPECT_TRUE(bech32Encode(hrp, payload, Bech32Encoding::Bech32m).empty());
}

TEST(Crypto_Bech32, EncodeRejectsInvalidHrpCharacter)
{
  const std::vector<uint8_t> payload = {0x00, 0x01};
  EXPECT_TRUE(bech32Encode("bad hrp", payload, Bech32Encoding::Bech32m).empty());
}

TEST(Crypto_Bech32, EncodeRejectsResultTooLong)
{
  const std::string hrp(83, 'a');
  const std::vector<uint8_t> payload(60, 0x01);
  EXPECT_TRUE(bech32Encode(hrp, payload, Bech32Encoding::Bech32m).empty());
}

//  5-bit conversion

TEST(Crypto_Bech32, ConvertBitsRoundTrip)
{
  std::vector<uint8_t> input(256);
  for (int i = 0; i < 256; ++i)
    input[static_cast<size_t>(i)] = uint8_t(i);

  std::vector<uint8_t> as5;
  ASSERT_TRUE(convertBitsTo5(input.data(), input.size(), as5, /*pad=*/true));

  std::vector<uint8_t> back;
  ASSERT_TRUE(convertBitsFrom5(as5.data(), as5.size(), back, /*pad=*/true));

  ASSERT_GE(back.size(), input.size());
  back.resize(input.size());
  EXPECT_EQ(back, input);
}

TEST(Crypto_Bech32, ConvertBitsStrictRejectsNonzeroPadding)
{
  const std::vector<uint8_t> bad = {1, 0, 1};
  std::vector<uint8_t> out;
  EXPECT_FALSE(convertBitsFrom5(bad.data(), bad.size(), out, /*pad=*/false));
}