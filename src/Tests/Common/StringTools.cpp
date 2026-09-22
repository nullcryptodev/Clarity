// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/StringTools.h"

#include <vector>

using namespace Common;

TEST(Hex, ToHexEmpty)
{
  EXPECT_EQ(toHex(nullptr, 0), "");
}

TEST(Hex, ToHexSingleByte)
{
  uint8_t data[] = {0x00};
  EXPECT_EQ(toHex(data, 1), "00");

  uint8_t data2[] = {0xFF};
  EXPECT_EQ(toHex(data2, 1), "ff");

  uint8_t data3[] = {0xAB};
  EXPECT_EQ(toHex(data3, 1), "ab");
}

TEST(Hex, ToHexMultiByte)
{
  uint8_t data[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
  EXPECT_EQ(toHex(data, 8), "0123456789abcdef");
}

TEST(Hex, RoundTrip)
{
  uint8_t original[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33};
  std::string hex = toHex(original, 8);

  std::vector<uint8_t> decoded;
  ASSERT_TRUE(fromHex(hex, decoded));
  ASSERT_EQ(decoded.size(), 8);

  EXPECT_EQ(std::memcmp(decoded.data(), original, 8), 0);
}

TEST(Hex, FromHexUppercase)
{
  std::vector<uint8_t> data;
  ASSERT_TRUE(fromHex("DEADBEEF", data));
  ASSERT_EQ(data.size(), 4);

  EXPECT_EQ(data[0], 0xDE);
  EXPECT_EQ(data[1], 0xAD);
  EXPECT_EQ(data[2], 0xBE);
  EXPECT_EQ(data[3], 0xEF);
}

TEST(Hex, FromHexInvalidOddLength)
{
  std::vector<uint8_t> data;
  EXPECT_FALSE(fromHex("abc", data));
}

TEST(Hex, FromHexInvalidCharacter)
{
  std::vector<uint8_t> data;
  EXPECT_FALSE(fromHex("zz", data));
}

TEST(PodToHex, RoundTrip)
{
  uint32_t original = 0xDEADBEEF;
  std::string hex = podToHex(original);

  // toHex writes the bytes in memory order (little-endian on x86).
  // So "efbeadde" on little-endian, "deadbeef" on big-endian.
  EXPECT_EQ(hex.size(), 8);

  uint32_t decoded;
  ASSERT_TRUE(podFromHex(hex, decoded));
  EXPECT_EQ(decoded, original);
}

TEST(Strings, Extract)
{
  std::string text = "a,b,c";
  EXPECT_EQ(extract(text, ','), "a");
  EXPECT_EQ(extract(text, ','), "b");
  EXPECT_EQ(extract(text, ','), "c");
  EXPECT_EQ(text, "");
}

TEST(Strings, ExtractNoDelimiter)
{
  std::string text = "abc";
  EXPECT_EQ(extract(text, ','), "abc");
  EXPECT_EQ(text, "");
}

TEST(Strings, ExtractWithOffset)
{
  std::string text = "a,b,c";
  size_t offset = 0;

  EXPECT_EQ(extract(text, ',', offset), "a");
  EXPECT_EQ(offset, 2);
  EXPECT_EQ(extract(text, ',', offset), "b");
  EXPECT_EQ(offset, 4);
  EXPECT_EQ(extract(text, ',', offset), "c");
  EXPECT_EQ(offset, 5);
}

TEST(IP, AddressToString)
{
  // 192.168.1.1 = 0xC0A80101 in big-endian integer form
  // ipAddressToString expects ip in network byte order when stored as uint32.
  // This test depends on how the caller packs the address.
  // For a big-endian packed value:
  uint32_t ip = (192 << 24) | (168 << 16) | (1 << 8) | 1;
  EXPECT_EQ(ipAddressToString(ip), "192.168.1.1");
}

TEST(IP, ParseAndFormatRoundTrip)
{
  uint32_t ip = 0;
  uint32_t port = 0;
  EXPECT_TRUE(parseIpAddressAndPort(ip, port, "10.0.0.5:19444"));
  EXPECT_EQ(port, 19444);
  EXPECT_EQ(ipAddressToString(ip), "10.0.0.5");
}

TEST(Time, FormatInterval)
{
  EXPECT_EQ(timeIntervalToString(0), "0s");
  EXPECT_EQ(timeIntervalToString(1), "1s");
  EXPECT_EQ(timeIntervalToString(60), "1m 0s");
  EXPECT_EQ(timeIntervalToString(3600), "1h 0m 0s");
  EXPECT_EQ(timeIntervalToString(86400), "1d 0h 0m 0s");
  EXPECT_EQ(timeIntervalToString(90061), "1d 1h 1m 1s");
}