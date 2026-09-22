// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/CRC32.h"

#include <string>

using namespace Common;

// Standard CRC32 test vectors (IEEE 802.3, the same polynomial as zlib).

TEST(CRC32, EmptyString)
{
  // CRC32 of empty string is 0.
  EXPECT_EQ(crc32(""), 0);
}

TEST(CRC32, KnownVectors)
{
  // Well-known CRC32 test vectors (IEEE polynomial).
  EXPECT_EQ(crc32("The quick brown fox jumps over the lazy dog"),
            uint64_t(0x414FA339));
  EXPECT_EQ(crc32("a"), uint64_t(0xE8B7BE43));
  EXPECT_EQ(crc32("abc"), uint64_t(0x352441C2));
  EXPECT_EQ(crc32("123456789"), uint64_t(0xCBF43926));
}

TEST(CRC32, DeterministicForSameInput)
{
  std::string s = "hello world";
  EXPECT_EQ(crc32(s), crc32(s));
}

TEST(CRC32, DifferentInputsDifferentCRC)
{
  EXPECT_NE(crc32("hello"), crc32("world"));
}