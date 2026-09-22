// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Common/Varint.h"

#include <cstdint>
#include <vector>

using namespace Common;

// ============================================================================
//  Round-trip
// ============================================================================

TEST(Varint, RoundTripU8)
{
  for (uint8_t v : {0, 1, 42, 127, 128, 200, 255})
  {
    auto encoded = to_varint(v);
    auto decoded = read_varint_from_string<uint8_t>(encoded);

    ASSERT_TRUE(decoded.success()) << "value: " << (int)v;
    EXPECT_EQ(decoded.value, v);
    EXPECT_EQ(decoded.bytesRead, encoded.size());
  }
}

TEST(Varint, RoundTripU16)
{
  for (uint16_t v : {uint16_t(0), uint16_t(127), uint16_t(128),
                     uint16_t(16383), uint16_t(16384),
                     uint16_t(65535)})
  {
    auto encoded = to_varint(v);
    auto decoded = read_varint_from_string<uint16_t>(encoded);

    ASSERT_TRUE(decoded.success()) << "value: " << v;
    EXPECT_EQ(decoded.value, v);
  }
}

TEST(Varint, RoundTripU32)
{
  for (uint32_t v : {uint32_t(0), uint32_t(127), uint32_t(128),
                     uint32_t(16383), uint32_t(16384),
                     uint32_t(2097151), uint32_t(2097152),
                     uint32_t(0xFFFFFFFF)})
  {
    auto encoded = to_varint(v);
    auto decoded = read_varint_from_string<uint32_t>(encoded);

    ASSERT_TRUE(decoded.success()) << "value: " << v;
    EXPECT_EQ(decoded.value, v);
  }
}

TEST(Varint, RoundTripU64)
{
  for (uint64_t v : {uint64_t(0), uint64_t(127), uint64_t(128),
                     uint64_t(16383), uint64_t(16384),
                     uint64_t(0xFFFFFFFFFFFFFFFFULL),
                     uint64_t(0x1234567890ABCDEFULL)})
  {
    auto encoded = to_varint(v);
    auto decoded = read_varint_from_string<uint64_t>(encoded);

    ASSERT_TRUE(decoded.success()) << "value: " << v;
    EXPECT_EQ(decoded.value, v);
  }
}

// ============================================================================
//  Encoding sizes
// ============================================================================

TEST(Varint, SizeOneByte)
{
  EXPECT_EQ(to_varint(uint64_t(0)).size(), 1);
  EXPECT_EQ(to_varint(uint64_t(1)).size(), 1);
  EXPECT_EQ(to_varint(uint64_t(127)).size(), 1);
}

TEST(Varint, SizeTwoBytes)
{
  EXPECT_EQ(to_varint(uint64_t(128)).size(), 2);
  EXPECT_EQ(to_varint(uint64_t(16383)).size(), 2);
}

TEST(Varint, SizeThreeBytes)
{
  EXPECT_EQ(to_varint(uint64_t(16384)).size(), 3);
}

TEST(Varint, SizeMax)
{
  // 64-bit max needs 10 bytes.
  EXPECT_EQ(to_varint(uint64_t(0xFFFFFFFFFFFFFFFFULL)).size(), 10);
}

TEST(Varint, SizeHelper)
{
  EXPECT_EQ(varint_size(uint64_t(0)), 1);
  EXPECT_EQ(varint_size(uint64_t(127)), 1);
  EXPECT_EQ(varint_size(uint64_t(128)), 2);
  EXPECT_EQ(varint_size(uint64_t(0xFFFFFFFFFFFFFFFFULL)), 10);
}

// ============================================================================
//  Error handling
// ============================================================================

TEST(Varint, EmptyInput)
{
  auto result = read_varint_from_string<uint32_t>("");
  EXPECT_FALSE(result.success());
  EXPECT_EQ(result.error, VarintError::InsufficientData);
}

TEST(Varint, IncompleteVarint)
{
  // 0x80 signals "more bytes follow" — but there's nothing after it.
  std::string bad;
  bad.push_back(static_cast<char>(0x80));

  auto result = read_varint_from_string<uint32_t>(bad);
  EXPECT_FALSE(result.success());
  EXPECT_EQ(result.error, VarintError::InsufficientData);
}

TEST(Varint, OverflowForU8)
{
  // Encode a value that's too big for uint8_t.
  auto encoded = to_varint(uint64_t(300));
  auto result = read_varint_from_string<uint8_t>(encoded);
  EXPECT_FALSE(result.success());
  EXPECT_EQ(result.error, VarintError::Overflow);
}

// ============================================================================
//  Buffer-based read/write
// ============================================================================

TEST(Varint, WriteToBuffer)
{
  uint8_t buffer[16];
  size_t n = write_varint_to_buffer(uint64_t(300), buffer);
  EXPECT_EQ(n, 2);

  auto result = read_varint_from_buffer<uint64_t>(buffer, n);
  ASSERT_TRUE(result.success());
  EXPECT_EQ(result.value, 300);
}

TEST(Varint, WriteToVector)
{
  std::vector<uint8_t> out;
  write_varint_to_vector(uint64_t(16384), out);
  EXPECT_EQ(out.size(), 3);

  auto result = read_varint_from_buffer<uint64_t>(out.data(), out.size());
  ASSERT_TRUE(result.success());
  EXPECT_EQ(result.value, 16384);
}