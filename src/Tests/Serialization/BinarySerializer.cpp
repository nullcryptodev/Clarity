// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <cstring>

#include "Tests/Fixtures.h"
#include "Tests/Types.h"

#include "Serialization/BinarySerializer.h"
#include "Serialization/MemoryStream.h"
#include "Serialization/SerializationTools.h"

using namespace Serialization;
using namespace Tests;

// Primitive Type Tests

TEST_F(BinarySerializerTestFixture, UInt8)
{
  uint8_t original = 0xFF;
  uint8_t result = 0;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, UInt16)
{
  uint16_t original = 0xFFFF;
  uint16_t result = 0;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, UInt32)
{
  uint32_t original = 0xFFFFFFFF;
  uint32_t result = 0;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, UInt64)
{
  uint64_t original = 0xFFFFFFFFFFFFFFFFULL;
  uint64_t result = 0;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, Int8)
{
  int8_t original = -128;
  int8_t result = 0;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, Int16)
{
  int16_t original = -32768;
  int16_t result = 0;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, Int32)
{
  int32_t original = -2147483647 - 1;
  int32_t result = 0;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, Int64)
{
  int64_t original = -9223372036854775807LL - 1;
  int64_t result = 0;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, Bool)
{
  bool original = true;
  bool result = false;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);

  original = false;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, String)
{
  std::string original = "Hello, World!";
  std::string result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, EmptyString)
{
  std::string original;
  std::string result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, StringWithSpecialChars)
{
  std::string original = "Hello\nWorld\tTest\0Embedded";
  std::string result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

// SimpleType Tests

TEST_F(BinarySerializerTestFixture, SimpleType)
{
  SimpleType original;
  original.u8 = 0x12;
  original.u16 = 0x1234;
  original.u32 = 0x12345678;
  original.u64 = 0x123456789ABCDEF0ULL;
  original.i8 = -123;
  original.i16 = -12345;
  original.i32 = -123456789;
  original.i64 = -123456789012345LL;
  original.b = true;
  original.str = "Simple test string";

  SimpleType result;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_TRUE(original == result);
}

// Vector Tests

TEST_F(BinarySerializerTestFixture, VectorInt)
{
  std::vector<int32_t> original = {1, 2, 3, 4, 5, 10, 20, 30, 100, 200, 300};
  std::vector<int32_t> result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, EmptyVector)
{
  std::vector<int32_t> original;
  std::vector<int32_t> result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, VectorString)
{
  std::vector<std::string> original = {"one", "two", "three", "four", "five"};
  std::vector<std::string> result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, VectorUInt8)
{
  std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0xFF, 0xFE};
  std::vector<uint8_t> result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

// Map Tests

TEST_F(BinarySerializerTestFixture, MapStringToUInt)
{
  std::map<std::string, uint64_t> original = {
      {"one", 1},
      {"two", 2},
      {"three", 3},
      {"four", 4},
      {"five", 5}};
  std::map<std::string, uint64_t> result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, EmptyMap)
{
  std::map<std::string, uint64_t> original;
  std::map<std::string, uint64_t> result;

  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

// NestedType Tests

TEST_F(BinarySerializerTestFixture, NestedType)
{
  NestedType original;
  original.simple.u8 = 0x42;
  original.simple.u16 = 0x4242;
  original.simple.u32 = 0x42424242;
  original.simple.u64 = 0x4242424242424242ULL;
  original.simple.i8 = -42;
  original.simple.i16 = -4242;
  original.simple.i32 = -42424242;
  original.simple.i64 = -424242424242LL;
  original.simple.b = true;
  original.simple.str = "Nested test";
  original.numbers = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  original.map = {{"key1", 100}, {"key2", 200}, {"key3", 300}};

  NestedType result;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_TRUE(original == result);
}

// BinaryType Tests

TEST_F(BinarySerializerTestFixture, BinaryType)
{
  BinaryType original;
  original.data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  original.hash.data.fill(0xAA);
  original.sig.data.fill(0xBB);

  BinaryType result;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_TRUE(original == result);
}

// EnumType Tests

TEST_F(BinarySerializerTestFixture, EnumType)
{
  EnumType original;
  original.value = TestEnum::Two;
  original.values = {TestEnum::Zero, TestEnum::One, TestEnum::Two, TestEnum::Three};

  EnumType result;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_TRUE(original == result);
}

// Varint Tests (edge cases)

TEST_F(BinarySerializerTestFixture, VarintSmall)
{
  uint64_t original = 0x00;
  uint64_t result = 0;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);

  original = 0x01;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);

  original = 0x7F;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, VarintMedium)
{
  uint64_t original = 0x80;
  uint64_t result = 0;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);

  original = 0xFF;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);

  original = 0x1000;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, VarintLarge)
{
  uint64_t original = 0xFFFFFFFFFFFFFFFFULL;
  uint64_t result = 0;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

// Negative Number Tests

TEST_F(BinarySerializerTestFixture, NegativeInt32)
{
  int32_t original = -1;
  int32_t result = 0;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);

  original = -1000000;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, NegativeInt64)
{
  int64_t original = -1;
  int64_t result = 0;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);

  original = -1000000000000LL;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

// Large Array Tests

TEST_F(BinarySerializerTestFixture, LargeVector)
{
  std::vector<int32_t> original;
  for (int i = 0; i < 1000; ++i)
  {
    original.push_back(i);
  }

  std::vector<int32_t> result;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}

TEST_F(BinarySerializerTestFixture, LargeString)
{
  std::string original;
  for (int i = 0; i < 10000; ++i)
  {
    original += 'A' + (i % 26);
  }

  std::string result;
  EXPECT_TRUE(roundTrip(original, result));
  EXPECT_EQ(original, result);
}