// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <sstream>
#include <cstring>

#include "Tests/Fixtures.h"
#include "Tests/Types.h"

#include "Serialization/JsonSerializer.h"
#include "Serialization/SerializationTools.h"

using namespace Serialization;
using namespace Tests;

// Primitive Type Tests

TEST_F(JsonSerializerTestFixture, UInt8)
{
  uint8_t original = 0xFF;
  uint8_t result = 0;
  std::string json = toJson(original);
  EXPECT_TRUE(fromJson(result, json));
  EXPECT_EQ(original, result);
}

TEST_F(JsonSerializerTestFixture, UInt64)
{
  uint64_t original = 0xFFFFFFFFFFFFFFFFULL;
  uint64_t result = 0;
  std::string json = toJson(original);
  EXPECT_TRUE(fromJson(result, json));
  EXPECT_EQ(original, result);
}

TEST_F(JsonSerializerTestFixture, Int64)
{
  int64_t original = -123456789012345LL;
  int64_t result = 0;
  std::string json = toJson(original);
  EXPECT_TRUE(fromJson(result, json));
  EXPECT_EQ(original, result);
}

TEST_F(JsonSerializerTestFixture, Bool)
{
  bool original = true;
  bool result = false;
  std::string json = toJson(original);
  EXPECT_TRUE(fromJson(result, json));
  EXPECT_EQ(original, result);
}

TEST_F(JsonSerializerTestFixture, String)
{
  std::string original = "Hello, World!";
  std::string result;
  std::string json = toJson(original);
  EXPECT_TRUE(fromJson(result, json));
  EXPECT_EQ(original, result);
}

TEST_F(JsonSerializerTestFixture, StringWithSpecialChars)
{
  std::string original = "Hello\nWorld\tTest\"Quote\"";
  std::string result;
  std::string json = toJson(original);
  EXPECT_TRUE(fromJson(result, json));
  EXPECT_EQ(original, result);
}

// SimpleType Tests

TEST_F(JsonSerializerTestFixture, SimpleType)
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

  std::string json = toJson(original);
  SimpleType result;
  EXPECT_TRUE(fromJson(result, json));
  EXPECT_TRUE(original == result);
}

// Pretty Print Tests

TEST_F(JsonSerializerTestFixture, PrettyPrint)
{
  SimpleType original;
  original.u8 = 0x12;
  original.str = "Pretty print test";

  std::string json = Serialization::toJsonString(original, 2);
  EXPECT_NE(json.find('\n'), std::string::npos);
  EXPECT_NE(json.find(' '), std::string::npos);
}

// Error Handling Tests

TEST_F(JsonSerializerTestFixture, InvalidJson)
{
  SimpleType result;
  EXPECT_FALSE(fromJson(result, "{invalid json}"));
}
