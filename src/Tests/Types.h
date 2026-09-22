#pragma once

#include <map>
#include <vector>

#include "Crypto/Types.h"

#include "Serialization/ISerializer.h"

// Types for serialization tests

namespace Tests
{
  struct SimpleType
  {
    uint8_t u8 = 0;
    uint16_t u16 = 0;
    uint32_t u32 = 0;
    uint64_t u64 = 0;
    int8_t i8 = 0;
    int16_t i16 = 0;
    int32_t i32 = 0;
    int64_t i64 = 0;
    bool b = false;
    std::string str;

    void serialize(Serialization::ISerializer &s)
    {
      s(u8, "u8");
      s(u16, "u16");
      s(u32, "u32");
      s(u64, "u64");
      s(i8, "i8");
      s(i16, "i16");
      s(i32, "i32");
      s(i64, "i64");
      s(b, "b");
      s(str, "str");
    }

    bool operator==(const SimpleType &other) const
    {
      return u8 == other.u8 &&
             u16 == other.u16 &&
             u32 == other.u32 &&
             u64 == other.u64 &&
             i8 == other.i8 &&
             i16 == other.i16 &&
             i32 == other.i32 &&
             i64 == other.i64 &&
             b == other.b &&
             str == other.str;
    }
  };

  struct NestedType
  {
    SimpleType simple;
    std::vector<int32_t> numbers;
    std::map<std::string, uint64_t> map;

    void serialize(Serialization::ISerializer &s)
    {
      s(simple, "simple");
      s(numbers, "numbers");
      s(map, "map");
    }

    bool operator==(const NestedType &other) const
    {
      return simple == other.simple &&
             numbers == other.numbers &&
             map == other.map;
    }
  };

  struct BinaryType
  {
    std::vector<uint8_t> data;
    Crypto::Hash hash;
    Crypto::Signature sig;

    void serialize(Serialization::ISerializer &s)
    {
      s(data, "data");
      s(hash, "hash");
      s(sig, "sig");
    }

    bool operator==(const BinaryType &other) const
    {
      // Crypto::Hash and Crypto::Signature provide operator== via their
      // ByteArray base class, which uses std::array comparison. No
      // manual memcmp needed.
      return data == other.data &&
             hash == other.hash &&
             sig == other.sig;
    }
  };

  enum class TestEnum : uint8_t
  {
    Zero = 0,
    One = 1,
    Two = 2,
    Three = 3,
    Max = 255
  };

  struct EnumType
  {
    TestEnum value = TestEnum::Zero;
    std::vector<TestEnum> values;

    void serialize(Serialization::ISerializer &s)
    {
      s(value, "value");
      s(values, "values");
    }

    bool operator==(const EnumType &other) const
    {
      return value == other.value && values == other.values;
    }
  };
}