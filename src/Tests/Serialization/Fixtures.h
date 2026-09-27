#pragma once

#include <gtest/gtest.h>

#include "Tests/Utils.h"

namespace Tests
{
  class Serialization_BinarySerializerFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    // Helper to round-trip serialize/deserialize
    template <typename T>
    bool roundTrip(T &original, T &result)
    {
      std::vector<uint8_t> buffer;
      Serialization::MemoryOutputStream outStream(buffer);
      Serialization::BinarySerializer outSerializer(outStream);

      serialize_object(original, outSerializer);

      Serialization::MemoryInputStream inStream(buffer.data(), buffer.size());
      Serialization::BinarySerializer inSerializer(inStream);

      try
      {
        serialize_object(result, inSerializer);
        return true;
      }
      catch (const std::exception &)
      {
        return false;
      }
    }
  };

  class Serialization_JsonSerializerFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    template <typename T>
    std::string toJson(const T &obj)
    {
      return Serialization::toJsonString(obj);
    }

    template <typename T>
    bool fromJson(T &obj, const std::string &json)
    {
      return Serialization::fromJsonString(obj, json);
    }
  };

  class Serialization_KVBinarySerializerFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    // Helper to round-trip serialize/deserialize
    template <typename T>
    bool roundTrip(T &original, T &result)
    {
      std::vector<uint8_t> buffer;
      Serialization::MemoryOutputStream outStream(buffer);
      Serialization::KVBinarySerializer outSerializer(outStream);

      serialize_object(original, outSerializer);
      outSerializer.dump(outStream);

      Serialization::MemoryInputStream inStream(buffer.data(), buffer.size());
      Serialization::KVBinarySerializer inSerializer(inStream);

      try
      {
        serialize_object(result, inSerializer);
        return true;
      }
      catch (const std::exception &)
      {
        return false;
      }
    }
  };
}