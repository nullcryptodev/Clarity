// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license

#include <cstring>
#include <gtest/gtest.h>

#include "Tests/Fixtures.h"
#include "Tests/Types.h"

#include "Serialization/KVBinarySerializer.h"
#include "Serialization/MemoryStream.h"
#include "Serialization/SerializationTools.h"

using namespace Serialization;
using namespace Tests;

// KV Binary Format Tests

TEST_F(KVBinarySerializerTestFixture, InvalidSignature)
{
  std::vector<uint8_t> buffer;
  // Write invalid signature
  uint32_t invalidSig = 0xDEADBEEF;
  buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(&invalidSig),
                reinterpret_cast<uint8_t *>(&invalidSig) + sizeof(invalidSig));
  buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(&invalidSig),
                reinterpret_cast<uint8_t *>(&invalidSig) + sizeof(invalidSig));
  uint8_t version = 1;
  buffer.push_back(version);

  MemoryInputStream stream(buffer.data(), buffer.size());
  EXPECT_THROW(createKVBinarySerializer(stream), std::runtime_error);
}

TEST_F(KVBinarySerializerTestFixture, InvalidVersion)
{
  std::vector<uint8_t> buffer;
  // Write valid signature but invalid version
  uint32_t sig = 0x01011101;
  buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(&sig),
                reinterpret_cast<uint8_t *>(&sig) + sizeof(sig));
  buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(&sig),
                reinterpret_cast<uint8_t *>(&sig) + sizeof(sig));
  uint8_t version = 99;
  buffer.push_back(version);

  MemoryInputStream stream(buffer.data(), buffer.size());
  EXPECT_THROW(createKVBinarySerializer(stream), std::runtime_error);
}