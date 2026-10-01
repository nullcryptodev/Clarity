// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Crypto/Types.h"
#include "RPC/Encoding.h"
#include "RPC/JsonRpcDispatcher.h"

using Common::Json;
using Rpc::encodeAddress;
using Rpc::encodeBytesHex;
using Rpc::encodeHash;
using Rpc::encodeSignature;
using Rpc::encodeU64Hex;
using Rpc::parseAddress;
using Rpc::parseBytesHex;
using Rpc::parseHash;
using Rpc::parseHexU64;
using Rpc::parseSignature;
using Rpc::RpcMethodError;

// ============================================================================
//  encodeU64Hex
// ============================================================================

TEST(RPC_Encoding, U64HexZero)
{
  EXPECT_EQ(encodeU64Hex(0), "0x0");
}

TEST(RPC_Encoding, U64HexSmall)
{
  EXPECT_EQ(encodeU64Hex(1), "0x1");
  EXPECT_EQ(encodeU64Hex(15), "0xf");
  EXPECT_EQ(encodeU64Hex(16), "0x10");
  EXPECT_EQ(encodeU64Hex(255), "0xff");
  EXPECT_EQ(encodeU64Hex(256), "0x100");
}

TEST(RPC_Encoding, U64HexNoLeadingZeros)
{
  EXPECT_EQ(encodeU64Hex(0x0123), "0x123");
  EXPECT_EQ(encodeU64Hex(0x0000FFFFFFFFFFFFFFFFULL),
            "0xffffffffffffffff");
}

TEST(RPC_Encoding, U64HexMax)
{
  EXPECT_EQ(encodeU64Hex(UINT64_MAX), "0xffffffffffffffff");
}

// ============================================================================
//  encodeBytesHex
// ============================================================================

TEST(RPC_Encoding, BytesHexEmpty)
{
  EXPECT_EQ(encodeBytesHex(std::vector<uint8_t>{}), "0x");
}

TEST(RPC_Encoding, BytesHexSingle)
{
  EXPECT_EQ(encodeBytesHex(std::vector<uint8_t>{0x00}), "0x00");
  EXPECT_EQ(encodeBytesHex(std::vector<uint8_t>{0xff}), "0xff");
  EXPECT_EQ(encodeBytesHex(std::vector<uint8_t>{0xab}), "0xab");
}

TEST(RPC_Encoding, BytesHexMultiplePreservesOrder)
{
  std::vector<uint8_t> b{0x01, 0x02, 0x03, 0x04};
  EXPECT_EQ(encodeBytesHex(b), "0x01020304");
}

// ============================================================================
//  encodeHash / encodeAddress / encodeSignature
// ============================================================================

TEST(RPC_Encoding, HashIsPrefixedAnd64Chars)
{
  Crypto::Hash h;
  std::string s = encodeHash(h);

  ASSERT_GE(s.size(), 2u);
  EXPECT_EQ(s.substr(0, 2), "0x");
  EXPECT_EQ(s.size(), 66u); // "0x" + 64 hex chars
}

TEST(RPC_Encoding, AddressIsBech32m)
{
  Crypto::Address a;
  for (size_t i = 0; i < 32; ++i)
    a.data[i] = static_cast<uint8_t>(0x10 + i);

  std::string s = encodeAddress(a, GlobalConfig::MAINNET_HRP);

  ASSERT_FALSE(s.empty());
  EXPECT_EQ(s.substr(0, 6), "clrty1");
  EXPECT_NE(s.substr(0, 2), "0x");
}

TEST(RPC_Encoding, SignatureIsPrefixedAnd128Chars)
{
  Crypto::Signature sig;
  std::string s = encodeSignature(sig);

  ASSERT_GE(s.size(), 2u);
  EXPECT_EQ(s.substr(0, 2), "0x");
  EXPECT_EQ(s.size(), 130u); // "0x" + 128 hex
}

// ============================================================================
//  parseHexU64 (requires 0x prefix)
// ============================================================================

TEST(RPC_Encoding, ParseHexU64RequiresPrefix)
{
  uint64_t v = 0;
  // Bare decimal-looking strings must NOT be parsed as hex.
  EXPECT_FALSE(parseHexU64("26", v));
  EXPECT_FALSE(parseHexU64("ff", v));
}

TEST(RPC_Encoding, ParseHexU64WithPrefix)
{
  uint64_t v = 0;
  ASSERT_TRUE(parseHexU64("0x26", v));
  EXPECT_EQ(v, 0x26u);
  ASSERT_TRUE(parseHexU64("0XFF", v));
  EXPECT_EQ(v, 0xFFu);
  ASSERT_TRUE(parseHexU64("0x0", v));
  EXPECT_EQ(v, 0u);
}

TEST(RPC_Encoding, ParseHexU64RejectsGarbage)
{
  uint64_t v = 0;
  EXPECT_FALSE(parseHexU64("0x", v));
  EXPECT_FALSE(parseHexU64("0xGG", v));
  EXPECT_FALSE(parseHexU64("0x1234567890abcdefa", v)); // 17 hex digits
}

// ============================================================================
//  parseHash / parseSignature / parseAddress
// ============================================================================

TEST(RPC_Encoding, ParseHashRoundTrip)
{
  Crypto::Hash orig;
  for (size_t i = 0; i < 32; ++i)
    orig.data[i] = uint8_t(i);

  std::string s = encodeHash(orig);
  Crypto::Hash parsed;
  ASSERT_TRUE(parseHash(s, parsed));
  EXPECT_EQ(parsed, orig);
}

TEST(RPC_Encoding, ParseHashRejectsWrongLength)
{
  Crypto::Hash out;
  EXPECT_FALSE(parseHash("0x00", out));
  EXPECT_FALSE(parseHash("0x" + std::string(62, '0'), out));
  EXPECT_FALSE(parseHash("0x" + std::string(66, '0'), out));
}

TEST(RPC_Encoding, ParseAddressRoundTripFromBech32m)
{
  Crypto::Address orig;
  for (size_t i = 0; i < 32; ++i)
    orig.data[i] = uint8_t(0xA0 + i);

  std::string bech32 = encodeAddress(orig, GlobalConfig::MAINNET_HRP);
  ASSERT_FALSE(bech32.empty());
  ASSERT_EQ(bech32.substr(0, 6), "clrty1");

  Crypto::Address parsed;
  ASSERT_TRUE(parseAddress(bech32, GlobalConfig::MAINNET_HRP, parsed));
  EXPECT_EQ(parsed, orig);
}

TEST(RPC_Encoding, ParseAddressRoundTripFromHex)
{
  Crypto::Address orig;
  for (size_t i = 0; i < 32; ++i)
    orig.data[i] = uint8_t(0xA0 + i);

  // Build 64-char hex manually (the encoder now emits Bech32m).
  std::string hex;
  hex.reserve(64);
  static const char *kHexDigits = "0123456789abcdef";
  for (size_t i = 0; i < 32; ++i)
  {
    hex.push_back(kHexDigits[orig.data[i] >> 4]);
    hex.push_back(kHexDigits[orig.data[i] & 0x0F]);
  }
  ASSERT_EQ(hex.size(), 64u);

  Crypto::Address parsed;
  // Bare hex accepted.
  ASSERT_TRUE(parseAddress(hex, GlobalConfig::MAINNET_HRP, parsed));
  EXPECT_EQ(parsed, orig);

  // 0x-prefixed hex also accepted.
  ASSERT_TRUE(parseAddress("0x" + hex, GlobalConfig::MAINNET_HRP, parsed));
  EXPECT_EQ(parsed, orig);
}

// ============================================================================
//  JSON field helpers
// ============================================================================

TEST(RPC_Encoding, PutU64)
{
  Json j = Json::object();
  Rpc::putU64(j, "x", 42);
  EXPECT_EQ(j["x"], "0x2a");
}

TEST(RPC_Encoding, PutHash)
{
  Crypto::Hash h;
  Json j = Json::object();
  Rpc::putHash(j, "h", h);
  ASSERT_TRUE(j["h"].is_string());
  EXPECT_EQ(j["h"].get<std::string>().substr(0, 2), "0x");
}

TEST(RPC_Encoding, RequireU64Hex)
{
  Json j = {{"x", "0x2a"}};
  EXPECT_EQ(Rpc::requireU64(j, "x"), 42u);
}

TEST(RPC_Encoding, RequireU64Decimal)
{
  Json j = {{"x", "42"}};
  EXPECT_EQ(Rpc::requireU64(j, "x"), 42u);
}

TEST(RPC_Encoding, RequireU64Number)
{
  Json j = {{"x", 42}};
  EXPECT_EQ(Rpc::requireU64(j, "x"), 42u);
}

TEST(RPC_Encoding, RequireU64NegativeRejected)
{
  Json j = {{"x", -1}};
  EXPECT_THROW(Rpc::requireU64(j, "x"), RpcMethodError);
}

TEST(RPC_Encoding, RequireU64MissingRejected)
{
  Json j = Json::object();
  EXPECT_THROW(Rpc::requireU64(j, "x"), RpcMethodError);
}

TEST(RPC_Encoding, RequireU64FloatRejected)
{
  Json j = {{"x", 1.5}};
  EXPECT_THROW(Rpc::requireU64(j, "x"), RpcMethodError);
}

TEST(RPC_Encoding, OptionalU64Absent)
{
  Json j = Json::object();
  auto v = Rpc::optionalU64(j, "x");
  EXPECT_FALSE(v.has_value());
}

TEST(RPC_Encoding, OptionalU64Null)
{
  Json j = {{"x", nullptr}};
  auto v = Rpc::optionalU64(j, "x");
  EXPECT_FALSE(v.has_value());
}

TEST(RPC_Encoding, OptionalU64Present)
{
  Json j = {{"x", "0xff"}};
  auto v = Rpc::optionalU64(j, "x");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, 0xffu);
}

TEST(RPC_Encoding, OptionalBoolAbsent)
{
  Json j = Json::object();
  EXPECT_FALSE(Rpc::optionalBool(j, "x").has_value());
}

TEST(RPC_Encoding, OptionalBoolPresent)
{
  Json j = {{"x", true}};
  auto v = Rpc::optionalBool(j, "x");
  ASSERT_TRUE(v.has_value());
  EXPECT_TRUE(*v);

  Json j2 = {{"x", false}};
  auto v2 = Rpc::optionalBool(j2, "x");
  ASSERT_TRUE(v2.has_value());
  EXPECT_FALSE(*v2);
}

TEST(RPC_Encoding, RequireString)
{
  Json j = {{"s", "hello"}};
  EXPECT_EQ(Rpc::requireString(j, "s"), "hello");
}

TEST(RPC_Encoding, RequireStringRejectsNonString)
{
  Json j = {{"s", 42}};
  EXPECT_THROW(Rpc::requireString(j, "s"), RpcMethodError);
}