// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/TokenTypes.h"
#include "RPC/Encoders/TokenEncoder.h"

using Common::Json;
using Rpc::encodeToken;

namespace
{
  Core::TokenInfo makeNative()
  {
    Core::TokenInfo t;
    t.id = 0;
    t.name = "Clarity";
    t.symbol = "CLRTY";
    t.decimals = 5;
    t.creator = Crypto::Address{}; // zero
    t.backing = Core::BackingModel::Unbacked;
    t.maxSupply = 0;
    t.royaltyBps = 0;
    return t;
  }

  Core::TokenInfo makeCustom()
  {
    Core::TokenInfo t;
    t.id = 42;
    t.name = "Test Token";
    t.symbol = "TST";
    t.decimals = 8;
    t.creator = Crypto::addrFromHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    t.backing = Core::BackingModel::Backed;
    t.maxSupply = 1'000'000;
    t.royaltyBps = 250;
    return t;
  }
} // namespace

TEST(RPC_TokenEncoder, NativeToken)
{
  Json j = encodeToken(makeNative(), "clrty");

  EXPECT_EQ(j["id"], "0x0");
  EXPECT_EQ(j["name"], "Clarity");
  EXPECT_EQ(j["symbol"], "CLRTY");
  EXPECT_EQ(j["decimals"], 5);
  EXPECT_TRUE(j["creator"].is_null()); // zero address -> null
  EXPECT_EQ(j["backing"], "unbacked");
  EXPECT_EQ(j["backing_code"], 0);
  EXPECT_EQ(j["max_supply"], "0x0");
  EXPECT_EQ(j["royalty_bps"], 0);
  EXPECT_TRUE(j["fingerprint"].is_null());
  EXPECT_EQ(j["is_native"], true);
  EXPECT_EQ(j["is_bridged"], false);
}

TEST(RPC_TokenEncoder, CustomTokenWithAddress)
{
  Json j = encodeToken(makeCustom(), "clrty");

  EXPECT_EQ(j["id"], "0x2a");
  EXPECT_EQ(j["name"], "Test Token");
  EXPECT_EQ(j["symbol"], "TST");
  EXPECT_EQ(j["decimals"], 8);
  ASSERT_TRUE(j["creator"].is_string());
  // Bech32m address starts with the HRP.
  EXPECT_EQ(j["creator"].get<std::string>().substr(0, 5), "clrty");
  EXPECT_EQ(j["backing"], "backed");
  EXPECT_EQ(j["backing_code"], 1);
  EXPECT_EQ(j["is_native"], false);
}

TEST(RPC_TokenEncoder, HybridBacking)
{
  Core::TokenInfo t = makeCustom();
  t.backing = Core::BackingModel::Hybrid;

  Json j = encodeToken(t, "clrty");
  EXPECT_EQ(j["backing"], "hybrid");
  EXPECT_EQ(j["backing_code"], 2);
}

TEST(RPC_TokenEncoder, BridgedTokenHasFingerprint)
{
  Core::TokenInfo t = makeCustom();
  Crypto::Hash fp;
  for (size_t i = 0; i < 32; ++i)
    fp.data[i] = uint8_t(i);
  t.fingerprint = fp;

  Json j = encodeToken(t, "clrty");
  EXPECT_EQ(j["is_bridged"], true);
  ASSERT_TRUE(j["fingerprint"].is_string());
  EXPECT_EQ(j["fingerprint"].get<std::string>().size(), 66u); // 0x + 64
}