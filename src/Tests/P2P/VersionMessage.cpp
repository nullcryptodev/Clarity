// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "P2P/VersionMessage.h"
#include "P2P/MessageTypes.h"

using namespace P2P;
using namespace Tests;

// Version round-trip

TEST(VersionMessage, RoundTrip)
{
  VersionMessage v;
  v.protocolVersion = GlobalConfig::CURRENT_PROTOCOL_VERSION;
  v.networkNonce = 0x1234'5678'9ABC'DEF0ULL;
  v.timestamp = 1'700'000'000;
  v.listenPort = 19444;
  v.agentString = GlobalConfig::PROJECT_AGENT_STRING;
  v.bestHeight = 42;
  v.peerNonce = 0xDEAD'BEEF'CAFE'BABEULL;

  auto bytes = serializeVersion(v);
  VersionMessage decoded;
  ASSERT_TRUE(deserializeVersion(bytes.data(), bytes.size(), decoded));

  EXPECT_EQ(decoded.protocolVersion, v.protocolVersion);
  EXPECT_EQ(decoded.networkNonce, v.networkNonce);
  EXPECT_EQ(decoded.timestamp, v.timestamp);
  EXPECT_EQ(decoded.listenPort, v.listenPort);
  EXPECT_EQ(decoded.agentString, v.agentString);
  EXPECT_EQ(decoded.bestHeight, v.bestHeight);
  EXPECT_EQ(decoded.peerNonce, v.peerNonce);
}

TEST(VersionMessage, RoundTripEmptyAgent)
{
  VersionMessage v;
  v.protocolVersion = 1;
  v.agentString = "";

  auto bytes = serializeVersion(v);
  VersionMessage decoded;
  ASSERT_TRUE(deserializeVersion(bytes.data(), bytes.size(), decoded));
  EXPECT_EQ(decoded.agentString, "");
}

TEST(VersionMessage, DeserializeRejectsTruncated)
{
  VersionMessage v;
  v.agentString = GlobalConfig::PROJECT_AGENT_STRING;
  auto bytes = serializeVersion(v);

  // Cut off the tail.
  bytes.resize(bytes.size() - 1);
  VersionMessage decoded;
  EXPECT_FALSE(deserializeVersion(bytes.data(), bytes.size(), decoded));
}

// Peers round-trip

TEST(VersionMessage, PeersRoundTrip)
{
  std::vector<PeerAddressEntry> peers = {
      {"10.0.0.1", 19444},
      {"192.168.1.100", 8333},
      {"seed.example.com", 19444},
  };

  auto bytes = serializePeers(peers);
  std::vector<PeerAddressEntry> decoded;
  ASSERT_TRUE(deserializePeers(bytes.data(), bytes.size(), decoded));

  ASSERT_EQ(decoded.size(), peers.size());
  for (size_t i = 0; i < peers.size(); ++i)
  {
    EXPECT_EQ(decoded[i].ip, peers[i].ip);
    EXPECT_EQ(decoded[i].port, peers[i].port);
  }
}

TEST(VersionMessage, PeersEmptyRoundTrip)
{
  auto bytes = serializePeers({});
  std::vector<PeerAddressEntry> decoded;
  ASSERT_TRUE(deserializePeers(bytes.data(), bytes.size(), decoded));
  EXPECT_TRUE(decoded.empty());
}

// GetHeaders round-trip

TEST(VersionMessage, GetHeadersRoundTrip)
{
  GetHeadersMessage m;
  m.startHeight = 42;
  m.limit = 500;

  auto bytes = serializeGetHeaders(m);
  GetHeadersMessage decoded;
  ASSERT_TRUE(deserializeGetHeaders(bytes.data(), bytes.size(), decoded));

  EXPECT_EQ(decoded.startHeight, m.startHeight);
  EXPECT_EQ(decoded.limit, m.limit);
}

// Inv round-trip

TEST(VersionMessage, InvRoundTrip)
{
  std::vector<InvEntry> entries;
  for (uint64_t i = 0; i < 3; ++i)
  {
    InvEntry e;
    e.type = (i % 2 == 0) ? InvType::Tx : InvType::Block;
    e.hash = makeHash(i + 1).data;
    entries.push_back(e);
  }

  auto bytes = serializeInv(entries);
  std::vector<InvEntry> decoded;
  ASSERT_TRUE(deserializeInv(bytes.data(), bytes.size(), decoded));

  ASSERT_EQ(decoded.size(), 3u);
  for (size_t i = 0; i < entries.size(); ++i)
  {
    EXPECT_EQ(decoded[i].type, entries[i].type);
    EXPECT_EQ(decoded[i].hash, entries[i].hash);
  }
}

TEST(VersionMessage, InvRejectsOversize)
{
  // Count field says 20000, but no entries follow.
  std::vector<uint8_t> bytes;
  for (int i = 0; i < 4; ++i)
    bytes.push_back(uint8_t(20000 >> (i * 8)));

  std::vector<InvEntry> decoded;
  EXPECT_FALSE(deserializeInv(bytes.data(), bytes.size(), decoded));
}

TEST(VersionMessage, GetDataRoundTrip)
{
  std::vector<InvEntry> entries;
  InvEntry e;
  e.type = InvType::Block;
  e.hash = makeHash(99).data;
  entries.push_back(e);

  auto bytes = serializeGetData(entries);
  GetDataMessage decoded;
  ASSERT_TRUE(deserializeGetData(bytes.data(), bytes.size(), decoded));
  ASSERT_EQ(decoded.size(), 1u);
  EXPECT_EQ(decoded[0].type, InvType::Block);
}