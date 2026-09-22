// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "P2P/MessageTypes.h"

using namespace P2P;

TEST(MessageTypes, TypeNames)
{
  EXPECT_EQ(messageTypeName(MessageType::Version), "version");
  EXPECT_EQ(messageTypeName(MessageType::Verack), "verack");
  EXPECT_EQ(messageTypeName(MessageType::Ping), "ping");
  EXPECT_EQ(messageTypeName(MessageType::Pong), "pong");
  EXPECT_EQ(messageTypeName(MessageType::GetPeers), "getpeers");
  EXPECT_EQ(messageTypeName(MessageType::Peers), "peers");
  EXPECT_EQ(messageTypeName(MessageType::GetHeaders), "getheaders");
  EXPECT_EQ(messageTypeName(MessageType::Headers), "headers");
  EXPECT_EQ(messageTypeName(MessageType::GetBlocks), "getblocks");
  EXPECT_EQ(messageTypeName(MessageType::Blocks), "blocks");
  EXPECT_EQ(messageTypeName(MessageType::Inv), "inv");
  EXPECT_EQ(messageTypeName(MessageType::GetData), "getdata");
  EXPECT_EQ(messageTypeName(MessageType::Tx), "tx");
  EXPECT_EQ(messageTypeName(MessageType::Block), "block");
  EXPECT_EQ(messageTypeName(MessageType::Proposal), "proposal");
  EXPECT_EQ(messageTypeName(MessageType::Prevote), "prevote");
  EXPECT_EQ(messageTypeName(MessageType::Precommit), "precommit");
  EXPECT_EQ(messageTypeName(MessageType::Disconnect), "disconnect");
}

TEST(MessageTypes, UnknownTypeName)
{
  auto unknown = static_cast<MessageType>(0xFFFF);
  EXPECT_EQ(messageTypeName(unknown), "unknown");
}

TEST(MessageTypes, MagicForNetwork)
{
  EXPECT_EQ(magicForNetwork(0), MAGIC_MAINNET);
  EXPECT_EQ(magicForNetwork(1), MAGIC_TESTNET);
  EXPECT_EQ(magicForNetwork(2), MAGIC_REGTEST);
  // Unknown network falls back to regtest.
  EXPECT_EQ(magicForNetwork(99), MAGIC_REGTEST);
}