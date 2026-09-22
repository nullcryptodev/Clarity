// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "P2P/Message.h"

using namespace P2P;
using namespace Tests;

// Encode / decode round-trips

TEST(P2PMessage, EncodeEmptyPayload)
{
  Message msg(MessageType::Ping);
  auto bytes = encodeMessage(msg, MAGIC_REGTEST);

  EXPECT_EQ(bytes.size(), MESSAGE_HEADER_SIZE);

  // Magic (LE)
  EXPECT_EQ(bytes[0], uint8_t(MAGIC_REGTEST & 0xFF));
  EXPECT_EQ(bytes[1], uint8_t((MAGIC_REGTEST >> 8) & 0xFF));
  EXPECT_EQ(bytes[2], uint8_t((MAGIC_REGTEST >> 16) & 0xFF));
  EXPECT_EQ(bytes[3], uint8_t((MAGIC_REGTEST >> 24) & 0xFF));

  // Type (LE)
  EXPECT_EQ(bytes[4], uint8_t(uint16_t(MessageType::Ping) & 0xFF));
  EXPECT_EQ(bytes[5], uint8_t((uint16_t(MessageType::Ping) >> 8) & 0xFF));

  // Size (LE) = 0
  EXPECT_EQ(bytes[6], 0);
  EXPECT_EQ(bytes[7], 0);
  EXPECT_EQ(bytes[8], 0);
  EXPECT_EQ(bytes[9], 0);
}

TEST(P2PMessage, EncodeWithPayload)
{
  Message msg(MessageType::Tx, {0xAA, 0xBB, 0xCC, 0xDD});
  auto bytes = encodeMessage(msg, MAGIC_TESTNET);

  EXPECT_EQ(bytes.size(), MESSAGE_HEADER_SIZE + 4);
  EXPECT_EQ(bytes[MESSAGE_HEADER_SIZE + 0], 0xAA);
  EXPECT_EQ(bytes[MESSAGE_HEADER_SIZE + 1], 0xBB);
  EXPECT_EQ(bytes[MESSAGE_HEADER_SIZE + 2], 0xCC);
  EXPECT_EQ(bytes[MESSAGE_HEADER_SIZE + 3], 0xDD);

  // Size (LE) = 4
  EXPECT_EQ(bytes[6], 4);
  EXPECT_EQ(bytes[7], 0);
}

TEST(P2PMessage, EncodeRejectsOversizePayload)
{
  Message msg(MessageType::Tx, std::vector<uint8_t>(100));
  EXPECT_THROW(encodeMessage(msg, MAGIC_REGTEST, /*maxSize=*/10),
               std::length_error);
}

// Decoder, whole messages

TEST(P2PMessage, DecodeWholeMessage)
{
  MessageDecoder decoder(MAGIC_REGTEST, MAX_MESSAGE_SIZE);

  Message original(MessageType::GetPeers, {1, 2, 3});
  auto bytes = encodeMessage(original, MAGIC_REGTEST);
  decoder.feed(bytes.data(), bytes.size());

  auto result = decoder.next();
  ASSERT_EQ(result.status, DecodeStatus::Ok);
  ASSERT_TRUE(result.message.has_value());
  EXPECT_EQ(result.message->type, MessageType::GetPeers);
  EXPECT_EQ(result.message->payload, std::vector<uint8_t>({1, 2, 3}));

  // No more data.
  auto empty = decoder.next();
  EXPECT_EQ(empty.status, DecodeStatus::NeedMoreData);
}

// Decoder, partial / streaming

TEST(P2PMessage, DecodePartialHeader)
{
  MessageDecoder decoder(MAGIC_REGTEST, MAX_MESSAGE_SIZE);

  auto bytes = encodeMessage(Message(MessageType::Ping), MAGIC_REGTEST);
  // Feed only 4 bytes of the header.
  decoder.feed(bytes.data(), 4);
  EXPECT_EQ(decoder.next().status, DecodeStatus::NeedMoreData);
}

TEST(P2PMessage, DecodePartialBody)
{
  MessageDecoder decoder(MAGIC_REGTEST, MAX_MESSAGE_SIZE);

  Message original(MessageType::Tx, {1, 2, 3, 4, 5});
  auto bytes = encodeMessage(original, MAGIC_REGTEST);

  // Feed everything except the last byte.
  decoder.feed(bytes.data(), bytes.size() - 1);
  EXPECT_EQ(decoder.next().status, DecodeStatus::NeedMoreData);

  // Feed the final byte.
  decoder.feed(bytes.data() + bytes.size() - 1, 1);
  auto result = decoder.next();
  ASSERT_EQ(result.status, DecodeStatus::Ok);
  EXPECT_EQ(result.message->payload.size(), 5u);
}

TEST(P2PMessage, DecodeByteByByte)
{
  MessageDecoder decoder(MAGIC_REGTEST, MAX_MESSAGE_SIZE);

  Message original(MessageType::Peers, {1, 2, 3, 4, 5, 6, 7, 8});
  auto bytes = encodeMessage(original, MAGIC_REGTEST);

  for (size_t i = 0; i + 1 < bytes.size(); ++i)
  {
    decoder.feed(&bytes[i], 1);
    EXPECT_EQ(decoder.next().status, DecodeStatus::NeedMoreData);
  }
  // Last byte completes the message.
  decoder.feed(&bytes.back(), 1);
  auto result = decoder.next();
  ASSERT_EQ(result.status, DecodeStatus::Ok);
  EXPECT_EQ(result.message->payload.size(), 8u);
}

// Decoder, multiple messages in the stream

TEST(P2PMessage, DecodeMultipleMessages)
{
  MessageDecoder decoder(MAGIC_REGTEST, MAX_MESSAGE_SIZE);

  auto m1 = encodeMessage(Message(MessageType::Ping), MAGIC_REGTEST);
  auto m2 = encodeMessage(Message(MessageType::Pong), MAGIC_REGTEST);
  auto m3 = encodeMessage(Message(MessageType::Verack), MAGIC_REGTEST);

  std::vector<uint8_t> all;
  all.insert(all.end(), m1.begin(), m1.end());
  all.insert(all.end(), m2.begin(), m2.end());
  all.insert(all.end(), m3.begin(), m3.end());

  decoder.feed(all.data(), all.size());

  auto r1 = decoder.next();
  ASSERT_EQ(r1.status, DecodeStatus::Ok);
  EXPECT_EQ(r1.message->type, MessageType::Ping);

  auto r2 = decoder.next();
  ASSERT_EQ(r2.status, DecodeStatus::Ok);
  EXPECT_EQ(r2.message->type, MessageType::Pong);

  auto r3 = decoder.next();
  ASSERT_EQ(r3.status, DecodeStatus::Ok);
  EXPECT_EQ(r3.message->type, MessageType::Verack);

  auto r4 = decoder.next();
  EXPECT_EQ(r4.status, DecodeStatus::NeedMoreData);
}

// Decoder, corrupted input

TEST(P2PMessage, DecodeRejectsBadMagic)
{
  MessageDecoder decoder(MAGIC_REGTEST, MAX_MESSAGE_SIZE);

  Message original(MessageType::Ping);
  auto bytes = encodeMessage(original, MAGIC_REGTEST);
  bytes[0] ^= 0xFF; // corrupt magic

  decoder.feed(bytes.data(), bytes.size());
  auto result = decoder.next();
  EXPECT_EQ(result.status, DecodeStatus::Corrupted);
}

TEST(P2PMessage, DecodeRejectsOversize)
{
  MessageDecoder decoder(MAGIC_REGTEST, /*maxSize=*/10);

  Message original(MessageType::Tx, std::vector<uint8_t>(100));
  // encodeMessage with default maxSize doesn't throw, so it produces bytes
  // larger than our decoder's limit.
  auto bytes = encodeMessage(original, MAGIC_REGTEST, 1024);

  decoder.feed(bytes.data(), bytes.size());
  auto result = decoder.next();
  EXPECT_EQ(result.status, DecodeStatus::Corrupted);
}

// Reset

TEST(P2PMessage, ResetClearsBuffer)
{
  MessageDecoder decoder(MAGIC_REGTEST, MAX_MESSAGE_SIZE);

  auto bytes = encodeMessage(Message(MessageType::Ping), MAGIC_REGTEST);
  decoder.feed(bytes.data(), bytes.size() / 2);
  EXPECT_GT(decoder.bufferedBytes(), 0u);

  decoder.reset();
  EXPECT_EQ(decoder.bufferedBytes(), 0u);
  EXPECT_EQ(decoder.next().status, DecodeStatus::NeedMoreData);
}

// Factory methods

TEST(P2PMessage, FactoryMethods)
{
  EXPECT_EQ(Message::ping().type, MessageType::Ping);
  EXPECT_EQ(Message::pong().type, MessageType::Pong);
  EXPECT_EQ(Message::verack().type, MessageType::Verack);
  EXPECT_EQ(Message::getPeers().type, MessageType::GetPeers);
  EXPECT_EQ(Message::disconnect().type, MessageType::Disconnect);

  EXPECT_TRUE(Message::ping().payload.empty());
  EXPECT_TRUE(Message::pong().payload.empty());
}