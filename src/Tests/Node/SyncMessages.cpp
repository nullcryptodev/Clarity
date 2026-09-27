// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <vector>

#include "P2P/SyncMessages.h"

#include "Core/Block.h"
#include "Crypto/Types.h"

namespace
{
  Crypto::Hash makeHash(uint8_t seed)
  {
    Crypto::Hash h;
    for (size_t i = 0; i < h.data.size(); ++i)
      h.data[i] = uint8_t(seed + i);
    return h;
  }

  Core::Block makeEmptyBlock(uint64_t height)
  {
    Core::Block b;
    b.header.version = 1;
    b.header.chain_id = 0x434C5247;
    b.header.height = height;
    b.header.parent_hash = makeHash(uint8_t(height));
    b.header.timestamp_ms = 1'700'000'000'000ULL + height * 1000;
    return b;
  }
} // anonymous namespace

// ============================================================================
//  Headers
// ============================================================================

TEST(Node_SyncMessages, HeadersRoundTrip)
{
  P2P::HeadersMessage in;
  for (uint32_t i = 0; i < 10; ++i)
    in.entries.push_back({1000 + i, makeHash(uint8_t(i))});

  auto bytes = P2P::serializeHeaders(in);
  ASSERT_EQ(bytes.size(), 4u + 10u * 40u);

  P2P::HeadersMessage out;
  ASSERT_TRUE(P2P::deserializeHeaders(bytes.data(), bytes.size(), out));

  ASSERT_EQ(out.entries.size(), in.entries.size());
  for (size_t i = 0; i < out.entries.size(); ++i)
  {
    EXPECT_EQ(out.entries[i].height, in.entries[i].height);
    EXPECT_EQ(out.entries[i].hash, in.entries[i].hash);
  }
}

TEST(Node_SyncMessages, HeadersEmptyRoundTrip)
{
  P2P::HeadersMessage in; // no entries

  auto bytes = P2P::serializeHeaders(in);
  ASSERT_EQ(bytes.size(), 4u);

  P2P::HeadersMessage out;
  ASSERT_TRUE(P2P::deserializeHeaders(bytes.data(), bytes.size(), out));
  EXPECT_TRUE(out.entries.empty());
}

TEST(Node_SyncMessages, HeadersRejectsOversizeCount)
{
  // Forge a payload with count = MAX_HEADERS_PER_REQUEST + 1 and no
  // actual entries. The deserializer must reject on the count alone,
  // before attempting to reserve.
  std::vector<uint8_t> bytes(4, 0);
  uint32_t count = P2P::MAX_HEADERS_PER_REQUEST + 1;
  bytes[0] = uint8_t(count);
  bytes[1] = uint8_t(count >> 8);
  bytes[2] = uint8_t(count >> 16);
  bytes[3] = uint8_t(count >> 24);

  P2P::HeadersMessage out;
  EXPECT_FALSE(P2P::deserializeHeaders(bytes.data(), bytes.size(), out));
}

TEST(Node_SyncMessages, HeadersRejectsTruncatedPayload)
{
  P2P::HeadersMessage in;
  in.entries.push_back({1000, makeHash(0)});
  in.entries.push_back({1001, makeHash(1)});

  auto bytes = P2P::serializeHeaders(in);
  bytes.resize(bytes.size() - 1); // truncate mid-entry

  P2P::HeadersMessage out;
  EXPECT_FALSE(P2P::deserializeHeaders(bytes.data(), bytes.size(), out));
}

TEST(Node_SyncMessages, HeadersRejectsDeclaredCountLargerThanPayload)
{
  // Payload claims 100 entries but only carries 40 bytes (1 entry's
  // worth). Must reject without allocating.
  std::vector<uint8_t> bytes(4 + 40, 0);
  uint32_t count = 100;
  bytes[0] = uint8_t(count);
  bytes[1] = uint8_t(count >> 8);
  bytes[2] = uint8_t(count >> 16);
  bytes[3] = uint8_t(count >> 24);

  P2P::HeadersMessage out;
  EXPECT_FALSE(P2P::deserializeHeaders(bytes.data(), bytes.size(), out));
}

// ============================================================================
//  GetBlocks
// ============================================================================

TEST(Node_SyncMessages, GetBlocksRoundTrip)
{
  P2P::GetBlocksMessage in;
  for (uint32_t i = 0; i < 5; ++i)
    in.hashes.push_back(makeHash(uint8_t(i * 7)));

  auto bytes = P2P::serializeGetBlocks(in);
  ASSERT_EQ(bytes.size(), 4u + 5u * 32u);

  P2P::GetBlocksMessage out;
  ASSERT_TRUE(P2P::deserializeGetBlocks(bytes.data(), bytes.size(), out));
  ASSERT_EQ(out.hashes.size(), in.hashes.size());
  for (size_t i = 0; i < out.hashes.size(); ++i)
    EXPECT_EQ(out.hashes[i], in.hashes[i]);
}

TEST(Node_SyncMessages, GetBlocksRejectsOversizeCount)
{
  std::vector<uint8_t> bytes(4, 0);
  uint32_t count = P2P::MAX_BLOCKS_PER_REQUEST + 1;
  bytes[0] = uint8_t(count);
  bytes[1] = uint8_t(count >> 8);
  bytes[2] = uint8_t(count >> 16);
  bytes[3] = uint8_t(count >> 24);

  P2P::GetBlocksMessage out;
  EXPECT_FALSE(P2P::deserializeGetBlocks(bytes.data(), bytes.size(), out));
}

TEST(Node_SyncMessages, GetBlocksRejectsTruncatedPayload)
{
  P2P::GetBlocksMessage in;
  in.hashes.push_back(makeHash(0));
  in.hashes.push_back(makeHash(1));

  auto bytes = P2P::serializeGetBlocks(in);
  bytes.resize(bytes.size() - 1);

  P2P::GetBlocksMessage out;
  EXPECT_FALSE(P2P::deserializeGetBlocks(bytes.data(), bytes.size(), out));
}

// ============================================================================
//  Blocks
// ============================================================================

TEST(Node_SyncMessages, BlocksRoundTrip)
{
  P2P::BlocksMessage in;
  in.blocks.push_back(makeEmptyBlock(1));
  in.blocks.push_back(makeEmptyBlock(2));

  auto bytes = P2P::serializeBlocks(in);
  ASSERT_GT(bytes.size(), 4u);

  P2P::BlocksMessage out;
  ASSERT_TRUE(P2P::deserializeBlocks(bytes.data(), bytes.size(), out));
  ASSERT_EQ(out.blocks.size(), in.blocks.size());
  for (size_t i = 0; i < out.blocks.size(); ++i)
  {
    EXPECT_EQ(out.blocks[i].header.height, in.blocks[i].header.height);
    EXPECT_EQ(out.blocks[i].header.parent_hash, in.blocks[i].header.parent_hash);
  }
}

TEST(Node_SyncMessages, BlocksEmptyRoundTrip)
{
  P2P::BlocksMessage in;
  auto bytes = P2P::serializeBlocks(in);
  ASSERT_EQ(bytes.size(), 4u);

  P2P::BlocksMessage out;
  ASSERT_TRUE(P2P::deserializeBlocks(bytes.data(), bytes.size(), out));
  EXPECT_TRUE(out.blocks.empty());
}

TEST(Node_SyncMessages, BlocksRejectsOversizeCount)
{
  std::vector<uint8_t> bytes(4, 0);
  uint32_t count = P2P::MAX_BLOCKS_PER_REQUEST + 1;
  bytes[0] = uint8_t(count);
  bytes[1] = uint8_t(count >> 8);
  bytes[2] = uint8_t(count >> 16);
  bytes[3] = uint8_t(count >> 24);

  P2P::BlocksMessage out;
  EXPECT_FALSE(P2P::deserializeBlocks(bytes.data(), bytes.size(), out));
}

TEST(Node_SyncMessages, BlocksRejectsDeclaredLengthLargerThanPayload)
{
  // Forge a Blocks payload claiming one block of 10 MB, in a 100-byte
  // buffer. Must reject without allocating.
  std::vector<uint8_t> bytes;
  bytes.push_back(1); // count = 1
  bytes.push_back(0);
  bytes.push_back(0);
  bytes.push_back(0);
  uint32_t bogus_len = 10 * 1024 * 1024;
  bytes.push_back(uint8_t(bogus_len));
  bytes.push_back(uint8_t(bogus_len >> 8));
  bytes.push_back(uint8_t(bogus_len >> 16));
  bytes.push_back(uint8_t(bogus_len >> 24));
  bytes.resize(100, 0); // rest is zeros

  P2P::BlocksMessage out;
  EXPECT_FALSE(P2P::deserializeBlocks(bytes.data(), bytes.size(), out));
}

TEST(Node_SyncMessages, BlocksRejectsZeroLengthBlock)
{
  std::vector<uint8_t> bytes;
  bytes.push_back(1); // count = 1
  bytes.push_back(0);
  bytes.push_back(0);
  bytes.push_back(0);
  bytes.push_back(0); // block_len = 0
  bytes.push_back(0);
  bytes.push_back(0);
  bytes.push_back(0);

  P2P::BlocksMessage out;
  EXPECT_FALSE(P2P::deserializeBlocks(bytes.data(), bytes.size(), out));
}

TEST(Node_SyncMessages, BlocksRejectsMalformedBlockBytes)
{
  // Valid framing, but the block bytes are garbage — Block::deserialize
  // must fail.
  std::vector<uint8_t> bytes;
  bytes.push_back(1); // count = 1
  bytes.push_back(0);
  bytes.push_back(0);
  bytes.push_back(0);
  uint32_t len = 16;
  bytes.push_back(uint8_t(len));
  bytes.push_back(uint8_t(len >> 8));
  bytes.push_back(uint8_t(len >> 16));
  bytes.push_back(uint8_t(len >> 24));
  for (int i = 0; i < 16; ++i)
    bytes.push_back(0xAB);

  P2P::BlocksMessage out;
  EXPECT_FALSE(P2P::deserializeBlocks(bytes.data(), bytes.size(), out));
}

// ============================================================================
//  Sizing
// ============================================================================

TEST(Node_SyncMessages, MaxBlocksPerRequestDefaultConfig)
{
  // Default max_block_bytes = 256 KiB, MAX_MESSAGE_SIZE = 16 MiB.
  // (16 MiB) / (256 KiB + 4) = 63.99..., floor = 63.
  EXPECT_EQ(P2P::maxBlocksPerRequest(256 * 1024), 63u);
}

TEST(Node_SyncMessages, MaxBlocksPerRequestCapsAtHardLimit)
{
  // Tiny blocks: the hard cap applies.
  EXPECT_EQ(P2P::maxBlocksPerRequest(1), P2P::MAX_BLOCKS_PER_REQUEST);
}

TEST(Node_SyncMessages, MaxBlocksPerRequestReturnsAtLeastOne)
{
  // Pathological: max_block_bytes >= MAX_MESSAGE_SIZE. Must still
  // return 1 — requesting one block always makes progress.
  EXPECT_EQ(P2P::maxBlocksPerRequest(P2P::MAX_MESSAGE_SIZE), 1u);
  EXPECT_EQ(P2P::maxBlocksPerRequest(P2P::MAX_MESSAGE_SIZE * 2), 1u);
  EXPECT_EQ(P2P::maxBlocksPerRequest(0), P2P::MAX_BLOCKS_PER_REQUEST);
}