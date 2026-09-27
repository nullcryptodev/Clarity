// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Core/Block.h"
#include "Crypto/Types.h"
#include "MessageTypes.h"

namespace P2P
{
  // Sync protocol wire formats.
  //
  // GetHeaders is declared in VersionMessage.h (it predates this file)
  // and is reused unchanged:
  //
  //     GetHeadersMessage { u64 startHeight; u32 limit; }   // 12 bytes
  //
  // The three new messages live here.
  //
  // All counts are bounded by the constants below. Deserializers reject
  // payloads whose declared count exceeds the bound, before allocating.
  // This is the guard against a peer sending `count = 0xFFFFFFFF` and
  // forcing a multi-gigabyte allocation.

  inline constexpr uint32_t MAX_HEADERS_PER_REQUEST = 2000;
  inline constexpr uint32_t MAX_BLOCKS_PER_REQUEST = 128;

  // ---- Headers ----
  //
  // Response to GetHeaders. Carries (height, hash) pairs so the
  // requester can verify the peer is answering the range it asked for:
  // a peer that claims heights [999, 1000, 1001] in response to
  // GetHeaders(startHeight=1001) is lying, and the requester can tell
  // without fetching a single block.
  //
  // Wire format:
  //     count   : u32                       (0 <= count <= MAX_HEADERS_PER_REQUEST)
  //     entries : count * [height: u64, hash: 32 bytes]
  //               40 bytes per entry, max ~80 KB.

  struct HeadersEntry
  {
    uint64_t height{0};
    Crypto::Hash hash{};
  };

  struct HeadersMessage
  {
    std::vector<HeadersEntry> entries;
  };

  std::vector<uint8_t> serializeHeaders(const HeadersMessage &m);
  bool deserializeHeaders(const uint8_t *data, size_t len, HeadersMessage &out);

  // ---- GetBlocks ----
  //
  // Request for full blocks by hash. The requester builds the hash list
  // from a previous Headers response (or from an Inv message, later).
  //
  // Wire format:
  //     count  : u32                        (0 <= count <= MAX_BLOCKS_PER_REQUEST)
  //     hashes : count * 32 bytes
  //              32 bytes per entry, max ~4 KB.

  struct GetBlocksMessage
  {
    std::vector<Crypto::Hash> hashes;
  };

  std::vector<uint8_t> serializeGetBlocks(const GetBlocksMessage &m);
  bool deserializeGetBlocks(const uint8_t *data, size_t len, GetBlocksMessage &out);

  // ---- Blocks ----
  //
  // Response to GetBlocks. Carries fully serialized blocks, in the same
  // order as the hashes in the request. A peer that doesn't have one of
  // the requested blocks simply omits it and sends the rest — the
  // requester re-requests the missing ones on the next round.
  //
  // Wire format:
  //     count   : u32                       (0 <= count <= MAX_BLOCKS_PER_REQUEST)
  //     entries : count * [length: u32, bytes: length]
  //               length is the serialized Block size, bounded by
  //               the peer's max_block_bytes (enforced on the send
  //               side by Peer::send, on the receive side by the
  //               caller's decode budget).
  //
  // The total serialized size is not capped by this format — a peer
  // could send 128 x 256 KiB = 32 MiB, which exceeds MAX_MESSAGE_SIZE.
  // The sender is responsible for staying under MAX_MESSAGE_SIZE
  // (see SyncManager::requestBlocks), and the receiver relies on the
  // existing Peer-layer max-message-size check to reject anything
  // larger.

  struct BlocksMessage
  {
    std::vector<Core::Block> blocks;
  };

  std::vector<uint8_t> serializeBlocks(const BlocksMessage &m);
  bool deserializeBlocks(const uint8_t *data, size_t len, BlocksMessage &out);

  // Compute the maximum number of full blocks that fit in one message
  // given the network's max_block_bytes. Used by SyncManager to size
  // its GetBlocks requests so the response can't overflow MAX_MESSAGE_SIZE.
  //
  // Returns 1 if the numbers are pathological (max_block_bytes close to
  // or above MAX_MESSAGE_SIZE), never 0 — requesting one block always
  // makes progress.
  uint32_t maxBlocksPerRequest(uint64_t max_block_bytes) noexcept;

} // namespace P2P