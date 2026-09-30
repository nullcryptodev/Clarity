// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "SyncMessages.h"

#include "Common/Wire.h"

#include <cstring>

namespace P2P
{
  // ---- Headers ----

  std::vector<uint8_t> serializeHeaders(const HeadersMessage &m)
  {
    // Cap the declared count. A malformed caller (or a bug) shouldn't
    // be able to produce a message the peer will reject; truncating is
    // the same behavior the deserializer enforces on the wire.
    const uint32_t count = static_cast<uint32_t>(
        m.entries.size() > MAX_HEADERS_PER_REQUEST ? MAX_HEADERS_PER_REQUEST
                                                   : m.entries.size());

    std::vector<uint8_t> out;
    out.reserve(4 + count * 40);

    Common::Writer w(out);
    w.writeU32(count);

    for (uint32_t i = 0; i < count; ++i)
    {
      w.writeU64(m.entries[i].height);
      w.writeBytes(m.entries[i].hash.data.data(), m.entries[i].hash.data.size());
    }

    return out;
  }

  bool deserializeHeaders(const uint8_t *data, size_t len, HeadersMessage &out)
  {
    Common::Reader r(data, len);

    const uint32_t count = r.readU32();
    if (!r.ok())
      return false;

    // Reject before allocating.
    if (count > MAX_HEADERS_PER_REQUEST)
      return false;

    // Guard against a declared count that can't possibly fit in the
    // remaining payload. 40 bytes per entry is the minimum.
    if (static_cast<uint64_t>(count) * 40ull > static_cast<uint64_t>(len))
      return false;

    out.entries.clear();
    out.entries.reserve(count);

    for (uint32_t i = 0; i < count && r.ok(); ++i)
    {
      HeadersEntry e;
      e.height = r.readU64();
      r.readBytes(e.hash.data.data(), e.hash.data.size());
      if (!r.ok())
        return false;
      out.entries.push_back(e);
    }

    return r.ok();
  }

  // ---- GetBlocks ----

  std::vector<uint8_t> serializeGetBlocks(const GetBlocksMessage &m)
  {
    const uint32_t count = static_cast<uint32_t>(
        m.hashes.size() > MAX_BLOCKS_PER_REQUEST ? MAX_BLOCKS_PER_REQUEST
                                                 : m.hashes.size());

    std::vector<uint8_t> out;
    out.reserve(4 + count * 32);

    Common::Writer w(out);
    w.writeU32(count);

    for (uint32_t i = 0; i < count; ++i)
      w.writeBytes(m.hashes[i].data.data(), m.hashes[i].data.size());

    return out;
  }

  bool deserializeGetBlocks(const uint8_t *data, size_t len, GetBlocksMessage &out)
  {
    Common::Reader r(data, len);

    const uint32_t count = r.readU32();
    if (!r.ok())
      return false;

    if (count > MAX_BLOCKS_PER_REQUEST)
      return false;

    if (static_cast<uint64_t>(count) * 32ull > static_cast<uint64_t>(len))
      return false;

    out.hashes.clear();
    out.hashes.reserve(count);

    for (uint32_t i = 0; i < count && r.ok(); ++i)
    {
      Crypto::Hash h;
      r.readBytes(h.data.data(), h.data.size());
      if (!r.ok())
        return false;
      out.hashes.push_back(h);
    }

    return r.ok();
  }

  // ---- Blocks ----

  std::vector<uint8_t> serializeBlocks(const BlocksMessage &m)
  {
    const uint32_t count = static_cast<uint32_t>(
        m.blocks.size() > MAX_BLOCKS_PER_REQUEST ? MAX_BLOCKS_PER_REQUEST
                                                 : m.blocks.size());

    std::vector<uint8_t> out;

    Common::Writer w(out);
    w.writeU32(count);

    for (uint32_t i = 0; i < count; ++i)
    {
      std::vector<uint8_t> bytes = m.blocks[i].serialize();
      w.writeU32(static_cast<uint32_t>(bytes.size()));
      w.writeBytes(bytes.data(), bytes.size());
    }

    return out;
  }

  bool deserializeBlocks(const uint8_t *data, size_t len, BlocksMessage &out)
  {
    Common::Reader r(data, len);

    const uint32_t count = r.readU32();
    if (!r.ok())
      return false;

    if (count > MAX_BLOCKS_PER_REQUEST)
      return false;

    out.blocks.clear();
    out.blocks.reserve(count);

    for (uint32_t i = 0; i < count && r.ok(); ++i)
    {
      const uint32_t block_len = r.readU32();
      if (!r.ok())
        return false;

      // Guard: block_len must fit in the remaining payload.
      // Common::Reader::readBytes will fail if it doesn't, but we
      // also want to reject absurd lengths before allocating.
      if (static_cast<uint64_t>(block_len) > static_cast<uint64_t>(len))
        return false;

      if (block_len == 0)
        return false; // a zero-length block is malformed

      std::vector<uint8_t> block_bytes(block_len);
      r.readBytes(block_bytes.data(), block_len);
      if (!r.ok())
        return false;

      Core::Block b;
      if (!Core::Block::deserialize(block_bytes.data(), block_bytes.size(), b))
        return false;

      out.blocks.push_back(std::move(b));
    }

    return r.ok();
  }

  // ---- Sizing ----

  uint32_t maxBlocksPerRequest(uint64_t max_block_bytes) noexcept
  {
    // Worst-case serialized block size, plus the 4-byte length prefix.
    const uint64_t per_block = max_block_bytes + 4;

    if (per_block == 0 || per_block > MAX_MESSAGE_SIZE)
      return 1;

    const uint64_t fit = MAX_MESSAGE_SIZE / per_block;
    if (fit == 0)
      return 1;

    return fit < MAX_BLOCKS_PER_REQUEST
               ? static_cast<uint32_t>(fit)
               : MAX_BLOCKS_PER_REQUEST;
  }

} // namespace P2P