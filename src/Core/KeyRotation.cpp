// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "KeyRotation.h"

#include "Common/Wire.h"

#include <cstring>

namespace Core
{
  std::vector<uint8_t> encodeKeyHistory(
      const std::vector<KeyRotation> &history)
  {
    std::vector<uint8_t> out;
    out.reserve(4 + history.size() * KEY_ROTATION_WIRE_SIZE);

    Common::Writer w(out);

    w.writeU32(static_cast<uint32_t>(history.size()));

    for (const auto &entry : history)
    {
      w.writeBytes(entry.key.data.data(), entry.key.data.size());
      w.writeU64(entry.valid_from_height);
      w.writeU64(entry.valid_until_height);
    }

    return out;
  }

  bool decodeKeyHistory(const uint8_t *data, size_t len,
                        std::vector<KeyRotation> &out)
  {
    out.clear();

    if (len < 4)
      return false;

    Common::Reader r(data, len);

    const uint32_t count = r.readU32();
    if (!r.ok())
      return false;

    //  Guard against an absurd count before the size check, so a
    //  hostile length can't trigger a huge reserve.
    constexpr uint32_t MAX_KEY_ROTATIONS = 1024;
    if (count > MAX_KEY_ROTATIONS)
      return false;

    const size_t expected = 4 + static_cast<size_t>(count) *
                                    KEY_ROTATION_WIRE_SIZE;
    if (len != expected)
      return false;

    out.reserve(count);

    for (uint32_t i = 0; i < count; ++i)
    {
      KeyRotation entry;
      r.readBytes(entry.key.data.data(), entry.key.data.size());
      entry.valid_from_height = r.readU64();
      entry.valid_until_height = r.readU64();
      if (!r.ok())
        return false;
      out.push_back(entry);
    }

    return true;
  }
} // namespace Core