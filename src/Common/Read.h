#pragma once

#include <cstdint>

namespace Common
{
  inline uint8_t readU8(const uint8_t *p)
  {
    return p[0];
  }

  inline uint16_t readU16(const uint8_t *p) noexcept
  {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
  }

  inline uint32_t readU32(const uint8_t *p) noexcept
  {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
  }

  inline uint64_t readU64(const uint8_t *p) noexcept
  {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
      v |= uint64_t(p[i]) << (i * 8);
    return v;
  }
} // namespace Common
