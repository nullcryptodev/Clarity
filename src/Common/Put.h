#pragma once

#include <vector>
#include <cstdint>

namespace Common
{
  inline void putU8(std::vector<uint8_t> &out, uint8_t v)
  {
    out.push_back(v);
  }

  inline void putU16(std::vector<uint8_t> &out, uint16_t v)
  {
    out.push_back(uint8_t(v));
    out.push_back(uint8_t(v >> 8));
  }

  inline void putU32(std::vector<uint8_t> &out, uint32_t v)
  {
    for (int i = 0; i < 4; ++i)
      out.push_back(uint8_t(v >> (i * 8)));
  }

  inline void putU64(std::vector<uint8_t> &out, uint64_t v)
  {
    for (int i = 0; i < 8; ++i)
      out.push_back(uint8_t(v >> (i * 8)));
  }

  inline void putBytes(std::vector<uint8_t> &out, const uint8_t *p, size_t n)
  {
    out.insert(out.end(), p, p + n);
  }
}