#pragma once

#include <cstdint>
#include <string>
#include <cstring>

namespace Common
{
  class Reader
  {
  public:
    Reader(const uint8_t *data, size_t len) : p_(data), end_(data + len) {}

    bool ok() const { return !error_; }
    size_t remaining() const { return end_ - p_; }

    uint8_t readU8()
    {
      if (p_ >= end_)
      {
        error_ = true;
        return 0;
      }
      return *p_++;
    }

    uint16_t readU16()
    {
      if (end_ - p_ < 2)
      {
        error_ = true;
        return 0;
      }
      uint16_t v = uint16_t(p_[0]) | (uint16_t(p_[1]) << 8);
      p_ += 2;
      return v;
    }

    uint32_t readU32()
    {
      if (end_ - p_ < 4)
      {
        error_ = true;
        return 0;
      }
      uint32_t v = uint32_t(p_[0]) | (uint32_t(p_[1]) << 8) | (uint32_t(p_[2]) << 16) | (uint32_t(p_[3]) << 24);
      p_ += 4;
      return v;
    }

    uint64_t readU64()
    {
      if (end_ - p_ < 8)
      {
        error_ = true;
        return 0;
      }
      uint64_t v = 0;
      for (int i = 0; i < 8; ++i)
        v |= uint64_t(p_[i]) << (i * 8);
      p_ += 8;
      return v;
    }

    void readBytes(uint8_t *out, size_t n)
    {
      if (end_ - p_ < (ptrdiff_t)n)
      {
        error_ = true;
        return;
      }
      std::memcpy(out, p_, n);
      p_ += n;
    }

    std::string readString(size_t n)
    {
      if (end_ - p_ < (ptrdiff_t)n)
      {
        error_ = true;
        return {};
      }
      std::string s(reinterpret_cast<const char *>(p_), n);
      p_ += n;
      return s;
    }

    std::vector<uint8_t> readVector(size_t n)
    {
      std::vector<uint8_t> v(n);
      readBytes(v.data(), n);
      return v;
    }

    int64_t readI64()
    {
      return static_cast<int64_t>(readU64());
    }

    std::string readLengthPrefixedString()
    {
      uint8_t len = readU8();
      if (error_ || end_ - p_ < len)
      {
        error_ = true;
        return {};
      }
      std::string s(reinterpret_cast<const char *>(p_), len);
      p_ += len;
      return s;
    }

  private:
    const uint8_t *p_;
    const uint8_t *end_;
    bool error_ = false;
  };
}