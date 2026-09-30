// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

// Wire format helpers: little-endian, no padding, no framing.
//
// Three layers, bottom to top:
//
//   1. read*/put* primitives
//        pure functions over a raw pointer or vector, no state, no bounds
//        checking. Use these when you already know the data is in range
//        (e.g. fixed-size stack buffers, or a size you checked yourself).
//
//   2. Reader
//        a bounds-checked cursor over a byte range. Every read advances
//        the cursor and sets error_ on underflow. Call ok() once after a
//        batch of reads instead of checking each return value.
//
//   3. Writer
//        the mirror of Reader over a growing std::vector<uint8_t>.
//        It cannot run out of room; ok() exists only so call sites look
//        symmetric with Reader. See the class comment for the one case
//        that can fail.
//
// All multi-byte values are little-endian.
// Nothing in this header does endianness conversion for big-endian hosts.
// If that ever matters, it matters here and only here.

namespace Common
{
  //  Primitives

  inline uint8_t readU8(const uint8_t *p) noexcept
  {
    return p[0];
  }

  inline uint16_t readU16(const uint8_t *p) noexcept
  {
    return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
  }

  inline uint32_t readU32(const uint8_t *p) noexcept
  {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) |
           (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
  }

  inline uint64_t readU64(const uint8_t *p) noexcept
  {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
      v |= uint64_t(p[i]) << (i * 8);
    return v;
  }

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
    out.push_back(uint8_t(v));
    out.push_back(uint8_t(v >> 8));
    out.push_back(uint8_t(v >> 16));
    out.push_back(uint8_t(v >> 24));
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

  class Reader
  {
  public:
    Reader(const uint8_t *data, size_t len) noexcept
        : p_(data), end_(data + len) {}

    bool ok() const noexcept { return !error_; }

    size_t remaining() const noexcept
    {
      return static_cast<size_t>(end_ - p_);
    }

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
      uint16_t v = Common::readU16(p_);
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
      uint32_t v = Common::readU32(p_);
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
      uint64_t v = Common::readU64(p_);
      p_ += 8;
      return v;
    }

    void readBytes(uint8_t *out, size_t n)
    {
      if (remaining() < n)
      {
        error_ = true;
        return;
      }
      std::memcpy(out, p_, n);
      p_ += n;
    }

    bool skip(size_t n)
    {
      if (remaining() < n)
      {
        error_ = true;
        return false;
      }
      p_ += n;
      return true;
    }

    std::string readString(size_t n)
    {
      if (remaining() < n)
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
      // Bounds-check before allocating: a bogus wire length must not
      // trigger a huge allocation that readBytes would then reject.
      if (remaining() < n)
      {
        error_ = true;
        return {};
      }
      std::vector<uint8_t> v(n);
      std::memcpy(v.data(), p_, n);
      p_ += n;
      return v;
    }

    // Cast from uint64_t to int64_t is implementation-defined pre-C++20,
    // but every compiler we target uses two's-complement wraparound, so
    // the static_cast produces the expected value. If we ever build on
    // something exotic, switch to memcpy into an int64_t.
    int64_t readI64()
    {
      return static_cast<int64_t>(readU64());
    }

    std::string readLengthPrefixedString()
    {
      uint8_t len = readU8();
      if (!ok())
        return {};
      if (remaining() < len)
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

  // Writer cannot run out of room because the backing std::vector grows, so
  // unlike Reader there is no per-call bounds failure. The ok()/error_
  // pair exists so call sites look symmetric with Reader. The only way
  // to set error_ is writeLengthPrefixedString() with a string longer
  // than 255 bytes. If you never call that, ok() is always true.
  class Writer
  {
  public:
    explicit Writer(std::vector<uint8_t> &out) noexcept : out_(out) {}

    bool ok() const noexcept { return !error_; }

    // Bytes currently in the backing buffer. The Writer equivalent of
    // Reader::remaining() — tells you your position.
    size_t size() const noexcept { return out_.size(); }

    void writeU8(uint8_t v) { putU8(out_, v); }
    void writeU16(uint16_t v) { putU16(out_, v); }
    void writeU32(uint32_t v) { putU32(out_, v); }
    void writeU64(uint64_t v) { putU64(out_, v); }
    void writeI64(int64_t v) { putU64(out_, static_cast<uint64_t>(v)); }

    void writeBytes(const uint8_t *p, size_t n)
    {
      putBytes(out_, p, n);
    }

    void writeString(std::string_view s)
    {
      putBytes(out_, reinterpret_cast<const uint8_t *>(s.data()), s.size());
    }

    void writeVector(const std::vector<uint8_t> &v)
    {
      putBytes(out_, v.data(), v.size());
    }

    // Mirrors Reader::readLengthPrefixedString: 1-byte length, then
    // bytes. Caps at 255 bytes. Sets error_ and writes nothing if longer.
    void writeLengthPrefixedString(std::string_view s)
    {
      if (s.size() > 255)
      {
        error_ = true;
        return;
      }
      putU8(out_, static_cast<uint8_t>(s.size()));
      putBytes(out_, reinterpret_cast<const uint8_t *>(s.data()), s.size());
    }

  private:
    std::vector<uint8_t> &out_;
    bool error_ = false;
  };

} // namespace Common