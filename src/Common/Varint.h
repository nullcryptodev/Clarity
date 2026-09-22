// Varint.h
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <limits>
#include <string>
#include <type_traits>
#include <iterator>
#include <optional>
#include <string_view>
#include <stdexcept>
#include <cstdint>
#include <vector>

#include "Serialization/IStream.h"

namespace Common
{

  // Error Codes for Varint Operations

  enum class VarintError : uint8_t
  {
    None = 0,
    InsufficientData,
    Overflow,
    NonCanonical,
    MaxBytesExceeded
  };

  // Varint Read Result

  template <typename T>
  struct VarintReadResult
  {
    T value{};
    size_t bytesRead = 0;
    VarintError error = VarintError::None;

    bool success() const { return error == VarintError::None; }
    explicit operator bool() const { return success(); }

    T valueOrThrow() const
    {
      if (error != VarintError::None)
      {
        throw std::runtime_error("Varint decode error: " + errorToString(error));
      }
      return value;
    }

    static std::string errorToString(VarintError err)
    {
      switch (err)
      {
      case VarintError::None:
        return "None";
      case VarintError::InsufficientData:
        return "Insufficient data";
      case VarintError::Overflow:
        return "Value overflow";
      case VarintError::NonCanonical:
        return "Non-canonical encoding";
      case VarintError::MaxBytesExceeded:
        return "Maximum bytes exceeded";
      default:
        return "Unknown error";
      }
    }
  };

  // Varint Constants

  namespace VarintConstants
  {
    static constexpr int MAX_VARINT_BYTES = 10;
  }

  // Write Varint

  template <typename OutputIt, typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, void>::type
  write_varint(OutputIt dest, T value)
  {
    int bytesWritten = 0;

    while (value >= 0x80)
    {
      if (bytesWritten >= VarintConstants::MAX_VARINT_BYTES)
      {
        throw std::runtime_error(
            "Varint exceeds maximum length of " +
            std::to_string(VarintConstants::MAX_VARINT_BYTES) + " bytes");
      }
      *dest++ = static_cast<char>((value & 0x7f) | 0x80);
      value >>= 7;
      bytesWritten++;
    }
    *dest++ = static_cast<char>(value);
  }

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, std::string>::type
  to_varint(T value)
  {
    std::string result;
    result.reserve(VarintConstants::MAX_VARINT_BYTES);
    write_varint(std::back_inserter(result), value);
    return result;
  }

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, size_t>::type
  write_varint_to_buffer(T value, uint8_t *buffer)
  {
    size_t bytesWritten = 0;

    while (value >= 0x80)
    {
      if (bytesWritten >= VarintConstants::MAX_VARINT_BYTES)
      {
        throw std::runtime_error("Varint exceeds maximum length");
      }
      buffer[bytesWritten++] = static_cast<uint8_t>((value & 0x7f) | 0x80);
      value >>= 7;
    }
    buffer[bytesWritten++] = static_cast<uint8_t>(value);

    return bytesWritten;
  }

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, void>::type
  write_varint_to_vector(T value, std::vector<uint8_t> &out)
  {
    size_t oldSize = out.size();
    out.resize(oldSize + VarintConstants::MAX_VARINT_BYTES);
    size_t written = write_varint_to_buffer(value, out.data() + oldSize);
    out.resize(oldSize + written);
  }

  // Read Varint

  template <typename InputIt, typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, VarintReadResult<T>>::type
  read_varint(InputIt &first, InputIt last)
  {
    T value = 0;
    size_t bytesRead = 0;
    int shift = 0;
    constexpr int maxBits = std::numeric_limits<T>::digits;

    while (true)
    {
      if (first == last)
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::InsufficientData};
      }

      if (bytesRead >= VarintConstants::MAX_VARINT_BYTES)
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::MaxBytesExceeded};
      }

      unsigned char byte = static_cast<unsigned char>(*first);
      ++first;
      ++bytesRead;

      // FIX: check `shift >= maxBits` (not maxBits - 1). For uint64_t,
      // shift can legitimately be 63 on the final byte. Only shifting
      // *past* maxBits is an error.
      if (shift >= maxBits)
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::Overflow};
      }

      // Overflow check: does the final byte contribute bits that don't fit?
      if (shift + 7 >= maxBits && byte >= (1 << (maxBits - shift)))
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::Overflow};
      }

      // Reject non-canonical encoding (trailing zeros).
      if (byte == 0 && shift != 0)
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::NonCanonical};
      }

      value |= static_cast<T>(byte & 0x7f) << shift;

      if ((byte & 0x80) == 0)
      {
        break;
      }

      shift += 7;
    }

    return VarintReadResult<T>{value, bytesRead, VarintError::None};
  }

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, VarintReadResult<T>>::type
  read_varint_from_string(std::string_view data)
  {
    const char *it = data.data();
    const char *end = data.data() + data.size();
    return read_varint<const char *, T>(it, end);
  }

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, VarintReadResult<T>>::type
  read_varint_from_buffer(const uint8_t *data, size_t size)
  {
    const uint8_t *it = data;
    const uint8_t *end = data + size;
    return read_varint<const uint8_t *, T>(it, end);
  }

  template <typename InputIt, typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, T>::type
  read_varint_or_throw(InputIt &first, InputIt last)
  {
    auto result = read_varint<InputIt, T>(first, last);
    if (result.error != VarintError::None)
    {
      throw std::runtime_error(
          "Failed to read varint: " + VarintReadResult<T>::errorToString(result.error));
    }
    return result.value;
  }

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, size_t>::type
  varint_size(T value)
  {
    if (value == 0)
      return 1;

    size_t size = 0;
    while (value > 0)
    {
      value >>= 7;
      size++;
    }
    return size;
  }

  // Stream Integration Helper

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, VarintReadResult<T>>::type
  read_varint_from_stream(Serialization::IInputStream &stream)
  {
    T value = 0;
    size_t bytesRead = 0;
    int shift = 0;
    constexpr int maxBits = std::numeric_limits<T>::digits;

    while (true)
    {
      if (bytesRead >= VarintConstants::MAX_VARINT_BYTES)
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::MaxBytesExceeded};
      }

      unsigned char byte = 0;
      if (stream.read(reinterpret_cast<char *>(&byte), 1) != 1)
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::InsufficientData};
      }
      bytesRead++;

      // FIX: same off-by-one as `read_varint`.
      if (shift >= maxBits)
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::Overflow};
      }

      if (shift + 7 >= maxBits && byte >= (1 << (maxBits - shift)))
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::Overflow};
      }

      if (byte == 0 && shift != 0)
      {
        return VarintReadResult<T>{T(), bytesRead, VarintError::NonCanonical};
      }

      value |= static_cast<T>(byte & 0x7f) << shift;

      if ((byte & 0x80) == 0)
      {
        break;
      }

      shift += 7;
    }

    return VarintReadResult<T>{value, bytesRead, VarintError::None};
  }

  template <typename T>
  typename std::enable_if<std::is_integral<T>::value && std::is_unsigned<T>::value, void>::type
  write_varint_to_stream(Serialization::IOutputStream &stream, T value)
  {
    uint8_t buffer[VarintConstants::MAX_VARINT_BYTES];
    size_t bytesWritten = write_varint_to_buffer(value, buffer);
    stream.write(reinterpret_cast<const char *>(buffer), bytesWritten);
  }

} // namespace Common