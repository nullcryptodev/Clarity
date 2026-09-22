// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <stdexcept>
#include <type_traits>
#include <vector>

namespace Serialization
{
  /**
   * @brief Input stream interface
   *
   * Provides abstract interface for reading data from various sources.
   */
  class IInputStream
  {
  public:
    virtual ~IInputStream() = default;

    /// Read data into buffer, return bytes read
    virtual size_t read(char *buffer, size_t size) = 0;

    /// Check if end of stream has been reached
    virtual bool eof() const = 0;

    /// Read exact number of bytes or throw
    void readExact(char *buffer, size_t size)
    {
      size_t bytesRead = read(buffer, size);
      if (bytesRead != size)
      {
        throw std::runtime_error("Failed to read exact number of bytes");
      }
    }

    /// Read a POD type
    template <typename T>
    std::enable_if_t<std::is_trivially_copyable_v<T>, void>
    read(T &value)
    {
      readExact(reinterpret_cast<char *>(&value), sizeof(T));
    }

    /// Read a string of given size
    void read(std::string &value, size_t size)
    {
      value.resize(size);
      if (size > 0)
      {
        readExact(value.data(), size);
      }
    }

    /// Read into a vector
    void read(std::vector<uint8_t> &value, size_t size)
    {
      value.resize(size);
      if (size > 0)
      {
        readExact(reinterpret_cast<char *>(value.data()), size);
      }
    }
  };

  /**
   * @brief Output stream interface
   *
   * Provides abstract interface for writing data to various destinations.
   */
  class IOutputStream
  {
  public:
    virtual ~IOutputStream() = default;

    /// Write data from buffer
    virtual void write(const char *data, size_t size) = 0;

    /// Write a POD type
    template <typename T>
    std::enable_if_t<std::is_trivially_copyable_v<T>, void>
    write(const T &value)
    {
      write(reinterpret_cast<const char *>(&value), sizeof(T));
    }

    /// Write a string view
    void write(std::string_view value)
    {
      write(value.data(), value.size());
    }

    /// Write a string
    void write(const std::string &value)
    {
      write(value.data(), value.size());
    }

    /// Write a vector
    void write(const std::vector<uint8_t> &value)
    {
      write(reinterpret_cast<const char *>(value.data()), value.size());
    }

    /// Flush any buffered data
    virtual void flush() {}
  };

} // namespace