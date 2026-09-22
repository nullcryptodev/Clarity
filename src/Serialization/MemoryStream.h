// Streams/MemoryStream.hpp
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <vector>
#include <cstring>
#include <cstdint>
#include <string_view>

#include "IStream.h"

namespace Serialization
{
  /**
   * @brief Memory-based input stream
   *
   * Reads from a memory buffer.
   */
  class MemoryInputStream : public IInputStream
  {
  public:
    MemoryInputStream() = default;

    MemoryInputStream(const uint8_t *data, size_t size)
    {
      init(data, size);
    }

    MemoryInputStream(const char *data, size_t size)
    {
      init(reinterpret_cast<const uint8_t *>(data), size);
    }

    explicit MemoryInputStream(std::string_view data)
    {
      init(reinterpret_cast<const uint8_t *>(data.data()), data.size());
    }

    explicit MemoryInputStream(const std::vector<uint8_t> &data)
    {
      init(data.data(), data.size());
    }

    void init(const uint8_t *data, size_t size)
    {
      m_data = data;
      m_size = size;
      m_pos = 0;
    }

    size_t read(char *buffer, size_t size) override
    {
      size_t bytesToRead = std::min(size, m_size - m_pos);
      if (bytesToRead > 0)
      {
        std::memcpy(buffer, m_data + m_pos, bytesToRead);
        m_pos += bytesToRead;
      }
      return bytesToRead;
    }

    bool eof() const override
    {
      return m_pos >= m_size;
    }

    /// Get current position
    size_t tell() const { return m_pos; }

    /// Seek to position
    void seek(size_t pos)
    {
      if (pos > m_size)
      {
        throw std::runtime_error("Seek position out of bounds");
      }
      m_pos = pos;
    }

    /// Get remaining bytes
    size_t remaining() const { return m_size - m_pos; }

  private:
    const uint8_t *m_data = nullptr;
    size_t m_size = 0;
    size_t m_pos = 0;
  };

  /**
   * @brief Memory-based output stream
   *
   * Writes to a memory buffer.
   */
  class MemoryOutputStream : public IOutputStream
  {
  public:
    MemoryOutputStream() = default;
    explicit MemoryOutputStream(std::vector<uint8_t> &buffer) : m_buffer(&buffer) {}

    void setBuffer(std::vector<uint8_t> &buffer)
    {
      m_buffer = &buffer;
    }

    void write(const char *data, size_t size) override
    {
      if (!m_buffer)
      {
        throw std::runtime_error("No buffer set for MemoryOutputStream");
      }
      m_buffer->insert(m_buffer->end(), data, data + size);
    }

    void flush() override {}

    /// Get current data as string
    std::string str() const
    {
      return m_buffer ? std::string(m_buffer->begin(), m_buffer->end()) : std::string();
    }

    /// Get current data as string_view
    std::string_view view() const
    {
      return m_buffer ? std::string_view(
                            reinterpret_cast<const char *>(m_buffer->data()),
                            m_buffer->size())
                      : std::string_view();
    }

    /// Clear the buffer
    void clear()
    {
      if (m_buffer)
      {
        m_buffer->clear();
      }
    }

    /// Get buffer size
    size_t size() const
    {
      return m_buffer ? m_buffer->size() : 0;
    }

  private:
    std::vector<uint8_t> *m_buffer = nullptr;
  };

} // namespace Serialization