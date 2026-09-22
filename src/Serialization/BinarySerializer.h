// Binary/BinarySerializer.hpp
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <stdexcept>

#include "ISerializer.h"
#include "IStream.h"

#include "Common/Varint.h"

namespace Serialization
{

  /**
   * @brief Binary serializer (unified input/output)
   *
   * Implements binary serialization using varint encoding for integers.
   * Supports both input and output modes with the same class.
   */
  class BinarySerializer : public ISerializer
  {
  public:
    // ========================================================================
    // Constructors
    // ========================================================================

    /// Create an input serializer (reading from stream)
    explicit BinarySerializer(IInputStream &stream)
        : m_mode(InternalMode::Input), m_inputStream(&stream) {}

    /// Create an output serializer (writing to stream)
    explicit BinarySerializer(IOutputStream &stream)
        : m_mode(InternalMode::Output), m_outputStream(&stream) {}

    // ========================================================================
    // ISerializer Interface
    // ========================================================================

    InternalMode mode() const override { return m_mode; }

    bool beginObject(std::string_view name) override { return true; }
    void endObject() override {}

    bool beginArray(size_t &size, std::string_view name) override
    {
      if (isInput())
      {
        uint64_t temp;
        readVarint(temp);
        size = static_cast<size_t>(temp);
        if (size > MAX_ARRAY_SIZE)
        {
          throw std::runtime_error("Array size too large: " + std::to_string(size));
        }
      }
      else
      {
        writeVarint(size);
      }
      return true;
    }

    void endArray() override {}

    // ========================================================================
    // Primitive Serialization
    // ========================================================================

    bool operator()(uint8_t &value, std::string_view name) override
    {
      if (isInput())
        readVarint(value);
      else
        writeVarint(value);
      return true;
    }

    bool operator()(int16_t &value, std::string_view name) override
    {
      if (isInput())
      {
        uint16_t temp;
        readVarint(temp);
        value = static_cast<int16_t>(temp);
      }
      else
      {
        writeVarint(static_cast<uint16_t>(value));
      }
      return true;
    }

    bool operator()(uint16_t &value, std::string_view name) override
    {
      if (isInput())
        readVarint(value);
      else
        writeVarint(value);
      return true;
    }

    bool operator()(int32_t &value, std::string_view name) override
    {
      if (isInput())
      {
        uint32_t temp;
        readVarint(temp);
        value = static_cast<int32_t>(temp);
      }
      else
      {
        writeVarint(static_cast<uint32_t>(value));
      }
      return true;
    }

    bool operator()(uint32_t &value, std::string_view name) override
    {
      if (isInput())
        readVarint(value);
      else
        writeVarint(value);
      return true;
    }

    bool operator()(int64_t &value, std::string_view name) override
    {
      if (isInput())
      {
        uint64_t temp;
        readVarint(temp);
        value = static_cast<int64_t>(temp);
      }
      else
      {
        writeVarint(static_cast<uint64_t>(value));
      }
      return true;
    }

    bool operator()(uint64_t &value, std::string_view name) override
    {
      if (isInput())
        readVarint(value);
      else
        writeVarint(value);
      return true;
    }

    bool operator()(float &value, std::string_view name) override
    {
      throw std::runtime_error("Float serialization not supported in binary format");
      return false;
    }

    bool operator()(double &value, std::string_view name) override
    {
      throw std::runtime_error("Double serialization not supported in binary format");
      return false;
    }

    bool operator()(bool &value, std::string_view name) override
    {
      if (isInput())
      {
        uint8_t byte;
        readPod(byte);
        value = (byte != 0);
      }
      else
      {
        uint8_t byte = value ? 1 : 0;
        writePod(byte);
      }
      return true;
    }

    bool operator()(std::string &value, std::string_view name) override
    {
      if (isInput())
      {
        uint64_t size;
        readVarint(size);
        if (size > MAX_STRING_SIZE)
        {
          throw std::runtime_error("String size too large: " + std::to_string(size));
        }
        value.resize(static_cast<size_t>(size));
        if (size > 0)
        {
          readExact(value.data(), static_cast<size_t>(size));
        }
      }
      else
      {
        writeVarint(value.size());
        writeExact(value.data(), value.size());
      }
      return true;
    }

    bool binary(void *value, size_t size, std::string_view name) override
    {
      if (size == 0)
        return true;
      if (isInput())
      {
        readExact(static_cast<char *>(value), size);
      }
      else
      {
        writeExact(static_cast<const char *>(value), size);
      }
      return true;
    }

    bool binary(std::string &value, std::string_view name) override
    {
      return (*this)(value, name);
    }

  private:
    // ========================================================================
    // Constants
    // ========================================================================

    static constexpr size_t MAX_ARRAY_SIZE = 128 * 1024 * 1024;
    static constexpr size_t MAX_STRING_SIZE = 128 * 1024 * 1024;

    // ========================================================================
    // Member Variables
    // ========================================================================

    InternalMode m_mode;
    IInputStream *m_inputStream = nullptr;
    IOutputStream *m_outputStream = nullptr;

    // ========================================================================
    // Helper Methods
    // ========================================================================

    bool isInput() const { return m_mode == InternalMode::Input; }
    bool isOutput() const { return m_mode == InternalMode::Output; }

    IInputStream &input() const
    {
      if (!m_inputStream)
        throw std::runtime_error("Not in input mode");
      return *m_inputStream;
    }

    IOutputStream &output() const
    {
      if (!m_outputStream)
        throw std::runtime_error("Not in output mode");
      return *m_outputStream;
    }

    // Read/Write POD
    template <typename T>
    void readPod(T &value)
    {
      input().readExact(reinterpret_cast<char *>(&value), sizeof(T));
    }

    template <typename T>
    void writePod(const T &value)
    {
      output().write(reinterpret_cast<const char *>(&value), sizeof(T));
    }

    // Read/Write varint
    template <typename T>
    void readVarint(T &value)
    {
      uint8_t byte;
      T result = 0;
      int shift = 0;

      do
      {
        readPod(byte);
        result |= static_cast<T>(byte & 0x7F) << shift;
        shift += 7;
      } while ((byte & 0x80) != 0 && shift < static_cast<int>(sizeof(T) * 8));

      value = result;
    }

    template <typename T>
    void writeVarint(T value)
    {
      while (value >= 0x80)
      {
        uint8_t byte = static_cast<uint8_t>((value & 0x7F) | 0x80);
        writePod(byte);
        value >>= 7;
      }
      writePod(static_cast<uint8_t>(value));
    }

    // Read/Write exact bytes
    void readExact(char *buffer, size_t size)
    {
      input().readExact(buffer, size);
    }

    void writeExact(const char *data, size_t size)
    {
      output().write(data, size);
    }
  };

} // namespace Serialization