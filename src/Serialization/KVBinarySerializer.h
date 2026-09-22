// KV/KVBinarySerializer.hpp
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <cstdint>
#include <stdexcept>
#include <cstring>

#include "ISerializer.h"
#include "IStream.h"
#include "KVBinaryCommon.h"

#include "Common/Varint.h"

namespace Serialization
{

  /**
   * @brief KV Binary serializer (unified input/output)
   *
   * Implements key-value binary serialization format.
   * Supports both input and output modes with the same class.
   */
  class KVBinarySerializer : public ISerializer
  {
  public:
    // ========================================================================
    // Constructors
    // ========================================================================

    /// Create an input serializer (reading from stream)
    explicit KVBinarySerializer(IInputStream &stream);

    /// Create an output serializer (writing to stream)
    explicit KVBinarySerializer(IOutputStream &stream);

    // ========================================================================
    // ISerializer Interface
    // ========================================================================

    InternalMode mode() const override { return m_mode; }

    bool beginObject(std::string_view name) override;
    void endObject() override;

    bool beginArray(size_t &size, std::string_view name) override;
    void endArray() override;

    bool operator()(uint8_t &value, std::string_view name) override;
    bool operator()(int16_t &value, std::string_view name) override;
    bool operator()(uint16_t &value, std::string_view name) override;
    bool operator()(int32_t &value, std::string_view name) override;
    bool operator()(uint32_t &value, std::string_view name) override;
    bool operator()(int64_t &value, std::string_view name) override;
    bool operator()(uint64_t &value, std::string_view name) override;
    bool operator()(float &value, std::string_view name) override;
    bool operator()(double &value, std::string_view name) override;
    bool operator()(bool &value, std::string_view name) override;
    bool operator()(std::string &value, std::string_view name) override;

    bool binary(void *value, size_t size, std::string_view name) override;
    bool binary(std::string &value, std::string_view name) override;

    // ========================================================================
    // Output-Only Methods
    // ========================================================================

    /// Write the complete structure to the output stream
    void dump(IOutputStream &target);

  private:
    // ========================================================================
    // Types
    // ========================================================================

    enum class State
    {
      Root,
      Object,
      ArrayPrefix,
      Array
    };

    struct Level
    {
      State state;
      std::string name;
      size_t count;

      explicit Level(std::string_view nm)
          : name(nm), state(State::Object), count(0) {}

      Level(std::string_view nm, size_t arraySize)
          : name(nm), state(State::ArrayPrefix), count(arraySize) {}
    };

    // ========================================================================
    // Constants
    // ========================================================================

    static constexpr size_t MAX_STRING_SIZE = 128 * 1024 * 1024;

    // ========================================================================
    // Member Variables
    // ========================================================================

    InternalMode m_mode;
    IInputStream *m_inputStream = nullptr;
    IOutputStream *m_outputStream = nullptr;

    std::vector<IOutputStream *> m_outputStack;
    std::vector<Level> m_levels;

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

    // Input methods
    template <typename T>
    T readPod();

    uint64_t readVarint();
    std::string readString();
    void readName(std::string &name);
    void readObject();
    void readArray(uint8_t itemType);
    void readValue(uint8_t type);

    // Output methods
    template <typename T>
    void writePod(IOutputStream &stream, const T &value);

    template <typename T>
    void writeVarint(IOutputStream &stream, T value);

    void writeName(IOutputStream &stream, std::string_view name);
    void writeArraySize(IOutputStream &stream, size_t value);
    void writeElementPrefix(uint8_t type, std::string_view name);
    void checkArrayPreamble(uint8_t type);

    IOutputStream &currentStream();
  };

  // Template Implementations

  // Input templates
  template <typename T>
  inline T KVBinarySerializer::readPod()
  {
    T value;
    input().readExact(reinterpret_cast<char *>(&value), sizeof(T));
    return value;
  }

  // Output templates
  template <typename T>
  inline void KVBinarySerializer::writePod(IOutputStream &stream, const T &value)
  {
    stream.write(reinterpret_cast<const char *>(&value), sizeof(T));
  }

  template <typename T>
  inline void KVBinarySerializer::writeVarint(IOutputStream &stream, T value)
  {
    while (value >= 0x80)
    {
      uint8_t byte = static_cast<uint8_t>((value & 0x7F) | 0x80);
      writePod(stream, byte);
      value >>= 7;
    }
    writePod(stream, static_cast<uint8_t>(value));
  }

} // namespace Serialization