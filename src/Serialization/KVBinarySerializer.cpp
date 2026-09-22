// KV/KVBinarySerializer.cpp
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#include "KVBinarySerializer.h"
#include <cassert>
#include <limits>

namespace Serialization
{

  // Constructors

  KVBinarySerializer::KVBinarySerializer(IInputStream &stream)
      : m_mode(InternalMode::Input), m_inputStream(&stream)
  {
    // Read and validate header
    auto header = readPod<Header>();
    if (!header.valid())
    {
      throw std::runtime_error("Invalid KV binary storage signature or version");
    }

    // Read root object
    readObject();
  }

  KVBinarySerializer::KVBinarySerializer(IOutputStream &stream)
      : m_mode(InternalMode::Output), m_outputStream(&stream)
  {
    m_outputStack.push_back(&stream);
    m_levels.emplace_back("");
  }

  // Input Implementation

  void KVBinarySerializer::readName(std::string &name)
  {
    uint8_t len = readPod<uint8_t>();
    if (len > 0)
    {
      name.resize(len);
      input().readExact(name.data(), len);
    }
    else
    {
      name.clear();
    }
  }

  uint64_t KVBinarySerializer::readVarint()
  {
    uint8_t b = readPod<uint8_t>();
    uint8_t sizeMask = b & SIZE_MARK_MASK;
    size_t bytesLeft = 0;

    switch (sizeMask)
    {
    case SIZE_MARK_BYTE:
      bytesLeft = 0;
      break;
    case SIZE_MARK_WORD:
      bytesLeft = 1;
      break;
    case SIZE_MARK_DWORD:
      bytesLeft = 3;
      break;
    case SIZE_MARK_INT64:
      bytesLeft = 7;
      break;
    default:
      throw std::runtime_error("Invalid varint size marker");
    }

    uint64_t value = b;
    for (size_t i = 1; i <= bytesLeft; ++i)
    {
      uint64_t n = readPod<uint8_t>();
      value |= n << (i * 8);
    }

    value >>= 2;
    return value;
  }

  std::string KVBinarySerializer::readString()
  {
    auto size = readVarint();
    if (size > MAX_STRING_SIZE)
    {
      throw std::runtime_error("String size too large: " + std::to_string(size));
    }
    std::string str;
    str.resize(static_cast<size_t>(size));
    if (size > 0)
    {
      input().readExact(str.data(), static_cast<size_t>(size));
    }
    return str;
  }

  void KVBinarySerializer::readValue(uint8_t type)
  {
    switch (type)
    {
    case TYPE_INT64:
      readPod<int64_t>();
      break;
    case TYPE_INT32:
      readPod<int32_t>();
      break;
    case TYPE_INT16:
      readPod<int16_t>();
      break;
    case TYPE_INT8:
      readPod<int8_t>();
      break;
    case TYPE_UINT64:
      readPod<uint64_t>();
      break;
    case TYPE_UINT32:
      readPod<uint32_t>();
      break;
    case TYPE_UINT16:
      readPod<uint16_t>();
      break;
    case TYPE_UINT8:
      readPod<uint8_t>();
      break;
    case TYPE_DOUBLE:
      readPod<double>();
      break;
    case TYPE_BOOL:
    {
      uint8_t b = readPod<uint8_t>(); // readPod returns the value
      (void)b;                        // Suppress unused variable warning
      break;
    }
    break;
    case TYPE_STRING:
      readString();
      break;
    case TYPE_OBJECT:
      readObject();
      break;
    default:
      throw std::runtime_error("Unknown KV binary data type: " + std::to_string(type));
    }
  }

  void KVBinarySerializer::readArray(uint8_t itemType)
  {
    size_t count = static_cast<size_t>(readVarint());
    for (size_t i = 0; i < count; ++i)
    {
      readValue(itemType);
    }
  }

  void KVBinarySerializer::readObject()
  {
    size_t count = static_cast<size_t>(readVarint());
    for (size_t i = 0; i < count; ++i)
    {
      std::string name;
      readName(name);
      uint8_t type = readPod<uint8_t>();
      if (type & FLAG_ARRAY)
      {
        readArray(type & ~FLAG_ARRAY);
      }
      else
      {
        readValue(type);
      }
    }
  }

  // Output Implementation

  IOutputStream &KVBinarySerializer::currentStream()
  {
    if (m_outputStack.empty())
    {
      throw std::runtime_error("No current output stream");
    }
    return *m_outputStack.back();
  }

  void KVBinarySerializer::writeName(IOutputStream &stream, std::string_view name)
  {
    if (name.size() > std::numeric_limits<uint8_t>::max())
    {
      throw std::runtime_error("Element name too long: " + std::to_string(name.size()));
    }
    uint8_t len = static_cast<uint8_t>(name.size());
    writePod(stream, len);
    stream.write(name.data(), name.size());
  }

  void KVBinarySerializer::writeArraySize(IOutputStream &stream, size_t value)
  {
    if (value <= 63)
    {
      uint8_t v = static_cast<uint8_t>((value << 2) | SIZE_MARK_BYTE);
      writePod(stream, v);
    }
    else if (value <= 16383)
    {
      uint16_t v = static_cast<uint16_t>((value << 2) | SIZE_MARK_WORD);
      writePod(stream, v);
    }
    else if (value <= 1073741823)
    {
      uint32_t v = static_cast<uint32_t>((value << 2) | SIZE_MARK_DWORD);
      writePod(stream, v);
    }
    else
    {
      if (value > 4611686018427387903ULL)
      {
        throw std::runtime_error("Value too large for varint");
      }
      uint64_t v = static_cast<uint64_t>((value << 2) | SIZE_MARK_INT64);
      writePod(stream, v);
    }
  }

  void KVBinarySerializer::writeElementPrefix(uint8_t type, std::string_view name)
  {
    if (m_levels.empty())
      return;

    checkArrayPreamble(type);
    auto &level = m_levels.back();

    if (level.state != State::Array)
    {
      if (!name.empty())
      {
        auto &stream = currentStream();
        writeName(stream, name);
        writePod(stream, type);
      }
      ++level.count;
    }
  }

  void KVBinarySerializer::checkArrayPreamble(uint8_t type)
  {
    if (m_levels.empty())
      return;

    auto &level = m_levels.back();
    if (level.state == State::ArrayPrefix)
    {
      auto &stream = currentStream();
      writeName(stream, level.name);
      writePod(stream, static_cast<uint8_t>(FLAG_ARRAY | type));
      writeArraySize(stream, level.count);
      level.state = State::Array;
    }
  }

  // ISerializer Implementation

  bool KVBinarySerializer::beginObject(std::string_view name)
  {
    if (isOutput())
    {
      checkArrayPreamble(TYPE_OBJECT);
      m_levels.emplace_back(name);
      // Create a new stream for this object
      // For simplicity, we write directly to the current stream
      // In a full implementation, you'd use a separate buffer
      return true;
    }
    // Input mode: objects are parsed during construction
    return true;
  }

  void KVBinarySerializer::endObject()
  {
    if (isOutput() && !m_levels.empty())
    {
      auto level = std::move(m_levels.back());
      m_levels.pop_back();

      auto &stream = currentStream();
      writeElementPrefix(TYPE_OBJECT, level.name);
      writeArraySize(stream, level.count);
    }
  }

  bool KVBinarySerializer::beginArray(size_t &size, std::string_view name)
  {
    if (isOutput())
    {
      m_levels.emplace_back(name, size);
      return true;
    }
    return true;
  }

  void KVBinarySerializer::endArray()
  {
    if (isOutput() && !m_levels.empty())
    {
      bool isArray = (m_levels.back().state == State::Array);
      m_levels.pop_back();

      if (!m_levels.empty() && m_levels.back().state == State::Object && isArray)
      {
        ++m_levels.back().count;
      }
    }
  }

  bool KVBinarySerializer::operator()(uint8_t &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_UINT8, name);
      writePod(currentStream(), value);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(int16_t &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_INT16, name);
      writePod(currentStream(), value);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(uint16_t &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_UINT16, name);
      writePod(currentStream(), value);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(int32_t &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_INT32, name);
      writePod(currentStream(), value);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(uint32_t &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_UINT32, name);
      writePod(currentStream(), value);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(int64_t &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_INT64, name);
      writePod(currentStream(), value);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(uint64_t &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_UINT64, name);
      writePod(currentStream(), value);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(float &value, std::string_view name)
  {
    // Not supported in KV binary format
    return false;
  }

  bool KVBinarySerializer::operator()(double &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_DOUBLE, name);
      writePod(currentStream(), value);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(bool &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_BOOL, name);
      uint8_t byte = value ? 1 : 0;
      writePod(currentStream(), byte);
    }
    return true;
  }

  bool KVBinarySerializer::operator()(std::string &value, std::string_view name)
  {
    if (isOutput())
    {
      writeElementPrefix(TYPE_STRING, name);
      auto &stream = currentStream();
      writeArraySize(stream, value.size());
      stream.write(value.data(), value.size());
    }
    return true;
  }

  bool KVBinarySerializer::binary(void *value, size_t size, std::string_view name)
  {
    if (isOutput())
    {
      if (size > 0)
      {
        writeElementPrefix(TYPE_STRING, name);
        auto &stream = currentStream();
        writeArraySize(stream, size);
        stream.write(static_cast<const char *>(value), size);
      }
    }
    return true;
  }

  bool KVBinarySerializer::binary(std::string &value, std::string_view name)
  {
    return (*this)(value, name);
  }

  // Output-Only Methods

  void KVBinarySerializer::dump(IOutputStream &target)
  {
    if (!isOutput())
    {
      throw std::runtime_error("Cannot dump from input serializer");
    }

    // Write header
    Header header;
    header.signatureA = SIGNATURE_A;
    header.signatureB = SIGNATURE_B;
    header.version = FORMAT_VERSION;

    target.write(reinterpret_cast<const char *>(&header), sizeof(header));

    // Write root object size
    if (!m_levels.empty())
    {
      writeArraySize(target, m_levels.front().count);
    }
  }

} // namespace Serialization