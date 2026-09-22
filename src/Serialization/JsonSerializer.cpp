// Json/JsonSerializer.cpp
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#include <cstring>
#include <fstream>

#include "JsonSerializer.h"

#include "Common/Base.h"

namespace Serialization
{

  // Constructors - INPUT mode

  JsonSerializer::JsonSerializer(std::istream &stream)
      : m_internalMode(InternalMode::Input)
  {
    try
    {
      stream >> m_root;
      initInput();
    }
    catch (const std::exception &e)
    {
      throw std::runtime_error(std::string("Failed to parse JSON: ") + e.what());
    }
  }

  JsonSerializer::JsonSerializer(const Common::Json &json)
      : m_internalMode(InternalMode::Input), m_root(json)
  {
    initInput();
  }

  JsonSerializer::JsonSerializer(const std::string &jsonString)
      : m_internalMode(InternalMode::Input)
  {
    try
    {
      m_root = Common::Json::parse(jsonString);
      initInput();
    }
    catch (const std::exception &e)
    {
      throw std::runtime_error(std::string("Failed to parse JSON: ") + e.what());
    }
  }

  // Constructor - OUTPUT mode

  JsonSerializer::JsonSerializer()
      : m_internalMode(InternalMode::Output)
  {
    initOutput();
  }

  // Initialization

  void JsonSerializer::initInput()
  {
    if (!m_root.is_object() && !m_root.is_array())
    {
      throw std::runtime_error("JSON root must be an object or array");
    }
    m_stack.push_back(&m_root);
  }

  void JsonSerializer::initOutput()
  {
    m_root = Common::Json::object();
    m_stack.push_back(&m_root);
  }

  // Helper Methods

  Common::Json &JsonSerializer::current()
  {
    if (m_stack.empty())
    {
      throw std::runtime_error("No current object in serializer");
    }
    return *m_stack.back();
  }

  const Common::Json &JsonSerializer::current() const
  {
    if (m_stack.empty())
    {
      throw std::runtime_error("No current object in serializer");
    }
    return *m_stack.back();
  }

  Common::Json *JsonSerializer::getValue(std::string_view name)
  {
    if (!isInput())
    {
      throw std::runtime_error("getValue only valid in INPUT mode");
    }

    auto &cur = current();

    if (cur.is_array())
    {
      if (m_indices.empty() || m_indices.back() >= cur.size())
      {
        return nullptr;
      }
      return &cur[m_indices.back()];
    }

    std::string key(name);
    if (!cur.is_object() || !cur.contains(key))
    {
      return nullptr;
    }
    return &cur[key];
  }

  void JsonSerializer::insertOrPush(std::string_view name, const Common::Json &value)
  {
    if (!isOutput())
    {
      throw std::runtime_error("insertOrPush only valid in OUTPUT mode");
    }

    auto &cur = current();

    if (cur.is_array())
    {
      cur.push_back(value);
    }
    else if (cur.is_object())
    {
      // For empty name, this is a special case for vectors
      // We'll just use an empty string key
      std::string key(name);
      cur[key] = value;
    }
    else
    {
      throw std::runtime_error("Current JSON value is neither object nor array");
    }
  }

  void JsonSerializer::incrementArrayIndex()
  {
    if (!m_stack.empty() && m_stack.back()->is_array() && !m_indices.empty())
    {
      m_indices.back()++;
    }
  }

  // ISerializer Implementation - Object/Array

  bool JsonSerializer::beginObject(std::string_view name)
  {
    if (isInput())
    {
      auto *ptr = getValue(name);
      if (!ptr)
        return false;
      if (!ptr->is_object())
      {
        throw std::runtime_error("Expected JSON object");
      }
      m_stack.push_back(ptr);
      return true;
    }
    else
    {
      Common::Json obj = Common::Json::object();

      auto &cur = current();

      if (name.empty() && cur.is_array())
      {
        cur.push_back(obj);
        m_stack.push_back(&cur.back());
        return true;
      }

      if (cur.is_object())
      {
        std::string key(name);
        cur[key] = obj;
        m_stack.push_back(&cur[key]);
      }
      else
      {
        cur.push_back(obj);
        m_stack.push_back(&cur.back());
      }
      return true;
    }
  }

  void JsonSerializer::endObject()
  {
    if (m_stack.size() <= 1)
    {
      throw std::runtime_error("Unbalanced object nesting");
    }
    m_stack.pop_back();
    if (!m_stack.empty() && m_stack.back()->is_array() && !m_indices.empty())
    {
      m_indices.back()++;
    }
  }

  bool JsonSerializer::beginArray(size_t &size, std::string_view name)
  {
    if (isInput())
    {
      auto *ptr = getValue(name);
      if (!ptr)
      {
        size = 0;
        return false;
      }
      if (!ptr->is_array())
      {
        throw std::runtime_error("Expected JSON array");
      }
      size = ptr->size();
      m_stack.push_back(ptr);
      m_indices.push_back(0);
      return true;
    }
    else
    {
      Common::Json arr = Common::Json::array();

      auto &cur = current();

      if (name.empty() && cur.is_array())
      {
        cur.push_back(arr);
        m_stack.push_back(&cur.back());
      }
      else if (cur.is_object())
      {
        std::string key(name);
        cur[key] = arr;
        m_stack.push_back(&cur[key]);
      }
      else
      {
        cur.push_back(arr);
        m_stack.push_back(&cur.back());
      }
      size = 0;
      return true;
    }
  }

  void JsonSerializer::endArray()
  {
    if (m_stack.size() <= 1 || m_indices.empty())
    {
      throw std::runtime_error("Unbalanced array nesting");
    }
    m_stack.pop_back();
    m_indices.pop_back();
  }

  // ISerializer Implementation - Primitives

  template <typename T>
  bool JsonSerializer::readNumber(std::string_view name, T &value)
  {
    auto *ptr = getValue(name);
    if (!ptr)
      return false;
    if (!ptr->is_number())
      return false;
    value = ptr->get<T>();
    incrementArrayIndex();
    return true;
  }

  template <typename T>
  void JsonSerializer::writeNumber(std::string_view name, const T &value)
  {
    insertOrPush(name, Common::Json(value));
  }

  bool JsonSerializer::operator()(uint8_t &value, std::string_view name)
  {
    if (isInput())
    {
      uint16_t temp;
      if (!readNumber(name, temp))
        return false;
      value = static_cast<uint8_t>(temp);
      return true;
    }
    writeNumber(name, static_cast<uint16_t>(value));
    return true;
  }

  bool JsonSerializer::operator()(int16_t &value, std::string_view name)
  {
    if (isInput())
      return readNumber(name, value);
    writeNumber(name, value);
    return true;
  }

  bool JsonSerializer::operator()(uint16_t &value, std::string_view name)
  {
    if (isInput())
      return readNumber(name, value);
    writeNumber(name, value);
    return true;
  }

  bool JsonSerializer::operator()(int32_t &value, std::string_view name)
  {
    if (isInput())
      return readNumber(name, value);
    writeNumber(name, value);
    return true;
  }

  bool JsonSerializer::operator()(uint32_t &value, std::string_view name)
  {
    if (isInput())
      return readNumber(name, value);
    writeNumber(name, value);
    return true;
  }

  bool JsonSerializer::operator()(int64_t &value, std::string_view name)
  {
    if (isInput())
      return readNumber(name, value);
    writeNumber(name, value);
    return true;
  }

  bool JsonSerializer::operator()(uint64_t &value, std::string_view name)
  {
    if (isInput())
      return readNumber(name, value);
    writeNumber(name, value);
    return true;
  }

  bool JsonSerializer::operator()(float &value, std::string_view name)
  {
    if (isInput())
      return readNumber(name, value);
    writeNumber(name, value);
    return true;
  }

  bool JsonSerializer::operator()(double &value, std::string_view name)
  {
    if (isInput())
      return readNumber(name, value);
    writeNumber(name, value);
    return true;
  }

  bool JsonSerializer::operator()(bool &value, std::string_view name)
  {
    if (isInput())
    {
      auto *ptr = getValue(name);
      if (!ptr)
        return false;
      if (!ptr->is_boolean())
        return false;
      value = ptr->get<bool>();
      incrementArrayIndex();
      return true;
    }
    else
    {
      insertOrPush(name, Common::Json(value));
      return true;
    }
  }

  bool JsonSerializer::operator()(std::string &value, std::string_view name)
  {
    if (isInput())
    {
      auto *ptr = getValue(name);
      if (!ptr)
        return false;
      if (!ptr->is_string())
        return false;
      value = ptr->get<std::string>();
      incrementArrayIndex();
      return true;
    }
    else
    {
      insertOrPush(name, Common::Json(value));
      return true;
    }
  }

  // ISerializer Implementation - Binary

  bool JsonSerializer::binary(void *value, size_t size, std::string_view name)
  {
    if (isInput())
    {
      std::string str;
      if (!operator()(str, name))
        return false;

      try
      {
        std::string decoded = Common::decodeBase64(str);
        if (decoded.size() != size)
          return false;
        std::memcpy(value, decoded.data(), size);
        return true;
      }
      catch (const std::exception &)
      {
        return false;
      }
    }
    else
    {
      std::string base64Str = Common::encodeBase64(
          std::string_view(static_cast<const char *>(value), size));
      insertOrPush(name, Common::Json(base64Str));
      return true;
    }
  }

  bool JsonSerializer::binary(std::string &value, std::string_view name)
  {
    if (isInput())
    {
      std::string str;
      if (!operator()(str, name))
        return false;

      try
      {
        value = Common::decodeBase64(str);
        return true;
      }
      catch (const std::exception &)
      {
        return false;
      }
    }
    else
    {
      std::string base64Str = Common::encodeBase64(value);
      insertOrPush(name, Common::Json(base64Str));
      return true;
    }
  }

  // Output Methods

  std::string JsonSerializer::toString() const
  {
    if (!isOutput())
    {
      throw std::runtime_error("toString only valid in OUTPUT mode");
    }
    return m_root.dump();
  }

  std::string JsonSerializer::toStringPretty(int indent) const
  {
    if (!isOutput())
    {
      throw std::runtime_error("toStringPretty only valid in OUTPUT mode");
    }
    return m_root.dump(indent);
  }

  void JsonSerializer::writeToStream(std::ostream &os) const
  {
    if (!isOutput())
    {
      throw std::runtime_error("writeToStream only valid in OUTPUT mode");
    }
    os << m_root.dump(4);
  }

  void JsonSerializer::writeToFile(const std::string &filename) const
  {
    if (!isOutput())
    {
      throw std::runtime_error("writeToFile only valid in OUTPUT mode");
    }
    std::ofstream file(filename);
    if (!file.is_open())
    {
      throw std::runtime_error("Failed to open file: " + filename);
    }
    file << m_root.dump(4);
    file.close();
  }

  // Stream Operators

  std::ostream &operator<<(std::ostream &os, const JsonSerializer &serializer)
  {
    os << serializer.m_root.dump(4);
    return os;
  }

} // namespace Serialization