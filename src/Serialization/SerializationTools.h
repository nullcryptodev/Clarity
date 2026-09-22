// SerializationTools.hpp
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <type_traits>

#include "ISerializer.h"
#include "JsonSerializer.h"
#include "BinarySerializer.h"
#include "KVBinarySerializer.h"
#include "MemoryStream.h"

namespace Serialization
{

  // Helper to detect if a type has a serialize method

  template <typename T, typename = void>
  struct has_serialize : std::false_type
  {
  };

  template <typename T>
  struct has_serialize<T, std::void_t<decltype(std::declval<T>().serialize(std::declval<ISerializer &>()))>>
      : std::true_type
  {
  };

  // Primitive Type Serialization

  // For int8_t - serialize as int16_t to preserve sign (BinarySerializer doesn't have int8_t support)
  inline void serialize_object(int8_t &value, ISerializer &serializer)
  {
    int16_t temp = value;
    serializer(temp, "");
    if (serializer.mode() == ISerializer::InternalMode::Input)
    {
      value = static_cast<int8_t>(temp);
    }
  }

  // For uint8_t - serialize as uint16_t
  inline void serialize_object(uint8_t &value, ISerializer &serializer)
  {
    uint16_t temp = value;
    serializer(temp, "");
    if (serializer.mode() == ISerializer::InternalMode::Input)
    {
      value = static_cast<uint8_t>(temp);
    }
  }

  // For arithmetic types (excluding int8_t and uint8_t which are handled above)
  template <typename T>
  std::enable_if_t<std::is_arithmetic_v<T> && !std::is_same_v<T, int8_t> && !std::is_same_v<T, uint8_t> && !std::is_enum_v<T>>
  serialize_object(T &value, ISerializer &serializer)
  {
    serializer(value, "");
  }

  // For enum types
  template <typename T>
  std::enable_if_t<std::is_enum_v<T>>
  serialize_object(T &value, ISerializer &serializer)
  {
    // Serialize enum as its underlying type
    using Underlying = std::underlying_type_t<T>;
    Underlying temp = static_cast<Underlying>(value);
    serializer(temp, "");
    if (serializer.mode() == ISerializer::InternalMode::Input)
    {
      value = static_cast<T>(temp);
    }
  }

  // For std::string
  inline void serialize_object(std::string &value, ISerializer &serializer)
  {
    serializer(value, "");
  }

  // For bool
  inline void serialize_object(bool &value, ISerializer &serializer)
  {
    serializer(value, "");
  }

  // std::vector serialization

  // Overload for std::vector<uint8_t> (binary data)
  inline void serialize_object(std::vector<uint8_t> &value, ISerializer &serializer)
  {
    size_t size = value.size();
    serializer(size, "size");

    if (serializer.mode() == ISerializer::InternalMode::Input)
    {
      value.resize(size);
    }

    for (size_t i = 0; i < size; ++i)
    {
      if (serializer.mode() == ISerializer::InternalMode::Input)
      {
        uint8_t byte = 0;
        serializer(byte, "byte");
        value[i] = byte;
      }
      else
      {
        uint8_t byte = value[i];
        serializer(byte, "byte");
      }
    }
  }

  // Generic vector serialization
  template <typename T>
  void serialize_object(std::vector<T> &value, ISerializer &serializer)
  {
    size_t size = value.size();
    serializer(size, "size");

    if (serializer.mode() == ISerializer::InternalMode::Input)
    {
      value.resize(size);
    }

    for (size_t i = 0; i < size; ++i)
    {
      serialize_object(value[i], serializer);
    }
  }

  // std::map serialization

  template <typename K, typename V>
  void serialize_object(std::map<K, V> &value, ISerializer &serializer)
  {
    size_t size = value.size();
    serializer(size, "size");

    if (serializer.mode() == ISerializer::InternalMode::Input)
    {
      value.clear();
      for (size_t i = 0; i < size; ++i)
      {
        K key{};
        V val{};
        serializer.beginObject("");
        serializer(key, "key");
        serializer(val, "value");
        serializer.endObject();
        value.emplace(std::move(key), std::move(val));
      }
    }
    else
    {
      for (auto &kv : value)
      {
        serializer.beginObject("");
        serializer(const_cast<K &>(kv.first), "key");
        serializer(kv.second, "value");
        serializer.endObject();
      }
    }
  }

  // Main serialization functions

  /**
   * @brief serialize_object for types that have a serialize method
   *
   * This is the fallback for types that have a serialize method.
   * It uses SFINAE to only match types with a serialize method.
   */
  template <typename T>
  std::enable_if_t<has_serialize<T>::value>
  serialize_object(T &value, ISerializer &serializer)
  {
    value.serialize(serializer);
  }

  /**
   * @brief Serialize an object with a name (creates an object wrapper)
   */
  template <typename T>
  bool serialize(T &value, std::string_view name, ISerializer &serializer)
  {
    if (!serializer.beginObject(name))
    {
      return false;
    }
    serialize_object(value, serializer);
    serializer.endObject();
    return true;
  }

  template <typename T>
  bool serialize(const T &value, std::string_view name, ISerializer &serializer)
  {
    if (!serializer.beginObject(name))
      return false;
    serialize_object(const_cast<T &>(value), serializer);
    serializer.endObject();
    return true;
  }

  /// Store object to JSON string
  template <typename T>
  std::string toJsonString(const T &obj, int indent = -1)
  {
    JsonSerializer serializer;
    serialize_object(const_cast<T &>(obj), serializer);
    return indent >= 0 ? serializer.toStringPretty(indent) : serializer.toString();
  }

  /// Store object to JSON value
  template <typename T>
  Common::Json toJson(const T &obj)
  {
    JsonSerializer serializer;
    serialize_object(const_cast<T &>(obj), serializer);
    return serializer.value();
  }

  /// Load object from JSON string
  template <typename T>
  bool fromJsonString(T &obj, const std::string &json)
  {
    try
    {
      JsonSerializer serializer(json);
      serialize_object(obj, serializer);
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  /// Load object from JSON value
  template <typename T>
  bool fromJson(T &obj, const Common::Json &json)
  {
    try
    {
      JsonSerializer serializer(json);
      serialize_object(obj, serializer);
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  /// Load object from JSON file
  template <typename T>
  bool fromJsonFile(T &obj, const std::string &filename)
  {
    try
    {
      std::ifstream file(filename);
      if (!file.is_open())
        return false;
      JsonSerializer serializer(file);
      serialize_object(obj, serializer);
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  /// Store object to JSON file
  template <typename T>
  bool toJsonFile(const T &obj, const std::string &filename, int indent = 4)
  {
    try
    {
      std::ofstream file(filename);
      if (!file.is_open())
        return false;
      JsonSerializer serializer;
      serialize_object(const_cast<T &>(obj), serializer);
      file << serializer.toStringPretty(indent);
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  // Binary Utilities

  /// Store object to binary blob
  template <typename T>
  std::vector<uint8_t> toBinaryBlob(const T &obj)
  {
    std::vector<uint8_t> buffer;
    MemoryOutputStream stream(buffer);
    BinarySerializer serializer(stream);
    serialize_object(const_cast<T &>(obj), serializer);
    return buffer;
  }

  /// Load object from binary blob
  template <typename T>
  bool fromBinaryBlob(T &obj, const std::vector<uint8_t> &blob)
  {
    try
    {
      MemoryInputStream stream(blob.data(), blob.size());
      BinarySerializer serializer(stream);
      serialize_object(obj, serializer);
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  /// Store object to binary file
  template <typename T>
  bool toBinaryFile(const T &obj, const std::string &filename)
  {
    try
    {
      std::ofstream file(filename, std::ios::binary);
      if (!file.is_open())
        return false;
      auto blob = toBinaryBlob(obj);
      file.write(reinterpret_cast<const char *>(blob.data()), blob.size());
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  /// Load object from binary file
  template <typename T>
  bool fromBinaryFile(T &obj, const std::string &filename)
  {
    try
    {
      std::ifstream file(filename, std::ios::binary);
      if (!file.is_open())
        return false;
      file.seekg(0, std::ios::end);
      size_t size = file.tellg();
      file.seekg(0, std::ios::beg);
      std::vector<uint8_t> blob(size);
      file.read(reinterpret_cast<char *>(blob.data()), size);
      return fromBinaryBlob(obj, blob);
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  // KV Binary Utilities

  /// Store object to KV binary blob
  template <typename T>
  std::vector<uint8_t> toKVBinary(const T &obj)
  {
    std::vector<uint8_t> buffer;
    MemoryOutputStream stream(buffer);
    KVBinarySerializer serializer(stream);
    serialize_object(const_cast<T &>(obj), serializer);
    serializer.dump(stream);
    return buffer;
  }

  /// Load object from KV binary blob
  template <typename T>
  bool fromKVBinary(T &obj, const std::vector<uint8_t> &blob)
  {
    try
    {
      MemoryInputStream stream(blob.data(), blob.size());
      KVBinarySerializer serializer(stream);
      serialize_object(obj, serializer);
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  /// Store object to KV binary file
  template <typename T>
  bool toKVBinaryFile(const T &obj, const std::string &filename)
  {
    try
    {
      std::ofstream file(filename, std::ios::binary);
      if (!file.is_open())
        return false;
      auto blob = toKVBinary(obj);
      file.write(reinterpret_cast<const char *>(blob.data()), blob.size());
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  /// Load object from KV binary file
  template <typename T>
  bool fromKVBinaryFile(T &obj, const std::string &filename)
  {
    try
    {
      std::ifstream file(filename, std::ios::binary);
      if (!file.is_open())
        return false;
      file.seekg(0, std::ios::end);
      size_t size = file.tellg();
      file.seekg(0, std::ios::beg);
      std::vector<uint8_t> blob(size);
      file.read(reinterpret_cast<char *>(blob.data()), size);
      return fromKVBinary(obj, blob);
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

} // namespace Serialization