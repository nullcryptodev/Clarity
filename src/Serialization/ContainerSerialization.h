// Containers/ContainerSerialization.hpp
// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
// Distributed under the MIT/X11 software license.

#pragma once

#include <vector>
#include <list>
#include <map>
#include <unordered_map>
#include <set>
#include <unordered_set>
#include <array>
#include <string>
#include <type_traits>

#include "ISerializer.h"

namespace Serialization
{

  // Container Serialization

  /// Serialize a vector
  template <typename T>
  bool serialize(std::vector<T> &value, std::string_view name, ISerializer &serializer)
  {
    size_t size = value.size();
    if (!serializer.beginArray(size, name))
    {
      value.clear();
      return false;
    }

    value.resize(size);
    for (auto &item : value)
    {
      serializer(item, "");
    }
    serializer.endArray();
    return true;
  }

  /// Serialize a list
  template <typename T>
  bool serialize(std::list<T> &value, std::string_view name, ISerializer &serializer)
  {
    size_t size = value.size();
    if (!serializer.beginArray(size, name))
    {
      value.clear();
      return false;
    }

    if (serializer.isInput())
    {
      value.clear();
      for (size_t i = 0; i < size; ++i)
      {
        T item;
        serializer(item, "");
        value.push_back(std::move(item));
      }
    }
    else
    {
      for (auto &item : value)
      {
        serializer(item, "");
      }
    }
    serializer.endArray();
    return true;
  }

  /// Serialize a set
  template <typename SetT>
  bool serializeSet(SetT &value, std::string_view name, ISerializer &serializer)
  {
    size_t size = value.size();
    if (!serializer.beginArray(size, name))
    {
      value.clear();
      return false;
    }

    if (serializer.isInput())
    {
      value.clear();
      for (size_t i = 0; i < size; ++i)
      {
        typename SetT::value_type key;
        serializer(key, "");
        value.insert(std::move(key));
      }
    }
    else
    {
      for (auto &key : value)
      {
        serializer(const_cast<typename SetT::value_type &>(key), "");
      }
    }
    serializer.endArray();
    return true;
  }

  /// Serialize a map
  template <typename MapT, typename ReserveOp>
  bool serializeMap(MapT &value, std::string_view name, ISerializer &serializer, ReserveOp reserve)
  {
    size_t size = value.size();
    if (!serializer.beginArray(size, name))
    {
      value.clear();
      return false;
    }

    if (serializer.isInput())
    {
      reserve(size);
      for (size_t i = 0; i < size; ++i)
      {
        typename MapT::key_type key;
        typename MapT::mapped_type val;

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
        serializer(const_cast<typename MapT::key_type &>(kv.first), "key");
        serializer(kv.second, "value");
        serializer.endObject();
      }
    }
    serializer.endArray();
    return true;
  }

  // STL Container Specializations

  // Vector
  template <typename T>
  bool serialize(std::vector<T> &value, std::string_view name, ISerializer &serializer);

  // List
  template <typename T>
  bool serialize(std::list<T> &value, std::string_view name, ISerializer &serializer);

  // Set
  template <typename K, typename Cmp>
  bool serialize(std::set<K, Cmp> &value, std::string_view name, ISerializer &serializer)
  {
    return serializeSet(value, name, serializer);
  }

  template <typename K, typename Hash>
  bool serialize(std::unordered_set<K, Hash> &value, std::string_view name, ISerializer &serializer)
  {
    return serializeSet(value, name, serializer);
  }

  // Map
  template <typename K, typename V, typename Cmp>
  bool serialize(std::map<K, V, Cmp> &value, std::string_view name, ISerializer &serializer)
  {
    return serializeMap(value, name, serializer, [](size_t) {});
  }

  template <typename K, typename V, typename Hash>
  bool serialize(std::unordered_map<K, V, Hash> &value, std::string_view name, ISerializer &serializer)
  {
    return serializeMap(value, name, serializer, [&value](size_t size)
                        { value.reserve(size); });
  }

  // Array
  template <size_t N>
  bool serialize(std::array<uint8_t, N> &value, std::string_view name, ISerializer &serializer)
  {
    return serializer.binary(value.data(), value.size(), name);
  }

  // Pair
  template <typename T1, typename T2>
  void serialize(std::pair<T1, T2> &value, ISerializer &serializer)
  {
    serializer(value.first, "first");
    serializer(value.second, "second");
  }

  // POD Binary Serialization

  /// Serialize POD vector as binary blob
  template <typename T>
  std::enable_if_t<std::is_trivially_copyable_v<T>>
  serializeAsBinary(std::vector<T> &value, std::string_view name, ISerializer &serializer)
  {
    std::string blob;
    if (serializer.isInput())
    {
      serializer.binary(blob, name);
      size_t blobSize = blob.size();
      value.resize(blobSize / sizeof(T));
      if (blobSize % sizeof(T) != 0)
      {
        throw std::runtime_error("Invalid blob size");
      }
      if (blobSize > 0)
      {
        std::memcpy(value.data(), blob.data(), blobSize);
      }
    }
    else
    {
      if (!value.empty())
      {
        blob.assign(reinterpret_cast<const char *>(value.data()), value.size() * sizeof(T));
      }
      serializer.binary(blob, name);
    }
  }

  // Enum Class Serialization

  /// Serialize enum class
  template <typename E>
  std::enable_if_t<std::is_enum_v<E>, bool>
  serializeEnumClass(E &value, std::string_view name, ISerializer &serializer)
  {
    using Underlying = std::underlying_type_t<E>;

    if (serializer.isInput())
    {
      Underlying numericValue;
      serializer(numericValue, name);
      value = static_cast<E>(numericValue);
    }
    else
    {
      auto numericValue = static_cast<Underlying>(value);
      serializer(numericValue, name);
    }
    return true;
  }

} // namespace Serialization