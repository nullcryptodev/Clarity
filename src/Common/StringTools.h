// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Crypto/Blake2b.h"

#include "Serialization/SerializationTools.h"
#include "Serialization/BinarySerializer.h"
#include "Serialization/MemoryStream.h"

namespace Common
{
  using BinaryArray = std::vector<uint8_t>;

  //  String <-> bytes

  // Interpret raw bytes as a string. Never throws.
  std::string asString(const void *data, size_t size);
  std::string asString(const std::vector<uint8_t> &data);

  // Interpret a string as bytes. Never throws.
  std::vector<uint8_t> asBinaryArray(const std::string &data);

  //  Hex

  // Throwing versions
  uint8_t fromHex(char character);
  size_t fromHex(const std::string &text, void *data, size_t bufferSize);
  std::vector<uint8_t> fromHex(const std::string &text);

  // Non-throwing versions
  bool fromHex(char character, uint8_t &value);
  bool fromHex(const std::string &text, void *data, size_t bufferSize, size_t &size);
  bool fromHex(const std::string &text, std::vector<uint8_t> &data);

  template <typename T>
  bool podFromHex(const std::string &text, T &val)
  {
    size_t outSize = 0;
    return fromHex(text, &val, sizeof(val), outSize) && outSize == sizeof(val);
  }

  std::string toHex(const void *data, size_t size);
  void toHex(const void *data, size_t size, std::string &text);
  std::string toHex(const std::vector<uint8_t> &data);
  void toHex(const std::vector<uint8_t> &data, std::string &text);

  template <class T>
  std::string podToHex(const T &s)
  {
    return toHex(&s, sizeof(s));
  }

  //  String parsing

  std::string extract(std::string &text, char delimiter);
  std::string extract(const std::string &text, char delimiter, size_t &offset);

  template <typename T>
  T fromString(const std::string &text)
  {
    T value;
    std::istringstream stream(text);
    stream >> value;
    if (stream.fail())
    {
      throw std::runtime_error("fromString: unable to parse value");
    }
    return value;
  }

  template <typename T>
  bool fromString(const std::string &text, T &value)
  {
    std::istringstream stream(text);
    stream >> value;
    return !stream.fail();
  }

  template <typename T>
  std::vector<T> fromDelimitedString(const std::string &source, char delimiter)
  {
    std::vector<T> data;
    for (size_t offset = 0; offset != source.size();)
    {
      data.emplace_back(fromString<T>(extract(source, delimiter, offset)));
    }
    return data;
  }

  template <typename T>
  bool fromDelimitedString(const std::string &source, char delimiter,
                           std::vector<T> &data)
  {
    for (size_t offset = 0; offset != source.size();)
    {
      T value;
      if (!fromString<T>(extract(source, delimiter, offset), value))
      {
        return false;
      }
      data.emplace_back(value);
    }
    return true;
  }

  template <typename T>
  std::string toString(const T &value)
  {
    std::ostringstream stream;
    stream << value;
    return stream.str();
  }

  template <typename T>
  void toString(const T &value, std::string &text)
  {
    std::ostringstream stream;
    stream << value;
    text += stream.str();
  }

  //  Network and formatting

  std::string ipAddressToString(uint32_t ip);
  bool parseIpAddressAndPort(uint32_t &ip, uint32_t &port,
                             const std::string &addr);

  std::string timeIntervalToString(uint64_t intervalInSeconds);
  std::string makeCenteredString(size_t width, const std::string &text);
  std::string formatTimestamp(time_t timestamp);

  //  Binary serialization helpers

  // Hash a byte array using Clarity's canonical hash (Blake2b-256).
  void getBinaryArrayHash(const BinaryArray &data, Crypto::Hash &hash);
  Crypto::Hash getBinaryArrayHash(const BinaryArray &data);

  // Serialize any T that has a member or free `serialize(ISerializer&)`.
  template <class T>
  bool toBinaryArray(const T &object, BinaryArray &binaryArray)
  {
    try
    {
      Serialization::MemoryOutputStream stream(binaryArray);
      Serialization::BinarySerializer serializer(stream);
      Serialization::serialize_object(const_cast<T &>(object), serializer);
      return true;
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  template <class T>
  BinaryArray toBinaryArray(const T &object)
  {
    BinaryArray ba;
    toBinaryArray(object, ba);
    return ba;
  }

  // Deserialize any T. Fails if there are trailing bytes.
  template <class T>
  bool fromBinaryArray(T &object, const BinaryArray &binaryArray)
  {
    try
    {
      Serialization::MemoryInputStream stream(binaryArray.data(),
                                              binaryArray.size());
      Serialization::BinarySerializer serializer(stream);
      Serialization::serialize_object(object, serializer);
      return stream.eof();
    }
    catch (const std::exception &)
    {
      return false;
    }
  }

  // Byte size of a serialized object.
  template <class T>
  bool getObjectBinarySize(const T &object, size_t &size)
  {
    BinaryArray ba;
    if (!toBinaryArray(object, ba))
    {
      size = (std::numeric_limits<size_t>::max)();
      return false;
    }
    size = ba.size();
    return true;
  }

  template <class T>
  size_t getObjectBinarySize(const T &object)
  {
    size_t size = 0;
    getObjectBinarySize(object, size);
    return size;
  }

  // Canonical hash of an object (Blake2b-256 of its serialization).
  template <class T>
  bool getObjectHash(const T &object, Crypto::Hash &hash)
  {
    BinaryArray ba;
    if (!toBinaryArray(object, ba))
    {
      hash = Crypto::NULL_HASH;
      return false;
    }
    hash = getBinaryArrayHash(ba);
    return true;
  }

  template <class T>
  bool getObjectHash(const T &object, Crypto::Hash &hash, size_t &size)
  {
    BinaryArray ba;
    if (!toBinaryArray(object, ba))
    {
      hash = Crypto::NULL_HASH;
      size = (std::numeric_limits<size_t>::max)();
      return false;
    }
    size = ba.size();
    hash = getBinaryArrayHash(ba);
    return true;
  }

  template <class T>
  Crypto::Hash getObjectHash(const T &object)
  {
    Crypto::Hash hash;
    getObjectHash(object, hash);
    return hash;
  }

} // namespace Common