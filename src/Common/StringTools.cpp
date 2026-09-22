// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "StringTools.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Types.h"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace Common
{

  //  String <-> bytes

  std::string asString(const void *data, size_t size)
  {
    return std::string(static_cast<const char *>(data), size);
  }

  std::string asString(const std::vector<uint8_t> &data)
  {
    return std::string(reinterpret_cast<const char *>(data.data()), data.size());
  }

  std::vector<uint8_t> asBinaryArray(const std::string &data)
  {
    return std::vector<uint8_t>(data.begin(), data.end());
  }

  //  Hex — decoding

  uint8_t fromHex(char character)
  {
    uint8_t value;
    if (!fromHex(character, value))
    {
      throw std::runtime_error("fromHex: invalid character");
    }
    return value;
  }

  bool fromHex(char character, uint8_t &value)
  {
    if (character >= '0' && character <= '9')
    {
      value = static_cast<uint8_t>(character - '0');
      return true;
    }
    if (character >= 'a' && character <= 'f')
    {
      value = static_cast<uint8_t>(character - 'a' + 10);
      return true;
    }
    if (character >= 'A' && character <= 'F')
    {
      value = static_cast<uint8_t>(character - 'A' + 10);
      return true;
    }
    return false;
  }

  size_t fromHex(const std::string &text, void *data, size_t bufferSize)
  {
    size_t size = 0;
    if (!fromHex(text, data, bufferSize, size))
    {
      throw std::runtime_error("fromHex: invalid hex string");
    }
    return size;
  }

  bool fromHex(const std::string &text, void *data, size_t bufferSize,
               size_t &size)
  {
    if (text.size() % 2 != 0)
    {
      return false;
    }

    size = text.size() / 2;
    if (size > bufferSize)
    {
      return false;
    }

    uint8_t *byteData = static_cast<uint8_t *>(data);
    for (size_t i = 0; i < size; ++i)
    {
      uint8_t high = 0;
      uint8_t low = 0;
      if (!fromHex(text[i * 2], high) || !fromHex(text[i * 2 + 1], low))
      {
        return false;
      }
      byteData[i] = static_cast<uint8_t>((high << 4) | low);
    }

    return true;
  }

  std::vector<uint8_t> fromHex(const std::string &text)
  {
    std::vector<uint8_t> data;
    if (!fromHex(text, data))
    {
      throw std::runtime_error("fromHex: invalid hex string");
    }
    return data;
  }

  bool fromHex(const std::string &text, std::vector<uint8_t> &data)
  {
    if (text.size() % 2 != 0)
    {
      return false;
    }

    size_t oldSize = data.size();
    size_t newSize = text.size() / 2;
    data.resize(oldSize + newSize);

    for (size_t i = 0; i < newSize; ++i)
    {
      uint8_t high = 0;
      uint8_t low = 0;
      if (!fromHex(text[i * 2], high) || !fromHex(text[i * 2 + 1], low))
      {
        data.resize(oldSize);
        return false;
      }
      data[oldSize + i] = static_cast<uint8_t>((high << 4) | low);
    }

    return true;
  }

  //  Hex — encoding

  std::string toHex(const void *data, size_t size)
  {
    std::string text;
    toHex(data, size, text);
    return text;
  }

  void toHex(const void *data, size_t size, std::string &text)
  {
    const uint8_t *byteData = static_cast<const uint8_t *>(data);
    static const char hexChars[] = "0123456789abcdef";

    text.reserve(text.size() + size * 2);
    for (size_t i = 0; i < size; ++i)
    {
      text.push_back(hexChars[byteData[i] >> 4]);
      text.push_back(hexChars[byteData[i] & 0x0F]);
    }
  }

  std::string toHex(const std::vector<uint8_t> &data)
  {
    return toHex(data.data(), data.size());
  }

  void toHex(const std::vector<uint8_t> &data, std::string &text)
  {
    toHex(data.data(), data.size(), text);
  }

  //  String parsing

  std::string extract(std::string &text, char delimiter)
  {
    size_t delimiterPos = text.find(delimiter);
    if (delimiterPos == std::string::npos)
    {
      std::string result = text;
      text.clear();
      return result;
    }

    std::string result = text.substr(0, delimiterPos);
    text.erase(0, delimiterPos + 1);
    return result;
  }

  std::string extract(const std::string &text, char delimiter, size_t &offset)
  {
    size_t delimiterPos = text.find(delimiter, offset);
    if (delimiterPos == std::string::npos)
    {
      std::string result = text.substr(offset);
      offset = text.size();
      return result;
    }

    std::string result = text.substr(offset, delimiterPos - offset);
    offset = delimiterPos + 1;
    return result;
  }

  //  Network

  std::string ipAddressToString(uint32_t ip)
  {
    std::ostringstream stream;
    stream << ((ip >> 24) & 0xFF) << '.'
           << ((ip >> 16) & 0xFF) << '.'
           << ((ip >> 8) & 0xFF) << '.'
           << (ip & 0xFF);
    return stream.str();
  }

  bool parseIpAddressAndPort(uint32_t &ip, uint32_t &port,
                             const std::string &addr)
  {
    size_t colonPos = addr.find(':');
    if (colonPos == std::string::npos)
    {
      return false;
    }

    std::string ipStr = addr.substr(0, colonPos);
    std::string portStr = addr.substr(colonPos + 1);

    uint32_t octets[4] = {0, 0, 0, 0};
    std::istringstream ipStream(ipStr);
    char dot = 0;
    for (int i = 0; i < 4; ++i)
    {
      ipStream >> octets[i];
      if (i < 3 && !(ipStream >> dot))
      {
        return false;
      }
      if (octets[i] > 255)
        return false;
    }

    ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    return fromString(portStr, port);
  }

  //  Formatting

  std::string timeIntervalToString(uint64_t intervalInSeconds)
  {
    uint64_t days = intervalInSeconds / (24 * 3600);
    intervalInSeconds %= (24 * 3600);
    uint64_t hours = intervalInSeconds / 3600;
    intervalInSeconds %= 3600;
    uint64_t minutes = intervalInSeconds / 60;
    uint64_t seconds = intervalInSeconds % 60;

    std::ostringstream stream;
    if (days > 0)
      stream << days << "d ";
    if (hours > 0 || days > 0)
      stream << hours << "h ";
    if (minutes > 0 || hours > 0 || days > 0)
      stream << minutes << "m ";
    stream << seconds << "s";
    return stream.str();
  }

  std::string makeCenteredString(size_t width, const std::string &text)
  {
    if (text.size() >= width)
    {
      return text;
    }
    size_t padding = (width - text.size()) / 2;
    return std::string(padding, ' ') + text + std::string(width - text.size() - padding, ' ');
  }

  std::string formatTimestamp(time_t timestamp)
  {
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &timestamp);
#else
    gmtime_r(&timestamp, &tm);
#endif
    std::ostringstream stream;
    stream << std::put_time(&tm, "%Y-%m-%d %H:%M:%S UTC");
    return stream.str();
  }

  //  Binary hashing (Blake2b, Clarity's canonical hash)

  void getBinaryArrayHash(const BinaryArray &binaryArray, Crypto::Hash &hash)
  {
    Crypto::blake2b(binaryArray.data(), binaryArray.size(),
                    hash.data.data(), 32);
  }

  Crypto::Hash getBinaryArrayHash(const BinaryArray &binaryArray)
  {
    Crypto::Hash hash;
    getBinaryArrayHash(binaryArray, hash);
    return hash;
  }

} // namespace Common