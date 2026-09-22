#include "Base.h"

#include <array>
#include <cassert>
#include <string_view>
#include <algorithm>
#include <cstring>

#include "Common/Varint.h"

#include "Crypto/Types.h"

namespace
{
  // Base58 Implementation
  constexpr std::string_view alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  constexpr size_t alphabetSize = alphabet.size();

  constexpr std::array<size_t, 9> encodedBlockSizes = {0, 2, 3, 5, 6, 7, 9, 10, 11};
  constexpr size_t fullBlockSize = encodedBlockSizes.size() - 1;
  constexpr size_t fullEncodedBlockSize = encodedBlockSizes[fullBlockSize];
  constexpr size_t addressChecksumSize = 4;

  class ReverseAlphabet
  {
  public:
    constexpr ReverseAlphabet() : m_data{}
    {
      for (auto &val : m_data)
        val = -1;

      for (size_t i = 0; i < alphabetSize; ++i)
      {
        size_t idx = static_cast<size_t>(alphabet[i] - alphabet[0]);
        m_data[idx] = static_cast<int8_t>(i);
      }
    }

    constexpr int operator()(char letter) const
    {
      size_t idx = static_cast<size_t>(letter - alphabet[0]);
      return idx < m_data.size() ? m_data[idx] : -1;
    }

  private:
    std::array<int8_t, alphabet[alphabetSize - 1] - alphabet[0] + 1> m_data;
  };

  class DecodedBlockSizes
  {
  public:
    constexpr DecodedBlockSizes() : m_data{}
    {
      for (auto &val : m_data)
        val = -1;

      for (size_t i = 0; i <= fullBlockSize; ++i)
      {
        m_data[encodedBlockSizes[i]] = static_cast<int>(i);
      }
    }

    constexpr int operator()(size_t encodedBlockSize) const
    {
      assert(encodedBlockSize <= fullEncodedBlockSize);
      return m_data[encodedBlockSize];
    }

  private:
    std::array<int, fullEncodedBlockSize + 1> m_data;
  };

  constexpr ReverseAlphabet reverseAlphabet{};
  constexpr DecodedBlockSizes decodedBlockSizes{};

  constexpr uint64_t uint8BeTo64(const uint8_t *data, size_t size)
  {
    assert(1 <= size && size <= sizeof(uint64_t));

    uint64_t res = 0;
    for (size_t i = 0; i < size; ++i)
    {
      res = (res << 8) | data[i];
    }
    return res;
  }

  constexpr void uint64To8Be(uint64_t num, size_t size, uint8_t *data)
  {
    assert(1 <= size && size <= sizeof(uint64_t));

    for (size_t i = 0; i < size; ++i)
    {
      data[i] = static_cast<uint8_t>((num >> (8 * (size - 1 - i))) & 0xFF);
    }
  }

  void encodeBlock(const char *block, size_t size, char *res)
  {
    assert(1 <= size && size <= fullBlockSize);

    uint64_t num = uint8BeTo64(reinterpret_cast<const uint8_t *>(block), size);
    int i = static_cast<int>(encodedBlockSizes[size]) - 1;
    while (num > 0)
    {
      uint64_t remainder = num % alphabetSize;
      num /= alphabetSize;
      res[i] = alphabet[remainder];
      --i;
    }
  }

  bool decodeBlock(const char *block, size_t size, char *res)
  {
    assert(1 <= size && size <= fullEncodedBlockSize);

    int resSize = decodedBlockSizes(size);
    if (resSize <= 0)
      return false;

    uint64_t res_num = 0;
    uint64_t order = 1;

    for (size_t i = size; i > 0; --i)
    {
      int digit = reverseAlphabet(block[i - 1]);
      if (digit < 0)
        return false;

      uint64_t product;
      if (__builtin_mul_overflow(order, digit, &product))
        return false;

      uint64_t tmp;
      if (__builtin_add_overflow(res_num, product, &tmp))
        return false;

      res_num = tmp;
      order *= alphabetSize;
    }

    if (static_cast<size_t>(resSize) < fullBlockSize &&
        (UINT64_C(1) << (8 * resSize)) <= res_num)
      return false;

    uint64To8Be(res_num, resSize, reinterpret_cast<uint8_t *>(res));

    return true;
  }

  // Base64 Implementation
  constexpr std::string_view base64Chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "abcdefghijklmnopqrstuvwxyz"
      "0123456789+/";

  constexpr char base64Padding = '=';
  constexpr size_t base64ChunkSize = 4;
  constexpr size_t base64InputChunk = 3;

  class Base64DecodeTable
  {
  public:
    constexpr Base64DecodeTable() : m_data{}
    {
      for (auto &val : m_data)
        val = -1;

      for (size_t i = 0; i < base64Chars.size(); ++i)
      {
        m_data[static_cast<unsigned char>(base64Chars[i])] = static_cast<int8_t>(i);
      }
    }

    constexpr int operator()(char c) const
    {
      return m_data[static_cast<unsigned char>(c)];
    }

  private:
    std::array<int8_t, 256> m_data;
  };

  constexpr Base64DecodeTable base64DecodeTable{};

  constexpr bool isValidBase64Char(char c)
  {
    return base64DecodeTable(c) >= 0 || c == base64Padding;
  }
} // anonymous namespace

namespace Common
{
  std::string encodeBase58(std::string_view data)
  {
    if (data.empty())
      return {};

    size_t fullBlockCount = data.size() / fullBlockSize;
    size_t lastBlockSize = data.size() % fullBlockSize;
    size_t resSize = fullBlockCount * fullEncodedBlockSize + encodedBlockSizes[lastBlockSize];

    std::string res(resSize, alphabet[0]);

    for (size_t i = 0; i < fullBlockCount; ++i)
    {
      encodeBlock(data.data() + i * fullBlockSize, fullBlockSize,
                  res.data() + i * fullEncodedBlockSize);
    }

    if (lastBlockSize > 0)
    {
      encodeBlock(data.data() + fullBlockCount * fullBlockSize, lastBlockSize,
                  res.data() + fullBlockCount * fullEncodedBlockSize);
    }

    return res;
  }

  bool decodeBase58(std::string_view enc, std::string &data)
  {
    if (enc.empty())
    {
      data.clear();
      return true;
    }

    size_t fullBlockCount = enc.size() / fullEncodedBlockSize;
    size_t lastBlockSize = enc.size() % fullEncodedBlockSize;
    int lastBlockDecodedSize = decodedBlockSizes(lastBlockSize);
    if (lastBlockDecodedSize < 0)
      return false;

    size_t data_size = fullBlockCount * fullBlockSize + lastBlockDecodedSize;
    data.resize(data_size, 0);

    for (size_t i = 0; i < fullBlockCount; ++i)
    {
      if (!decodeBlock(enc.data() + i * fullEncodedBlockSize, fullEncodedBlockSize,
                       data.data() + i * fullBlockSize))
        return false;
    }

    if (lastBlockSize > 0)
    {
      if (!decodeBlock(enc.data() + fullBlockCount * fullEncodedBlockSize, lastBlockSize,
                       data.data() + fullBlockCount * fullBlockSize))
        return false;
    }

    return true;
  }

  std::string encodeBase64(std::string_view data)
  {
    if (data.empty())
      return {};

    size_t outputSize = base64ChunkSize * ((data.size() + base64InputChunk - 1) / base64InputChunk);
    std::string result;
    result.reserve(outputSize);

    for (size_t i = 0; i < data.size(); i += base64InputChunk)
    {
      unsigned char a = static_cast<unsigned char>(data[i]);
      unsigned char b = (i + 1 < data.size()) ? static_cast<unsigned char>(data[i + 1]) : 0;
      unsigned char c = (i + 2 < data.size()) ? static_cast<unsigned char>(data[i + 2]) : 0;

      result.push_back(base64Chars[a >> 2]);
      result.push_back(base64Chars[((a & 0x03) << 4) | (b >> 4)]);

      if (i + 1 < data.size())
      {
        result.push_back(base64Chars[((b & 0x0F) << 2) | (c >> 6)]);
        if (i + 2 < data.size())
        {
          result.push_back(base64Chars[c & 0x3F]);
        }
        else
        {
          result.push_back(base64Padding);
        }
      }
      else
      {
        result.push_back(base64Padding);
        result.push_back(base64Padding);
      }
    }

    return result;
  }

  std::string decodeBase64(std::string_view data)
  {
    if (data.empty())
      return {};

    std::string input;
    input.reserve(data.size());

    for (char c : data)
    {
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
        continue;

      if (!isValidBase64Char(c))
        return {};

      input.push_back(c);
    }

    if (input.empty())
      return {};

    if (input.size() % base64ChunkSize != 0)
      return {};

    size_t paddingCount = 0;
    if (input.size() >= 2 && input[input.size() - 2] == base64Padding)
      paddingCount = 2;
    else if (input.size() >= 1 && input[input.size() - 1] == base64Padding)
      paddingCount = 1;

    size_t outputSize = (input.size() / base64ChunkSize) * base64InputChunk - paddingCount;
    std::string result;
    result.reserve(outputSize);

    for (size_t i = 0; i < input.size(); i += base64ChunkSize)
    {
      int v0 = base64DecodeTable(input[i]);
      int v1 = base64DecodeTable(input[i + 1]);
      int v2 = base64DecodeTable(input[i + 2]);
      int v3 = base64DecodeTable(input[i + 3]);

      result.push_back(static_cast<char>((v0 << 2) | (v1 >> 4)));

      if (v2 >= 0 && static_cast<size_t>(i + 2) < input.size() && input[i + 2] != base64Padding)
      {
        result.push_back(static_cast<char>(((v1 & 0x0F) << 4) | (v2 >> 2)));
      }

      if (v3 >= 0 && static_cast<size_t>(i + 3) < input.size() && input[i + 3] != base64Padding)
      {
        result.push_back(static_cast<char>(((v2 & 0x03) << 6) | v3));
      }
    }

    return result;
  }
} // namespace Common