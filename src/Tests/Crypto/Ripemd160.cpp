#include <gtest/gtest.h>

#include "Crypto/Ripemd160.h"

#include <string>
#include <vector>

using namespace Crypto;

namespace
{
  std::string hex(const uint8_t *p, size_t n)
  {
    static const char H[] = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
      s.push_back(H[p[i] >> 4]);
      s.push_back(H[p[i] & 0xF]);
    }
    return s;
  }

  std::string ripemd(const std::string &in)
  {
    uint8_t out[20];
    Ripemd160::hash(reinterpret_cast<const uint8_t *>(in.data()),
                    in.size(), out);
    return hex(out, 20);
  }
} // namespace

TEST(Crypto_Ripemd160, EmptyString)
{
  EXPECT_EQ(ripemd(""), "9c1185a5c5e9fc54612808977ee8f548b2258d31");
}

TEST(Crypto_Ripemd160, Abc)
{
  EXPECT_EQ(ripemd("abc"), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
}

TEST(Crypto_Ripemd160, MessageDigest)
{
  EXPECT_EQ(ripemd("message digest"),
            "5d0689ef49d2fae572b881b123a85ffa21595f36");
}

TEST(Crypto_Ripemd160, AtoZAndDigits)
{
  EXPECT_EQ(ripemd("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "b0e20b6e3116640286ed3a87a5713079b21f5189");
}

TEST(Crypto_Ripemd160, StreamingMatchesOneShot)
{
  Ripemd160 h;
  h.update(reinterpret_cast<const uint8_t *>("ab"), 2);
  h.update(reinterpret_cast<const uint8_t *>("c"), 1);
  uint8_t out[20];
  h.finalize(out);
  EXPECT_EQ(hex(out, 20), ripemd("abc"));
}