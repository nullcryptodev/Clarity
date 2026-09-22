// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Blake2b.h"

using namespace Crypto;
using namespace Tests;

TEST(Blake2b, EmptyInput)
{
  uint8_t out[32];
  blake2b(reinterpret_cast<const uint8_t *>(""), 0, out, 32);

  EXPECT_EQ(toHex(out, 32),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
}

TEST(Blake2b, Abc)
{
  uint8_t out[32];
  blake2b(reinterpret_cast<const uint8_t *>("abc"), 3, out, 32);

  EXPECT_EQ(toHex(out, 32),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
}

TEST(Blake2b, LongerMessage)
{
  const char *msg =
      "The quick brown fox jumps over the lazy dog";

  uint8_t out[32];
  blake2b(reinterpret_cast<const uint8_t *>(msg),
          std::strlen(msg), out, 32);

  // Reference value computed by a known-good implementation.
  EXPECT_EQ(toHex(out, 32),
            "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9");
}