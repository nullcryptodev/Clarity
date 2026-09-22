// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Sha512.h"

using namespace Crypto;
using namespace Tests;

TEST(Sha512, Empty)
{
  uint8_t out[64];
  sha512(reinterpret_cast<const uint8_t *>(""), 0, out);

  EXPECT_EQ(toHex(out, 64),
            "cf83e1357eefb8bdf1542850d66d8007"
            "d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f"
            "63b931bd47417a81a538327af927da3e");
}

TEST(Sha512, Abc)
{
  uint8_t out[64];
  sha512(reinterpret_cast<const uint8_t *>("abc"), 3, out);

  EXPECT_EQ(toHex(out, 64),
            "ddaf35a193617abacc417349ae204131"
            "12e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd"
            "454d4423643ce80e2a9ac94fa54ca49f");
}

TEST(Sha512, LongerMessage)
{
  const char *msg =
      "The quick brown fox jumps over the lazy dog";

  uint8_t out[64];
  sha512(reinterpret_cast<const uint8_t *>(msg),
         std::strlen(msg), out);

  EXPECT_EQ(toHex(out, 64),
            "07e547d9586f6a73f73fbac0435ed769"
            "51218fb7d0c8d788a309d785436bbb64"
            "2e93a252a954f23912547d1e8a3b5ed6"
            "e1bfd7097821233fa0538f3db854fee6");
}