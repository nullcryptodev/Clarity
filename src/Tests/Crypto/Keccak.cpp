// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Keccak.h"

using namespace Crypto;
using namespace Tests;

TEST(Keccak, Empty)
{
  uint8_t out[32];
  keccak256(reinterpret_cast<const uint8_t *>(""), 0, out);

  EXPECT_EQ(toHex(out, 32),
            "c5d2460186f7233c927e7db2dcc703c0"
            "e500b653ca82273b7bfad8045d85a470");
}

TEST(Keccak, Abc)
{
  uint8_t out[32];
  keccak256(reinterpret_cast<const uint8_t *>("abc"), 3, out);

  // Correct Keccak-256("abc")
  EXPECT_EQ(toHex(out, 32),
            "4e03657aea45a94fc7d47ba826c8d667"
            "c0d1e6e33a64a036ec44f58fa12d6c45");
}

TEST(Sha3, Empty)
{
  uint8_t out[32];
  sha3_256(reinterpret_cast<const uint8_t *>(""), 0, out);

  EXPECT_EQ(toHex(out, 32),
            "a7ffc6f8bf1ed76651c14756a061d662"
            "f580ff4de43b49fa82d80a4b80f8434a");
}

TEST(Sha3, Abc)
{
  uint8_t out[32];
  sha3_256(reinterpret_cast<const uint8_t *>("abc"), 3, out);

  EXPECT_EQ(toHex(out, 32),
            "3a985da74fe225b2045c172d6bd390bd"
            "855f086e3e9d525b46bfe24511431532");
}