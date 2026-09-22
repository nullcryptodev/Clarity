// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <set>
#include <gtest/gtest.h>

#include "P2P/Nonce.h"

using namespace P2P;

TEST(Nonce, GeneratesNonZero)
{
  // It's astronomically unlikely that 100 random 64-bit values all
  // come back zero, but if the RNG is broken we'd see it immediately.
  int zeros = 0;
  for (int i = 0; i < 100; ++i)
  {
    if (generateNetworkNonce() == 0)
      ++zeros;
  }
  EXPECT_EQ(zeros, 0);
}

TEST(Nonce, GeneratesDistinct)
{
  std::set<uint64_t> seen;
  for (int i = 0; i < 100; ++i)
    seen.insert(generateNetworkNonce());

  // With 64-bit entropy, 100 draws should all be distinct.
  EXPECT_EQ(seen.size(), 100u);
}