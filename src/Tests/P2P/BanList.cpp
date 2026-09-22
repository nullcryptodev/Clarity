// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "P2P/BanList.h"

using namespace P2P;
using namespace Tests;

TEST(BanList, InitiallyEmpty)
{
  TempFile f;
  BanList bl(f.path(), /*threshold=*/100, /*durationSec=*/3600);

  EXPECT_FALSE(bl.isBanned("10.0.0.1"));
  EXPECT_EQ(bl.size(), 0u);
}

TEST(BanList, RecordMisbehaviorBelowThreshold)
{
  TempFile f;
  BanList bl(f.path(), 100, 3600);

  EXPECT_FALSE(bl.recordMisbehavior("10.0.0.1", 30));
  EXPECT_FALSE(bl.isBanned("10.0.0.1"));
}

TEST(BanList, RecordMisbehaviorReachesThreshold)
{
  TempFile f;
  BanList bl(f.path(), 100, 3600);

  EXPECT_FALSE(bl.recordMisbehavior("10.0.0.1", 60));
  EXPECT_TRUE(bl.recordMisbehavior("10.0.0.1", 50)); // total 110 >= 100
  EXPECT_TRUE(bl.isBanned("10.0.0.1"));
}

TEST(BanList, ExplicitBan)
{
  TempFile f;
  BanList bl(f.path(), 100, 3600);

  bl.ban("192.168.0.5", BanReason::BadMagic);
  EXPECT_TRUE(bl.isBanned("192.168.0.5"));
}

TEST(BanList, Unban)
{
  TempFile f;
  BanList bl(f.path(), 100, 3600);

  bl.ban("10.0.0.1", BanReason::Spam);
  ASSERT_TRUE(bl.isBanned("10.0.0.1"));

  bl.unban("10.0.0.1");
  EXPECT_FALSE(bl.isBanned("10.0.0.1"));
  EXPECT_EQ(bl.size(), 0u);
}

TEST(BanList, BanIsNotIdempotentOnScore)
{
  TempFile f;
  BanList bl(f.path(), 100, 3600);

  bl.ban("10.0.0.1", BanReason::Spam);
  // Second ban just refreshes the timer; size stays 1.
  bl.ban("10.0.0.1", BanReason::Spam);
  EXPECT_EQ(bl.size(), 1u);
}

TEST(BanList, MultipleIPs)
{
  TempFile f;
  BanList bl(f.path(), 100, 3600);

  bl.ban("10.0.0.1", BanReason::Spam);
  bl.ban("10.0.0.2", BanReason::BadMagic);
  bl.ban("10.0.0.3", BanReason::Other);

  EXPECT_TRUE(bl.isBanned("10.0.0.1"));
  EXPECT_TRUE(bl.isBanned("10.0.0.2"));
  EXPECT_TRUE(bl.isBanned("10.0.0.3"));
  EXPECT_EQ(bl.size(), 3u);
}

TEST(BanList, PersistAndReload)
{
  TempFile f;
  {
    BanList bl(f.path(), 100, 3600);
    bl.ban("10.0.0.1", BanReason::Spam);
    bl.ban("10.0.0.2", BanReason::BadMagic);
  }

  BanList bl2(f.path(), 100, 3600);
  EXPECT_TRUE(bl2.isBanned("10.0.0.1"));
  EXPECT_TRUE(bl2.isBanned("10.0.0.2"));
  EXPECT_FALSE(bl2.isBanned("10.0.0.3"));
  EXPECT_EQ(bl2.size(), 2u);
}

TEST(BanList, PurgeExpiredWithZeroScore)
{
  TempFile f;
  BanList bl(f.path(), 100, /*durationSec=*/0);

  // Ban with 0-second duration — expired immediately.
  bl.ban("10.0.0.1", BanReason::Spam);
  // Purge should remove entries whose ban expired and score is 0.
  // But `ban` sets score = threshold_, so this won't be purged.
  // This test documents that behavior.
  bl.purgeExpired();
  EXPECT_EQ(bl.size(), 1u);
}

TEST(BanList, PurgeExpiredEmptyIsSafe)
{
  TempFile f;
  BanList bl(f.path(), 100, 3600);
  EXPECT_NO_THROW(bl.purgeExpired());
  EXPECT_EQ(bl.size(), 0u);
}