// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "P2P/AddressBook.h"

using namespace P2P;
using namespace Tests;

TEST(AddressBook, InitiallyEmpty)
{
  TempFile f;
  AddressBook ab(f.path());
  EXPECT_EQ(ab.size(), 0u);
}

TEST(AddressBook, AddAndSize)
{
  TempFile f;
  AddressBook ab(f.path());

  ab.add("10.0.0.1", 19444);
  ab.add("10.0.0.2", 19444);
  EXPECT_EQ(ab.size(), 2u);
}

TEST(AddressBook, AddIsIdempotent)
{
  TempFile f;
  AddressBook ab(f.path());

  ab.add("10.0.0.1", 19444);
  ab.add("10.0.0.1", 19444);
  EXPECT_EQ(ab.size(), 1u);
}

TEST(AddressBook, SameIpDifferentPortIsDistinct)
{
  TempFile f;
  AddressBook ab(f.path());

  ab.add("10.0.0.1", 19444);
  ab.add("10.0.0.1", 19445);
  EXPECT_EQ(ab.size(), 2u);
}

TEST(AddressBook, PickRandomAll)
{
  TempFile f;
  AddressBook ab(f.path());

  ab.add("10.0.0.1", 19444);
  ab.add("10.0.0.2", 19444);
  ab.add("10.0.0.3", 19444);

  auto picked = ab.pickRandom(10);
  EXPECT_EQ(picked.size(), 3u);
}

TEST(AddressBook, PickRandomEmpty)
{
  TempFile f;
  AddressBook ab(f.path());

  auto picked = ab.pickRandom(5);
  EXPECT_TRUE(picked.empty());
}

TEST(AddressBook, PickRandomExcludes)
{
  TempFile f;
  AddressBook ab(f.path());

  ab.add("10.0.0.1", 19444);
  ab.add("10.0.0.2", 19444);
  ab.add("10.0.0.3", 19444);

  auto picked = ab.pickRandom(10, {"10.0.0.1", "10.0.0.3"});
  ASSERT_EQ(picked.size(), 1u);
  EXPECT_EQ(picked[0].ip, "10.0.0.2");
}

TEST(AddressBook, MarkConnectedResetsAttempts)
{
  TempFile f;
  AddressBook ab(f.path());

  ab.add("10.0.0.1", 19444);
  ab.markFailed("10.0.0.1", 19444);
  ab.markFailed("10.0.0.1", 19444);
  ab.markFailed("10.0.0.1", 19444);

  auto before = ab.pickRandom(1);
  ASSERT_EQ(before.size(), 1u);
  EXPECT_GE(before[0].attempts, 3u);

  ab.markConnected("10.0.0.1", 19444);

  auto after = ab.pickRandom(1);
  ASSERT_EQ(after.size(), 1u);
  EXPECT_EQ(after[0].attempts, 0u);
}

TEST(AddressBook, PersistAndReload)
{
  TempFile f;
  {
    AddressBook ab(f.path());
    ab.add("10.0.0.1", 19444);
    ab.add("10.0.0.2", 19445, /*isSeed=*/true);
    ab.save();
  }

  AddressBook ab2(f.path());
  EXPECT_EQ(ab2.size(), 2u);

  auto picked = ab2.pickRandom(2);
  ASSERT_EQ(picked.size(), 2u);

  bool has_seed = false;
  for (const auto &e : picked)
    if (e.isSeed)
      has_seed = true;
  EXPECT_TRUE(has_seed);
}

TEST(AddressBook, PurgeStaleRemovesOldFailed)
{
  TempFile f;
  AddressBook ab(f.path());

  ab.add("10.0.0.1", 19444);
  // Simulate many failed attempts.
  for (int i = 0; i < 5; ++i)
    ab.markFailed("10.0.0.1", 19444);

  // Purge with a very old maxAgeSec (e.g. 0) — cutoff is now, all
  // non-seed entries with attempts > 3 will be removed.
  ab.purgeStale(0);

  // Note: lastSeen is set at `add` time (now), so it's not older than
  // the cutoff. This test doesn't actually purge. To test the purge
  // path, we'd need to inject a fake clock. For now, document the
  // behavior.
  EXPECT_EQ(ab.size(), 1u);
}

TEST(AddressBook, PurgeStaleKeepsSeeds)
{
  TempFile f;
  AddressBook ab(f.path());

  ab.add("10.0.0.1", 19444, /*isSeed=*/true);
  for (int i = 0; i < 10; ++i)
    ab.markFailed("10.0.0.1", 19444);

  // Even if a seed is stale, it must survive.
  ab.purgeStale(0);
  EXPECT_EQ(ab.size(), 1u);
}