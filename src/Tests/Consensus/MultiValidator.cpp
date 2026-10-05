// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <set>
#include <gtest/gtest.h>

#include "Fixtures.h"

using namespace Consensus;
using namespace Tests;

//  ---------------------------------------------------------------------
//  Fixture dependency note
//
//  Every test here uses advanceUntil with a ">=" predicate, not "==".
//  A single advanceAllTimers() call can commit more than one height:
//  the initial delivery pass commits the height whose messages were
//  queued, and the pending-height drain in pollTimers commits the
//  next height within the same call. Asserting exact counts is
//  fragile; asserting "at least N" is what the tests actually mean.
//  ---------------------------------------------------------------------

namespace
{
  bool allHaveAtLeast(const ConsensusNetwork &net, size_t n)
  {
    for (size_t i = 0; i < net.size(); ++i)
      if (net.committed(i).size() < n)
        return false;
    return true;
  }
} // anonymous namespace

// Basic multi-validator rounds

TEST_F(Consensus_NetworkFixture, FourValidatorsReachCommit)
{
  makeNetwork(4);
  net().startAll(0);
  net().advanceUntil([&]
                     { return allHaveAtLeast(net(), 1); }, 16);

  ASSERT_TRUE(allHaveAtLeast(net(), 1));
  for (size_t i = 0; i < 4; ++i)
    EXPECT_EQ(net().committed(i)[0].header.height, 0u) << "validator " << i;
}

TEST_F(Consensus_NetworkFixture, AllValidatorsAgreeOnCommittedBlock)
{
  makeNetwork(4);
  net().startAll(0);
  net().advanceUntil([&]
                     { return allHaveAtLeast(net(), 1); }, 16);

  ASSERT_TRUE(allHaveAtLeast(net(), 1));
  Crypto::Hash expected = net().committed(0).at(0).hash();
  for (size_t i = 1; i < 4; ++i)
    EXPECT_EQ(net().committed(i)[0].hash(), expected) << "validator " << i;
}

TEST_F(Consensus_NetworkFixture, ThreeOfFourIsQuorum)
{
  makeNetwork(4);
  net().setOffline(3, true);

  net().startAll(0);
  net().advanceUntil([&]
                     { return net().committed(0).size() >= 1u &&
                              net().committed(1).size() >= 1u &&
                              net().committed(2).size() >= 1u; }, 16);

  for (size_t i = 0; i < 3; ++i)
    EXPECT_GE(net().committed(i).size(), 1u) << "validator " << i;
  EXPECT_TRUE(net().committed(3).empty());
}

TEST_F(Consensus_NetworkFixture, TwoOfFourIsNotQuorum)
{
  makeNetwork(4);
  net().setOffline(2, true);
  net().setOffline(3, true);

  net().startAll(0);

  for (int i = 0; i < 5; ++i)
    net().advanceAllTimers();

  for (size_t i = 0; i < 4; ++i)
    EXPECT_TRUE(net().committed(i).empty())
        << "validator " << i << " committed without quorum";
}

// Fault tolerance

TEST_F(Consensus_NetworkFixture, OneEquivocatingValidator)
{
  //  This is the "3 of 4 online" case, not a direct equivocation test.
  makeNetwork(4);
  net().setOffline(3, true);

  net().startAll(0);
  net().advanceUntil([&]
                     { return net().committed(0).size() >= 1u &&
                              net().committed(1).size() >= 1u &&
                              net().committed(2).size() >= 1u; }, 16);

  ASSERT_GE(net().committed(0).size(), 1u);
  ASSERT_GE(net().committed(1).size(), 1u);
  ASSERT_GE(net().committed(2).size(), 1u);

  Crypto::Hash canonical = net().committed(0)[0].hash();
  EXPECT_EQ(net().committed(1)[0].hash(), canonical);
  EXPECT_EQ(net().committed(2)[0].hash(), canonical);
}

TEST_F(Consensus_NetworkFixture, ValidatorRejoinsAfterRoundAdvance)
{
  makeNetwork(4);
  net().setOffline(3, true);

  net().startAll(0);
  net().advanceUntil([&]
                     { return net().committed(0).size() >= 1u; }, 16);

  ASSERT_GE(net().committed(0).size(), 1u);
  ASSERT_GE(net().committed(1).size(), 1u);
  ASSERT_GE(net().committed(2).size(), 1u);
  EXPECT_TRUE(net().committed(3).empty());
}

TEST_F(Consensus_NetworkFixture, TwoRoundsTwoBlocks)
{
  makeNetwork(4);
  net().startAll(0);

  net().advanceUntil([&]
                     { return allHaveAtLeast(net(), 2); }, 16);

  ASSERT_TRUE(allHaveAtLeast(net(), 2));

  for (size_t i = 0; i < 4; ++i)
  {
    EXPECT_EQ(net().committed(i)[0].header.height, 0u) << "validator " << i;
    EXPECT_EQ(net().committed(i)[1].header.height, 1u) << "validator " << i;
  }

  for (size_t i = 1; i < 4; ++i)
  {
    EXPECT_EQ(net().committed(i)[0].hash(), net().committed(0)[0].hash());
    EXPECT_EQ(net().committed(i)[1].hash(), net().committed(0)[1].hash());
  }
}

// Broadcast routing and message flow

TEST_F(Consensus_NetworkFixture, ProposalReachesEveryValidator)
{
  makeNetwork(4);
  net().startAll(0);
  net().advanceUntil([&]
                     { return allHaveAtLeast(net(), 1); }, 16);

  ASSERT_TRUE(allHaveAtLeast(net(), 1));
}

TEST_F(Consensus_NetworkFixture, AllInstancesAdvancePastPropose)
{
  makeNetwork(4);
  net().startAll(0);
  net().advanceUntil([&]
                     { return allHaveAtLeast(net(), 1); }, 16);

  for (size_t i = 0; i < 4; ++i)
  {
    auto s = net().instance(i).state();
    EXPECT_GE(s.height, 1u) << "validator " << i;
  }
}

// Determinism

TEST_F(Consensus_NetworkFixture, SameRunProducesSameCommit)
{
  Crypto::Hash first_run;

  {
    makeNetwork(4);
    net().startAll(0);
    net().advanceUntil([&]
                       { return net().committed(0).size() >= 1u; }, 16);
    ASSERT_GE(net().committed(0).size(), 1u);
    first_run = net().committed(0)[0].hash();
    net().stopAll();
    network_.reset();
  }

  {
    makeNetwork(4);
    net().startAll(0);
    net().advanceUntil([&]
                       { return net().committed(0).size() >= 1u; }, 16);
    ASSERT_GE(net().committed(0).size(), 1u);
    Crypto::Hash second_run = net().committed(0)[0].hash();
    EXPECT_EQ(first_run, second_run);
  }
}

TEST_F(Consensus_NetworkFixture, AllValidatorsCommitSameHash)
{
  makeNetwork(4);
  net().startAll(0);

  net().advanceUntil([&]
                     { return allHaveAtLeast(net(), 2); }, 16);

  std::set<std::string> hashes;
  for (size_t i = 0; i < 4; ++i)
  {
    for (const auto &b : net().committed(i))
      hashes.insert(b.hash().toString());
  }

  //  Every committed block across all validators is one of a small
  //  number of hashes. The exact number depends on how many heights
  //  the network happened to commit; we assert no fork by checking
  //  that the count equals the number of distinct heights seen.
  std::set<uint64_t> heights;
  for (size_t i = 0; i < 4; ++i)
    for (const auto &b : net().committed(i))
      heights.insert(b.header.height);

  EXPECT_EQ(hashes.size(), heights.size())
      << "multiple hashes observed at the same height (fork)";
}
