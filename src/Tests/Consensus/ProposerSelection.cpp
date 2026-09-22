// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Consensus/ProposerSelection.h"

using namespace Consensus;

TEST(ProposerSelection, EmptySetReturnsZero)
{
  EXPECT_EQ(proposerIndex(0, 0, 0), 0u);
  EXPECT_EQ(proposerIndex(100, 5, 0), 0u);
}

TEST(ProposerSelection, FormulaHeightPlusRound)
{
  // (height + round) % active_size
  EXPECT_EQ(proposerIndex(0, 0, 4), 0u);
  EXPECT_EQ(proposerIndex(1, 0, 4), 1u);
  EXPECT_EQ(proposerIndex(2, 0, 4), 2u);
  EXPECT_EQ(proposerIndex(3, 0, 4), 3u);
  EXPECT_EQ(proposerIndex(4, 0, 4), 0u);
  EXPECT_EQ(proposerIndex(0, 1, 4), 1u);
  EXPECT_EQ(proposerIndex(0, 2, 4), 2u);
  EXPECT_EQ(proposerIndex(3, 1, 4), 0u); // (3+1)%4
}

TEST(ProposerSelection, LargeHeight)
{
  EXPECT_EQ(proposerIndex(1'000'000, 0, 7), 1'000'000u % 7u);
  EXPECT_EQ(proposerIndex(1'000'000, 3, 7), (1'000'000u + 3u) % 7u);
}

TEST(ProposerSelection, SingleValidatorAlwaysZero)
{
  EXPECT_EQ(proposerIndex(0, 0, 1), 0u);
  EXPECT_EQ(proposerIndex(999, 0, 1), 0u);
  EXPECT_EQ(proposerIndex(999, 999, 1), 0u);
}

TEST(ProposerSelection, EmptyActiveSetReturnsInvalidId)
{
  std::vector<Id> empty;
  EXPECT_EQ(proposerFor(0, 0, empty), INVALID_ID);
}

TEST(ProposerSelection, ProposerForSelectsRightValidator)
{
  std::vector<Id> active = {10, 20, 30, 40};

  EXPECT_EQ(proposerFor(0, 0, active), 10u);
  EXPECT_EQ(proposerFor(1, 0, active), 20u);
  EXPECT_EQ(proposerFor(2, 0, active), 30u);
  EXPECT_EQ(proposerFor(3, 0, active), 40u);
  EXPECT_EQ(proposerFor(4, 0, active), 10u);
  EXPECT_EQ(proposerFor(0, 1, active), 20u);
}

TEST(ProposerSelection, RotatesWithRoundIncrement)
{
  std::vector<Id> active = {10, 20, 30};
  auto p0 = proposerFor(5, 0, active);
  auto p1 = proposerFor(5, 1, active);
  auto p2 = proposerFor(5, 2, active);
  auto p3 = proposerFor(5, 3, active);

  EXPECT_NE(p0, p1);
  EXPECT_NE(p1, p2);
  EXPECT_NE(p2, p3);
  EXPECT_EQ(p0, p3); // wraps
}