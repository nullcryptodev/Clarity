// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Consensus/Types.h"

using namespace Consensus;

// ============================================================================
//  stepName
// ============================================================================

TEST(ConsensusTypes, StepNames)
{
  EXPECT_STREQ(stepName(Step::NewHeight), "new-height");
  EXPECT_STREQ(stepName(Step::Propose), "propose");
  EXPECT_STREQ(stepName(Step::Prevote), "prevote");
  EXPECT_STREQ(stepName(Step::Precommit), "precommit");
  EXPECT_STREQ(stepName(Step::Commit), "commit");
}

TEST(ConsensusTypes, StepNameUnknownReturnsString)
{
  // Casting an arbitrary byte to Step and querying stepName must not
  // crash and must return a sentinel string.
  auto unknown = static_cast<Step>(0xFF);
  const char *name = stepName(unknown);
  ASSERT_NE(name, nullptr);
  EXPECT_STREQ(name, "unknown");
}

// ============================================================================
//  Vote::isValid
// ============================================================================

TEST(ConsensusTypes, DefaultVoteIsInvalid)
{
  Vote v;
  EXPECT_FALSE(v.isValid());
  EXPECT_EQ(v.signer_index, INVALID_INDEX);
}

TEST(ConsensusTypes, VoteWithSignerAndSignatureIsValid)
{
  Vote v;
  v.signer_index = 3;
  // Fill signature with non-zero bytes.
  for (auto &b : v.signature.data)
    b = 0xAB;
  EXPECT_TRUE(v.isValid());
}

TEST(ConsensusTypes, VoteWithSignerButNoSignatureIsInvalid)
{
  Vote v;
  v.signer_index = 3;
  EXPECT_FALSE(v.isValid());
}

// ============================================================================
//  Proposal::isValid
// ============================================================================

TEST(ConsensusTypes, DefaultProposalIsInvalid)
{
  Proposal p;
  EXPECT_FALSE(p.isValid());
}

TEST(ConsensusTypes, ProposalRequiresAllFields)
{
  Proposal p;
  p.signer_index = 1;
  p.block_hash.data[0] = 0x01;
  p.block_bytes = {1, 2, 3, 4};
  for (auto &b : p.signature.data)
    b = 0xCD;

  EXPECT_TRUE(p.isValid());

  // Remove each required field in turn; must become invalid.
  {
    Proposal q = p;
    q.signer_index = INVALID_INDEX;
    EXPECT_FALSE(q.isValid());
  }
  {
    Proposal q = p;
    for (auto &b : q.signature.data)
      b = 0;
    EXPECT_FALSE(q.isValid());
  }
  {
    Proposal q = p;
    q.block_hash = Crypto::Hash{};
    EXPECT_FALSE(q.isValid());
  }
  {
    Proposal q = p;
    q.block_bytes.clear();
    EXPECT_FALSE(q.isValid());
  }
}

// ============================================================================
//  Quorum
// ============================================================================

TEST(ConsensusTypes, QuorumCountMatchesVotes)
{
  Quorum q;
  EXPECT_EQ(q.count(), 0u);

  Vote v;
  q.votes.push_back(v);
  q.votes.push_back(v);
  EXPECT_EQ(q.count(), 2u);
}