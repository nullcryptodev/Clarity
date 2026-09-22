// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

using namespace Consensus;
using namespace Tests;

// ============================================================================
//  Proposal encode/decode
// ============================================================================

TEST(ConsensusMessage, ProposalRoundTrip)
{
  Core::Block block;
  block.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
  block.header.chain_id = 0x434C5247;
  block.header.height = 42;
  block.header.parent_hash = Crypto::Hash{};
  block.header.timestamp_ms = 1'700'000'000'000ULL;
  block.header.proposer = Crypto::Address{};
  for (size_t i = 0; i < 32; ++i)
    block.header.proposer.data[i] = 0x80;
  block.header.tx_root = Core::computeTxRoot({});
  block.header.state_root = Crypto::Hash{};
  block.header.receipts_root = Crypto::Hash{};
  block.header.validator_set_root = Crypto::Hash{};
  block.header.active_validator_count = 4;
  block.header.tx_count = 0;

  // Fill quorum signatures so Block::isWellFormed() passes after
  // deserialize. bftQuorum(4) == 3.
  block.quorum_signatures.resize(Core::bftQuorum(4));
  for (size_t i = 0; i < block.quorum_signatures.size(); ++i)
  {
    block.quorum_signatures[i].signer_index = static_cast<uint16_t>(i);
  }

  Proposal p;
  p.height = 42;
  p.round = 3;
  p.signer_index = 1;
  p.block_hash = block.hash();
  p.block_bytes = block.serialize();
  for (auto &b : p.signature.data)
    b = 0xCD;

  auto bytes = encodeProposal(p);
  Proposal decoded;
  ASSERT_TRUE(decodeProposal(bytes.data(), bytes.size(), decoded));

  EXPECT_EQ(decoded.height, p.height);
  EXPECT_EQ(decoded.round, p.round);
  EXPECT_EQ(decoded.signer_index, p.signer_index);
  EXPECT_EQ(decoded.block_bytes, p.block_bytes);
  EXPECT_EQ(decoded.signature.data, p.signature.data);
  EXPECT_EQ(decoded.block_hash, p.block_hash);
}

TEST(ConsensusMessage, DecodeProposalRejectsTruncated)
{
  Proposal p;
  p.height = 1;
  p.round = 0;
  p.signer_index = 0;
  p.block_bytes = {1, 2, 3};
  for (auto &b : p.signature.data)
    b = 0xAA;

  auto bytes = encodeProposal(p);

  // Truncate by one byte.
  bytes.pop_back();
  Proposal decoded;
  EXPECT_FALSE(decodeProposal(bytes.data(), bytes.size(), decoded));

  // Truncate far below minimum.
  std::vector<uint8_t> tiny = {0, 0, 0};
  EXPECT_FALSE(decodeProposal(tiny.data(), tiny.size(), decoded));
}

TEST(ConsensusMessage, DecodeProposalRejectsOversizedBlockSize)
{
  // Craft a header that claims a block_bytes size larger than the
  // payload actually contains.
  std::vector<uint8_t> bytes;

  auto putU16 = [&](uint16_t v)
  {
    bytes.push_back(uint8_t(v));
    bytes.push_back(uint8_t(v >> 8));
  };
  auto putU32 = [&](uint32_t v)
  {
    bytes.push_back(uint8_t(v));
    bytes.push_back(uint8_t(v >> 8));
    bytes.push_back(uint8_t(v >> 16));
    bytes.push_back(uint8_t(v >> 24));
  };
  auto putU64 = [&](uint64_t v)
  {
    for (int i = 0; i < 8; ++i)
      bytes.push_back(uint8_t(v >> (i * 8)));
  };

  putU64(1);         // height
  putU64(0);         // round
  putU16(0);         // signer
  putU32(1'000'000); // block_size — impossible
  // No block bytes.

  Proposal decoded;
  EXPECT_FALSE(decodeProposal(bytes.data(), bytes.size(), decoded));
}

// ============================================================================
//  Vote encode/decode
// ============================================================================

TEST(ConsensusMessage, VoteRoundTripInclusion)
{
  Vote v;
  v.height = 100;
  v.round = 7;
  v.signer_index = 2;
  v.is_nil = false;
  v.block_hash.data[0] = 0xDE;
  v.block_hash.data[1] = 0xAD;
  for (auto &b : v.signature.data)
    b = 0xBE;

  auto bytes = encodeVote(v);
  Vote decoded;
  ASSERT_TRUE(decodeVote(bytes.data(), bytes.size(), decoded));

  EXPECT_EQ(decoded.height, v.height);
  EXPECT_EQ(decoded.round, v.round);
  EXPECT_EQ(decoded.signer_index, v.signer_index);
  EXPECT_EQ(decoded.is_nil, v.is_nil);
  EXPECT_EQ(decoded.block_hash, v.block_hash);
  EXPECT_EQ(decoded.signature.data, v.signature.data);
}

TEST(ConsensusMessage, VoteRoundTripNil)
{
  Vote v;
  v.height = 200;
  v.round = 0;
  v.signer_index = 0;
  v.is_nil = true;
  v.block_hash = Crypto::Hash{};
  for (auto &b : v.signature.data)
    b = 0x11;

  auto bytes = encodeVote(v);
  Vote decoded;
  ASSERT_TRUE(decodeVote(bytes.data(), bytes.size(), decoded));

  EXPECT_TRUE(decoded.is_nil);
  EXPECT_TRUE(decoded.block_hash.isNull());
  EXPECT_EQ(decoded.height, v.height);
  EXPECT_EQ(decoded.signer_index, v.signer_index);
}

TEST(ConsensusMessage, DecodeVoteRejectsTruncated)
{
  Vote v;
  v.height = 1;
  v.round = 0;
  v.signer_index = 0;
  v.is_nil = false;
  for (auto &b : v.signature.data)
    b = 0x42;

  auto bytes = encodeVote(v);
  bytes.pop_back();

  Vote decoded;
  EXPECT_FALSE(decodeVote(bytes.data(), bytes.size(), decoded));

  std::vector<uint8_t> tiny = {0};
  EXPECT_FALSE(decodeVote(tiny.data(), tiny.size(), decoded));
}

// ============================================================================
//  Signing hashes
// ============================================================================

TEST(ConsensusMessage, ProposalSigningHashIsDeterministic)
{
  Crypto::Hash block_hash;
  block_hash.data[0] = 0xAA;

  auto h1 = proposalSigningHash(1, 2, block_hash);
  auto h2 = proposalSigningHash(1, 2, block_hash);
  EXPECT_EQ(h1, h2);
}

TEST(ConsensusMessage, ProposalSigningHashCoversAllFields)
{
  Crypto::Hash block_hash;
  block_hash.data[0] = 0xAA;

  auto base = proposalSigningHash(1, 2, block_hash);

  EXPECT_NE(base, proposalSigningHash(2, 2, block_hash)); // height
  EXPECT_NE(base, proposalSigningHash(1, 3, block_hash)); // round

  Crypto::Hash other_hash = block_hash;
  other_hash.data[31] ^= 0x01;
  EXPECT_NE(base, proposalSigningHash(1, 2, other_hash)); // block_hash
}

TEST(ConsensusMessage, VoteSigningHashIsDeterministic)
{
  Crypto::Hash block_hash;
  block_hash.data[0] = 0xBB;

  auto h1 = voteSigningHash(5, 3, false, block_hash);
  auto h2 = voteSigningHash(5, 3, false, block_hash);
  EXPECT_EQ(h1, h2);
}

TEST(ConsensusMessage, VoteSigningHashCoversAllFields)
{
  Crypto::Hash block_hash;
  block_hash.data[0] = 0xBB;

  auto base = voteSigningHash(5, 3, false, block_hash);

  EXPECT_NE(base, voteSigningHash(6, 3, false, block_hash)); // height
  EXPECT_NE(base, voteSigningHash(5, 4, false, block_hash)); // round
  EXPECT_NE(base, voteSigningHash(5, 3, true, block_hash));  // is_nil

  Crypto::Hash other_hash = block_hash;
  other_hash.data[0] ^= 0xFF;
  EXPECT_NE(base, voteSigningHash(5, 3, false, other_hash)); // block_hash
}

TEST(ConsensusMessage, ProposalAndVoteDomainsDiffer)
{
  // Same height/round/block_hash: proposal and vote signing hashes
  // must differ (different domain strings).
  Crypto::Hash block_hash;
  block_hash.data[0] = 0xCC;

  auto ph = proposalSigningHash(1, 2, block_hash);
  auto vh = voteSigningHash(1, 2, false, block_hash);
  EXPECT_NE(ph, vh);
}