// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Core/Block.h"
#include "Core/Transaction.h"

using namespace Core;
using namespace Tests;

// ============================================================================
//  BlockHeader
// ============================================================================

TEST(Core_Core_BlockHeader, WellFormedBaseline)
{
  EXPECT_TRUE(makeHeader().isWellFormed());
}

TEST(Core_Core_BlockHeader, RejectsWrongVersion)
{
  BlockHeader h = makeHeader();
  h.version = 999;
  EXPECT_FALSE(h.isWellFormed());
}

TEST(Core_Core_BlockHeader, RejectsZeroChainId)
{
  BlockHeader h = makeHeader();
  h.chain_id = 0;
  EXPECT_FALSE(h.isWellFormed());
}

TEST(Core_Core_BlockHeader, RejectsNullProposer)
{
  BlockHeader h = makeHeader();
  h.proposer = Crypto::Address{};
  EXPECT_FALSE(h.isWellFormed());
}

TEST(Core_Core_BlockHeader, RejectsZeroActiveValidators)
{
  BlockHeader h = makeHeader();
  h.active_validator_count = 0;
  EXPECT_FALSE(h.isWellFormed());
}

TEST(Core_Core_BlockHeader, HashIsDeterministic)
{
  BlockHeader h = makeHeader();
  EXPECT_EQ(h.hash().toString(), h.hash().toString());
}

TEST(Core_Core_BlockHeader, HashChangesWithContent)
{
  BlockHeader h1 = makeHeader();
  BlockHeader h2 = makeHeader();
  h2.height += 1;

  EXPECT_NE(h1.hash().toString(), h2.hash().toString());
}

//  commit_round and emergency_rotation have opposite semantics:
//
//    commit_round is EXCLUDED from the hash. It can change between
//    proposal and commit (the round-crossing case) without changing
//    the block's identity. Validators sign over the block hash, and
//    the round they signed in becomes commit_round — but the hash
//    stays stable.

//    emergency_rotation is INCLUDED in the hash. It changes which
//    validator set the block was validated against, so two blocks
//    that differ only in this field are different blocks.

TEST(Core_Core_BlockHeader, CommitRoundNotInHash)
{
  BlockHeader h1 = makeHeader();
  h1.commit_round = 5;

  BlockHeader h2 = makeHeader();
  h2.commit_round = 99;

  EXPECT_EQ(h1.hash().toString(), h2.hash().toString())
      << "changing commit_round must not change the block hash";
}

TEST(Core_Core_BlockHeader, EmergencyRotationInHash)
{
  BlockHeader h1 = makeHeader();
  h1.emergency_rotation = 0;

  BlockHeader h2 = makeHeader();
  h2.emergency_rotation = 1;

  EXPECT_NE(h1.hash().toString(), h2.hash().toString())
      << "changing emergency_rotation must change the block hash";
}

TEST(Core_Core_BlockHeader, SerializeRoundTrip)
{
  BlockHeader original = makeHeader();

  auto bytes = original.serialize();
  BlockHeader restored;
  ASSERT_TRUE(BlockHeader::deserialize(bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.version, original.version);
  EXPECT_EQ(restored.chain_id, original.chain_id);
  EXPECT_EQ(restored.height, original.height);
  EXPECT_EQ(restored.parent_hash.toString(), original.parent_hash.toString());
  EXPECT_EQ(restored.timestamp_ms, original.timestamp_ms);
  EXPECT_EQ(restored.proposer.toString(), original.proposer.toString());
  EXPECT_EQ(restored.epoch, original.epoch);
  EXPECT_EQ(restored.rotation_index, original.rotation_index);
  EXPECT_EQ(restored.commit_round, original.commit_round);
  EXPECT_EQ(restored.emergency_rotation, original.emergency_rotation);
  EXPECT_EQ(restored.state_root.toString(), original.state_root.toString());
  EXPECT_EQ(restored.tx_root.toString(), original.tx_root.toString());
  EXPECT_EQ(restored.receipts_root.toString(), original.receipts_root.toString());
  EXPECT_EQ(restored.validator_set_root.toString(), original.validator_set_root.toString());
  EXPECT_EQ(restored.total_fees, original.total_fees);
  EXPECT_EQ(restored.tx_count, original.tx_count);
  EXPECT_EQ(restored.active_validator_count, original.active_validator_count);
}

TEST(Core_Core_BlockHeader, SerializeDeterministic)
{
  BlockHeader h = makeHeader();
  EXPECT_EQ(h.serialize(), h.serialize());
}

// ============================================================================
//  Block
// ============================================================================

TEST(Core_Block, WellFormedEmpty)
{
  Block b;
  b.header = makeHeader();
  b.header.tx_count = 0;
  b.header.active_validator_count = 21;

  // Empty transaction list with matching tx_count is well-formed so far,
  // but isWellFormed() also requires a quorum of signatures.
  b.quorum_signatures.clear();
  EXPECT_FALSE(b.isWellFormed());
}

TEST(Core_Block, WellFormedWithQuorum)
{
  Block b;
  b.header = makeHeader();
  b.header.tx_count = 0;
  b.header.active_validator_count = 21;

  // Fill 15 signatures (BFT quorum for 21).
  for (int i = 0; i < 15; ++i)
  {
    Crypto::ValidatorSignature vs;
    vs.signer_index = static_cast<Index>(i);
    // Signature bytes are arbitrary — well-formedness doesn't verify
    // cryptographic validity.
    for (size_t j = 0; j < 64; ++j)
      vs.signature.data[j] = static_cast<uint8_t>(i + j);
    b.quorum_signatures.push_back(vs);
  }

  EXPECT_TRUE(b.isWellFormed());
}

TEST(Core_Block, WellFormedWithEmergencyRotation)
{
  //  A block carrying a nonzero emergency_rotation is still
  //  well-formed. The field changes what set the block was validated
  //  against, not whether the header is structurally valid.
  Block b;
  b.header = makeHeader();
  b.header.tx_count = 0;
  b.header.active_validator_count = 21;
  b.header.emergency_rotation = 42;

  for (int i = 0; i < 15; ++i)
  {
    Crypto::ValidatorSignature vs;
    vs.signer_index = static_cast<Index>(i);
    for (size_t j = 0; j < 64; ++j)
      vs.signature.data[j] = static_cast<uint8_t>(i + j);
    b.quorum_signatures.push_back(vs);
  }

  EXPECT_TRUE(b.isWellFormed());
}

TEST(Core_Block, RejectsTxCountMismatch)
{
  Block b;
  b.header = makeHeader();
  b.header.tx_count = 5;  // claims 5 txs
  b.transactions.clear(); // but has 0

  for (int i = 0; i < 15; ++i)
  {
    Crypto::ValidatorSignature vs;
    vs.signer_index = static_cast<Index>(i);
    for (size_t j = 0; j < 64; ++j)
      vs.signature.data[j] = 0xAA;
    b.quorum_signatures.push_back(vs);
  }

  EXPECT_FALSE(b.isWellFormed());
}

TEST(Core_Block, SerializeRoundTripEmpty)
{
  Block original;
  original.header = makeHeader();
  original.header.tx_count = 0;

  for (int i = 0; i < 15; ++i)
  {
    Crypto::ValidatorSignature vs;
    vs.signer_index = static_cast<Index>(i);
    for (size_t j = 0; j < 64; ++j)
      vs.signature.data[j] = static_cast<uint8_t>(i);
    original.quorum_signatures.push_back(vs);
  }

  auto bytes = original.serialize();
  Block restored;
  ASSERT_TRUE(Block::deserialize(bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.header.height, original.header.height);
  EXPECT_EQ(restored.header.chain_id, original.header.chain_id);
  EXPECT_EQ(restored.header.emergency_rotation, original.header.emergency_rotation);
  EXPECT_EQ(restored.transactions.size(), original.transactions.size());
  EXPECT_EQ(restored.quorum_signatures.size(), original.quorum_signatures.size());
}

TEST(Core_Block, SerializeRoundTripWithTransactions)
{
  Block original;
  original.header = makeHeader();
  original.header.tx_count = 3;

  original.transactions.push_back(makeSimpleTx(1));
  original.transactions.push_back(makeSimpleTx(2));
  original.transactions.push_back(makeSimpleTx(3));

  for (int i = 0; i < 15; ++i)
  {
    Crypto::ValidatorSignature vs;
    vs.signer_index = static_cast<Index>(i);
    for (size_t j = 0; j < 64; ++j)
      vs.signature.data[j] = static_cast<uint8_t>(i + j);
    original.quorum_signatures.push_back(vs);
  }

  auto bytes = original.serialize();
  Block restored;
  ASSERT_TRUE(Block::deserialize(bytes.data(), bytes.size(), restored));

  ASSERT_EQ(restored.transactions.size(), 3u);
  EXPECT_EQ(restored.transactions[0].nonce, original.transactions[0].nonce);
  EXPECT_EQ(restored.transactions[1].nonce, original.transactions[1].nonce);
  EXPECT_EQ(restored.transactions[2].nonce, original.transactions[2].nonce);
}

TEST(Core_Block, SerializeRoundTripWithParticipants)
{
  Block original;
  original.header = makeHeader();
  original.header.tx_count = 0;

  for (int i = 0; i < 15; ++i)
  {
    Crypto::ValidatorSignature vs;
    vs.signer_index = static_cast<Index>(i);
    for (size_t j = 0; j < 64; ++j)
      vs.signature.data[j] = static_cast<uint8_t>(i);
    original.quorum_signatures.push_back(vs);
  }

  // Add some participants.
  for (uint64_t i = 100; i < 121; ++i)
  {
    original.participants.push_back(i);
  }

  auto bytes = original.serialize();
  Block restored;
  ASSERT_TRUE(Block::deserialize(bytes.data(), bytes.size(), restored));

  ASSERT_EQ(restored.participants.size(), original.participants.size());
  for (size_t i = 0; i < original.participants.size(); ++i)
  {
    EXPECT_EQ(restored.participants[i], original.participants[i]);
  }
}

TEST(Core_Block, SerializeDeterministic)
{
  Block b;
  b.header = makeHeader();
  b.header.tx_count = 0;
  for (int i = 0; i < 15; ++i)
  {
    Crypto::ValidatorSignature vs;
    vs.signer_index = static_cast<Index>(i);
    for (size_t j = 0; j < 64; ++j)
      vs.signature.data[j] = 0xAA;
    b.quorum_signatures.push_back(vs);
  }

  EXPECT_EQ(b.serialize(), b.serialize());
}

TEST(Core_Block, SerializedSizeMatchesActual)
{
  Block b;
  b.header = makeHeader();
  b.header.tx_count = 2;
  b.transactions.push_back(makeSimpleTx(1));
  b.transactions.push_back(makeSimpleTx(2));

  for (int i = 0; i < 15; ++i)
  {
    Crypto::ValidatorSignature vs;
    vs.signer_index = static_cast<Index>(i);
    for (size_t j = 0; j < 64; ++j)
      vs.signature.data[j] = 0xAA;
    b.quorum_signatures.push_back(vs);
  }

  b.participants = {1, 2, 3};

  EXPECT_EQ(b.serialize().size(), b.serializedSize());
}

TEST(Core_Block, HashEqualsHeaderHash)
{
  Block b;
  b.header = makeHeader();
  EXPECT_EQ(b.hash().toString(), b.header.hash().toString());
}

// ============================================================================
//  Merkle roots
// ============================================================================

TEST(Core_MerkleRoot, EmptyReturnsNullHash)
{
  std::vector<Crypto::Hash> empty;
  Crypto::Hash root = computeMerkleRoot(empty);
  EXPECT_TRUE(root.isNull());
}

TEST(Core_MerkleRoot, SingleLeaf)
{
  Crypto::Hash leaf;
  for (size_t i = 0; i < 32; ++i)
    leaf.data[i] = static_cast<uint8_t>(i);

  std::vector<Crypto::Hash> leaves = {leaf};
  Crypto::Hash root = computeMerkleRoot(leaves);

  // With a single leaf, the root is a hash of (domain || leaf || leaf)
  // because we duplicate odd-level nodes.
  EXPECT_FALSE(root.isNull());
}

TEST(Core_MerkleRoot, Deterministic)
{
  std::vector<Crypto::Hash> leaves;
  for (int i = 0; i < 4; ++i)
  {
    Crypto::Hash h;
    for (size_t j = 0; j < 32; ++j)
      h.data[j] = static_cast<uint8_t>(i * 32 + j);
    leaves.push_back(h);
  }

  EXPECT_EQ(computeMerkleRoot(leaves).toString(),
            computeMerkleRoot(leaves).toString());
}

TEST(Core_MerkleRoot, ChangesWithLeaves)
{
  std::vector<Crypto::Hash> leaves1;
  std::vector<Crypto::Hash> leaves2;
  for (int i = 0; i < 4; ++i)
  {
    Crypto::Hash h1;
    for (size_t j = 0; j < 32; ++j)
      h1.data[j] = static_cast<uint8_t>(i + j);
    leaves1.push_back(h1);

    Crypto::Hash h2 = h1;
    if (i == 2)
      h2.data[0] ^= 0xFF;
    leaves2.push_back(h2);
  }

  EXPECT_NE(computeMerkleRoot(leaves1).toString(),
            computeMerkleRoot(leaves2).toString());
}

TEST(Core_TxRoot, Deterministic)
{
  std::vector<Transaction> txs;
  txs.push_back(makeSimpleTx(1));
  txs.push_back(makeSimpleTx(2));

  EXPECT_EQ(computeTxRoot(txs).toString(),
            computeTxRoot(txs).toString());
}

TEST(Core_TxRoot, ChangesWithTransactions)
{
  std::vector<Transaction> txs1;
  txs1.push_back(makeSimpleTx(1));

  std::vector<Transaction> txs2;
  txs2.push_back(makeSimpleTx(2));

  EXPECT_NE(computeTxRoot(txs1).toString(),
            computeTxRoot(txs2).toString());
}

TEST(Core_ValidatorSetRoot, Deterministic)
{
  std::vector<Id> set = {1, 2, 3, 4, 5};
  EXPECT_EQ(computeValidatorSetRoot(set).toString(),
            computeValidatorSetRoot(set).toString());
}

TEST(Core_ValidatorSetRoot, OrderIndependent)
{
  std::vector<Id> set1 = {1, 2, 3, 4, 5};
  std::vector<Id> set2 = {5, 3, 1, 4, 2};

  // The function sorts internally, so the roots must match.
  EXPECT_EQ(computeValidatorSetRoot(set1).toString(),
            computeValidatorSetRoot(set2).toString());
}

TEST(Core_ValidatorSetRoot, ChangesWithMembers)
{
  std::vector<Id> set1 = {1, 2, 3, 4, 5};
  std::vector<Id> set2 = {1, 2, 3, 4, 6};

  EXPECT_NE(computeValidatorSetRoot(set1).toString(),
            computeValidatorSetRoot(set2).toString());
}

TEST(Core_ValidatorSetRoot, EmptyReturnsNullHash)
{
  std::vector<Id> empty;
  Crypto::Hash root = computeValidatorSetRoot(empty);
  EXPECT_TRUE(root.isNull());
}

TEST(Core_BlockRoundTrip, HashSurvivesSerializeDeserialize)
{
  Core::Block original;
  original.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
  original.header.chain_id = 0x434C5247;
  original.header.height = 1;
  original.header.parent_hash = Crypto::Hash{};
  original.header.timestamp_ms = 1'700'000'000'000ULL;
  for (size_t i = 0; i < 32; ++i)
    original.header.proposer.data[i] = uint8_t(0x80 + i);
  original.header.tx_root = Core::computeTxRoot({});
  original.header.state_root = Crypto::Hash{};
  original.header.receipts_root = Crypto::Hash{};
  original.header.validator_set_root = Core::computeValidatorSetRoot({1, 2});
  original.header.active_validator_count = 2;
  original.header.tx_count = 0;
  original.header.total_fees = 0;
  original.header.emergency_rotation = 0;

  // Hash before round-trip.
  Crypto::Hash hash_before = original.hash();

  // Round-trip.
  auto bytes = original.serialize();
  Core::Block restored;
  ASSERT_TRUE(Core::Block::deserialize(bytes.data(), bytes.size(), restored));

  // Hash after round-trip.
  Crypto::Hash hash_after = restored.hash();

  EXPECT_EQ(hash_before, hash_after);
}

TEST(Core_BlockRoundTrip, HashSurvivesWithEmergencyRotation)
{
  //  A block with a nonzero emergency_rotation hashes the same on both
  //  sides of the wire. This pins the fact that the field is included
  //  in serializeForHash and survives deserialization unchanged.
  Core::Block original;
  original.header.version = GlobalConfig::CURRENT_BLOCK_VERSION;
  original.header.chain_id = 0x434C5247;
  original.header.height = 1;
  original.header.parent_hash.data[0] = 0x01;
  original.header.timestamp_ms = 1'700'000'000'000ULL;
  for (size_t i = 0; i < 32; ++i)
    original.header.proposer.data[i] = uint8_t(0x80 + i);
  original.header.tx_root = Core::computeTxRoot({});
  original.header.state_root.data[0] = 0x02;
  original.header.receipts_root = Crypto::Hash{};
  original.header.validator_set_root = Core::computeValidatorSetRoot({1, 2});
  original.header.active_validator_count = 2;
  original.header.tx_count = 0;
  original.header.total_fees = 0;
  original.header.emergency_rotation = 42;

  Crypto::Hash hash_before = original.hash();

  auto bytes = original.serialize();
  Core::Block restored;
  ASSERT_TRUE(Core::Block::deserialize(bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.header.emergency_rotation, 42u);
  EXPECT_EQ(hash_before, restored.hash());
}