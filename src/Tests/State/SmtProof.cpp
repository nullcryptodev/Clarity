// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <algorithm>
#include <cstring>

#include "Tests/Fixtures.h"

#include "State/SmtProof.h"
#include "State/StateAccess.h"

using namespace State;
using namespace Tests;

// Inclusion proofs

TEST_F(SmtTestFixture, ProveSingleLeaf)
{
  Crypto::Hash key = makeHash(1);
  std::vector<uint8_t> val = proofValue(100);
  tree_->update(key, val, 0);

  auto proof = State::prove(*tree_, key);
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(proof->isInclusion());
  EXPECT_EQ(proof->key, key);
  ASSERT_TRUE(proof->value.has_value());
  EXPECT_EQ(*proof->value, val);
  EXPECT_EQ(proof->siblings.size(), SparseMerkleTree::DEPTH);

  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, ProveKeyInTenLeafTree)
{
  for (uint64_t i = 1; i <= 10; ++i)
    tree_->update(makeHash(i), proofValue(i * 100), 0);

  auto proof = State::prove(*tree_, makeHash(5));
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, ProveKeyInHundredLeafTree)
{
  for (uint64_t i = 1; i <= 100; ++i)
    tree_->update(makeHash(i), proofValue(i), 0);

  auto proof = State::prove(*tree_, makeHash(42));
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, ProveKeyWithDeepSharedPrefix)
{
  // Two keys that share 255 bits of prefix — differ only in the last bit.
  Crypto::Hash k1, k2;
  for (size_t i = 0; i < 32; ++i)
  {
    k1.data[i] = 0xAA;
    k2.data[i] = 0xAA;
  }
  k2.data[31] ^= 0x01;

  tree_->update(k1, proofValue(1), 0);
  tree_->update(k2, proofValue(2), 0);

  auto proof = State::prove(*tree_, k1);
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));

  auto proof2 = State::prove(*tree_, k2);
  ASSERT_TRUE(proof2.has_value());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof2));
}

TEST_F(SmtTestFixture, ProofAgainstStaleRootFails)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());
  Crypto::Hash old_root = tree_->root();

  // Change a different key.
  tree_->update(makeHash(2), proofValue(200), 0);
  ASSERT_NE(tree_->root(), old_root);

  // The proof is valid against the old root.
  EXPECT_TRUE(State::verifyProof(old_root, *proof));
  // But not against the new one.
  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

// Non-inclusion proofs

TEST_F(SmtTestFixture, ProveAbsenceInEmptyTree)
{
  auto proof = State::prove(*tree_, makeHash(999));
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_FALSE(proof->value.has_value());
  EXPECT_EQ(proof->siblings.size(), SparseMerkleTree::DEPTH);
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, ProveAbsenceInPopulatedTree)
{
  for (uint64_t i = 1; i <= 20; ++i)
    tree_->update(makeHash(i), proofValue(i), 0);

  auto proof = State::prove(*tree_, makeHash(999));
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, ProveAbsenceOfAdjacentKey)
{
  // Insert a key. Prove absence of a key whose path shares all but
  // the last bit.
  Crypto::Hash present, absent;
  for (size_t i = 0; i < 32; ++i)
  {
    present.data[i] = 0x55;
    absent.data[i] = 0x55;
  }
  absent.data[31] ^= 0x01;

  tree_->update(present, proofValue(1), 0);

  auto proof = State::prove(*tree_, absent);
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, AbsenceProofAgainstWrongRootFails)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(999));
  ASSERT_TRUE(proof.has_value());

  Crypto::Hash wrong_root = makeHash(1234); // arbitrary 32-byte value
  EXPECT_FALSE(State::verifyProof(wrong_root, *proof));
}

// Tamper detection

TEST_F(SmtTestFixture, TamperedSiblingFails)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());

  proof->siblings[0].data[0] ^= 0x01;

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, TamperedValueFails)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());

  ASSERT_TRUE(proof->value.has_value());
  (*proof->value)[0] ^= 0x01;

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, TamperedKeyFails)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());

  proof->key.data[0] ^= 0x01;

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, FlippedInclusionFlagFails)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());
  ASSERT_TRUE(proof->value.has_value());

  // Turn an inclusion proof into a non-inclusion proof.
  proof->value.reset();

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(SmtTestFixture, TruncatedSiblingsFail)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());

  proof->siblings.resize(SparseMerkleTree::DEPTH - 1);

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

// Serialization

TEST_F(SmtTestFixture, SerializationRoundTrip)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());

  auto bytes = proof->serialize();

  SmtProof decoded;
  ASSERT_TRUE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));

  EXPECT_EQ(decoded.key, proof->key);
  EXPECT_EQ(decoded.value.has_value(), proof->value.has_value());
  if (decoded.value.has_value())
  {
    EXPECT_EQ(*decoded.value, *proof->value);
  }
  EXPECT_EQ(decoded.siblings, proof->siblings);
  EXPECT_TRUE(State::verifyProof(tree_->root(), decoded));
}

TEST_F(SmtTestFixture, SerializationRoundTripNonInclusion)
{
  auto proof = State::prove(*tree_, makeHash(999));
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());

  auto bytes = proof->serialize();
  SmtProof decoded;
  ASSERT_TRUE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
  EXPECT_FALSE(decoded.isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), decoded));
}

TEST_F(SmtTestFixture, SerializedSizeMatches)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());

  EXPECT_EQ(proof->serialize().size(), proof->serializedSize());
}

TEST_F(SmtTestFixture, DeserializeRejectsTruncated)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());
  auto bytes = proof->serialize();

  // Truncate to one byte short of minimum.
  bytes.resize(32 + 1 + 4 + 32 * SparseMerkleTree::DEPTH - 1);

  SmtProof decoded;
  EXPECT_FALSE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
}

TEST_F(SmtTestFixture, DeserializeRejectsOversizedValueSize)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());
  auto bytes = proof->serialize();

  // The value_size field is at offset 32 + 1 = 33, 4 bytes LE.
  // Set it to a huge value (over the 64 KiB sanity cap).
  bytes[33] = 0xFF;
  bytes[34] = 0xFF;
  bytes[35] = 0xFF;
  bytes[36] = 0x7F;

  SmtProof decoded;
  EXPECT_FALSE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
}

// Scale, many proofs from one tree

TEST_F(SmtTestFixture, ManyProofsFromOneTree)
{
  constexpr uint64_t N = 50;
  for (uint64_t i = 1; i <= N; ++i)
    tree_->update(makeHash(i), proofValue(i), 0);

  Crypto::Hash root = tree_->root();

  for (uint64_t i = 1; i <= N; ++i)
  {
    auto proof = State::prove(*tree_, makeHash(i));
    ASSERT_TRUE(proof.has_value()) << "key " << i;
    EXPECT_TRUE(State::verifyProof(root, *proof)) << "key " << i;
  }
}

TEST_F(SmtTestFixture, ProofsAfterUpdate)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  auto proof_v1 = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof_v1.has_value());
  Crypto::Hash root_v1 = tree_->root();

  tree_->update(makeHash(1), proofValue(200), 0);
  auto proof_v2 = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof_v2.has_value());
  Crypto::Hash root_v2 = tree_->root();

  // Each proof verifies against its own root.
  EXPECT_TRUE(State::verifyProof(root_v1, *proof_v1));
  EXPECT_TRUE(State::verifyProof(root_v2, *proof_v2));

  // And fails against the other.
  EXPECT_FALSE(State::verifyProof(root_v2, *proof_v1));
  EXPECT_FALSE(State::verifyProof(root_v1, *proof_v2));
}

TEST_F(SmtTestFixture, ProofAfterRemove)
{
  tree_->update(makeHash(1), proofValue(100), 0);
  Crypto::Hash root_with = tree_->root();

  tree_->remove(makeHash(1), 0);
  Crypto::Hash root_without = tree_->root();

  EXPECT_NE(root_with, root_without);

  auto proof = State::prove(*tree_, makeHash(1));
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(root_without, *proof));
}

// Cross-check with StateAccess

TEST_F(SmtPersistenceTestFixture, ProveAccountViaStateAccess)
{
  auto db = openDB();

  Crypto::Address addr;
  addr.data[0] = 0x42;

  // Write an account through StateAccess.
  {
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 0);

    Core::Account acct;
    acct.balance = 1'234'567;
    acct.nonce = 7;
    access.putAccount(addr, acct);

    access.commit(0);
    txn.commit();
  }

  // Read back through a fresh tree and prove.
  {
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 0);

    Crypto::Hash root = access.stateRoot();

    // Build a tree from the same DB and prove the account leaf.
    SparseMerkleTree tree(*db);
    tree.setTxn(&txn);
    tree.load();

    Crypto::Hash key = Keys::account(addr);
    auto proof = State::prove(tree, key);
    ASSERT_TRUE(proof.has_value());
    EXPECT_TRUE(proof->isInclusion());

    // The proof must verify against the StateAccess's stateRoot.
    EXPECT_EQ(tree.root(), root);
    EXPECT_TRUE(State::verifyProof(root, *proof));

    txn.abort();
  }

  db->close();
}

TEST_F(SmtPersistenceTestFixture, ProveGlobalViaStateAccess)
{
  auto db = openDB();

  {
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 0);
    std::vector<uint8_t> val = {1, 2, 3, 4, 5};
    access.putGlobal("test_global", val);
    access.commit(0);
    txn.commit();
  }

  {
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 0);

    SparseMerkleTree tree(*db);
    tree.setTxn(&txn);
    tree.load();

    Crypto::Hash key = Keys::global("test_global");
    auto proof = State::prove(tree, key);
    ASSERT_TRUE(proof.has_value());
    EXPECT_TRUE(proof->isInclusion());
    EXPECT_TRUE(State::verifyProof(access.stateRoot(), *proof));

    txn.abort();
  }

  db->close();
}

// Key helpers

TEST_F(SmtTestFixture, ProofKeysMatchKeys)
{
  Crypto::Address addr;
  addr.data[0] = 0xAB;

  EXPECT_EQ(ProofKeys::forAccount(addr), Keys::account(addr));
  EXPECT_EQ(ProofKeys::forTokenBalance(addr, 42),
            Keys::tokenBalance(addr, 42));
  EXPECT_EQ(ProofKeys::forGlobal("x"), Keys::global("x"));
}

TEST_F(SmtTestFixture, ProofKeysForTokenBalanceAreDistinct)
{
  Crypto::Address addr;
  addr.data[0] = 0xAB;

  // Different token IDs must produce different keys.
  EXPECT_NE(ProofKeys::forTokenBalance(addr, 1),
            ProofKeys::forTokenBalance(addr, 2));
}