// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Tests/State/Fixtures.h"

#include "State/Keys.h"
#include "State/SmtProof.h"
#include "State/StateAccess.h"

using namespace State;
using namespace Tests;

// ============================================================================
//  Inclusion proofs
// ============================================================================

TEST_F(State_SmtFixture, ProveSingleLeaf)
{
  Crypto::Hash key = makeKey(1);
  std::vector<uint8_t> val = makeValue(100);
  tree_->update(key, val, 0);

  auto proof = State::prove(*tree_, key);
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(proof->isInclusion());
  EXPECT_EQ(proof->key, key);
  ASSERT_TRUE(proof->value.has_value());
  EXPECT_EQ(*proof->value, val);

  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, ProveKeyInTenLeafTree)
{
  for (uint64_t i = 1; i <= 10; ++i)
    tree_->update(makeKey(i), makeValue(i * 100), 0);

  auto proof = State::prove(*tree_, makeKey(5));
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, ProveKeyInHundredLeafTree)
{
  for (uint64_t i = 1; i <= 100; ++i)
    tree_->update(makeKey(i), makeValue(i), 0);

  auto proof = State::prove(*tree_, makeKey(42));
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, ProofHasVariableSiblingCount)
{
  //  In a compressed tree, a proof's sibling count is O(log N), not a
  //  fixed 256. Insert a handful of keys and verify the proof is
  //  short.
  for (uint64_t i = 1; i <= 10; ++i)
    tree_->update(makeKey(i), makeValue(i), 0);

  auto proof = State::prove(*tree_, makeKey(5));
  ASSERT_TRUE(proof.has_value());

  //  With 10 leaves, expected height is ~4. Allow generous slack for
  //  the random key distribution.
  EXPECT_LE(proof->siblings.size(), 16u)
      << "proof has " << proof->siblings.size() << " siblings";

  //  But at least one sibling is required unless the tree has only
  //  one leaf. With 10 leaves the tree definitely has branches.
  EXPECT_GE(proof->siblings.size(), 1u);
}

TEST_F(State_SmtFixture, ProofAgainstStaleRootFails)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());
  Crypto::Hash old_root = tree_->root();

  tree_->update(makeKey(2), makeValue(200), 0);
  ASSERT_NE(tree_->root(), old_root);

  EXPECT_TRUE(State::verifyProof(old_root, *proof));
  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

// ============================================================================
//  Non-inclusion proofs: default subtree
// ============================================================================

TEST_F(State_SmtFixture, ProveAbsenceInEmptyTree)
{
  auto proof = State::prove(*tree_, makeKey(999));
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_EQ(proof->terminal_kind, ProofTerminalKind::Default);
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, ProveAbsenceInPopulatedTree)
{
  for (uint64_t i = 1; i <= 20; ++i)
    tree_->update(makeKey(i), makeValue(i), 0);

  auto proof = State::prove(*tree_, makeKey(999));
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

// ============================================================================
//  Non-inclusion proofs: divergent leaf
//
//  When the proven key's slot is occupied by a leaf with a different
//  key, the walk stops at that leaf. The proof's terminal_kind is
//  DifferentLeaf and it carries the divergent leaf's key and value
//  hash.
// ============================================================================

TEST_F(State_SmtFixture, ProveAbsenceAdjacentToExistingLeaf)
{
  //  Insert one key, prove the absence of a key that diverges from it
  //  only in the last bit. The walk goes down to the leaf and stops.
  auto [k1, k2] = SmtKeys::makeSiblingKeys(255);

  tree_->update(k1, makeValue(1), 0);

  auto proof = State::prove(*tree_, k2);
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_EQ(proof->terminal_kind, ProofTerminalKind::DifferentLeaf);
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

// ============================================================================
//  Non-inclusion proofs: divergent branch
//
//  When the proven key's bits diverge from a branch's prefix before
//  reaching a leaf, the walk stops at that branch. The proof's
//  terminal_kind is DivergentBranch and it carries the branch's prefix
//  and both child hashes.
// ============================================================================

TEST_F(State_SmtFixture, ProveAbsenceAtDivergentBranch)
{
  //  Two keys that share a long prefix. The tree has a branch with a
  //  long prefix at the root. Prove absence of a third key that
  //  diverges from the prefix earlier.
  auto [k1, k2] = SmtKeys::makeSiblingKeys(200);
  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);

  //  k3 has a 1 bit at position 0, so it diverges from the branch
  //  at the root.
  Crypto::Hash k3{};
  k3.data[0] |= 0x80;

  auto proof = State::prove(*tree_, k3);
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_EQ(proof->terminal_kind, ProofTerminalKind::DivergentBranch);
  EXPECT_TRUE(State::verifyProof(tree_->root(), *proof));
}

// ============================================================================
//  Tamper detection
// ============================================================================

TEST_F(State_SmtFixture, TamperedSiblingFails)
{
  //  Build a tree with enough leaves that proofs have at least one
  //  sibling. A single-leaf tree has no siblings.
  for (uint64_t i = 1; i <= 4; ++i)
    tree_->update(makeKey(i), makeValue(i * 100), 0);

  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());
  ASSERT_FALSE(proof->siblings.empty());

  proof->siblings[0].hash.data[0] ^= 0x01;

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, TamperedValueFails)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());

  ASSERT_TRUE(proof->value.has_value());
  (*proof->value)[0] ^= 0x01;

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, TamperedKeyFails)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());

  proof->key.data[0] ^= 0x01;

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, FlippedTerminalKindFails)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());

  //  Turn an inclusion into a default non-inclusion. The verifier
  //  computes a different terminal hash and the root won't match.
  proof->terminal_kind = ProofTerminalKind::Default;
  proof->value.reset();

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, TamperedDivergentLeafKeyFails)
{
  auto [k1, k2] = SmtKeys::makeSiblingKeys(255);
  tree_->update(k1, makeValue(1), 0);

  auto proof = State::prove(*tree_, k2);
  ASSERT_TRUE(proof.has_value());
  ASSERT_EQ(proof->terminal_kind, ProofTerminalKind::DifferentLeaf);

  proof->divergent_leaf_key.data[0] ^= 0x01;

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

TEST_F(State_SmtFixture, TamperedDivergentBranchPrefixFails)
{
  auto [k1, k2] = SmtKeys::makeSiblingKeys(200);
  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);

  Crypto::Hash k3{};
  k3.data[0] |= 0x80;

  auto proof = State::prove(*tree_, k3);
  ASSERT_TRUE(proof.has_value());
  ASSERT_EQ(proof->terminal_kind, ProofTerminalKind::DivergentBranch);
  ASSERT_FALSE(proof->divergent_branch_prefix_bits.empty());

  proof->divergent_branch_prefix_bits[0] ^= 0x01;

  EXPECT_FALSE(State::verifyProof(tree_->root(), *proof));
}

// ============================================================================
//  Serialization
// ============================================================================

TEST_F(State_SmtFixture, SerializationRoundTripInclusion)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());

  auto bytes = proof->serialize();

  SmtProof decoded;
  ASSERT_TRUE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));

  EXPECT_EQ(decoded.key, proof->key);
  EXPECT_EQ(decoded.terminal_kind, proof->terminal_kind);
  EXPECT_EQ(decoded.siblings.size(), proof->siblings.size());
  EXPECT_TRUE(State::verifyProof(tree_->root(), decoded));
}

TEST_F(State_SmtFixture, SerializationRoundTripDefault)
{
  auto proof = State::prove(*tree_, makeKey(999));
  ASSERT_TRUE(proof.has_value());
  ASSERT_EQ(proof->terminal_kind, ProofTerminalKind::Default);

  auto bytes = proof->serialize();
  SmtProof decoded;
  ASSERT_TRUE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
  EXPECT_EQ(decoded.terminal_kind, ProofTerminalKind::Default);
  EXPECT_TRUE(State::verifyProof(tree_->root(), decoded));
}

TEST_F(State_SmtFixture, SerializationRoundTripDifferentLeaf)
{
  auto [k1, k2] = SmtKeys::makeSiblingKeys(255);
  tree_->update(k1, makeValue(1), 0);

  auto proof = State::prove(*tree_, k2);
  ASSERT_TRUE(proof.has_value());
  ASSERT_EQ(proof->terminal_kind, ProofTerminalKind::DifferentLeaf);

  auto bytes = proof->serialize();
  SmtProof decoded;
  ASSERT_TRUE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
  EXPECT_EQ(decoded.terminal_kind, ProofTerminalKind::DifferentLeaf);
  EXPECT_EQ(decoded.divergent_leaf_key, proof->divergent_leaf_key);
  EXPECT_TRUE(State::verifyProof(tree_->root(), decoded));
}

TEST_F(State_SmtFixture, SerializationRoundTripDivergentBranch)
{
  auto [k1, k2] = SmtKeys::makeSiblingKeys(200);
  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);

  Crypto::Hash k3{};
  k3.data[0] |= 0x80;

  auto proof = State::prove(*tree_, k3);
  ASSERT_TRUE(proof.has_value());
  ASSERT_EQ(proof->terminal_kind, ProofTerminalKind::DivergentBranch);

  auto bytes = proof->serialize();
  SmtProof decoded;
  ASSERT_TRUE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
  EXPECT_EQ(decoded.terminal_kind, ProofTerminalKind::DivergentBranch);
  EXPECT_EQ(decoded.divergent_branch_prefix_len,
            proof->divergent_branch_prefix_len);
  EXPECT_TRUE(State::verifyProof(tree_->root(), decoded));
}

TEST_F(State_SmtFixture, SerializedSizeMatches)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());
  EXPECT_EQ(proof->serialize().size(), proof->serializedSize());
}

TEST_F(State_SmtFixture, DeserializeRejectsTruncated)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());
  auto bytes = proof->serialize();

  //  Truncate to a length that can't even hold the header.
  bytes.resize(10);

  SmtProof decoded;
  EXPECT_FALSE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
}

TEST_F(State_SmtFixture, DeserializeRejectsOversizedValueSize)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());
  auto bytes = proof->serialize();

  //  The value_size field is at offset 32 + 1 = 33, 4 bytes LE. Set
  //  it over the 64 KiB sanity cap.
  bytes[33] = 0xFF;
  bytes[34] = 0xFF;
  bytes[35] = 0xFF;
  bytes[36] = 0x7F;

  SmtProof decoded;
  EXPECT_FALSE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
}

TEST_F(State_SmtFixture, DeserializeRejectsUnknownTerminalKind)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());
  auto bytes = proof->serialize();

  //  terminal_kind is at offset 32.
  bytes[32] = 0xFF;

  SmtProof decoded;
  EXPECT_FALSE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
}

TEST_F(State_SmtFixture, DeserializeRejectsTrailingBytes)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());
  auto bytes = proof->serialize();
  bytes.push_back(0x00);

  SmtProof decoded;
  EXPECT_FALSE(SmtProof::deserialize(bytes.data(), bytes.size(), decoded));
}

// ============================================================================
//  Scale: many proofs from one tree
// ============================================================================

TEST_F(State_SmtFixture, ManyProofsFromOneTree)
{
  constexpr uint64_t N = 50;
  for (uint64_t i = 1; i <= N; ++i)
    tree_->update(makeKey(i), makeValue(i), 0);

  Crypto::Hash root = tree_->root();

  for (uint64_t i = 1; i <= N; ++i)
  {
    auto proof = State::prove(*tree_, makeKey(i));
    ASSERT_TRUE(proof.has_value()) << "key " << i;
    EXPECT_TRUE(State::verifyProof(root, *proof)) << "key " << i;
  }
}

TEST_F(State_SmtFixture, ManyAbsenceProofsFromOneTree)
{
  constexpr uint64_t N = 20;
  for (uint64_t i = 1; i <= N; ++i)
    tree_->update(makeKey(i), makeValue(i), 0);

  Crypto::Hash root = tree_->root();

  for (uint64_t i = 1000; i < 1000 + N; ++i)
  {
    auto proof = State::prove(*tree_, makeKey(i));
    ASSERT_TRUE(proof.has_value()) << "key " << i;
    EXPECT_FALSE(proof->isInclusion());
    EXPECT_TRUE(State::verifyProof(root, *proof)) << "key " << i;
  }
}

TEST_F(State_SmtFixture, ProofAfterUpdate)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  auto proof_v1 = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof_v1.has_value());
  Crypto::Hash root_v1 = tree_->root();

  tree_->update(makeKey(1), makeValue(200), 0);
  auto proof_v2 = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof_v2.has_value());
  Crypto::Hash root_v2 = tree_->root();

  EXPECT_TRUE(State::verifyProof(root_v1, *proof_v1));
  EXPECT_TRUE(State::verifyProof(root_v2, *proof_v2));

  EXPECT_FALSE(State::verifyProof(root_v2, *proof_v1));
  EXPECT_FALSE(State::verifyProof(root_v1, *proof_v2));
}

TEST_F(State_SmtFixture, ProofAfterRemove)
{
  tree_->update(makeKey(1), makeValue(100), 0);
  Crypto::Hash root_with = tree_->root();

  tree_->remove(makeKey(1), 0);
  Crypto::Hash root_without = tree_->root();

  EXPECT_NE(root_with, root_without);

  auto proof = State::prove(*tree_, makeKey(1));
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(root_without, *proof));
}

// ============================================================================
//  Cross-check with StateAccess
// ============================================================================

TEST_F(State_SmtPersistenceFixture, ProveAccountViaStateAccess)
{
  auto db = openDB();

  Crypto::Address addr;
  addr.data[0] = 0x42;

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

  {
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 0);

    Crypto::Hash root = access.stateRoot();

    SparseMerkleTree tree(*db);
    tree.setTxn(&txn);
    tree.load();

    Crypto::Hash key = Keys::account(addr);
    auto proof = State::prove(tree, key);
    ASSERT_TRUE(proof.has_value());
    EXPECT_TRUE(proof->isInclusion());

    EXPECT_EQ(tree.root(), root);
    EXPECT_TRUE(State::verifyProof(root, *proof));

    txn.abort();
  }

  db->close();
}

TEST_F(State_SmtPersistenceFixture, ProveGlobalViaStateAccess)
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

// ============================================================================
//  Key helpers
// ============================================================================

TEST_F(State_SmtFixture, ProofKeysMatchKeys)
{
  Crypto::Address addr;
  addr.data[0] = 0xAB;

  EXPECT_EQ(ProofKeys::forAccount(addr), Keys::account(addr));
  EXPECT_EQ(ProofKeys::forTokenBalance(addr, 42),
            Keys::tokenBalance(addr, 42));
  EXPECT_EQ(ProofKeys::forGlobal("x"), Keys::global("x"));
}

TEST_F(State_SmtFixture, ProofKeysForTokenBalanceAreDistinct)
{
  Crypto::Address addr;
  addr.data[0] = 0xAB;

  EXPECT_NE(ProofKeys::forTokenBalance(addr, 1),
            ProofKeys::forTokenBalance(addr, 2));
}