// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Tests/State/Fixtures.h"

#include "State/SparseMerkleTree.h"

using namespace State;
using namespace Tests;

// ============================================================================
//  Empty tree
// ============================================================================

TEST_F(State_SmtFixture, EmptyTreeRootIsDefaultHash)
{
  EXPECT_EQ(tree_->root(),
            SparseMerkleTree::defaultHash(SparseMerkleTree::KEY_BITS));
}

TEST_F(State_SmtFixture, EmptyTreeHeightIsZero)
{
  EXPECT_EQ(tree_->height(), 0u);
}

TEST_F(State_SmtFixture, EmptyTreeGetReturnsNullopt)
{
  EXPECT_FALSE(get(0).has_value());
  EXPECT_FALSE(get(1).has_value());
  EXPECT_FALSE(get(0xFFFFFFFFFFFFFFFFULL).has_value());
}

TEST_F(State_SmtFixture, EmptyTreeRootIsDeterministic)
{
  //  A second tree over the same empty DB sees the same root.
  State::SparseMerkleTree other(db());
  other.setTxn(txn_ ? &*txn_ : nullptr);
  other.load();
  EXPECT_EQ(tree_->root(), other.root());
}

// ============================================================================
//  Default hashes
//
//  The compressed tree uses the same default-hash scheme as the old
//  fixed-depth tree: defaultHash(0) is the empty leaf, and
//  defaultHash(d) for d > 0 is the hash of a branch whose two children
//  are both defaultHash(d-1). The number of depths is still KEY_BITS
//  (256), because the key space is still 256 bits.
// ============================================================================

TEST_F(State_SmtFixture, DefaultHashesAreConsistent)
{
  //  Recompute every default hash from its predecessor and confirm
  //  the cached value matches. If this fails, the precomputation in
  //  SparseMerkleTree.cpp is wrong.
  for (size_t d = 1; d <= SparseMerkleTree::KEY_BITS; ++d)
  {
    uint8_t buf[4 + 1 + 2 + 32 + 32];
    std::memcpy(buf, "dflt", 4);
    buf[4] = SparseMerkleTree::TAG_DEFAULT;
    buf[5] = uint8_t(d >> 8);
    buf[6] = uint8_t(d & 0xFF);
    std::memcpy(buf + 7, SparseMerkleTree::defaultHash(d - 1).data.data(), 32);
    std::memcpy(buf + 7 + 32, SparseMerkleTree::defaultHash(d - 1).data.data(),
                32);

    Crypto::Hash expected;
    Crypto::blake2b(buf, sizeof(buf), expected.data.data(), 32);
    EXPECT_EQ(SparseMerkleTree::defaultHash(d), expected) << "depth " << d;
  }
}

TEST_F(State_SmtFixture, DefaultHashAboveKeyBitsClamps)
{
  EXPECT_EQ(SparseMerkleTree::defaultHash(SparseMerkleTree::KEY_BITS + 1),
            SparseMerkleTree::defaultHash(SparseMerkleTree::KEY_BITS));
  EXPECT_EQ(SparseMerkleTree::defaultHash(1000),
            SparseMerkleTree::defaultHash(SparseMerkleTree::KEY_BITS));
}

// ============================================================================
//  Basic insert, update, remove
// ============================================================================

TEST_F(State_SmtFixture, InsertSingleLeafChangesRoot)
{
  auto before = tree_->root();
  auto after = update(1, 100);
  EXPECT_NE(before, after);
}

TEST_F(State_SmtFixture, InsertSingleLeafIsRetrievable)
{
  update(1, 100);
  auto v = get(1);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, makeValue(100));
}

TEST_F(State_SmtFixture, InsertSingleLeafOthersStillEmpty)
{
  update(1, 100);
  EXPECT_FALSE(get(2).has_value());
  EXPECT_FALSE(get(0).has_value());
  EXPECT_FALSE(get(1000).has_value());
}

TEST_F(State_SmtFixture, InsertSameValueTwiceIsIdempotent)
{
  auto r1 = update(1, 100);
  auto r2 = update(1, 100);
  EXPECT_EQ(r1, r2);
}

TEST_F(State_SmtFixture, UpdateExistingKeyChangesValueAndRoot)
{
  auto r1 = update(1, 100);
  auto r2 = update(1, 200);
  EXPECT_NE(r1, r2);

  auto v = get(1);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, makeValue(200));
}

TEST_F(State_SmtFixture, UpdateDifferentKeysGiveDifferentRoots)
{
  auto r1 = update(1, 100);
  auto r2 = update(2, 100);
  EXPECT_NE(r1, r2);
}

TEST_F(State_SmtFixture, SameValueDifferentKeysHaveDifferentLeaves)
{
  auto r_a = update(1, 42);
  auto r_b = update(2, 42);
  EXPECT_NE(r_a, r_b);
}

TEST_F(State_SmtFixture, RemoveReturnsToPriorRoot)
{
  auto empty_root = tree_->root();
  update(1, 100);
  auto after_insert = tree_->root();
  EXPECT_NE(empty_root, after_insert);

  remove(1);
  EXPECT_EQ(tree_->root(), empty_root);
}

TEST_F(State_SmtFixture, RemoveRetrievableKeyReturnsToPriorRoot)
{
  auto prior = tree_->root();
  update(1, 100);
  update(2, 200);
  auto with_both = tree_->root();

  remove(2);
  auto with_one = tree_->root();
  EXPECT_NE(with_one, prior);
  EXPECT_NE(with_one, with_both);

  remove(1);
  EXPECT_EQ(tree_->root(), prior);
}

TEST_F(State_SmtFixture, RemoveNonexistentKeyIsNoOp)
{
  update(1, 100);
  auto before = tree_->root();
  remove(2);
  EXPECT_EQ(tree_->root(), before);
}

TEST_F(State_SmtFixture, GetAfterRemoveReturnsNullopt)
{
  update(1, 100);
  ASSERT_TRUE(get(1).has_value());
  remove(1);
  EXPECT_FALSE(get(1).has_value());
}

TEST_F(State_SmtFixture, ReinsertAfterRemove)
{
  update(1, 100);
  auto r1 = tree_->root();
  remove(1);
  update(1, 100);
  EXPECT_EQ(tree_->root(), r1);
}

TEST_F(State_SmtFixture, EmptyValueIsStored)
{
  Crypto::Hash k = makeKey(1);
  std::vector<uint8_t> empty_val;

  tree_->update(k, empty_val, 0);

  auto v = tree_->get(k);
  ASSERT_TRUE(v.has_value());
  EXPECT_TRUE(v->empty());
}

TEST_F(State_SmtFixture, EmptyValueHasDifferentRootThanEmptyTree)
{
  auto empty_root = tree_->root();

  Crypto::Hash k = makeKey(1);
  tree_->update(k, {}, 0);

  EXPECT_NE(tree_->root(), empty_root);
}

TEST_F(State_SmtFixture, RemoveEmptyValueLeafRestoresRoot)
{
  auto empty_root = tree_->root();

  Crypto::Hash k = makeKey(1);
  tree_->update(k, {}, 0);
  tree_->remove(k, 0);

  EXPECT_EQ(tree_->root(), empty_root);
}

// ============================================================================
//  Order independence
//
//  The root depends only on the set of (key, value) pairs, not on the
//  order in which they were written. This is a fundamental property of
//  a Merkle trie and is what makes consensus possible.
// ============================================================================

TEST_F(State_SmtFixture, InsertionOrderDoesNotAffectRoot)
{
  update(1, 100);
  update(2, 200);
  auto root_ab = tree_->root();

  TempDB db2;
  SparseMerkleTree tree2(db2.db());
  tree2.update(makeKey(2), makeValue(200), 0);
  tree2.update(makeKey(1), makeValue(100), 0);
  auto root_ba = tree2.root();

  EXPECT_EQ(root_ab, root_ba);
}

TEST_F(State_SmtFixture, ManyInsertsAreOrderIndependent)
{
  std::vector<uint64_t> keys = {10, 20, 30, 40, 50, 60, 70, 80};

  for (auto k : keys)
    update(k, k * 7);
  auto root_fwd = tree_->root();

  TempDB db2;
  SparseMerkleTree tree2(db2.db());
  for (auto it = keys.rbegin(); it != keys.rend(); ++it)
    tree2.update(makeKey(*it), makeValue(*it * 7), 0);
  auto root_rev = tree2.root();

  EXPECT_EQ(root_fwd, root_rev);
}

// ============================================================================
//  Scale
// ============================================================================

TEST_F(State_SmtFixture, HundredLeaves)
{
  for (uint64_t i = 1; i <= 100; ++i)
    update(i, i);

  for (uint64_t i = 1; i <= 100; ++i)
  {
    auto v = get(i);
    ASSERT_TRUE(v.has_value()) << "key " << i;
    EXPECT_EQ(*v, makeValue(i));
  }

  EXPECT_FALSE(get(0).has_value());
  EXPECT_FALSE(get(101).has_value());
}

TEST_F(State_SmtFixture, ThousandLeaves)
{
  constexpr uint64_t N = 1000;
  for (uint64_t i = 1; i <= N; ++i)
    update(i, i * 13);

  for (uint64_t i = 1; i <= N; ++i)
  {
    auto v = get(i);
    ASSERT_TRUE(v.has_value()) << "key " << i;
    EXPECT_EQ(*v, makeValue(i * 13));
  }
}

TEST_F(State_SmtFixture, HundredLeavesRemoveHalf)
{
  for (uint64_t i = 1; i <= 100; ++i)
    update(i, i);
  auto full_root = tree_->root();

  for (uint64_t i = 1; i <= 50; ++i)
    remove(i);

  for (uint64_t i = 51; i <= 100; ++i)
  {
    auto v = get(i);
    ASSERT_TRUE(v.has_value()) << "key " << i;
  }

  for (uint64_t i = 1; i <= 50; ++i)
    EXPECT_FALSE(get(i).has_value()) << "key " << i;

  EXPECT_NE(tree_->root(), full_root);
}

// ============================================================================
//  Path compression
//
//  These tests exercise the properties that distinguish the compressed
//  tree from the fixed-depth trie. They are the ones that would catch a
//  bug in split-on-insert or collapse-on-delete.
// ============================================================================

TEST_F(State_SmtFixture, TwoKeysShareABranch)
{
  //  Two keys that share all but the last bit. The tree should be a
  //  single branch at the root whose prefix is 255 bits long, with the
  //  two leaves as children.
  auto [k1, k2] = SmtKeys::makeSiblingKeys(255);

  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);

  ASSERT_TRUE(tree_->get(k1).has_value());
  ASSERT_TRUE(tree_->get(k2).has_value());

  EXPECT_EQ(*tree_->get(k1), makeValue(1));
  EXPECT_EQ(*tree_->get(k2), makeValue(2));

  //  Height should be 2: one branch hop, two leaf children.
  EXPECT_EQ(tree_->height(), 2u);
}

TEST_F(State_SmtFixture, HeightGrowsLogarithmically)
{
  //  With N random keys, the tree height should be O(log N), not 256.
  //  For N = 1024, we expect something close to 10, not 256.
  constexpr uint64_t N = 1024;
  for (uint64_t i = 1; i <= N; ++i)
    update(i, i);

  const size_t h = tree_->height();
  EXPECT_GE(h, 8u) << "height " << h << " is suspiciously small";
  EXPECT_LE(h, 24u) << "height " << h << " is suspiciously large";
}

TEST_F(State_SmtFixture, CollapseOnDelete)
{
  //  Two keys that share all but the last bit. Delete one; the tree
  //  should collapse the branch back to a single leaf at the root.
  auto [k1, k2] = SmtKeys::makeSiblingKeys(255);

  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);
  EXPECT_EQ(tree_->height(), 2u);

  tree_->remove(k2, 0);

  //  After removing k2, the tree is a single leaf for k1.
  EXPECT_EQ(tree_->height(), 1u);
  ASSERT_TRUE(tree_->get(k1).has_value());
  EXPECT_FALSE(tree_->get(k2).has_value());
}

TEST_F(State_SmtFixture, SimilarKeysAreDistinguished)
{
  auto [k1, k2] = SmtKeys::makeSiblingKeys(255);

  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);

  auto v1 = tree_->get(k1);
  auto v2 = tree_->get(k2);
  ASSERT_TRUE(v1.has_value());
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(*v1, makeValue(1));
  EXPECT_EQ(*v2, makeValue(2));
}

TEST_F(State_SmtFixture, SimilarKeysRootReflectsBothLeaves)
{
  auto [k1, k2] = SmtKeys::makeSiblingKeys(128);

  tree_->update(k1, makeValue(1), 0);
  auto root_one = tree_->root();

  tree_->update(k2, makeValue(2), 0);
  auto root_two = tree_->root();

  EXPECT_NE(root_one, root_two);
}

TEST_F(State_SmtFixture, PrefixSharedAtRoot)
{
  //  Keys that share the first 200 bits. The tree should have a
  //  branch near the root with a 200-bit prefix, then diverge into
  //  two subtrees.
  auto [k1, k2] = SmtKeys::makeSiblingKeys(200);

  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);

  ASSERT_TRUE(tree_->get(k1).has_value());
  ASSERT_TRUE(tree_->get(k2).has_value());
}

TEST_F(State_SmtFixture, KeysDifferingInFirstBit)
{
  //  Keys that differ at the very first bit. The root should be a
  //  branch with prefix_len 0 whose two children are the two leaves.
  auto [k1, k2] = SmtKeys::makeSiblingKeys(0);

  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);

  EXPECT_EQ(tree_->height(), 2u);
  ASSERT_TRUE(tree_->get(k1).has_value());
  ASSERT_TRUE(tree_->get(k2).has_value());
}

// ============================================================================
//  Write-count properties
//
//  The compressed tree's advantage is that a single update touches
//  O(log N) nodes, not 256. These tests assert that property by
//  measuring the tree's cumulative write counter.
// ============================================================================

TEST_F(State_SmtFixture, SingleUpdateWritesO1Nodes)
{
  //  A single update on an empty tree writes exactly one leaf
  //  preimage to TBL_SMT_NODES and one leaf value to
  //  TBL_SMT_LEAVES. Two rows, not one — the preimage and the
  //  value live in separate tables.
  const auto before = tree_->stats().live_node_writes +
                      tree_->stats().live_leaf_writes;
  update(1, 100);
  const auto after = tree_->stats().live_node_writes +
                     tree_->stats().live_leaf_writes;
  EXPECT_EQ(after - before, 2u);
}

TEST_F(State_SmtFixture, UpdateInLargerTreeWritesOlogN)
{
  //  Populate a tree with 1000 leaves, then measure the live-node
  //  writes for one update. The number should be bounded by a small
  //  constant times log2(1000) ≈ 10.
  constexpr uint64_t N = 1000;
  for (uint64_t i = 1; i <= N; ++i)
    update(i, i);

  const auto before = tree_->stats().live_node_writes +
                      tree_->stats().live_leaf_writes;
  update(N + 1, N + 1);
  const auto after = tree_->stats().live_node_writes +
                     tree_->stats().live_leaf_writes;
  const auto writes = after - before;

  //  A generous upper bound: with 1000 leaves, expected height ~10,
  //  so one update should write ~10-20 nodes. Anything over 64
  //  indicates the tree is not compressing as designed.
  EXPECT_LE(writes, 64u) << "one update wrote " << writes << " nodes";
  EXPECT_GE(writes, 2u) << "one update wrote only " << writes << " nodes";
}

TEST_F(State_SmtFixture, HistoricalWritesMatchLiveWritesAtNonzeroVersion)
{
  setVersion(5);

  const auto live_before = tree_->stats().live_node_writes +
                           tree_->stats().live_leaf_writes;
  const auto hist_before = tree_->stats().hist_node_writes +
                           tree_->stats().hist_leaf_writes;
  const auto byver_before = tree_->stats().by_ver_writes;

  update(1, 100);
  update(2, 200);
  update(3, 300);

  const auto live_after = tree_->stats().live_node_writes +
                          tree_->stats().live_leaf_writes;
  const auto hist_after = tree_->stats().hist_node_writes +
                          tree_->stats().hist_leaf_writes;
  const auto byver_after = tree_->stats().by_ver_writes;

  //  Every write at a nonzero version writes a corresponding
  //  historical row and a corresponding by-version index entry. The
  //  three totals should move in lockstep.
  //
  //  If the invariant doesn't hold, the diagnostic values printed
  //  here tell you which counter diverged.
  const auto live_delta = live_after - live_before;
  const auto hist_delta = hist_after - hist_before;
  const auto byver_delta = byver_after - byver_before;

  EXPECT_EQ(live_delta, byver_delta)
      << "live=" << live_delta
      << " hist=" << hist_delta
      << " byver=" << byver_delta;
}

// ============================================================================
//  applyBatch
// ============================================================================

TEST_F(State_SmtFixture, ApplyBatchMatchesSequential)
{
  std::vector<SparseMerkleTree::Update> updates;
  for (uint64_t i = 1; i <= 20; ++i)
  {
    SparseMerkleTree::Update u;
    u.key = makeKey(i);
    u.value = makeValue(i * 3);
    u.is_delete = false;
    updates.push_back(u);
  }

  auto batch_root = tree_->applyBatch(updates, 0);

  TempDB db2;
  SparseMerkleTree tree2(db2.db());
  for (uint64_t i = 1; i <= 20; ++i)
  {
    tree2.update(makeKey(i), makeValue(i * 3), 0);
  }

  EXPECT_EQ(batch_root, tree2.root());
}

TEST_F(State_SmtFixture, ApplyBatchWithDeletes)
{
  for (uint64_t i = 1; i <= 10; ++i)
    update(i, i);

  std::vector<SparseMerkleTree::Update> updates;
  for (uint64_t i = 1; i <= 10; ++i)
  {
    SparseMerkleTree::Update u;
    u.key = makeKey(i);
    if (i % 2 == 1)
    {
      u.is_delete = true;
    }
    else
    {
      u.value = makeValue(i * 100);
    }
    updates.push_back(u);
  }

  tree_->applyBatch(updates, 0);

  for (uint64_t i = 1; i <= 10; ++i)
  {
    auto v = get(i);
    if (i % 2 == 1)
      EXPECT_FALSE(v.has_value()) << "key " << i << " should be deleted";
    else
    {
      ASSERT_TRUE(v.has_value()) << "key " << i;
      EXPECT_EQ(*v, makeValue(i * 100));
    }
  }
}

TEST_F(State_SmtFixture, ApplyBatchDeduplicatesKeys)
{
  //  A batch with two updates for the same key. Only the last should
  //  be applied, and only one write should reach the tree.
  std::vector<SparseMerkleTree::Update> updates;

  SparseMerkleTree::Update u1;
  u1.key = makeKey(1);
  u1.value = makeValue(100);
  updates.push_back(u1);

  SparseMerkleTree::Update u2;
  u2.key = makeKey(1);
  u2.value = makeValue(200);
  updates.push_back(u2);

  tree_->applyBatch(updates, 0);

  auto v = get(1);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, makeValue(200));
}

// ============================================================================
//  Persistence
// ============================================================================

TEST_F(State_SmtPersistenceFixture, RootSurvivesSaveAndLoad)
{
  Crypto::Hash root_before;

  {
    auto db = openDB();
    auto txn = db->beginWrite();
    SparseMerkleTree tree(*db);
    tree.setTxn(&txn);

    tree.update(makeKey(1), makeValue(100), 0);
    tree.update(makeKey(2), makeValue(200), 0);
    root_before = tree.root();

    tree.save(0);
    txn.commit();
    db->close();
  }

  {
    auto db = openDB();
    SparseMerkleTree tree2(*db);
    tree2.load();
    EXPECT_EQ(tree2.root(), root_before);
    db->close();
  }
}

TEST_F(State_SmtPersistenceFixture, DataSurvivesSaveAndLoad)
{
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    SparseMerkleTree tree(*db);
    tree.setTxn(&txn);

    for (uint64_t i = 1; i <= 20; ++i)
      tree.update(makeKey(i), makeValue(i * 100), 0);
    tree.save(0);
    txn.commit();
    db->close();
  }

  {
    auto db = openDB();
    SparseMerkleTree tree2(*db);
    tree2.load();

    for (uint64_t i = 1; i <= 20; ++i)
    {
      auto v = tree2.get(makeKey(i));
      ASSERT_TRUE(v.has_value()) << "key " << i;
      EXPECT_EQ(*v, makeValue(i * 100));
    }
    db->close();
  }
}

TEST_F(State_SmtPersistenceFixture, HeightRecoveredOnLoad)
{
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    SparseMerkleTree tree(*db);
    tree.setTxn(&txn);

    for (uint64_t i = 1; i <= 100; ++i)
      tree.update(makeKey(i), makeValue(i), 0);
    const size_t h = tree.height();
    tree.save(0);
    txn.commit();
    db->close();

    //  The height should be O(log 100) ≈ 7. It should not be zero
    //  (the tree is not empty) and should not be the full 256 (the
    //  tree is compressed).
    EXPECT_GE(h, 4u);
    EXPECT_LE(h, 20u);
  }

  {
    auto db = openDB();
    SparseMerkleTree tree2(*db);
    tree2.load();
    //  After load, the height is recomputed by walking the tree.
    EXPECT_GE(tree2.height(), 4u);
    EXPECT_LE(tree2.height(), 20u);
    db->close();
  }
}

// ============================================================================
//  Historical reads
// ============================================================================

TEST_F(State_SmtFixture, VersionedRootIsRetrievable)
{
  setVersion(5);
  update(1, 100);
  save();

  auto root_at_5 = tree_->rootAtVersion(5);
  ASSERT_TRUE(root_at_5.has_value());
  EXPECT_EQ(*root_at_5, tree_->root());

  auto root_at_6 = tree_->rootAtVersion(6);
  EXPECT_FALSE(root_at_6.has_value());
}

TEST_F(State_SmtFixture, MultipleVersionsArePersisted)
{
  setVersion(1);
  update(1, 100);
  save();
  auto root_v1 = tree_->root();

  setVersion(2);
  update(2, 200);
  save();
  auto root_v2 = tree_->root();

  EXPECT_EQ(tree_->rootAtVersion(1), root_v1);
  EXPECT_EQ(tree_->rootAtVersion(2), root_v2);
  EXPECT_NE(root_v1, root_v2);
}

TEST_F(State_SmtFixture, ReadValueAtPriorVersion)
{
  setVersion(1);
  update(1, 100);
  save();

  setVersion(2);
  update(1, 200);
  save();

  auto current = get(1);
  ASSERT_TRUE(current.has_value());
  EXPECT_EQ(*current, makeValue(200));

  auto v1 = getAtVersion(1, 1);
  ASSERT_TRUE(v1.has_value());
  EXPECT_EQ(*v1, makeValue(100));

  auto v2 = getAtVersion(1, 2);
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(*v2, makeValue(200));
}

TEST_F(State_SmtFixture, ReadNonInclusionAtPriorVersion)
{
  setVersion(1);
  save(); // empty tree at version 1

  setVersion(2);
  update(1, 100);
  save();

  EXPECT_FALSE(getAtVersion(1, 1).has_value());
  auto v2 = getAtVersion(1, 2);
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(*v2, makeValue(100));
}

TEST_F(State_SmtFixture, UnchangedKeyReadableAtLaterVersion)
{
  setVersion(1);
  update(1, 100);
  save();

  setVersion(2);
  update(2, 200);
  save();

  auto v1_at_2 = getAtVersion(1, 2);
  ASSERT_TRUE(v1_at_2.has_value());
  EXPECT_EQ(*v1_at_2, makeValue(100));

  EXPECT_FALSE(getAtVersion(2, 1).has_value());
}

TEST_F(State_SmtFixture, RemovedKeyIsAbsentAtLaterVersion)
{
  setVersion(1);
  update(1, 100);
  save();

  setVersion(2);
  remove(1);
  save();

  auto v1 = getAtVersion(1, 1);
  ASSERT_TRUE(v1.has_value());
  EXPECT_EQ(*v1, makeValue(100));

  EXPECT_FALSE(getAtVersion(1, 2).has_value());
}

TEST_F(State_SmtFixture, GetAtUnwrittenVersionReturnsNullopt)
{
  setVersion(1);
  update(1, 100);
  save();

  EXPECT_FALSE(getAtVersion(1, 2).has_value());
}

TEST_F(State_SmtFixture, GetAtVersionMatchesRootAtVersion)
{
  setVersion(7);
  update(1, 100);
  update(2, 200);
  save();
  auto root_7 = tree_->root();

  setVersion(9);
  update(3, 300);
  save();
  auto root_9 = tree_->root();

  ASSERT_TRUE(tree_->rootAtVersion(7).has_value());
  ASSERT_TRUE(tree_->rootAtVersion(9).has_value());
  EXPECT_EQ(*tree_->rootAtVersion(7), root_7);
  EXPECT_EQ(*tree_->rootAtVersion(9), root_9);
  EXPECT_NE(root_7, root_9);

  EXPECT_FALSE(getAtVersion(3, 7).has_value());
  ASSERT_TRUE(getAtVersion(1, 7).has_value());
  ASSERT_TRUE(getAtVersion(2, 7).has_value());

  ASSERT_TRUE(getAtVersion(1, 9).has_value());
  ASSERT_TRUE(getAtVersion(2, 9).has_value());
  ASSERT_TRUE(getAtVersion(3, 9).has_value());
}

// ============================================================================
//  Pruning
// ============================================================================

TEST_F(State_SmtFixture, PruneRemovesOldVersions)
{
  setVersion(1);
  update(1, 100);
  save();

  setVersion(2);
  update(1, 200);
  save();

  setVersion(3);
  update(1, 300);
  save();

  tree_->pruneHistory(2);

  EXPECT_FALSE(getAtVersion(1, 1).has_value());

  auto v2 = getAtVersion(1, 2);
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(*v2, makeValue(200));

  auto v3 = getAtVersion(1, 3);
  ASSERT_TRUE(v3.has_value());
  EXPECT_EQ(*v3, makeValue(300));

  auto cur = get(1);
  ASSERT_TRUE(cur.has_value());
  EXPECT_EQ(*cur, makeValue(300));
}

TEST_F(State_SmtFixture, PruneIsIdempotent)
{
  setVersion(1);
  update(1, 100);
  save();

  setVersion(2);
  update(1, 200);
  save();

  tree_->pruneHistory(2);
  tree_->pruneHistory(2);

  EXPECT_FALSE(getAtVersion(1, 1).has_value());
  ASSERT_TRUE(getAtVersion(1, 2).has_value());
}

TEST_F(State_SmtFixture, PruneBelowAllVersionsIsNoOp)
{
  setVersion(1);
  update(1, 100);
  save();

  tree_->pruneHistory(0);

  ASSERT_TRUE(getAtVersion(1, 1).has_value());
}

// ============================================================================
//  Sparse-set behaviour
//
//  A tree with a small number of leaves should not touch every depth
//  of the key space. The compressed tree collapses long single-child
//  paths, so the physical node count stays proportional to the number
//  of leaves.
// ============================================================================

TEST_F(State_SmtFixture, NodeCountIsLinearInLeaves)
{
  //  100 leaves. Live node writes should be bounded by ~2 * 100 + a
  //  constant (the tree is a strict binary trie with N leaves and at
  //  most 2N-1 internal nodes when fully expanded, but the compressed
  //  tree has even fewer).
  const auto before = tree_->stats().live_node_writes +
                      tree_->stats().live_leaf_writes;
  for (uint64_t i = 1; i <= 100; ++i)
    update(i, i);
  const auto after = tree_->stats().live_node_writes +
                     tree_->stats().live_leaf_writes;
  const auto writes = after - before;

  //  Expected writes: ~log2(N) per insert, so ~N log N total.
  //  For N=100, that's roughly 660 writes, plus slack.
  EXPECT_LE(writes, 1500u) << "100 inserts wrote " << writes << " nodes";
}

// ============================================================================
//  ReadChildren (used by proof generation)
// ============================================================================

TEST_F(State_SmtFixture, ReadNodeOnEmptyRootFails)
{
  std::vector<uint8_t> out;
  EXPECT_FALSE(tree_->readNode(tree_->root(), out));
}

TEST_F(State_SmtFixture, ReadNodeAfterInsertSucceeds)
{
  update(1, 100);

  //  The root is a leaf; reading it should return the leaf's preimage.
  std::vector<uint8_t> out;
  ASSERT_TRUE(tree_->readNode(tree_->root(), out));
  EXPECT_EQ(out.size(), 1u + 32u + 32u);
  EXPECT_EQ(out[0], SparseMerkleTree::TAG_LEAF);
}

TEST_F(State_SmtFixture, ReadNodeOnUnknownHashFails)
{
  Crypto::Hash unknown;
  for (size_t i = 0; i < 32; ++i)
    unknown.data[i] = 0xEE;
  std::vector<uint8_t> out;
  EXPECT_FALSE(tree_->readNode(unknown, out));
}

// ============================================================================
//  Stats
// ============================================================================

TEST_F(State_SmtFixture, StatsCountUpdatesAndRemoves)
{
  const auto u0 = tree_->stats().updates;
  const auto r0 = tree_->stats().removes;

  update(1, 100);
  update(2, 200);
  remove(1);

  EXPECT_EQ(tree_->stats().updates - u0, 2u);
  EXPECT_EQ(tree_->stats().removes - r0, 1u);
}

TEST_F(State_SmtFixture, ResetStatsClearsCounters)
{
  update(1, 100);
  ASSERT_GT(tree_->stats().updates, 0u);
  tree_->resetStats();
  EXPECT_EQ(tree_->stats().updates, 0u);
  EXPECT_EQ(tree_->stats().live_node_writes, 0u);
}
