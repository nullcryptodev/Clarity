// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Tests/Fixtures.h"

using namespace State;
using namespace Tests;

TEST_F(SmtTestFixture, EmptyTreeRootIsDefaultHash)
{
  EXPECT_EQ(tree_->root(), SparseMerkleTree::defaultHash(SparseMerkleTree::DEPTH));
}

TEST_F(SmtTestFixture, EmptyTreeGetReturnsNullopt)
{
  EXPECT_FALSE(get(0).has_value());
  EXPECT_FALSE(get(1).has_value());
  EXPECT_FALSE(get(0xFFFFFFFFFFFFFFFFULL).has_value());
}

TEST_F(SmtTestFixture, EmptyTreeRootIsDeterministic)
{
  SparseMerkleTree other(db_.db());
  EXPECT_EQ(tree_->root(), other.root());
}

TEST_F(SmtTestFixture, DefaultHashesAreConsistent)
{
  for (size_t d = 1; d <= SparseMerkleTree::DEPTH; ++d)
  {
    Crypto::Hash expected;
    uint8_t buf[1 + 32 + 32];
    buf[0] = 0x01;
    std::memcpy(buf + 1, SparseMerkleTree::defaultHash(d - 1).data.data(), 32);
    std::memcpy(buf + 33, SparseMerkleTree::defaultHash(d - 1).data.data(), 32);
    Crypto::blake2b(buf, sizeof(buf), expected.data.data(), 32);

    EXPECT_EQ(SparseMerkleTree::defaultHash(d), expected)
        << "depth " << d;
  }
}

TEST_F(SmtTestFixture, DefaultHashAboveDepthClamps)
{
  EXPECT_EQ(SparseMerkleTree::defaultHash(257),
            SparseMerkleTree::defaultHash(256));
  EXPECT_EQ(SparseMerkleTree::defaultHash(1000),
            SparseMerkleTree::defaultHash(256));
}

TEST_F(SmtTestFixture, InsertSingleLeafChangesRoot)
{
  auto before = tree_->root();
  auto after = update(1, 100);
  EXPECT_NE(before, after);
}

TEST_F(SmtTestFixture, InsertSingleLeafIsRetrievable)
{
  update(1, 100);
  auto v = get(1);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, makeValue(100));
}

TEST_F(SmtTestFixture, InsertSingleLeafOthersStillEmpty)
{
  update(1, 100);
  EXPECT_FALSE(get(2).has_value());
  EXPECT_FALSE(get(0).has_value());
  EXPECT_FALSE(get(1000).has_value());
}

TEST_F(SmtTestFixture, InsertSameValueTwiceIsIdempotent)
{
  auto r1 = update(1, 100);
  auto r2 = update(1, 100);
  EXPECT_EQ(r1, r2);
}

TEST_F(SmtTestFixture, UpdateExistingKeyChangesValueAndRoot)
{
  auto r1 = update(1, 100);
  auto r2 = update(1, 200);
  EXPECT_NE(r1, r2);

  auto v = get(1);
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(*v, makeValue(200));
}

TEST_F(SmtTestFixture, UpdateDifferentKeysGiveDifferentRoots)
{
  auto r1 = update(1, 100);
  auto r2 = update(2, 100);
  EXPECT_NE(r1, r2);
}

TEST_F(SmtTestFixture, SameValueDifferentKeysHaveDifferentLeaves)
{
  auto r_a = update(1, 42);
  auto r_b = update(2, 42);
  EXPECT_NE(r_a, r_b);
}

TEST_F(SmtTestFixture, RemoveReturnsToPriorRoot)
{
  auto empty_root = tree_->root();
  update(1, 100);
  auto after_insert = tree_->root();
  EXPECT_NE(empty_root, after_insert);

  remove(1);
  EXPECT_EQ(tree_->root(), empty_root);
}

TEST_F(SmtTestFixture, RemoveRetrievableKeyReturnsToPriorRoot)
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

TEST_F(SmtTestFixture, RemoveNonexistentKeyIsNoOp)
{
  update(1, 100);
  auto before = tree_->root();
  remove(2);
  EXPECT_EQ(tree_->root(), before);
}

TEST_F(SmtTestFixture, GetAfterRemoveReturnsNullopt)
{
  update(1, 100);
  ASSERT_TRUE(get(1).has_value());
  remove(1);
  EXPECT_FALSE(get(1).has_value());
}

TEST_F(SmtTestFixture, ReinsertAfterRemove)
{
  update(1, 100);
  auto r1 = tree_->root();
  remove(1);
  update(1, 100);
  EXPECT_EQ(tree_->root(), r1);
}

TEST_F(SmtTestFixture, InsertionOrderDoesNotAffectRoot)
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

TEST_F(SmtTestFixture, ManyInsertsAreOrderIndependent)
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

TEST_F(SmtPersistenceTestFixture, RootSurvivesSaveAndLoad)
{
  Crypto::Hash root_before;

  // ---- Write phase ----
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

  // ---- Read phase: fresh DB ----
  {
    auto db = openDB();
    SparseMerkleTree tree2(*db);
    tree2.load();
    EXPECT_EQ(tree2.root(), root_before);
    db->close();
  }
}

TEST_F(SmtPersistenceTestFixture, DataSurvivesSaveAndLoad)
{
  // ---- Write phase ----
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

  // ---- Read phase ----
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

TEST_F(SmtTestFixture, VersionedRootIsRetrievable)
{
  update(1, 100);
  tree_->save(/*version=*/5);

  auto root_at_5 = tree_->rootAtVersion(5);
  ASSERT_TRUE(root_at_5.has_value());
  EXPECT_EQ(*root_at_5, tree_->root());

  auto root_at_6 = tree_->rootAtVersion(6);
  EXPECT_FALSE(root_at_6.has_value());
}

TEST_F(SmtTestFixture, MultipleVersionsArePersisted)
{
  update(1, 100);
  tree_->save(1);
  auto root_v1 = tree_->root();

  update(2, 200);
  tree_->save(2);
  auto root_v2 = tree_->root();

  EXPECT_EQ(tree_->rootAtVersion(1), root_v1);
  EXPECT_EQ(tree_->rootAtVersion(2), root_v2);
  EXPECT_NE(root_v1, root_v2);
}

TEST_F(SmtTestFixture, HundredLeaves)
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

TEST_F(SmtTestFixture, ThousandLeaves)
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

TEST_F(SmtTestFixture, HundredLeavesRemoveHalf)
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

TEST_F(SmtTestFixture, SimilarKeysAreDistinguished)
{
  Crypto::Hash k1;
  Crypto::Hash k2;
  for (size_t i = 0; i < 32; ++i)
  {
    k1.data[i] = 0xAA;
    k2.data[i] = 0xAA;
  }
  k2.data[31] ^= 0x01;

  tree_->update(k1, makeValue(1), 0);
  tree_->update(k2, makeValue(2), 0);

  auto v1 = tree_->get(k1);
  auto v2 = tree_->get(k2);
  ASSERT_TRUE(v1.has_value());
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(*v1, makeValue(1));
  EXPECT_EQ(*v2, makeValue(2));
}

TEST_F(SmtTestFixture, SimilarKeysRootReflectsBothLeaves)
{
  Crypto::Hash k1;
  Crypto::Hash k2;
  for (size_t i = 0; i < 32; ++i)
  {
    k1.data[i] = 0x55;
    k2.data[i] = 0x55;
  }
  k2.data[31] ^= 0x01;

  tree_->update(k1, makeValue(1), 0);
  auto root_one = tree_->root();

  tree_->update(k2, makeValue(2), 0);
  auto root_two = tree_->root();

  EXPECT_NE(root_one, root_two);
}

TEST_F(SmtTestFixture, EmptyValueIsStored)
{
  Crypto::Hash k = makeKey(1);
  std::vector<uint8_t> empty_val;

  tree_->update(k, empty_val, 0);

  auto v = tree_->get(k);
  ASSERT_TRUE(v.has_value());
  EXPECT_TRUE(v->empty());
}

TEST_F(SmtTestFixture, EmptyValueHasDifferentRootThanEmptyTree)
{
  auto empty_root = tree_->root();

  Crypto::Hash k = makeKey(1);
  tree_->update(k, {}, 0);

  EXPECT_NE(tree_->root(), empty_root);
}

TEST_F(SmtTestFixture, RemoveEmptyValueLeafRestoresRoot)
{
  auto empty_root = tree_->root();

  Crypto::Hash k = makeKey(1);
  tree_->update(k, {}, 0);
  tree_->remove(k, 0);

  EXPECT_EQ(tree_->root(), empty_root);
}

TEST_F(SmtTestFixture, ApplyBatchMatchesSequential)
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

TEST_F(SmtTestFixture, ApplyBatchWithDeletes)
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

TEST_F(SmtTestFixture, ReadChildrenOnEmptyRootFails)
{
  Crypto::Hash left, right;
  EXPECT_FALSE(tree_->readChildren(tree_->root(), left, right));
}

TEST_F(SmtTestFixture, ReadChildrenAfterInsertSucceeds)
{
  update(1, 100);

  Crypto::Hash left, right;
  ASSERT_TRUE(tree_->readChildren(tree_->root(), left, right));

  bool non_default = (left != SparseMerkleTree::defaultHash(SparseMerkleTree::DEPTH - 1)) ||
                     (right != SparseMerkleTree::defaultHash(SparseMerkleTree::DEPTH - 1));
  EXPECT_TRUE(non_default);
}

TEST_F(SmtTestFixture, ReadChildrenOnUnknownHashFails)
{
  Crypto::Hash left, right;
  Crypto::Hash unknown;
  for (size_t i = 0; i < 32; ++i)
    unknown.data[i] = 0xEE;
  EXPECT_FALSE(tree_->readChildren(unknown, left, right));
}