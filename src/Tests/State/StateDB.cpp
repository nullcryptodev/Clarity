// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fixtures.h"

using namespace State;
using namespace Tests;

TEST_F(State_StateDBFixture, RawPutGet)
{
  std::vector<uint8_t> out;
  EXPECT_FALSE(db_.db().rawGet(StateDB::TBL_META, "key", 3, out));

  std::vector<uint8_t> value = {1, 2, 3, 4};
  db_.db().rawPut(StateDB::TBL_META, "key", 3, value.data(), value.size());

  EXPECT_TRUE(db_.db().rawGet(StateDB::TBL_META, "key", 3, out));
  EXPECT_EQ(out, value);
}

TEST_F(State_StateDBFixture, RawPutOverwrites)
{
  std::vector<uint8_t> v1 = {1, 2, 3};
  std::vector<uint8_t> v2 = {4, 5, 6, 7, 8};
  db_.db().rawPut(StateDB::TBL_META, "k", 1, v1.data(), v1.size());
  db_.db().rawPut(StateDB::TBL_META, "k", 1, v2.data(), v2.size());

  std::vector<uint8_t> out;
  ASSERT_TRUE(db_.db().rawGet(StateDB::TBL_META, "k", 1, out));
  EXPECT_EQ(out, v2);
}

TEST_F(State_StateDBFixture, RawDel)
{
  std::vector<uint8_t> v = {1, 2, 3};
  db_.db().rawPut(StateDB::TBL_META, "k", 1, v.data(), v.size());
  EXPECT_TRUE(db_.db().rawHas(StateDB::TBL_META, "k", 1));

  db_.db().rawDel(StateDB::TBL_META, "k", 1);
  EXPECT_FALSE(db_.db().rawHas(StateDB::TBL_META, "k", 1));
}

TEST_F(State_StateDBFixture, RawDelMissingIsNoOp)
{
  db_.db().rawDel(StateDB::TBL_META, "nonexistent", 11);
}

TEST_F(State_StateDBFixture, RawHas)
{
  EXPECT_FALSE(db_.db().rawHas(StateDB::TBL_META, "a", 1));
  std::vector<uint8_t> v = {1};
  db_.db().rawPut(StateDB::TBL_META, "a", 1, v.data(), v.size());
  EXPECT_TRUE(db_.db().rawHas(StateDB::TBL_META, "a", 1));
}

TEST_F(State_StateDBFixture, RawEmptyValue)
{
  std::vector<uint8_t> empty;
  db_.db().rawPut(StateDB::TBL_META, "e", 1, empty.data(), 0);

  std::vector<uint8_t> out;
  ASSERT_TRUE(db_.db().rawGet(StateDB::TBL_META, "e", 1, out));
  EXPECT_TRUE(out.empty());
}

TEST_F(State_StateDBFixture, RawLargeValue)
{
  std::vector<uint8_t> big(1024 * 16);
  for (size_t i = 0; i < big.size(); ++i)
    big[i] = uint8_t(i);

  db_.db().rawPut(StateDB::TBL_SMT_NODES, "big", 3, big.data(), big.size());

  std::vector<uint8_t> out;
  ASSERT_TRUE(db_.db().rawGet(StateDB::TBL_SMT_NODES, "big", 3, out));
  EXPECT_EQ(out, big);
}

TEST_F(State_StateDBFixture, MetaPutGet)
{
  std::vector<uint8_t> v = {7, 8, 9};
  db_.db().putMeta("my_meta", v);

  std::vector<uint8_t> out;
  ASSERT_TRUE(db_.db().getMeta("my_meta", out));
  EXPECT_EQ(out, v);

  auto opt = db_.db().getMeta("my_meta");
  ASSERT_TRUE(opt.has_value());
  EXPECT_EQ(*opt, v);
}

TEST_F(State_StateDBFixture, MetaRemove)
{
  db_.db().putMeta("k", {1, 2});
  db_.db().removeMeta("k");

  std::vector<uint8_t> out;
  EXPECT_FALSE(db_.db().getMeta("k", out));
  EXPECT_FALSE(db_.db().getMeta("k").has_value());
}

TEST_F(State_StateDBFixture, MetaMissingReturnsFalse)
{
  std::vector<uint8_t> out;
  EXPECT_FALSE(db_.db().getMeta("never_set", out));
}

TEST_F(State_StateDBFixture, TxnCommitPersists)
{
  {
    auto txn = db_.db().beginWrite();
    std::vector<uint8_t> v = {1, 2, 3};
    txn.put(StateDB::TBL_META, "k", 1, v.data(), v.size());
    txn.commit();
  }

  std::vector<uint8_t> out;
  ASSERT_TRUE(db_.db().rawGet(StateDB::TBL_META, "k", 1, out));
  EXPECT_EQ(out, std::vector<uint8_t>({1, 2, 3}));
}

TEST_F(State_StateDBFixture, TxnAbortDiscards)
{
  {
    auto txn = db_.db().beginWrite();
    std::vector<uint8_t> v = {1, 2, 3};
    txn.put(StateDB::TBL_META, "k", 1, v.data(), v.size());
    txn.abort();
  }

  std::vector<uint8_t> out;
  EXPECT_FALSE(db_.db().rawGet(StateDB::TBL_META, "k", 1, out));
}

TEST_F(State_StateDBFixture, TxnDestructorAborts)
{
  {
    auto txn = db_.db().beginWrite();
    std::vector<uint8_t> v = {1, 2, 3};
    txn.put(StateDB::TBL_META, "k", 1, v.data(), v.size());
  }

  std::vector<uint8_t> out;
  EXPECT_FALSE(db_.db().rawGet(StateDB::TBL_META, "k", 1, out));
}

TEST_F(State_StateDBFixture, TxnSeesOwnWrites)
{
  auto txn = db_.db().beginWrite();
  std::vector<uint8_t> v = {1, 2, 3};
  txn.put(StateDB::TBL_META, "k", 1, v.data(), v.size());

  std::vector<uint8_t> out;
  ASSERT_TRUE(txn.get(StateDB::TBL_META, "k", 1, out));
  EXPECT_EQ(out, v);
}

TEST_F(State_StateDBFixture, TxnDelWithinTxn)
{
  {
    std::vector<uint8_t> v = {1, 2, 3};
    db_.db().rawPut(StateDB::TBL_META, "k", 1, v.data(), v.size());
  }

  {
    auto txn = db_.db().beginWrite();
    txn.del(StateDB::TBL_META, "k", 1);
    txn.commit();
  }

  std::vector<uint8_t> out;
  EXPECT_FALSE(db_.db().rawGet(StateDB::TBL_META, "k", 1, out));
}

TEST_F(State_StateDBFixture, TxnHas)
{
  auto txn = db_.db().beginWrite();
  EXPECT_FALSE(txn.has(StateDB::TBL_META, "k", 1));
  std::vector<uint8_t> v = {1};
  txn.put(StateDB::TBL_META, "k", 1, v.data(), v.size());
  EXPECT_TRUE(txn.has(StateDB::TBL_META, "k", 1));
  txn.abort();
}

TEST_F(State_StateDBFixture, TxnIsOpen)
{
  auto txn = db_.db().beginWrite();
  EXPECT_TRUE(txn.isOpen());
  txn.abort();
  EXPECT_FALSE(txn.isOpen());
}

TEST_F(State_StateDBFixture, BeginWriteFailsWithActiveTxn)
{
  auto txn1 = db_.db().beginWrite();
  EXPECT_THROW(db_.db().beginWrite(), StateDBError);
  txn1.abort();
}

TEST_F(State_StateDBFixture, BeginWriteAfterAbortSucceeds)
{
  {
    auto txn = db_.db().beginWrite();
    txn.abort();
  }
  auto txn2 = db_.db().beginWrite();
  txn2.abort();
}

TEST_F(State_StateDBFixture, TxnPutAfterCloseThrows)
{
  auto txn = db_.db().beginWrite();
  txn.commit();
  EXPECT_THROW(txn.put(StateDB::TBL_META, "k", 1, nullptr, 0),
               StateDBError);
}

TEST_F(State_StateDBFixture, DataSurvivesCloseReopen)
{
  {
    std::vector<uint8_t> v = {10, 20, 30};
    db_.db().rawPut(StateDB::TBL_META, "persisted", 9, v.data(), v.size());
  }

  auto path = db_.path();
  db_.db().close();

  StateDB db2(path.string(), 64ULL * 1024 * 1024);
  std::vector<uint8_t> out;
  ASSERT_TRUE(db2.rawGet(StateDB::TBL_META, "persisted", 9, out));
  EXPECT_EQ(out, std::vector<uint8_t>({10, 20, 30}));
  db2.close();
}

TEST_F(State_StateDBFixture, ForEachEntryVisitsAllKeys)
{
  for (uint64_t i = 0; i < 10; ++i)
  {
    std::vector<uint8_t> key = {uint8_t(i)};
    std::vector<uint8_t> val = {uint8_t(i * 2)};
    db_.db().rawPut(StateDB::TBL_META, key.data(), key.size(), val.data(), val.size());
  }

  std::vector<uint8_t> visited;
  db_.db().forEachEntry(StateDB::TBL_META,
                        [&](const std::vector<uint8_t> &k,
                            const std::vector<uint8_t> & /*v*/)
                        {
                          if (k.size() == 1)
                            visited.push_back(k[0]);
                          return true;
                        });

  std::vector<uint8_t> expected;
  for (uint8_t i = 0; i < 10; ++i)
    expected.push_back(i);

  for (auto e : expected)
    EXPECT_NE(std::find(visited.begin(), visited.end(), e), visited.end());
}

TEST_F(State_StateDBFixture, ForEachEntryStopsOnFalse)
{
  for (uint64_t i = 0; i < 10; ++i)
  {
    std::vector<uint8_t> key = {uint8_t(i)};
    std::vector<uint8_t> val = {uint8_t(i)};
    db_.db().rawPut(StateDB::TBL_ORDERS, key.data(), key.size(), val.data(), val.size());
  }

  int count = 0;
  db_.db().forEachEntry(StateDB::TBL_ORDERS,
                        [&](const std::vector<uint8_t> &, const std::vector<uint8_t> &)
                        {
                          ++count;
                          return count < 3;
                        });

  EXPECT_LE(count, 3);
}

TEST_F(State_StateDBFixture, EntryCount)
{
  size_t before = db_.db().entryCount(StateDB::TBL_ORDERS);
  for (uint64_t i = 0; i < 5; ++i)
  {
    std::vector<uint8_t> key = {uint8_t(i)};
    db_.db().rawPut(StateDB::TBL_ORDERS, key.data(), 1, nullptr, 0);
  }
  size_t after = db_.db().entryCount(StateDB::TBL_ORDERS);
  EXPECT_EQ(after - before, 5u);
}