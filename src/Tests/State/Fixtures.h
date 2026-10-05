#pragma once

#include "gtest/gtest.h"

#include "Tests/Temp.h"
#include "Tests/Utils.h"

namespace Tests
{

  // one DB, one write txn held for the whole test.
  class State_SmtFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      txn_.emplace(db_.db().beginWrite());
      tree_ = std::make_unique<State::SparseMerkleTree>(db_.db());
      tree_->setTxn(&*txn_);
    }

    void TearDown() override
    {
      tree_.reset();
      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();
    }

    static Crypto::Hash makeKey(uint64_t n)
    {
      Crypto::Hash h;
      for (int i = 0; i < 8; ++i)
        h.data[i] = uint8_t(n >> (i * 8));
      for (size_t i = 8; i < 32; ++i)
        h.data[i] = 0;
      return h;
    }

    static std::vector<uint8_t> makeValue(uint64_t n, size_t len = 32)
    {
      std::vector<uint8_t> v(len);
      for (size_t i = 0; i < len; ++i)
        v[i] = uint8_t((n >> ((i % 8) * 8)) ^ (i * 7));
      return v;
    }

    Crypto::Hash update(uint64_t key_num, uint64_t value_num)
    {
      return tree_->update(makeKey(key_num), makeValue(value_num),
                           current_version_);
    }

    Crypto::Hash remove(uint64_t key_num)
    {
      return tree_->remove(makeKey(key_num), current_version_);
    }

    std::optional<std::vector<uint8_t>> get(uint64_t key_num)
    {
      return tree_->get(makeKey(key_num));
    }

    //  Versioned read. Same argument convention as get(), plus the
    //  version to read at. Returns nullopt if the version has no
    //  saved root, or the key did not exist at that version.
    std::optional<std::vector<uint8_t>> getAtVersion(uint64_t key_num,
                                                     uint64_t version)
    {
      return tree_->getAtVersion(makeKey(key_num), version);
    }

    //  Save the current root at the current version.
    void save()
    {
      tree_->save(current_version_);
    }

    //  Set the version used by subsequent update/remove/save calls.
    //  Tests that want to exercise historical reads call this between
    //  writes. Tests that don't care leave it at the default 0 and
    //  behave exactly as before.
    void setVersion(uint64_t v)
    {
      current_version_ = v;
    }

    TempDB db_;
    std::optional<State::StateDB::Txn> txn_;
    std::unique_ptr<State::SparseMerkleTree> tree_;

  private:
    uint64_t current_version_{0};
  };

  //  StateDBTestFixture — one DB, no txn held. Tests manage their own.

  class State_StateDBFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    TempDB db_;
  };

  //  SmtPersistenceTestFixture — owns a path, opens/closes DBs explicitly.
  //
  //  Use this for tests that need to close and reopen the DB (i.e.
  //  persistence across restart, or save-then-load across a commit
  //  boundary).

  class State_SmtPersistenceFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      static std::atomic<uint64_t> counter{0};
      path_ = std::filesystem::temp_directory_path() /
              ("clrty_smt_persist_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(path_);
    }

    void TearDown() override
    {
      std::error_code ec;
      std::filesystem::remove_all(path_, ec);
    }

    std::unique_ptr<State::StateDB> openDB()
    {
      return std::make_unique<State::StateDB>(path_.string(), 64ULL * 1024 * 1024);
    }

    const std::filesystem::path &path() const { return path_; }

    static Crypto::Hash makeKey(uint64_t n)
    {
      Crypto::Hash h;
      for (int i = 0; i < 8; ++i)
        h.data[i] = uint8_t(n >> (i * 8));
      for (size_t i = 8; i < 32; ++i)
        h.data[i] = 0;
      return h;
    }

    static std::vector<uint8_t> makeValue(uint64_t n, size_t len = 32)
    {
      std::vector<uint8_t> v(len);
      for (size_t i = 0; i < len; ++i)
        v[i] = uint8_t((n >> ((i % 8) * 8)) ^ (i * 7));
      return v;
    }

    std::filesystem::path path_;
  };

  //  StateAccessTestFixture
  //
  //  One DB and one write txn per test. The StateAccess wraps the txn.
  //  TearDown aborts — nothing persists.

  class State_StateAccessFixture : public testing::Test
  {
  protected:
    void SetUp() override
    {
      txn_.emplace(db_.db().beginWrite());
      access_ = std::make_unique<State::StateAccess>(db_.db(), *txn_, 0);
    }

    void TearDown() override
    {
      access_.reset();
      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();
    }

    State::StateAccess &s() { return *access_; }
    State::StateDB &db() { return db_.db(); }

    // Rebuild the access at a specific version (height). Aborts the
    // current txn and opens a new one.
    void setVersion(uint64_t version)
    {
      access_.reset();
      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();

      txn_.emplace(db_.db().beginWrite());
      access_ = std::make_unique<State::StateAccess>(db_.db(), *txn_, version);
    }

    TempDB db_;
    std::optional<State::StateDB::Txn> txn_;
    std::unique_ptr<State::StateAccess> access_;
  };
}