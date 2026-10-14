// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "Crypto/Blake2b.h"
#include "Crypto/Types.h"
#include "Tests/Temp.h"
#include "Tests/Utils.h"

namespace Tests
{
  //  Common key/value helpers. These are shared by every State test
  //  that builds a tree or a StateAccess, so the layout is consistent
  //  across files.

  namespace SmtKeys
  {
    //  Deterministic key from a small integer. Uses a domain-separated
    //  Blake2b so the resulting 32 bytes are spread uniformly across
    //  the key space, matching what real state keys look like.
    //
    //  The old tests wrote the integer directly into the first 8 bytes
    //  and left the rest zero; that was fine for a fixed-depth trie
    //  because every key had a fixed path length. The compressed tree
    //  is sensitive to shared prefixes, so we want keys that behave
    //  like real ones: uniformly random, no accidental long common
    //  prefixes.
    inline Crypto::Hash makeKey(uint64_t n)
    {
      uint8_t buf[8];
      for (int i = 0; i < 8; ++i)
        buf[i] = uint8_t(n >> (i * 8));
      Crypto::Hash h;
      Crypto::blake2b(buf, sizeof(buf), h.data.data(), 32);
      return h;
    }

    //  Deterministic value of a given length. The first byte encodes
    //  the length so two values of different lengths never hash the
    //  same.
    inline std::vector<uint8_t> makeValue(uint64_t n, size_t len = 32)
    {
      std::vector<uint8_t> v(len);
      for (size_t i = 0; i < len; ++i)
        v[i] = uint8_t((n >> ((i % 8) * 8)) ^ (i * 7));
      return v;
    }

    //  A key that shares a long common prefix with another key.
    //  `prefix_bits` is the number of leading bits that should be
    //  common between the two keys; `differ_at` is the bit index
    //  (0-based from the MSB) where the two keys diverge. The two
    //  keys are otherwise all zeros.
    inline std::pair<Crypto::Hash, Crypto::Hash>
    makeSiblingKeys(size_t common_bits)
    {
      Crypto::Hash a{};
      Crypto::Hash b{};

      //  First `common_bits` bits are zero (the default). The next
      //  bit is 0 in a, 1 in b.
      const size_t diverge_at = common_bits;
      const size_t byte = diverge_at / 8;
      const uint8_t mask = uint8_t(0x80 >> (diverge_at % 8));
      b.data[byte] |= mask;

      return {a, b};
    }
  } // namespace SmtKeys

  //  =====================================================================
  //  SmtFixture
  //
  //  One DB, one write txn held for the whole test. The tree is bound
  //  to the txn. TearDown aborts the txn; nothing persists.
  //
  //  This fixture is for tests that operate on the tree directly. Tests
  //  that need commit/reopen semantics use State_SmtPersistenceFixture
  //  instead.
  //  =====================================================================

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

    //  --- Key/value helpers ---

    static Crypto::Hash makeKey(uint64_t n) { return SmtKeys::makeKey(n); }
    static std::vector<uint8_t> makeValue(uint64_t n, size_t len = 32)
    {
      return SmtKeys::makeValue(n, len);
    }

    //  --- Tree operations at the current version ---

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

    void save() { tree_->save(current_version_); }

    void setVersion(uint64_t v) { current_version_ = v; }

    //  --- Accessors for the underlying objects ---

    State::SparseMerkleTree &tree() { return *tree_; }
    State::StateDB &db() { return db_.db(); }

    TempDB db_;
    std::optional<State::StateDB::Txn> txn_;
    std::unique_ptr<State::SparseMerkleTree> tree_;

  private:
    uint64_t current_version_{0};
  };

  //  =====================================================================
  //  State_StateDBFixture
  //
  //  One DB, no txn held. Tests manage their own transactions.
  //  =====================================================================

  class State_StateDBFixture : public testing::Test
  {
  protected:
    void SetUp() override {}
    void TearDown() override {}

    TempDB db_;
  };

  //  =====================================================================
  //  State_SmtPersistenceFixture
  //
  //  Owns a path; opens and closes DBs explicitly. Use this for tests
  //  that need to close and reopen the DB (persistence across
  //  restart, save-then-load across a commit boundary, historical
  //  reads after commit).
  //  =====================================================================

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
      return std::make_unique<State::StateDB>(path_.string(),
                                              64ULL * 1024 * 1024);
    }

    const std::filesystem::path &path() const { return path_; }

    static Crypto::Hash makeKey(uint64_t n) { return SmtKeys::makeKey(n); }
    static std::vector<uint8_t> makeValue(uint64_t n, size_t len = 32)
    {
      return SmtKeys::makeValue(n, len);
    }

    std::filesystem::path path_;
  };

  //  =====================================================================
  //  State_StateAccessFixture
  //
  //  One DB and one write txn per test. The StateAccess wraps the txn.
  //  TearDown aborts; nothing persists.
  //
  //  setVersion(version) rebuilds the access at a new version. This is
  //  what historical-read tests use to write at one version, then
  //  another, then read both. It aborts the current txn and opens a
  //  new one, which means writes from the previous txn are discarded
  //  unless the test commits first.
  //
  //  For tests that need writes at multiple versions to persist, use
  //  State_SmtPersistenceFixture instead.
  //  =====================================================================

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

    void setVersion(uint64_t version)
    {
      access_.reset();
      if (txn_ && txn_->isOpen())
        txn_->abort();
      txn_.reset();

      txn_.emplace(db_.db().beginWrite());
      access_ =
          std::make_unique<State::StateAccess>(db_.db(), *txn_, version);
    }

    TempDB db_;
    std::optional<State::StateDB::Txn> txn_;
    std::unique_ptr<State::StateAccess> access_;
  };

} // namespace Tests