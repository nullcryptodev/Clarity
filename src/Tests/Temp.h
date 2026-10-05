#pragma once

#include <atomic>
#include <filesystem>
#include <string>

#include "State/StateDB.h"

namespace Tests
{
  // TempFile creates a unique temp file path, removes it on destruction.
  // The file itself is not created; the fixture's code does that.

  class TempFile
  {
  public:
    TempFile(const std::string &prefix = "clrty_p2p_test")
    {
      static std::atomic<uint64_t> counter{0};
      path_ = std::filesystem::temp_directory_path() /
              (prefix + "_" + std::to_string(counter.fetch_add(1)) + ".tmp");
      std::filesystem::remove(path_);
    }

    ~TempFile()
    {
      std::error_code ec;
      std::filesystem::remove(path_, ec);
    }

    TempFile(const TempFile &) = delete;
    TempFile &operator=(const TempFile &) = delete;

    std::string path() const { return path_.string(); }

  private:
    std::filesystem::path path_;
  };

  class TempDB
  {
  public:
    TempDB()
    {
      static std::atomic<uint64_t> counter{0};
      path_ = std::filesystem::temp_directory_path() /
              ("clrty_state_test_" + std::to_string(counter.fetch_add(1)));
      std::filesystem::remove_all(path_);
      db_ = std::make_unique<State::StateDB>(path_.string(), 64ULL * 1024 * 1024);
    }

    ~TempDB()
    {
      if (db_)
      {
        db_->close();
        db_.reset();
      }
      std::error_code ec;
      std::filesystem::remove_all(path_, ec);
    }

    TempDB(const TempDB &) = delete;
    TempDB &operator=(const TempDB &) = delete;

    State::StateDB &db() { return *db_; }
    const std::filesystem::path &path() const { return path_; }

  private:
    std::filesystem::path path_;
    std::unique_ptr<State::StateDB> db_;
  };
}