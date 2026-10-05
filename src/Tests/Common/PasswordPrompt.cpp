// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include "Common/PasswordPrompt.h"

namespace
{
  namespace fs = std::filesystem;

  //  RAII temp file. Kept local because the prompt tests only need
  //  "write some bytes, ask readPasswordFile to read them, clean up."
  //  Using the shared fixture would pull in node/genesis setup that
  //  has nothing to do with password reading.
  class TempFile
  {
  public:
    explicit TempFile(const std::string &contents,
                      std::ios::openmode mode = std::ios::binary)
    {
      static std::atomic<uint64_t> counter{0};
      path_ = fs::temp_directory_path() /
              ("clrty_pwtest_" + std::to_string(counter.fetch_add(1)));

      std::ofstream out(path_, std::ios::trunc | mode);
      out.write(contents.data(),
                static_cast<std::streamsize>(contents.size()));
      out.close();
    }

    ~TempFile()
    {
      std::error_code ec;
      fs::remove(path_, ec);
    }

    TempFile(const TempFile &) = delete;
    TempFile &operator=(const TempFile &) = delete;

    const std::string path() const { return path_.string(); }

  private:
    fs::path path_;
  };

  //  A path that is guaranteed not to exist. We pick a name in the
  //  temp dir and remove it, so the file is absent at the moment
  //  readPasswordFile() is called.
  std::string nonexistentPath()
  {
    static std::atomic<uint64_t> counter{0};
    fs::path p = fs::temp_directory_path() /
                 ("clrty_pwtest_missing_" +
                  std::to_string(counter.fetch_add(1)));
    std::error_code ec;
    fs::remove(p, ec);
    return p.string();
  }
} // anonymous namespace

// ============================================================================
//  readPasswordFile — happy paths
// ============================================================================

TEST(PasswordPrompt, ReadFileStripsTrailingNewline)
{
  TempFile f("hunter2\n");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "hunter2");
}

TEST(PasswordPrompt, ReadFileStripsTrailingCRLF)
{
  //  Windows-edited files, or files moved through a tool that adds
  //  CRLF, must not leave a stray \r on the password.
  TempFile f("hunter2\r\n");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "hunter2");
}

TEST(PasswordPrompt, ReadFileStripsTrailingWhitespaceMix)
{
  TempFile f("hunter2 \t\r\n\n");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "hunter2");
}

TEST(PasswordPrompt, ReadFilePreservesLeadingWhitespace)
{
  //  The contract is: trim trailing whitespace only. A leading
  //  space is part of the password.
  TempFile f("  hunter2\n");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "  hunter2");
}

TEST(PasswordPrompt, ReadFilePreservesInteriorWhitespace)
{
  TempFile f("hunter two\n");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "hunter two");
}

TEST(PasswordPrompt, ReadFilePreservesInternalNewlines)
{
  //  Only trailing whitespace is trimmed. Interior newlines are
  //  preserved; the caller is responsible for deciding whether a
  //  multi-line password is meaningful.
  TempFile f("line1\nline2\n");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "line1\nline2");
}

TEST(PasswordPrompt, ReadFileEmptyFileReturnsEmptyString)
{
  //  An empty file is a valid (empty) password, not a failure.
  TempFile f("");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "");
}

TEST(PasswordPrompt, ReadFileOnlyNewlineReturnsEmptyString)
{
  TempFile f("\n");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "");
}

TEST(PasswordPrompt, ReadFileOnlyWhitespaceReturnsEmptyString)
{
  TempFile f("   \t\r\n\n");
  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  EXPECT_EQ(*pw, "");
}

TEST(PasswordPrompt, ReadFilePreservesBinaryBytes)
{
  //  The file is opened in binary mode; bytes must come through
  //  unchanged except for trailing whitespace. Use a byte that is
  //  not whitespace and not ASCII, to catch any text-mode
  //  translation.
  std::string contents;
  contents.push_back('\x01');
  contents.push_back('\x7F');
  contents.push_back('\xFF');
  contents.push_back('\n');
  TempFile f(contents);

  auto pw = Apps::readPasswordFile(f.path());
  ASSERT_TRUE(pw.has_value());
  ASSERT_EQ(pw->size(), 3u);
  EXPECT_EQ((*pw)[0], '\x01');
  EXPECT_EQ((*pw)[1], '\x7F');
  EXPECT_EQ((*pw)[2], '\xFF');
}

// ============================================================================
//  readPasswordFile — failure paths
// ============================================================================

TEST(PasswordPrompt, ReadFileMissingReturnsNullopt)
{
  auto pw = Apps::readPasswordFile(nonexistentPath());
  EXPECT_FALSE(pw.has_value());
}

TEST(PasswordPrompt, ReadFileDirectoryReturnsNullopt)
{
  //  Reading a directory as a file must not crash and must not
  //  return a partial value. On most platforms ifstream on a
  //  directory fails to open cleanly; where it succeeds, read() on
  //  it fails and the bad() bit is set.
  std::error_code ec;
  const fs::path dir = fs::temp_directory_path() / "clrty_pwtest_dir";
  fs::remove_all(dir, ec);
  fs::create_directory(dir, ec);
  ASSERT_FALSE(ec);

  auto pw = Apps::readPasswordFile(dir.string());
  EXPECT_FALSE(pw.has_value());

  fs::remove_all(dir, ec);
}
