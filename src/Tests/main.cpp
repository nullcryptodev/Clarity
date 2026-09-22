// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <mdbx.h>
#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <fcntl.h>
#include <unistd.h>

namespace
{

  // Extracts `--log_file=<path>` or `--log_file <path>` from argv.
  // Returns an empty string if the flag isn't present.
  std::string extractLogFile(int argc, char **argv, int &out_argc, char **out_argv)
  {
    std::string path;
    int w = 0;
    out_argv[0] = argv[0]; // keep program name
    w = 1;

    for (int i = 1; i < argc; ++i)
    {
      const char *a = argv[i];

      if (std::strncmp(a, "--log_file=", 11) == 0)
      {
        path = a + 11;
        continue; // consumed
      }

      if (std::strcmp(a, "--log_file") == 0 && i + 1 < argc)
      {
        path = argv[i + 1];
        ++i; // consume value
        continue;
      }

      out_argv[w++] = argv[i];
    }

    out_argc = w;
    return path;
  }

  // A gtest environment that redirects stdout and stderr to the
  // log file for the whole run, then restores them at the end.
  class OutputRedirectEnv : public ::testing::Environment
  {
  public:
    explicit OutputRedirectEnv(std::string path)
        : path_(std::move(path)) {}

    void SetUp() override
    {
      if (path_.empty())
        return;

      // Open truncating — every run overwrites the previous log.
      file_.open(path_, std::ios::out | std::ios::trunc);
      if (!file_.is_open())
      {
        std::cerr << "[main] could not open log file: " << path_ << "\n";
        return;
      }

      // ---- Redirect the C++ streams ----
      old_cout_ = std::cout.rdbuf();
      old_cerr_ = std::cerr.rdbuf();
      old_clog_ = std::clog.rdbuf();

      std::cout.rdbuf(file_.rdbuf());
      std::cerr.rdbuf(file_.rdbuf());
      std::clog.rdbuf(file_.rdbuf());

      // ---- Redirect the C streams ----
      //
      // gtest's [ RUN ] / [ OK ] / [ FAILED ] lines go through
      // printf() to stdout, not std::cout. Redirecting only the C++
      // streams loses them. dup2() moves the underlying file
      // descriptors so both C and C++ writes land in the file.
      //
      // We duplicate the original file descriptors first so we can
      // restore them on TearDown.
      std::fflush(stdout);
      std::fflush(stderr);

      old_stdout_fd_ = ::dup(fileno(stdout));
      old_stderr_fd_ = ::dup(fileno(stderr));

      int file_fd = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (file_fd < 0)
      {
        // Couldn't open the file for fd redirection. Fall back to
        // C++ stream redirection only.
        active_ = true;
        return;
      }

      ::dup2(file_fd, fileno(stdout));
      ::dup2(file_fd, fileno(stderr));
      ::close(file_fd);

      active_ = true;
    }

    void TearDown() override
    {
      if (!active_)
        return;

      // ---- Flush everything before restoring ----
      std::cout.flush();
      std::cerr.flush();
      std::clog.flush();
      std::fflush(stdout);
      std::fflush(stderr);

      // ---- Restore the C streams ----
      if (old_stdout_fd_ >= 0)
      {
        ::dup2(old_stdout_fd_, fileno(stdout));
        ::close(old_stdout_fd_);
        old_stdout_fd_ = -1;
      }
      if (old_stderr_fd_ >= 0)
      {
        ::dup2(old_stderr_fd_, fileno(stderr));
        ::close(old_stderr_fd_);
        old_stderr_fd_ = -1;
      }

      // ---- Restore the C++ streams ----
      std::cout.rdbuf(old_cout_);
      std::cerr.rdbuf(old_cerr_);
      std::clog.rdbuf(old_clog_);

      file_.flush();
      file_.close();

      active_ = false;
    }

  private:
    std::string path_;
    std::ofstream file_;
    std::streambuf *old_cout_ = nullptr;
    std::streambuf *old_cerr_ = nullptr;
    std::streambuf *old_clog_ = nullptr;
    int old_stdout_fd_ = -1;
    int old_stderr_fd_ = -1;
    bool active_ = false;
  };

} // namespace

int main(int argc, char **argv)
{
  // Disable nonvital logs from mdbx.
  setenv("MDBX_LOG", "ERROR", 1);
  setenv("MDBX_DEBUG", "none", 1);
  mdbx_setup_debug(MDBX_LOG_ERROR, MDBX_DBG_NONE, nullptr);

  // Strip --log_file from argv before gtest parses it. gtest rejects
  // unknown flags.
  std::vector<char *> argv_vec(argc + 1);
  int filtered_argc = 0;
  std::string log_path = extractLogFile(argc, argv, filtered_argc, argv_vec.data());
  argv_vec[filtered_argc] = nullptr;

  // Create default log
  if (log_path.empty())
    log_path = "clarity_tests.log";

  testing::InitGoogleTest(&filtered_argc, argv_vec.data());

  // Register the redirect environment. gtest owns the pointer and
  // deletes it at shutdown.
  if (!log_path.empty())
  {
    ::testing::AddGlobalTestEnvironment(new OutputRedirectEnv(log_path));
  }

  return RUN_ALL_TESTS();
}