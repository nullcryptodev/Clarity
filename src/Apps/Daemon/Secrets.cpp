// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Secrets.h"

#include "Crypto/SecureZero.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace Daemon
{
  namespace
  {
    // Format an errno value into a human-readable suffix for an error
    // message. "No such file or directory" is far more useful to an
    // operator than "errno 2".
    std::string errnoString()
    {
      return std::strerror(errno);
    }
  } // anonymous namespace

  Crypto::SecretKey parseSecretKey(const std::string &hex)
  {
    if (hex.size() != 64)
    {
      throw std::runtime_error(
          "consensus key must be 64 hex characters (32 bytes), got " +
          std::to_string(hex.size()));
    }

    auto nib = [](char c) -> int
    {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return -1;
    };

    Crypto::SecretKey sk;
    for (size_t i = 0; i < 32; ++i)
    {
      int hi = nib(hex[i * 2]);
      int lo = nib(hex[i * 2 + 1]);
      if (hi < 0 || lo < 0)
      {
        // Name the offending character and its position. For a key
        // typed into a file, "index 17 is 'g'" is the difference
        // between a five-second fix and a five-minute one.
        const size_t bad_index = (hi < 0) ? (i * 2) : (i * 2 + 1);
        throw std::runtime_error(
            std::string("consensus key contains a non-hex character at "
                        "index ") +
            std::to_string(bad_index) + ": '" + hex[bad_index] + "'");
      }
      sk.data[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return sk;
  }

  Crypto::SecretKey loadConsensusKeyFile(const std::string &path)
  {
    // lstat, not stat: we want the link's own metadata so we can
    // detect a symlink, not the metadata of whatever it points at.
    struct stat st;
    if (::lstat(path.c_str(), &st) != 0)
    {
      throw std::runtime_error("consensus key file '" + path +
                               "' cannot be opened: " + errnoString());
    }

    if (S_ISLNK(st.st_mode))
    {
      throw std::runtime_error("consensus key file '" + path +
                               "' is a symlink; refusing to follow it");
    }

    if (!S_ISREG(st.st_mode))
    {
      throw std::runtime_error("consensus key file '" + path +
                               "' is not a regular file");
    }

    // Ownership: the daemon's effective uid, or root.
    const uid_t euid = ::geteuid();
    if (st.st_uid != euid && st.st_uid != 0)
    {
      throw std::runtime_error(
          "consensus key file '" + path + "' is owned by uid " +
          std::to_string(st.st_uid) +
          "; must be owned by the daemon user (uid " +
          std::to_string(euid) + ") or root");
    }

    // Permissions: no group or other access, read or write.
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0)
    {
      char mode_buf[8];
      std::snprintf(mode_buf, sizeof(mode_buf), "%04o",
                    static_cast<unsigned>(st.st_mode & 07777));
      throw std::runtime_error(
          "consensus key file '" + path + "' has mode " + mode_buf +
          "; must be 0600 or stricter (chmod 600 " + path + ")");
    }

    // Read the file. We cap the read at a generous but finite size so
    // a malicious or corrupt file cannot make us allocate arbitrarily
    // much memory before we reject it for being the wrong length.
    constexpr size_t kMaxBytes = 4096;
    if (st.st_size > static_cast<off_t>(kMaxBytes))
    {
      throw std::runtime_error("consensus key file '" + path +
                               "' is " + std::to_string(st.st_size) +
                               " bytes; expected at most " +
                               std::to_string(kMaxBytes));
    }

    std::string contents;
    contents.resize(static_cast<size_t>(st.st_size));

    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
      throw std::runtime_error("consensus key file '" + path +
                               "' cannot be read: " + errnoString());
    }
    if (!contents.empty())
    {
      in.read(&contents[0], static_cast<std::streamsize>(contents.size()));
      if (!in)
      {
        throw std::runtime_error("consensus key file '" + path +
                                 "' could not be read to the end");
      }
    }

    // Trim a single trailing newline (and a trailing CR, for files
    // that passed through Windows). Anything else -- leading
    // whitespace, embedded whitespace, multiple trailing newlines --
    // is left in place and will be rejected by parseSecretKey with a
    // clear message. We do not silently strip more than this, because
    // a key file with unexpected whitespace is more likely to be a
    // mistake than a formatting preference.
    if (!contents.empty() && contents.back() == '\n')
      contents.pop_back();
    if (!contents.empty() && contents.back() == '\r')
      contents.pop_back();

    Crypto::SecretKey sk;
    try
    {
      sk = parseSecretKey(contents);
    }
    catch (const std::exception &e)
    {
      // Zero the buffer before propagating: the contents may be
      // partially a key, and we don't want it lingering in a freed
      // std::string.
      Crypto::secureZero(contents.data(), contents.size());
      throw std::runtime_error("consensus key file '" + path +
                               "': " + e.what());
    }

    // Zero the raw contents now that the key has been copied into
    // the fixed-size SecretKey. This is the last place the key
    // material exists in a heap-allocated buffer.
    Crypto::secureZero(contents.data(), contents.size());

    return sk;
  }
} // namespace Daemon