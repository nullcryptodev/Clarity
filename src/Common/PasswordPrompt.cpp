// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PasswordPrompt.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>

#if defined(__unix__) || defined(__APPLE__)
#include <termios.h>
#include <unistd.h>
#endif

namespace Apps
{

  std::optional<std::string> readLineNoEcho(const char *prompt)
  {
    std::fputs(prompt, stderr);
    std::fflush(stderr);

    std::string line;

#if defined(__unix__) || defined(__APPLE__)
    if (::isatty(::fileno(stdin)))
    {
      termios oldt{};
      if (::tcgetattr(::fileno(stdin), &oldt) != 0)
      {
        // Not a tty after all, or the ioctl failed; fall through to
        // a normal read below.
      }
      else
      {
        termios newt = oldt;
        newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(::fileno(stdin), TCSANOW, &newt);

        if (!std::getline(std::cin, line))
        {
          ::tcsetattr(::fileno(stdin), TCSANOW, &oldt);
          std::fputs("\n", stderr);
          return std::nullopt;
        }

        ::tcsetattr(::fileno(stdin), TCSANOW, &oldt);
        std::fputs("\n", stderr);
        return line;
      }
    }
#endif

    if (!std::getline(std::cin, line))
      return std::nullopt;
    return line;
  }

  std::optional<std::string> promptForPassword(const char *prompt)
  {
    return readLineNoEcho(prompt);
  }

  namespace
  {
    //  Trim trailing whitespace (space, tab, CR, LF). We do NOT
    //  trim leading whitespace — a password could legitimately
    //  begin with a space, and file writers shouldn't add leading
    //  whitespace anyway.
    std::string trimTrailing(std::string s)
    {
      while (!s.empty())
      {
        const char c = s.back();
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
          s.pop_back();
        else
          break;
      }
      return s;
    }

    std::optional<std::string> readFromStream(std::istream &in)
    {
      std::ostringstream buf;
      buf << in.rdbuf();
      if (in.bad())
        return std::nullopt;
      return trimTrailing(buf.str());
    }
  } // anonymous namespace

  std::optional<std::string> readPasswordFile(const std::string &path)
  {
    //  Special case: "-" means stdin.
    if (path == "-")
    {
      return readFromStream(std::cin);
    }

    std::ifstream in(path, std::ios::binary);
    if (!in)
      return std::nullopt;

    return readFromStream(in);
  }

} // namespace Apps