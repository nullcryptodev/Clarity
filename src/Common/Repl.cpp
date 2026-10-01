// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Repl.h"

#include <cstdlib>

extern "C"
{
#include "linenoise.h"
}

namespace Common
{

  //  linenoise ships in several variants. Some declare
  //  `linenoiseFree` and `linenoiseHistoryFree`; older versions use
  //  plain `free` and leak the history at process exit. Rather than
  //  requiring a specific version, this file uses the small helpers
  //  below. If you upgrade to a version with different symbol names,
  //  the only place that needs changing is here.

  namespace
  {
    //  Free a line returned by linenoise().
    void freeLine(char *p) noexcept
    {
      if (p == nullptr)
        return;
      //  Some versions of linenoise allocate the line with malloc
      //  and expect `free`. Others expose linenoiseFree. If the
      //  latter is declared, use it; otherwise fall through to free.
#if defined(__has_include)
      //  No direct feature test for the symbol; assume free works.
      //  If linenoiseFree is declared by the header, it's the more
      //  correct call. We can't detect that at compile time, so we
      //  always use free here. See the comment in the file header.
#endif
      std::free(p);
    }
  } // anonymous namespace

  Repl::Repl()
  {
    //  linenoise doesn't need explicit initialization. If stdin is
    //  not a tty, it falls back to a plain line read internally.
  }

  Repl::~Repl()
  {
    //  Nothing to do. We do not call linenoiseHistoryFree because
    //  some versions of linenoise don't declare it. The history is
    //  a process-global buffer that is released by the OS at exit;
    //  not freeing it is harmless.
  }

  std::optional<std::string> Repl::readLine(const std::string &prompt)
  {
    char *line = linenoise(prompt.c_str());
    if (line == nullptr)
      return std::nullopt;

    std::string result(line);
    freeLine(line);
    return result;
  }

  void Repl::addHistory(const std::string &line)
  {
    if (!line.empty())
      linenoiseHistoryAdd(line.c_str());
  }

} // namespace Common