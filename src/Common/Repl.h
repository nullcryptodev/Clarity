// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <optional>
#include <string>

namespace Common
{
  //  Repl
  //
  //  A thin wrapper over linenoise. Provides a prompt and a way to
  //  register history, and returns std::nullopt on EOF (Ctrl+D).
  //
  //  This exists so that multiple interactive tools can share the
  //  same input loop without duplicating the linenoise glue. The
  //  actual line-editing behavior is entirely linenoise's.
  //
  //  Thread safety: none. A Repl instance is meant to be used from
  //  one thread — the one that is running the interactive session.

  class Repl
  {
  public:
    Repl();
    ~Repl();

    Repl(const Repl &) = delete;
    Repl &operator=(const Repl &) = delete;

    //  Read one line with the given prompt. Returns std::nullopt on
    //  EOF (Ctrl+D) or a fatal read error. An empty string is a
    //  valid response — the user pressed Enter on an empty line.
    //
    //  The returned string has no trailing newline.
    std::optional<std::string> readLine(const std::string &prompt);

    //  Add a line to the in-session history. Called by the caller
    //  after a successful readLine, so history reflects the commands
    //  the user actually typed (and only those).
    void addHistory(const std::string &line);
  };

} // namespace Common