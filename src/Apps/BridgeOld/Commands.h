// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <vector>

#include "Session.h"

namespace Bridge
{
  // Command
  //
  // A single REPL command. Mirrors Wallet::Command in shape: the
  // handler takes the session (mutable — commands like open,
  // connect, use, start, stop change it) and the
  // tokenized arguments.
  //
  // Handlers print output directly. They do not return values;
  // they report errors inline and the session continues.

  using CommandHandler = void (*)(WatcherSession &session,
                                  const std::vector<std::string> &args);

  struct Command
  {
    const char *name;
    const char *usage;
    const char *help;
    CommandHandler handler;
  };

  // The full command table. Null-terminated by an entry with a
  // null name. Used by the dispatcher and by the help command.
  const Command *commandTable();

  // Look up a command by name. Returns nullptr if not found.
  const Command *findCommand(const std::string &name);

  // Tokenize a line into whitespace-separated tokens. Quoted
  // strings are not supported in v1. An empty line yields an
  // empty vector.
  std::vector<std::string> tokenizeCommand(const std::string &line);

  // Dispatch a tokenized command. Returns true if the command was
  // recognized and executed (regardless of whether it succeeded);
  // false if the command name was unknown. In the false case, an
  // "unknown command" message has already been printed.
  bool dispatchCommand(WatcherSession &session,
                       const std::vector<std::string> &tokens);

  // ---- Individual command handlers ----
  //
  // All of them are exported so a future non-interactive mode
  // (--command "status") can call them directly.

  void cmd_status(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_chains(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_use(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_enable(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_disable(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_deposits(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_withdrawals(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_pending(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_start(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_stop(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_rescan(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_state(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_connect(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_open(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_close(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_help(WatcherSession &session, const std::vector<std::string> &args);
  void cmd_exit(WatcherSession &session, const std::vector<std::string> &args);

  // ---- Scan lifecycle ----
  //
  // These are the process-wide handles the scan threads use. They
  // live here (not on WatcherSession) because the scan threads are
  // owned by the REPL process, not by any one session — the
  // process only ever has one session, so making the ownership
  // explicit doesn't lose anything and keeps WatcherSession a pure
  // data holder.
  //
  // requestStopAllScans is called from exit and from main() on
  // clean shutdown. It sets the per-runtime stop flags and joins
  // any threads still running.
  void requestStopAllScans();

} // namespace Bridge