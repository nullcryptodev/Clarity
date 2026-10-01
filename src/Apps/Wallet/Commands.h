// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>
#include <vector>

#include "Session.h"

namespace Wallet
{
  //  Command
  //
  //  A single REPL command. The handler takes the session (mutable —
  //  commands like `open` and `connect` change it) and the tokenized
  //  arguments.
  //
  //  Handlers print output directly. They do not return values; they
  //  report errors inline and the session continues.

  using CommandHandler = void (*)(WalletSession &session,
                                  const std::vector<std::string> &args);

  struct Command
  {
    const char *name;
    const char *usage;
    const char *help;
    CommandHandler handler;
  };

  //  The full command table. Null-terminated by an entry with a null
  //  name. Used by the dispatcher and by the `help` command.
  const Command *commandTable();

  //  Look up a command by name. Returns nullptr if not found.
  const Command *findCommand(const std::string &name);

  //  Tokenize a line into whitespace-separated tokens. Quoted strings
  //  are not supported in v1. An empty line yields an empty vector.
  std::vector<std::string> tokenizeCommand(const std::string &line);

  //  Dispatch a tokenized command. Returns true if the command was
  //  recognized and executed (regardless of whether it succeeded);
  //  false if the command name was unknown. In the false case, an
  //  "unknown command" message has already been printed.
  bool dispatchCommand(WalletSession &session,
                       const std::vector<std::string> &tokens);

  //  ---- Individual command handlers ----
  //
  //  All of them are exported so that a future non-interactive mode
  //  (--command "balance") can call them directly.

  void cmd_balance(WalletSession &session, const std::vector<std::string> &args);
  void cmd_nonce(WalletSession &session, const std::vector<std::string> &args);
  void cmd_info(WalletSession &session, const std::vector<std::string> &args);
  void cmd_status(WalletSession &session, const std::vector<std::string> &args);
  void cmd_send(WalletSession &session, const std::vector<std::string> &args);
  void cmd_claim(WalletSession &session, const std::vector<std::string> &args);
  void cmd_stake(WalletSession &session, const std::vector<std::string> &args);
  void cmd_validator(WalletSession &session, const std::vector<std::string> &args);
  void cmd_open(WalletSession &session, const std::vector<std::string> &args);
  void cmd_close(WalletSession &session, const std::vector<std::string> &args);
  void cmd_connect(WalletSession &session, const std::vector<std::string> &args);
  void cmd_help(WalletSession &session, const std::vector<std::string> &args);
  void cmd_exit(WalletSession &session, const std::vector<std::string> &args);

} // namespace Wallet