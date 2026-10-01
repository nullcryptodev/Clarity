// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

#include "Session.h"

namespace Wallet
{
  //  StartupOptions
  //
  //  Inputs to the startup wizard. Every field is optional; the
  //  wizard prompts for anything that isn't provided.

  struct StartupOptions
  {
    //  If non-empty, the wizard skips keystore selection and
    //  confirmation, and goes straight to unlocking this path.
    std::string keystore_path;

    //  If non-empty, the wizard reads the password from this file
    //  instead of prompting.
    std::string password_file;

    //  If non-empty, the wizard uses this RPC endpoint spec. If the
    //  wizard can't connect to it, the user is still prompted.
    std::string rpc_spec;

    //  If true, the wizard runs in "non-interactive" mode: it uses
    //  whatever was provided and fails if anything is missing. Not
    //  used in v1, but reserved for a future --non-interactive flag.
    bool non_interactive{false};
  };

  //  Run the startup wizard. Populates the session with the RPC
  //  connection and, if the user chose one, an unlocked keystore.
  //
  //  Returns true on success. Returns false only if the user
  //  explicitly aborted the wizard (Ctrl+D at a prompt), in which
  //  case main() should exit with code 1.
  //
  //  All prompts are interactive. The wizard can be cancelled at any
  //  point by typing "cancel" or by sending EOF (Ctrl+D), which
  //  transitions to the REPL with whatever state exists at that
  //  point.
  bool runStartupWizard(WalletSession &session,
                        const StartupOptions &options);

} // namespace Wallet