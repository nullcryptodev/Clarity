// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

#include "WatcherConfig.h"

namespace Bridge
{
  struct Args
  {
    WatcherConfig config;

    //  Per-chain RPC overrides supplied on the CLI, before the
    //  wizard runs. Keyed by chain short_name. When a chain is
    //  enabled via --chain, the corresponding entry (if present)
    //  pre-populates its ChainWatcherConfig; if absent, the
    //  wizard prompts.
    std::vector<ChainWatcherConfig> cli_chain_configs;

    std::string log_level{"info"};
    std::string log_file;

    bool show_help{false};
    bool show_version{false};
    bool print_config{false};
    bool list_chains{false};

    //  Skip the interactive startup wizard. All required fields
    //  must be supplied on the command line: at minimum --keystore
    //  and one --chain, unless a read-only --command is also set,
    //  in which case neither is required.
    bool no_wizard{false};

    //  One-shot command to run instead of dropping into the REPL.
    //  Empty means "REPL" (the default). A non-empty value is
    //  validated at parse time against the command table, and
    //  dispatch happens in main() after setup.
    //
    //  `start` is the one long-running command: it enters a
    //  foreground loop and only returns on SIGINT/SIGTERM. All
    //  other commands run once and exit.
    //
    //  command_args holds any positional tokens that followed
    //  `--command <name>` on the command line. They are passed
    //  to the command's handler verbatim, in the same shape the
    //  REPL would produce.
    std::string command;
    std::vector<std::string> command_args;

    //  Path to a file containing the validator's consensus signing
    //  key (32 bytes as 64 hex chars). Used by SubmitAttestation to
    //  sign BridgeAttest transactions. Empty means "use the
    //  keystore's clrtyPath(0,0,0)" — only valid when the validator
    //  registered with that key.
    std::string consensus_key_file;

    //  Path to a file containing the custody wallet's 32-byte
    //  private view key (64 hex chars, optional 0x prefix, optional
    //  trailing newline). Required to identify which vout of a
    //  deposit pays to the custody address.
    std::optional<std::string> view_key_file;

    //  Custody wallet's 32-byte public spend key (64 hex chars).
    //  Not secret — it's part of the custody address — so it lives
    //  directly in config rather than a file.
    std::optional<std::string> custody_spend_pub;

    // todo remove
    std::string mint_destination;
  };

  Args parseArgs(int argc, char **argv);

  void printHelp(const char *argv0);
  void printVersion();
  void printConfig(const Args &args);

} // namespace Bridge