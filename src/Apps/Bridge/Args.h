// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

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
  };

  Args parseArgs(int argc, char **argv);

  void printHelp(const char *argv0);
  void printVersion();
  void printConfig(const Args &args);

} // namespace Bridge