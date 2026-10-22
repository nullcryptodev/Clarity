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
    bool show_help{false};
    bool show_version{false};
    bool list_chains{false};
    bool print_config{false};

    std::string config_file;
    std::string log_level{"info"};
    std::string log_file;

    std::string command;
    std::vector<std::string> command_args;

    WatcherConfig config;

    //  Chains specified with --chain. The config-file chains
    //  (args.config.chains) are separate; enableChainsFromArgs
    //  merges both.
    std::vector<ChainWatcherConfig> cli_chain_configs;
  };

  Args parseArgs(int argc, char **argv);

  void printHelp(const char *argv0);
  void printVersion();
  void printConfig(const Args &args);

} // namespace Bridge