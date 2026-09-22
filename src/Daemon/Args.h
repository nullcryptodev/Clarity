// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

#include "Node/NodeConfig.h"

namespace Daemon
{
  //  Args
  //
  //  Parsed command-line arguments. Populates a NodeConfig plus a few
  //  daemon-only fields (log level, log file).

  struct Args
  {
    // Node configuration (built from flags).
    Node::NodeConfig node;

    // Daemon-only options.
    std::string log_level{"info"}; // trace|debug|info|warn|error
    std::string log_file;          // empty = stderr only
    bool show_help{false};
    bool show_version{false};
    bool print_config{false}; // print resolved config and exit
  };

  // Parse argv into Args. Throws std::runtime_error on bad input.
  // On --help or --version, sets the corresponding flag and returns.
  Args parseArgs(int argc, char **argv);

  // Print help text to stdout.
  void printHelp(const char *argv0);

  // Print version to stdout.
  void printVersion();

  // Pretty-print the resolved config (for --print-config).
  void printConfig(const Args &args);

} // namespace Daemon