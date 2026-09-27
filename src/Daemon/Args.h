// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <string>

#include "Node/NodeConfig.h"
#include "RPC/Config.h"

namespace Daemon
{
  //  Args
  //
  //  Parsed command-line arguments. Populates a NodeConfig plus an
  //  RpcConfig plus a few daemon-only fields (log level, log file).

  struct Args
  {
    // Node configuration (built from flags).
    Node::NodeConfig node;

    // RPC configuration (built from flags).
    Rpc::RpcConfig rpc;

    // Daemon-only options.
    std::string log_level{"info"}; // trace|debug|info|warn|error
    std::string log_file;          // empty = stderr only
    bool show_help{false};
    bool show_version{false};
    bool print_config{false};
  };

  Args parseArgs(int argc, char **argv);

  void printHelp(const char *argv0);

  void printVersion();

  void printConfig(const Args &args);

} // namespace Daemon