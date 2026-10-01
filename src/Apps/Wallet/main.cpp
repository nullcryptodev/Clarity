// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Common/Repl.h"

#include "Commands.h"
#include "Session.h"
#include "Startup.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

namespace
{
  void printUsage(const char *argv0)
  {
    std::cout
        << "Usage: " << argv0 << " [options]\n"
        << "\n"
        << "Options:\n"
        << "  --keystore <path>       Open and unlock this keystore at startup\n"
        << "  --password-file <path>  Read the keystore password from a file\n"
        << "                          (default: prompt interactively)\n"
        << "  --rpc <host:port>       RPC endpoint (default: 127.0.0.1:9633)\n"
        << "  -h, --help              Show this help\n"
        << "\n"
        << "If no --keystore is given, an interactive setup runs at startup:\n"
        << "connect to RPC, find a keystore, confirm details, and unlock.\n"
        << "Once running, type 'help' at the prompt for a list of commands.\n";
  }

  struct StartupArgs
  {
    Wallet::StartupOptions startup;
    bool show_help{false};
  };

  bool parseStartupArgs(int argc, char **argv, StartupArgs &out)
  {
    for (int i = 1; i < argc; ++i)
    {
      const std::string arg = argv[i];

      auto next = [&]() -> std::string
      {
        if (i + 1 >= argc)
        {
          std::cerr << "error: missing value for " << arg << "\n";
          std::exit(1);
        }
        return argv[++i];
      };

      if (arg == "-h" || arg == "--help")
      {
        out.show_help = true;
        return true;
      }
      if (arg == "--keystore")
      {
        out.startup.keystore_path = next();
        continue;
      }
      if (arg == "--password-file")
      {
        out.startup.password_file = next();
        continue;
      }
      if (arg == "--password")
      {
        std::cerr << "error: --password is not accepted; use "
                     "--password-file or let the wallet prompt\n";
        return false;
      }
      if (arg == "--rpc")
      {
        out.startup.rpc_spec = next();
        continue;
      }

      std::cerr << "error: unknown argument '" << arg << "'\n";
      return false;
    }
    return true;
  }
} // anonymous namespace

int main(int argc, char **argv)
{
  StartupArgs args;
  if (!parseStartupArgs(argc, argv, args))
    return 1;

  if (args.show_help)
  {
    printUsage(argv[0]);
    return 0;
  }

  Wallet::WalletSession session;

  //  Default endpoint, overridden by --rpc in the wizard.
  session.rpc_endpoint.host = "127.0.0.1";
  session.rpc_endpoint.port = 9633;
  session.rpc = std::make_unique<Wallet::RpcClient>(session.rpc_endpoint);

  //  Run the startup wizard.
  if (!Wallet::runStartupWizard(session, args.startup))
  {
    std::cerr << "Setup aborted.\n";
    return 1;
  }

  //  REPL loop.
  Common::Repl repl;
  while (session.running)
  {
    auto line = repl.readLine("clrty> ");
    if (!line.has_value())
      break; // EOF / Ctrl+D

    if (line->empty())
      continue;

    repl.addHistory(*line);

    auto tokens = Wallet::tokenizeCommand(*line);
    Wallet::dispatchCommand(session, tokens);
  }

  //  Clean exit: lock and release the keystore.
  Wallet::closeKeystore(session);

  std::cout << "\n";
  return 0;
}