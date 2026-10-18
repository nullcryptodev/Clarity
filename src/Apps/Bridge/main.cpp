// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Args.h"
#include "ChainAdapter.h"
#include "Commands.h"
#include "Startup.h"
#include "Session.h"

#include "Common/Repl.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

namespace
{
  // Print the compiled-in adapter list and exit. Called from
  // main() when --list-chains is on the command line, before the
  // wizard runs. The registry is populated at static-init time
  // by each adapter's translation unit (see CcxAdapter.cpp), so
  // this works before any session exists.
  void listChainsAndExit()
  {
    auto adapters = Bridge::ChainAdapterRegistry::all();
    if (adapters.empty())
    {
      std::cout << "No chain adapters compiled into this binary.\n";
      return;
    }
    for (const auto &a : adapters)
    {
      std::cout << a->short_name() << "\t" << a->name() << "\n";
    }
  }
} // anonymous namespace

int main(int argc, char **argv)
{
  // ---- Parse args ----
  //
  // parseArgs throws on malformed input; catch and report. Same
  // pattern as the daemon and wallet.
  Bridge::Args args;
  try
  {
    args = Bridge::parseArgs(argc, argv);
  }
  catch (const std::exception &e)
  {
    std::cerr << "error: " << e.what() << "\n";
    std::cerr << "Run with --help for usage.\n";
    return 1;
  }

  if (args.show_help)
  {
    Bridge::printHelp(argv[0]);
    return 0;
  }

  if (args.show_version)
  {
    Bridge::printVersion();
    return 0;
  }

  // --list-chains: print the compiled-in adapters and exit.
  // Handled here (not in the wizard) because it's a discovery
  // flag that should work even if nothing else is configured.
  if (args.list_chains)
  {
    listChainsAndExit();
    return 0;
  }

  if (args.print_config)
  {
    Bridge::printConfig(args);
    return 0;
  }

  // ---- Construct the session ----
  Bridge::WatcherSession session;

  // Default Clarity endpoint. The wizard may override; if --rpc-clarity
  // was on the CLI it's already in args.config, and stepConnectClarity
  // reads it from there.
  session.clarity_endpoint.host = args.config.clarity_rpc_host;
  session.clarity_endpoint.port = args.config.clarity_rpc_port;

  // ---- Run the startup wizard ----
  //
  // Returns false only on explicit user abort (Ctrl+D at a prompt,
  // or a fatal configuration error like an unreadable keystore
  // path). We exit 1 in that case, matching the wallet's behavior.
  try
  {
    if (!Bridge::runStartupWizard(session, args))
    {
      std::cerr << "Setup aborted.\n";
      return 1;
    }
  }
  catch (const std::exception &e)
  {
    std::cerr << "error: setup failed: " << e.what() << "\n";
    return 1;
  }

  // ---- REPL loop ----
  //
  // Common::Repl owns the line editor (linenoise). We call it for
  // each line, dispatch through Commands, and continue until the
  // session's running flag is cleared (by exit/quit, or by
  // EOF on stdin).
  Common::Repl repl;

  while (session.running)
  {
    auto line = repl.readLine("bridge> ");
    if (!line.has_value())
      break; // EOF (Ctrl+D)

    if (line->empty())
      continue;

    repl.addHistory(*line);

    auto tokens = Bridge::tokenizeCommand(*line);

    // dispatchCommand may throw if a command handler does
    // something unexpected (out-of-memory, filesystem error we
    // forgot to catch). We don't want a bug in one command to
    // take down the REPL, so we catch, print, and continue.
    try
    {
      Bridge::dispatchCommand(session, tokens);
    }
    catch (const std::exception &e)
    {
      std::cerr << "error: command failed: " << e.what() << "\n";
    }
  }

  // ---- Clean shutdown ----
  //
  // Stop any scan workers before closing the keystore. Order
  // matters: the scan worker holds a raw pointer to the session,
  // and shutting down the keystore while a scan thread is running
  // would race on session.signer/keystore fields.
  Bridge::requestStopAllScans();

  // Lock and release the keystore.
  Bridge::closeKeystore(session);

  std::cout << "\n";
  return 0;
}