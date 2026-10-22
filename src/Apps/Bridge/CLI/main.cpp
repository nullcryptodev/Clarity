// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Args.h"
#include "Adapters/ChainAdapter.h"
#include "Repl/Commands.h"
#include "Session/Session.h"
#include "Signals.h"
#include "Startup.h"
#include "Config.h"

#include "Common/Repl.h"

#include "Crypto/Types.h"
#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"

#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace
{
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

  bool probeClarity(Bridge::WatcherSession &session)
  {
    if (!session.clarity_rpc)
      return false;

    Common::Json params = Common::Json::object();
    auto result = session.clarity_rpc->call("chainId", params);
    return result.ok();
  }

  bool enableChainsFromArgs(Bridge::WatcherSession &session,
                            const Bridge::Args &args)
  {
    //  Chains come from two sources: args.cli_chain_configs (--
    //  chain flags) and args.config.chains (--config-file). Merge
    //  them. A chain that appears in both is a conflict — reject
    //  rather than guess which wins.
    std::vector<Bridge::ChainWatcherConfig> to_enable;

    for (const auto &c : args.config.chains)
      to_enable.push_back(c);

    for (const auto &c : args.cli_chain_configs)
    {
      bool found = false;
      for (const auto &existing : to_enable)
      {
        if (existing.chain_short_name == c.chain_short_name)
        {
          found = true;
          break;
        }
      }
      if (found)
      {
        std::cerr << "error: chain '" << c.chain_short_name
                  << "' specified both in --config-file and with --chain\n";
        return false;
      }
      to_enable.push_back(c);
    }

    if (to_enable.empty())
      return true;

    for (auto cfg : to_enable)
    {
      auto adapter =
          Bridge::ChainAdapterRegistry::find(cfg.chain_short_name);
      if (!adapter)
      {
        std::cerr << "error: adapter vanished for '"
                  << cfg.chain_short_name << "'\n";
        return false;
      }

      std::cerr << "[setup] enabling " << cfg.chain_short_name
                << " raw_json=" << (cfg.raw_json.is_object() ? cfg.raw_json.dump() : "(not object)")
                << "\n";

      Bridge::applyAdapterDefaults(*adapter, cfg);

      if (cfg.raw_json.is_object())
        adapter->set_transport_config(cfg.raw_json);

      //  Parse the deposit address into the adapter's
      //  deposit_script_ before probing. Without this, the first
      //  scan_deposits call throws "deposit script not set".
      if (!cfg.bridge_address.empty())
      {
        std::string parse_err;
        auto blob = adapter->parse_deposit_address(cfg.bridge_address, &parse_err);
        if (!blob.has_value())
        {
          std::cerr << "warning: " << cfg.chain_short_name
                    << ": deposit address '" << cfg.bridge_address
                    << "' could not be parsed: " << parse_err << "\n";
        }
        else
        {
          adapter->set_deposit_address(*blob);
          std::cerr << "[setup] " << cfg.chain_short_name
                    << " deposit address configured ("
                    << blob->size() << " bytes)\n";
        }
      }

      auto *rt = session.enableChain(adapter, cfg);
      if (!rt)
      {
        std::cerr << "error: enableChain failed for '"
                  << cfg.chain_short_name << "'\n";
        return false;
      }
      if (rt->last_source_height == 0 && cfg.start_height != 0)
        rt->last_source_height = cfg.start_height - 1;
      Bridge::probeChain(*rt);
    }

    if (session.current_chain.empty() && !session.chains.empty())
      session.current_chain = session.chains.begin()->first;

    return true;
  }

  bool loadConsensusKeyFromFile(
      Bridge::WatcherSession &session,
      const std::string &path)
  {
    std::ifstream f(path);
    if (!f.good())
    {
      std::cerr << "error: cannot open --consensus-key-file "
                << path << "\n";
      return false;
    }

    std::string hex;
    std::getline(f, hex);
    f.close();

    while (!hex.empty() &&
           std::isspace(static_cast<unsigned char>(hex.back())))
      hex.pop_back();
    size_t start = 0;
    while (start < hex.size() &&
           std::isspace(static_cast<unsigned char>(hex[start])))
      ++start;
    if (start > 0)
      hex = hex.substr(start);

    if (hex.size() >= 2 && hex[0] == '0' &&
        (hex[1] == 'x' || hex[1] == 'X'))
      hex = hex.substr(2);

    if (hex.size() != 64)
    {
      std::cerr << "error: --consensus-key-file: expected 64 hex chars, "
                << "got " << hex.size() << "\n";
      return false;
    }

    auto nib = [](char c) -> int
    {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return -1;
    };

    Crypto::SecretKey key{};
    for (size_t i = 0; i < 32; ++i)
    {
      const int hi = nib(hex[i * 2]);
      const int lo = nib(hex[i * 2 + 1]);
      if (hi < 0 || lo < 0)
      {
        std::cerr << "error: --consensus-key-file: contains non-hex "
                  << "character at position " << (i * 2) << "\n";
        return false;
      }
      key.data[i] = static_cast<uint8_t>((hi << 4) | lo);
    }

    session.consensus_key = key;
    std::cerr << "[startup] loaded consensus_key from " << path << "\n";
    return true;
  }

  //  Load the custody wallet's private view key from a file.
  //
  //  Same file format as --consensus-key-file: a single 32-byte
  //  secret as 64 hex chars, optional 0x prefix, whitespace
  //  trimmed. The key is not a signing key — it is the "watch-
  //  only" half of the custody wallet, used solely by the
  //  adapter to identify which vout of a scanned deposit pays to
  //  the custody address (via Crypto::generateKeyDerivation and
  //  Crypto::derivePublicKey).
  bool loadViewKeyFromFile(
      Bridge::WatcherSession &session,
      const std::string &path)
  {
    std::ifstream f(path);
    if (!f.good())
    {
      std::cerr << "error: cannot open --view-key-file "
                << path << "\n";
      return false;
    }

    std::string hex;
    std::getline(f, hex);
    f.close();

    while (!hex.empty() &&
           std::isspace(static_cast<unsigned char>(hex.back())))
      hex.pop_back();
    size_t start = 0;
    while (start < hex.size() &&
           std::isspace(static_cast<unsigned char>(hex[start])))
      ++start;
    if (start > 0)
      hex = hex.substr(start);

    if (hex.size() >= 2 && hex[0] == '0' &&
        (hex[1] == 'x' || hex[1] == 'X'))
      hex = hex.substr(2);

    if (hex.size() != 64)
    {
      std::cerr << "error: --view-key-file: expected 64 hex chars, "
                << "got " << hex.size() << "\n";
      return false;
    }

    auto nib = [](char c) -> int
    {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return -1;
    };

    Crypto::SecretKey key{};
    for (size_t i = 0; i < 32; ++i)
    {
      const int hi = nib(hex[i * 2]);
      const int lo = nib(hex[i * 2 + 1]);
      if (hi < 0 || lo < 0)
      {
        std::cerr << "error: --view-key-file: contains non-hex "
                  << "character at position " << (i * 2) << "\n";
        return false;
      }
      key.data[i] = static_cast<uint8_t>((hi << 4) | lo);
    }

    session.custody_view_key = key;
    std::cerr << "[startup] loaded custody_view_key from " << path << "\n";
    return true;
  }

  bool loadMintDestination(
      Bridge::WatcherSession &session,
      const std::string &address_bech32m)
  {
    if (address_bech32m.empty())
      return true;

    auto addr = Wallet::decodeAddress(
        address_bech32m, session.currentNetwork());
    if (!addr.has_value())
    {
      std::cerr << "error: --mint-destination: could not decode '"
                << address_bech32m
                << "' for the current network\n";
      return false;
    }
    session.mint_destination = *addr;
    std::cerr << "[startup] mint_destination set to "
              << address_bech32m << "\n";
    return true;
  }
} // anonymous namespace

int main(int argc, char **argv)
{
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

  Bridge::WatcherSession session;

  try
  {
    //  ---- Wizard vs manual ----
    //
    //  args.config.no_wizard is the single source of truth: it is
    //  set by the config file's "no_wizard": true and by the
    //  --no-wizard flag. There is no Args::no_wizard field, and
    //  there shouldn't be — the two sources of truth would drift.
    if (args.config.no_wizard)
    {
      session.clarity_endpoint.host = args.config.clarity_rpc_host;
      session.clarity_endpoint.port = args.config.clarity_rpc_port;
      session.clarity_endpoint.user = args.config.clarity_rpc_user;
      session.clarity_endpoint.password = args.config.clarity_rpc_password;
      session.clarity_rpc =
          std::make_unique<Wallet::RpcClient>(session.clarity_endpoint);

      session.clarity_connected = probeClarity(session);

      const bool read_only_command =
          !args.command.empty() && args.command != "start";
      if (!session.clarity_connected && !read_only_command)
      {
        std::cerr << "error: could not reach Clarity RPC at "
                  << session.clarity_endpoint.host << ":"
                  << session.clarity_endpoint.port << "\n";
        return 1;
      }

      if (!read_only_command || !args.cli_chain_configs.empty() ||
          !args.config.chains.empty())
      {
        if (!enableChainsFromArgs(session, args))
          return 1;
      }

      if (!read_only_command || session.hasKeystore() ||
          !session.chains.empty())
      {
        args.config.state_dir =
            Bridge::expandHome(args.config.state_dir);
        if (!Bridge::ensureStateRoot(args.config.state_dir))
          return 1;
        for (auto &c : args.config.chains)
          c.state_subdir = c.chain_short_name;
        if (!Bridge::ensureChainStateDirs(args.config))
          return 1;
      }

      if (!args.config.keystore_path.empty())
      {
        if (!Bridge::openKeystore(session,
                                  args.config.keystore_path,
                                  args.config.password_file))
        {
          return 1;
        }
      }

      if (!args.config.consensus_key_file.empty())
      {
        if (!loadConsensusKeyFromFile(session, args.config.consensus_key_file))
          return 1;
      }

      if (!args.config.view_key_file.empty())
      {
        if (!loadViewKeyFromFile(session, args.config.view_key_file))
          return 1;
      }

      if (!loadMintDestination(session, args.config.mint_destination))
        return 1;
    }
    else
    {
      if (!Bridge::runStartupWizard(session, args))
      {
        std::cerr << "Setup aborted.\n";
        return 1;
      }

      if (!args.config.consensus_key_file.empty() &&
          !session.consensus_key.has_value())
      {
        if (!loadConsensusKeyFromFile(session, args.config.consensus_key_file))
          return 1;
      }

      if (!args.config.view_key_file.empty() &&
          !session.custody_view_key.has_value())
      {
        if (!loadViewKeyFromFile(session, args.config.view_key_file))
          return 1;
      }

      if (!loadMintDestination(session, args.config.mint_destination))
        return 1;
    }
  }
  catch (const std::exception &e)
  {
    std::cerr << "error: setup failed: " << e.what() << "\n";
    return 1;
  }

  if (!args.command.empty())
  {
    std::vector<std::string> tokens;
    tokens.reserve(1 + args.command_args.size());
    tokens.push_back(args.command);
    for (const auto &x : args.command_args)
      tokens.push_back(x);

    if (args.command == "start")
    {
      Bridge::installStopSignalHandlers();

      try
      {
        Bridge::dispatchCommand(session, tokens);
      }
      catch (const std::exception &e)
      {
        std::cerr << "error: start failed: " << e.what() << "\n";
        Bridge::requestStopAllScans();
        Bridge::closeKeystore(session);
        return 1;
      }

      while (session.running && !Bridge::g_stop_requested)
      {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }

      Bridge::requestStopAllScans();
      Bridge::closeKeystore(session);
      return 0;
    }

    int exit_code = 0;
    try
    {
      Bridge::dispatchCommand(session, tokens);
    }
    catch (const std::exception &e)
    {
      std::cerr << "error: " << args.command << " failed: "
                << e.what() << "\n";
      exit_code = 1;
    }

    Bridge::requestStopAllScans();
    Bridge::closeKeystore(session);
    return exit_code;
  }

  Common::Repl repl;

  while (session.running)
  {
    auto line = repl.readLine("bridge> ");
    if (!line.has_value())
      break;

    if (line->empty())
      continue;

    repl.addHistory(*line);

    auto tokens = Bridge::tokenizeCommand(*line);

    try
    {
      Bridge::dispatchCommand(session, tokens);
    }
    catch (const std::exception &e)
    {
      std::cerr << "error: command failed: " << e.what() << "\n";
    }
  }

  Bridge::requestStopAllScans();

  Bridge::closeKeystore(session);

  std::cout << "\n";
  return 0;
}