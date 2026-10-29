// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Args.h"
#include "Adapters/ChainAdapter.h"
#include "Http/HttpServer.h"
#include "Repl/Commands.h"
#include "Session/Session.h"
#include "Signals.h"
#include "Startup.h"
#include "Config.h"

#include "Core/Bridge/Bitcoin.h"

#include "Common/Repl.h"

#include "Crypto/Ed25519.h"
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

      //  Bitcoin no longer uses a static deposit address; its
      //  deposit addresses are derived per registration index.
      //  Skipping the parse for BTC avoids a spurious warning at
      //  startup (BitcoinAdapter::parse_deposit_address returns
      //  nullopt with a message that says exactly this).
      const bool is_btc =
          (adapter->source_chain_id() ==
           Core::BitcoinBridge::BTC_CHAIN_ID);
      if (!cfg.bridge_address.empty() && !is_btc)
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
  //  File format: a single 32-byte secret as 64 hex chars, optional
  //  0x prefix, whitespace trimmed. This is the value
  //  `conceal-wallet-rpc query_key --key-type view` returns, NOT
  //  the seed from get_seed or a mnemonic. The two are different
  //  byte sequences and only the reduced scalar works with
  //  Crypto::generateKeyDerivation (whose internal sc_check
  //  rejects a seed).
  //
  //  Rejecting a seed at load time is the whole point of this
  //  function's validation: a seed that got through would let the
  //  daemon start, connect to the chain, and then silently fail
  //  every deposit scan (generateKeyDerivation returns false for
  //  every tx, no deposits are detected, and the operator sees
  //  "no deposits" forever). Catching it here is the difference
  //  between a five-second fix and an afternoon of debugging.
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

    //  The 32 bytes must be a valid scalar mod the ed25519 group
    //  order — i.e. what `query_key` returns, not what `get_seed`
    //  returns. A seed is nearly always > ℓ and would be rejected
    //  by generateKeyDerivation, causing the scanner to silently
    //  detect zero deposits. Rejecting it here is loud and early.
    if (!Crypto::isValidScalar(key))
    {
      std::cerr << "error: --view-key-file: the value in '" << path
                << "' is not a valid CCX view key.\n"
                << "  The 32 bytes are not a canonical scalar mod the "
                   "ed25519 group order.\n"
                << "  You probably exported the *seed* (or a mnemonic-"
                   "derived value) instead of the view key.\n"
                << "  Run `conceal-wallet-rpc query_key --key-type view` "
                   "against the custody wallet to get the correct "
                   "32-byte scalar.\n";
      return false;
    }

    session.custody_view_key = key;
    std::cerr << "[startup] loaded custody_view_key from " << path << "\n";
    return true;
  }

  //  ---- HTTP API ----
  //
  //  Start the deposit-address HTTP server if it's enabled in
  //  the config. Returns nullptr if disabled or if the bind
  //  failed. A bind failure is non-fatal: the scan worker is the
  //  critical path; the HTTP API is for front ends, and an
  //  operator who can't bind can still run the bridge headless.
  std::unique_ptr<Bridge::HttpServer> startHttpApi(
      Bridge::WatcherSession &session,
      const Bridge::WatcherConfig &config)
  {
    if (config.deposit_api_port == 0)
    {
      std::cerr << "[startup] deposit-address API disabled "
                   "(deposit_api_port=0)\n";
      return nullptr;
    }

    auto server = std::make_unique<Bridge::HttpServer>(
        session,
        config.deposit_api_bind.empty()
            ? std::string("127.0.0.1")
            : config.deposit_api_bind,
        config.deposit_api_port);

    if (!server->start())
    {
      std::cerr << "[startup] deposit-address API unavailable "
                   "(bind failed); bridge continues without it\n";
      return nullptr;
    }

    return server;
  }

} // anonymous namespace

int main(int argc, char **argv)
{
  //  Populate the chain-adapter registry before anything touches
  //  it. This is what makes the static-init registrars in each
  //  adapter file reliable when the adapters are linked in from
  //  a static library. See ChainAdapterRegistry.cpp.
  Bridge::registerAllChainAdapters();

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

      //  ---- HTTP API ----
      //
      //  Start after `start` succeeds (custody is installed,
      //  signer is open, Clarity is reachable). The server must
      //  outlive the wait loop below; stop it before we close
      //  the keystore and return.
      auto http_api = startHttpApi(session, args.config);
      if (http_api)
      {
        std::cerr << "[startup] deposit-address API on http://"
                  << args.config.deposit_api_bind << ":"
                  << http_api->boundPort()
                  << "/bridge/deposit-address\n";
      }

      while (session.running && !Bridge::g_stop_requested)
      {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }

      //  ---- HTTP API shutdown ----
      if (http_api)
        http_api->stop();

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

  //  ---- HTTP API ----
  //
  //  Interactive mode. Start after keystore open, before the REPL
  //  loop. This means the API is available as soon as the operator
  //  can type into the REPL. `start btc` still has to be run before
  //  the API can answer (custody installs there), but the server
  //  itself is up immediately, so a front end can poll and get
  //  "custody not installed" instead of connection refused.
  auto http_api = startHttpApi(session, args.config);
  if (http_api)
  {
    std::cerr << "[startup] deposit-address API on http://"
              << args.config.deposit_api_bind << ":"
              << http_api->boundPort()
              << "/bridge/deposit-address\n";
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

  //  ---- HTTP API shutdown ----
  if (http_api)
    http_api->stop();

  Bridge::requestStopAllScans();

  Bridge::closeKeystore(session);

  std::cout << "\n";
  return 0;
}