// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Repl/Commands.h"

#include "Adapters/ChainAdapter.h"
#include "Adapters/Conceal/ConcealCCX.h"
#include "Adapters/Bitcoin/BitcoinAdapter.h"
#include "Release/ReleaseTracker.h"
#include "Release/Submission.h"
#include "Scan/ScanRegistry.h"
#include "Session/Session.h"

#include "Core/BridgeTypes.h"
#include "Core/Bridge/ConcealCCX.h"

#include "Common/StringTools.h"

#include "Crypto/Helpers.h"
#include "Crypto/Ed25519.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletError.h"
#include "Wallet/TransactionBuilder.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>

namespace Bridge
{
  inline constexpr uint64_t BTC_CHAIN_ID = 0x42544331ULL;

  //  ---- Scan lifecycle forwarder ----
  //
  //  The scan registry lives in Scan/ScanRegistry.cpp and owns the
  //  process-wide thread map. This forwarder keeps the public
  //  name Bridge::requestStopAllScans() (declared in Commands.h)
  //  stable for main.cpp's call sites, so the REPL module is the
  //  only thing main.cpp needs to know about. The actual
  //  startScan/stopScan/requestStopAllScans implementation is in
  //  Scan/.

  void requestStopAllScans()
  {
    Scan::requestStopAllScans();
  }

  namespace
  {
    const Command kCommands[] = {
        {"status", "status",
         "Show all enabled chains, their endpoints, current heights,\n"
         "pending deposit/withdrawal counts, and whether the scan\n"
         "worker is running.",
         cmd_status},

        {"chains", "chains",
         "List every chain adapter compiled into this binary, with\n"
         "whether it is enabled in this session.",
         cmd_chains},

        {"use", "use <chain>",
         "Select the chain that subsequent single-chain commands act\n"
         "on. Use 'chains' to see short names.",
         cmd_use},

        {"enable", "enable <chain>",
         "Enable a chain adapter for this session. By default uses\n"
         "the adapter's defaults; use --rpc and --confirmation-depth\n"
         "to override.",
         cmd_enable},

        {"disable", "disable <chain>",
         "Stop and disable a chain. Its state directory is preserved.\n"
         "Refuses if this is the last enabled chain.",
         cmd_disable},

        {"deposits", "deposits [--limit N]",
         "Scan the current chain from the last processed height to the\n"
         "tip, printing any deposits found. Does not submit mints —\n"
         "that is the signing service's job.",
         cmd_deposits},

        {"withdrawals", "withdrawals",
         "List pending withdrawals on Clarity for the current chain,\n"
         "showing each withdrawal's phase in the ack/release pipeline:\n"
         "Observed, Acking, Acked, Releasable, Releasing, Released,\n"
         "or Done.",
         cmd_withdrawals},

        {"pending", "pending",
         "Show the pending deposit and withdrawal counters for the\n"
         "current chain.",
         cmd_pending},

        {"start", "start [<chain>] [--bridge-address <addr>] "
                  "[--consensus-key <hex> | --consensus-key-file <path>]",
         "Start the scan worker for a chain (the current chain if no\n"
         "argument).\n"
         "--bridge-address is the CCX address that deposits must pay\n"
         "to. It is required for the CCX adapter to scan; without it\n"
         "scan_deposits throws on the first poll. The address is a\n"
         "base58 CCX address.\n"
         "--consensus-key / --consensus-key-file provide the 32-byte\n"
         "consensus key that signs deposit attestations. It is\n"
         "distinct from the account key in the keystore. If neither\n"
         "is passed on the start command, a key loaded at process\n"
         "startup (from --consensus-key-file on the main command\n"
         "line) is used.\n"
         "\n"
         "The destination a deposit mints to is a property of the\n"
         "deposit itself, not of this command: on Bitcoin it is the\n"
         "32-byte OP_RETURN output the depositor included in the\n"
         "deposit transaction; on CCX it is the subaddress\n"
         "registration the depositor submitted on Clarity. There is\n"
         "deliberately no --mint-destination flag.",
         cmd_start},

        {"address", "address <index>",
         "Show the deposit address for a registration index on the\n"
         "current chain. Read-only; no state is changed.\n"
         "\n"
         "The index is the one `register-deposit` assigned. Look it\n"
         "up with getBridgeDepositsForAuthority if you don't have it.\n"
         "For Bitcoin this returns a bech32 (bc1q...) address; for\n"
         "chains whose deposits don't have a per-registration address,\n"
         "it errors.\n"
         "\n"
         "The wallet calls this via the getBridgeDepositAddress RPC;\n"
         "the REPL form exists for operator checks and debugging.",
         cmd_address},

        {"register-deposit",
         "register-deposit <chain> <rclrty-address>",
         "Register a deposit destination for a bridge source chain.\n"
         "The executor assigns an index from a per-chain counter; that\n"
         "index identifies the address you deposit to.\n"
         "\n"
         "For Bitcoin: the index becomes a bech32 deposit address\n"
         "(bc1q...) derived from the bridge's custody xpub. After the\n"
         "registration tx confirms, ask the bridge for the address\n"
         "with `address <index>`, or call the getBridgeDepositAddress\n"
         "RPC. Send any normal Bitcoin transaction to that address.\n"
         "\n"
         "For CCX: the index becomes a subaddress derived by the\n"
         "scanner. Query it with getBridgeDepositsForAuthority after\n"
         "the tx confirms.\n"
         "\n"
         "Either way: one registration, one destination, one address.\n"
         "No OP_RETURN, no raw script construction.",
         cmd_register_deposit},

        {"register-chain",
         "register-chain <chain> [--collect <idx>:0x<sig>] "
         "[--submit] [--token-id <n>]",
         "Register a chain on Clarity. One-time setup per chain.\n"
         "\n"
         "  register-chain btc                build the blob, sign locally\n"
         "  register-chain btc --collect 1:0x...   add a peer's signature\n"
         "  register-chain btc --submit       submit once quorum is met\n"
         "\n"
         "Files are written to <state_dir>/register/<chain>.json.\n"
         "After the tx confirms, deposits for that chain are\n"
         "attested automatically on the next scan poll.",
         cmd_register_chain},

        {"stop", "stop [<chain>]",
         "Stop the scan worker for a chain. Does not disable the\n"
         "chain or affect pending deposits.",
         cmd_stop},

        {"rescan", "rescan [--from <height>]",
         "Reset the current chain's cursor and re-scan from the given\n"
         "height (or genesis). Does not submit mints. Use with care on\n"
         "a chain that has already processed millions of blocks.",
         cmd_rescan},

        {"state", "state [watcher|keystore|chains]",
         "Show the session's state: validator id and keystore (default),\n"
         "or the per-chain cursors and counters.",
         cmd_state},

        {"connect", "connect <chain> <host:port>",
         "Change the source-chain RPC endpoint for a chain. Re-probes\n"
         "the endpoint after connecting. Does not reset the cursor.",
         cmd_connect},

        {"open", "open <path> [--password-file <path>]",
         "Open and unlock a keystore. Only one keystore may be open\n"
         "per session; the same keystore is used across all chains.",
         cmd_open},

        {"close", "close",
         "Lock and close the currently-open keystore.",
         cmd_close},

        {"help", "help [command]",
         "Show help. With no argument, lists all commands.",
         cmd_help},

        {"exit", "exit",
         "Exit the bridge app. Stops all scan workers cleanly.",
         cmd_exit},

        {"quit", "quit",
         "Exit the bridge app.",
         cmd_exit},

        {nullptr, nullptr, nullptr, nullptr},
    };
  } // anonymous namespace

  const Command *commandTable() { return kCommands; }

  const Command *findCommand(const std::string &name)
  {
    for (const Command *c = kCommands; c->name != nullptr; ++c)
    {
      if (name == c->name)
        return c;
    }
    return nullptr;
  }

  std::vector<std::string> tokenizeCommand(const std::string &line)
  {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok)
      tokens.push_back(std::move(tok));
    return tokens;
  }

  bool dispatchCommand(WatcherSession &session,
                       const std::vector<std::string> &tokens)
  {
    if (tokens.empty())
      return true;

    const Command *cmd = findCommand(tokens[0]);
    if (cmd == nullptr)
    {
      std::cerr << "error: unknown command '" << tokens[0] << "'\n";
      std::cerr << "Type 'help' for a list of commands.\n";
      return false;
    }

    cmd->handler(session, tokens);
    return true;
  }

  namespace
  {
    std::optional<uint64_t> parseU64(const std::string &s)
    {
      if (s.empty())
        return std::nullopt;
      errno = 0;
      char *end = nullptr;
      const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
      if (errno != 0 || end == s.c_str() || *end != '\0')
        return std::nullopt;
      return static_cast<uint64_t>(v);
    }

    bool parseEndpointSpec(const std::string &spec,
                           std::string &host_out,
                           uint16_t &port_out)
    {
      const size_t colon = spec.find(':');
      if (colon == std::string::npos || colon == 0 ||
          colon + 1 >= spec.size())
        return false;

      const std::string host = spec.substr(0, colon);
      const std::string port_str = spec.substr(colon + 1);

      char *end = nullptr;
      const unsigned long port = std::strtoul(port_str.c_str(), &end, 10);
      if (end == port_str.c_str() || *end != '\0' ||
          port == 0 || port > 65535)
        return false;

      host_out = host;
      port_out = static_cast<uint16_t>(port);
      return true;
    }

    ChainRuntime *requireCurrent(WatcherSession &session,
                                 const char *command)
    {
      if (session.current_chain.empty())
      {
        std::cerr << "error: no chain selected. Use 'use <chain>' first.\n";
        std::cerr << " (see 'chains' for the available short names)\n";
        (void)command;
        return nullptr;
      }
      ChainRuntime *rt = session.current();
      if (!rt)
      {
        std::cerr << "error: current chain '" << session.current_chain
                  << "' is not enabled\n";
        return nullptr;
      }
      if (!rt->connected)
      {
        std::cerr << "warning: chain '" << session.current_chain
                  << "' is not reachable at "
                  << rt->config.rpc_host << ":" << rt->config.rpc_port
                  << "\n";
        std::cerr << " try 'connect " << session.current_chain
                  << " <host:port>' or check the daemon\n";
      }
      return rt;
    }

    std::string formatAmountWithDecimals(uint64_t atomic, uint8_t decimals)
    {
      if (decimals == 0)
        return std::to_string(atomic);
      uint64_t divisor = 1;
      for (uint8_t i = 0; i < decimals; ++i)
        divisor *= 10;
      const uint64_t whole = atomic / divisor;
      const uint64_t frac = atomic % divisor;
      if (frac == 0)
        return std::to_string(whole);
      std::string frac_str = std::to_string(frac);
      while (frac_str.size() < decimals)
        frac_str.insert(frac_str.begin(), '0');
      return std::to_string(whole) + "." + frac_str;
    }

    std::string formatHashShort(const Crypto::Hash &h)
    {
      static const char HEX[] = "0123456789abcdef";
      std::string out = "0x";
      for (int i = 0; i < 8; ++i)
      {
        out.push_back(HEX[h.data[i] >> 4]);
        out.push_back(HEX[h.data[i] & 0xF]);
      }
      return out + "...";
    }

    std::string formatDuration(int64_t seconds)
    {
      if (seconds <= 0)
        return "0s";
      const int64_t hours = seconds / 3600;
      const int64_t minutes = (seconds % 3600) / 60;
      const int64_t secs = seconds % 60;
      std::ostringstream oss;
      if (hours > 0)
        oss << hours << "h " << minutes << "m";
      else if (minutes > 0)
        oss << minutes << "m " << secs << "s";
      else
        oss << secs << "s";
      return oss.str();
    }

    std::string displayName(const ChainRuntime &rt)
    {
      if (rt.adapter)
        return rt.adapter->name() + " (" + rt.adapter->short_name() + ")";
      return rt.config.chain_short_name;
    }
  } // anonymous namespace

  void cmd_status(WatcherSession &session,
                  const std::vector<std::string> &args)
  {
    (void)args;

    std::cout << "Bridge status\n";
    std::cout << "=============\n\n";

    std::cout << "Clarity node: ";
    if (session.clarity_connected)
    {
      std::cout << session.clarity_endpoint.host << ":"
                << session.clarity_endpoint.port
                << " [connected]\n";
    }
    else
    {
      std::cout << session.clarity_endpoint.host << ":"
                << session.clarity_endpoint.port
                << " [offline]\n";
    }

    if (session.hasKeystore())
    {
      std::cout << "Keystore: " << session.address_bech32m << "\n";
      if (session.validator_id != 0)
        std::cout << "Validator id: " << session.validator_id << "\n";
      else
        std::cout << "Validator id: (unresolved)\n";
    }
    else
    {
      std::cout << "Keystore: (none)\n";
    }

    std::cout << "\nChains:\n";
    if (session.chains.empty())
    {
      std::cout << " (none enabled)\n";
      return;
    }

    std::vector<std::string> names;
    names.reserve(session.chains.size());
    for (const auto &[name, rt] : session.chains)
    {
      if (rt.enabled)
        names.push_back(name);
    }
    std::sort(names.begin(), names.end());

    for (const auto &n : names)
    {
      const auto &rt = session.chains.at(n);
      const bool is_current = (n == session.current_chain);

      std::cout << "\n " << (is_current ? "* " : " ")
                << n << " — " << displayName(rt) << "\n";
      std::cout << " rpc: " << rt.config.rpc_host
                << ":" << rt.config.rpc_port
                << (rt.connected ? " [reachable]" : " [not reachable]")
                << "\n";
      std::cout << " confirmations: " << rt.config.confirmation_depth
                << "\n";

      std::cout << " bridge address: ";
      if (rt.bridge_deposit_address.empty())
        std::cout << "(not configured)\n";
      else
        std::cout << rt.bridge_deposit_address << "\n";

      std::cout << " wallet rpc: ";
      if (rt.config.wallet_rpc_host.empty() ||
          rt.config.wallet_rpc_port == 0)
      {
        std::cout << "(not configured — releases disabled)\n";
      }
      else
      {
        std::cout << rt.config.wallet_rpc_host << ":"
                  << rt.config.wallet_rpc_port << "\n";
      }

      std::cout << " burn finality: " << rt.config.burn_finality_depth
                << " blocks\n";

      std::cout << " cursor: source_height="
                << rt.last_source_height
                << " clarity_height=" << rt.last_clarity_height
                << "\n";
      std::cout << " pending: deposits="
                << rt.pending_deposits
                << " withdrawals=" << rt.pending_withdrawals
                << "\n";

      if (rt.running)
      {
        const int64_t elapsed =
            rt.started_at > 0
                ? static_cast<int64_t>(std::time(nullptr)) - rt.started_at
                : 0;
        std::cout << " status: running";
        if (elapsed > 0)
          std::cout << " (for " << formatDuration(elapsed) << ")";
        std::cout << "\n";
      }
      else
      {
        std::cout << " status: stopped\n";
      }

      std::cout << " state dir: " << rt.config.state_subdir
                << "\n";
    }
  }

  void cmd_chains(WatcherSession &session,
                  const std::vector<std::string> &args)
  {
    (void)args;

    auto adapters = ChainAdapterRegistry::all();
    if (adapters.empty())
    {
      std::cout << "No chain adapters compiled into this binary.\n";
      return;
    }

    std::cout << "Available chain adapters:\n\n";
    for (const auto &adapter : adapters)
    {
      const std::string name = adapter->short_name();
      const auto it = session.chains.find(name);
      const bool enabled = (it != session.chains.end() && it->second.enabled);
      const bool is_current = (name == session.current_chain);

      std::cout << " " << (is_current ? "* " : " ")
                << name << " — " << adapter->name()
                << (enabled ? " [enabled]" : "")
                << "\n";
      std::cout << " default rpc: " << adapter->default_rpc_endpoint()
                << "\n";
      std::cout << " default conf: "
                << adapter->default_confirmation_depth() << "\n";
      if (enabled)
      {
        const auto &rt = it->second;
        std::cout << " current rpc: " << rt.config.rpc_host
                  << ":" << rt.config.rpc_port
                  << (rt.connected ? " [reachable]"
                                   : " [not reachable]")
                  << "\n";
        std::cout << " status: "
                  << (rt.running ? "running" : "stopped") << "\n";
      }
    }
  }

  void cmd_use(WatcherSession &session,
               const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      if (session.current_chain.empty())
      {
        std::cout << "no chain selected\n";
      }
      else
      {
        std::cout << "current: " << session.current_chain << "\n";
      }
      return;
    }

    const std::string &name = args[1];
    if (!session.selectChain(name))
    {
      std::cerr << "error: cannot select '" << name << "'\n";
      std::cerr << " 'chains' shows which are enabled.\n";
      return;
    }
    std::cout << "Current chain: " << name << "\n";
  }

  void cmd_enable(WatcherSession &session,
                  const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: enable <chain> [--rpc <host:port>] "
                   "[--confirmation-depth N]\n";
      return;
    }

    const std::string &name = args[1];

    auto adapter = ChainAdapterRegistry::find(name);
    if (!adapter)
    {
      std::cerr << "error: unknown chain '" << name << "'\n";
      std::cerr << " 'chains' shows the available adapters.\n";
      return;
    }

    ChainWatcherConfig cfg;
    cfg.chain_short_name = name;
    cfg.enabled = true;
    applyAdapterDefaults(*adapter, cfg);

    for (size_t i = 2; i < args.size(); ++i)
    {
      if (args[i] == "--rpc" && i + 1 < args.size())
      {
        std::string host;
        uint16_t port = 0;
        if (!parseEndpointSpec(args[++i], host, port))
        {
          std::cerr << "error: --rpc: invalid host:port\n";
          return;
        }
        cfg.rpc_host = host;
        cfg.rpc_port = port;
      }
      else if (args[i] == "--confirmation-depth" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value() || *v == 0 || *v > 65535)
        {
          std::cerr << "error: --confirmation-depth: invalid\n";
          return;
        }
        cfg.confirmation_depth = static_cast<uint16_t>(*v);
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    //  If the config provided a deposit address, parse it into
    //  the adapter's deposit_script_ now. Without this, the first
    //  scan_deposits call throws "deposit script not set". The
    //  CCX adapter parses in cmd_start; the Bitcoin adapter
    //  (and any future adapter) should parse as soon as the
    //  config is available.
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
      std::cerr << "error: enableChain failed\n";
      return;
    }

    std::cout << "Probing " << cfg.rpc_host << ":" << cfg.rpc_port
              << "...\n";
    if (probeChain(*rt))
      std::cout << " Reachable.\n";
    else
      std::cout << " Not reachable. Use 'connect " << name
                << " <host:port>' later.\n";

    if (session.current_chain.empty())
      session.current_chain = name;

    std::cout << "Enabled " << name << ".\n";
  }

  void cmd_disable(WatcherSession &session,
                   const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: disable <chain>\n";
      return;
    }

    const std::string &name = args[1];

    auto it = session.chains.find(name);
    if (it == session.chains.end() || !it->second.enabled)
    {
      std::cerr << "error: chain '" << name << "' is not enabled\n";
      return;
    }

    if (session.enabledChainCount() <= 1)
    {
      std::cerr << "error: cannot disable the last enabled chain\n";
      return;
    }

    if (it->second.running)
    {
      Scan::stopScan(name);
      it->second.running = false;
      it->second.started_at = 0;
    }

    it->second.enabled = false;

    if (session.current_chain == name)
    {
      for (auto &[other_name, rt] : session.chains)
      {
        if (other_name != name && rt.enabled)
        {
          session.current_chain = other_name;
          break;
        }
      }
    }

    std::cout << "Disabled " << name << ".\n";
  }

  void cmd_deposits(WatcherSession &session,
                    const std::vector<std::string> &args)
  {
    ChainRuntime *rt = requireCurrent(session, "deposits");
    if (!rt)
      return;

    if (!rt->connected)
    {
      std::cerr << "error: chain not reachable; scan would fail\n";
      return;
    }

    size_t limit = 20;
    for (size_t i = 1; i < args.size(); ++i)
    {
      if (args[i] == "--limit" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value())
        {
          std::cerr << "error: --limit: invalid\n";
          return;
        }
        limit = static_cast<size_t>(*v);
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    ChainStatus status;
    try
    {
      status = rt->adapter->fetch_status(*rt->rpc);
    }
    catch (const std::exception &e)
    {
      std::cerr << "error: fetch_status failed: " << e.what() << "\n";
      return;
    }

    if (!status.reachable)
    {
      std::cerr << "error: chain not reachable\n";
      return;
    }

    const uint64_t from = rt->last_source_height + 1;
    const uint64_t to = status.current_height;

    if (from > to)
    {
      std::cout << "No new blocks since height "
                << rt->last_source_height << ".\n";
      return;
    }

    std::cout << "Scanning heights " << from << ".." << to
              << " (tip " << to << ")...\n";

    if (session.custody_view_key.has_value())
    {
      rt->adapter->set_deposit_ident_secret(*session.custody_view_key);
    }

    size_t found = 0;
    try
    {
      rt->adapter->scan_deposits(
          *rt->rpc,
          from, to,
          [&](const ObservedDeposit &d)
          {
            std::cout << " height=" << d.block_height
                      << " tx=" << formatHashShort(d.source_tx_hash)
                      << " amount="
                      << formatAmountWithDecimals(
                             d.amount_source_atomic,
                             rt->adapter->source_decimals())
                      << "\n";
            ++found;
            if (found >= limit)
              return false;
            return true;
          });
    }
    catch (const std::exception &e)
    {
      std::cerr << "error: scan_deposits failed: " << e.what() << "\n";
      return;
    }

    if (found == 0)
    {
      std::cout << "No deposits found in that range.\n";
    }
    else
    {
      std::cout << "\n"
                << found << " deposit(s) found.\n";
      std::cout << "Use 'rescan' to advance the cursor to the tip.\n";
    }
  }

  void cmd_withdrawals(WatcherSession &session,
                       const std::vector<std::string> &args)
  {
    (void)args;

    ChainRuntime *rt = requireCurrent(session, "withdrawals");
    if (!rt)
      return;

    if (!session.clarity_connected)
    {
      std::cerr << "error: Clarity node is not reachable\n";
      return;
    }

    if (!session.clarity_rpc)
    {
      std::cerr << "error: no Clarity RPC client\n";
      return;
    }

    Wallet::RpcClient &clarity = *session.clarity_rpc;

    std::string err;
    auto res = Wallet::getPendingWithdrawals(
        clarity,
        /*from_height=*/0,
        /*limit=*/50,
        /*offset=*/0,
        &err);

    if (!res.has_value())
    {
      std::cerr << "error: getPendingWithdrawals failed: " << err << "\n";
      return;
    }
    if (!res->is_object() ||
        !res->contains("withdrawals") ||
        !(*res)["withdrawals"].is_array())
    {
      std::cerr << "error: getPendingWithdrawals returned an unexpected "
                   "shape\n";
      return;
    }

    const uint64_t my_chain = rt->adapter->source_chain_id();

    std::cout << "Pending withdrawals for " << rt->chain_short_name()
              << ":\n\n";

    size_t shown = 0;
    for (const auto &entry : (*res)["withdrawals"])
    {
      if (!entry.is_object())
        continue;

      uint64_t scid = 0;
      if (entry.contains("source_chain_id") &&
          entry["source_chain_id"].is_string())
      {
        try
        {
          scid = std::stoull(
              entry["source_chain_id"].get<std::string>(),
              nullptr, 0);
        }
        catch (...)
        {
          continue;
        }
      }
      if (scid != my_chain)
        continue;

      ++shown;

      uint64_t wid = 0;
      uint64_t amount = 0;
      uint64_t created_at = 0;
      uint64_t ack_count = 0;
      uint64_t quorum = 0;
      bool quorum_reached = false;
      bool is_released = false;

      if (entry.contains("withdrawal_id") &&
          entry["withdrawal_id"].is_string())
      {
        try
        {
          wid = std::stoull(
              entry["withdrawal_id"].get<std::string>(),
              nullptr, 0);
        }
        catch (...)
        {
          wid = 0;
        }
      }
      if (entry.contains("amount") && entry["amount"].is_string())
      {
        try
        {
          amount = std::stoull(
              entry["amount"].get<std::string>(),
              nullptr, 0);
        }
        catch (...)
        {
          amount = 0;
        }
      }
      if (entry.contains("created_at_height") &&
          entry["created_at_height"].is_string())
      {
        try
        {
          created_at = std::stoull(
              entry["created_at_height"].get<std::string>(),
              nullptr, 0);
        }
        catch (...)
        {
          created_at = 0;
        }
      }

      if (entry.contains("ack_attestation_count"))
      {
        const auto &c = entry["ack_attestation_count"];
        if (c.is_number_unsigned())
          ack_count = c.get<uint64_t>();
        else if (c.is_string())
        {
          try
          {
            ack_count = std::stoull(c.get<std::string>(), nullptr, 0);
          }
          catch (...)
          {
            ack_count = 0;
          }
        }
      }

      //  ack_quorum is emitted by the encoder as a hex string,
      //  but accept a JSON number too for forward-compatibility.
      if (entry.contains("ack_quorum"))
      {
        const auto &q = entry["ack_quorum"];
        if (q.is_number_unsigned())
          quorum = q.get<uint64_t>();
        else if (q.is_string())
        {
          try
          {
            quorum = std::stoull(q.get<std::string>(), nullptr, 0);
          }
          catch (...)
          {
            quorum = 0;
          }
        }
      }
      if (entry.contains("ack_quorum_reached") &&
          entry["ack_quorum_reached"].is_boolean())
      {
        quorum_reached =
            entry["ack_quorum_reached"].get<bool>();
      }
      if (entry.contains("is_released") &&
          entry["is_released"].is_boolean())
      {
        is_released = entry["is_released"].get<bool>();
      }

      const char *phase_label = "observed";
      if (is_released)
        phase_label = "done (released)";
      else if (quorum_reached)
        phase_label = "acked (awaiting finality/release)";
      else if (ack_count > 0)
        phase_label = "acking";

      std::cout << " withdrawal " << wid
                << "  amount=" << amount
                << "  created_at=" << created_at
                << "  acks=" << ack_count << "/" << quorum
                << "  [" << phase_label << "]\n";
    }

    if (shown == 0)
    {
      std::cout << " (none)\n";
    }
    else
    {
      std::cout << "\n"
                << shown << " pending withdrawal(s) found.\n";
    }
  }

  void cmd_pending(WatcherSession &session,
                   const std::vector<std::string> &args)
  {
    (void)args;
    ChainRuntime *rt = requireCurrent(session, "pending");
    if (!rt)
      return;

    std::cout << "Pending for " << rt->chain_short_name() << ":\n";
    std::cout << " deposits: " << rt->pending_deposits << "\n";
    std::cout << " withdrawals: " << rt->pending_withdrawals << "\n";
  }

  void cmd_address(WatcherSession &session,
                   const std::vector<std::string> &args)
  {
    ChainRuntime *rt = requireCurrent(session, "address");
    if (!rt)
      return;

    if (args.size() < 2)
    {
      std::cerr << "usage: address <index>\n";
      return;
    }

    auto idx = parseU64(args[1]);
    if (!idx.has_value())
    {
      std::cerr << "error: index must be a non-negative integer\n";
      return;
    }

    std::string err;
    auto addr = rt->adapter->deriveDepositAddress(*idx, &err);
    if (!addr.has_value())
    {
      std::cerr << "error: " << err << "\n";
      return;
    }

    std::cout << *addr << "\n";
  }

  void cmd_start(WatcherSession &session,
                 const std::vector<std::string> &args)
  {
    ChainRuntime *rt = nullptr;
    std::string consensus_key_hex;
    std::string bridge_address_str;

    for (size_t i = 1; i < args.size(); ++i)
    {
      if (args[i] == "--consensus-key" && i + 1 < args.size())
      {
        consensus_key_hex = args[++i];
      }
      else if (args[i] == "--consensus-key-file" && i + 1 < args.size())
      {
        std::string path = args[++i];
        std::FILE *f = std::fopen(path.c_str(), "rb");
        if (!f)
        {
          std::cerr << "error: cannot open --consensus-key-file '"
                    << path << "'\n";
          return;
        }
        std::string contents;
        char buf[256];
        size_t n;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
          contents.append(buf, n);
        std::fclose(f);
        while (!contents.empty() &&
               (contents.back() == '\n' || contents.back() == '\r' ||
                contents.back() == ' ' || contents.back() == '\t'))
          contents.pop_back();
        consensus_key_hex = contents;
      }
      else if (args[i] == "--bridge-address" && i + 1 < args.size())
      {
        bridge_address_str = args[++i];
      }
      else if (rt == nullptr && args[i].rfind("--", 0) != 0)
      {
        rt = session.findChain(args[i]);
        if (!rt)
        {
          std::cerr << "error: unknown chain '" << args[i] << "'\n";
          return;
        }
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    if (!rt)
      rt = requireCurrent(session, "start");
    if (!rt)
      return;

    if (!rt->enabled)
    {
      std::cerr << "error: chain is not enabled\n";
      return;
    }
    if (rt->running)
    {
      std::cout << rt->chain_short_name() << " is already running\n";
      return;
    }
    if (!rt->connected)
    {
      std::cerr << "error: chain is not reachable; "
                   "use 'connect' first\n";
      return;
    }
    if (!session.hasKeystore() || !session.signer)
    {
      std::cerr << "error: an open keystore is required to sign "
                   "attestations\n";
      return;
    }
    if (!session.address.has_value())
    {
      std::cerr << "error: session address is unresolved\n";
      return;
    }
    if (session.validator_id == 0)
    {
      std::cerr << "error: validator_id is unresolved; the keystore "
                   "address is not in the active validator set, so the "
                   "signer index cannot be determined\n";
      return;
    }

    if (consensus_key_hex.empty() && !session.consensus_key.has_value())
    {
      std::cerr << "error: a consensus key is required to start the "
                   "scan worker (--consensus-key-file, --consensus-key, "
                   "or --config)\n";
      std::cerr << " (the consensus key signs deposit attestations; "
                   "it is distinct from the account key in the keystore)\n";
      return;
    }

    if (!consensus_key_hex.empty())
    {
      auto bytes = Common::decodeHex(consensus_key_hex);
      if (!bytes.has_value() || bytes->size() != 32)
      {
        std::cerr << "error: consensus key must be 32 bytes of hex\n";
        return;
      }
      Crypto::SecretKey key;
      std::copy(bytes->begin(), bytes->end(), key.data.begin());
      session.consensus_key = key;
    }

    //  ---- Bridge address (per-chain custody / deposit address) ----

    const std::string configured_address = rt->config.bridge_address;
    if (!bridge_address_str.empty() &&
        !configured_address.empty() &&
        bridge_address_str != configured_address)
    {
      std::cerr << "warning: --bridge-address '" << bridge_address_str
                << "' differs from config 'bridge_address' '"
                << configured_address << "'; using the CLI value\n";
    }

    const std::string effective_bridge_address =
        !bridge_address_str.empty()
            ? bridge_address_str
            : configured_address;

    const bool is_btc_chain =
        (rt->adapter->source_chain_id() == BTC_CHAIN_ID);

    if (is_btc_chain)
    {
      if (!effective_bridge_address.empty() ||
          !rt->config.bridge_deposit_address.empty())
      {
        std::cerr << "warning: Bitcoin no longer uses a static "
                     "bridge_address; ignoring it. Deposit addresses "
                     "are derived per registration index from the "
                     "per-chain custody seed.\n";
      }
    }
    else if (!effective_bridge_address.empty())
    {
      std::string parse_err;
      auto blob = rt->adapter->parse_deposit_address(
          effective_bridge_address, &parse_err);
      if (!blob.has_value())
      {
        std::cerr << "error: bridge address '" << effective_bridge_address
                  << "': " << parse_err << "\n";
        return;
      }
      rt->adapter->set_deposit_address(*blob);
      rt->bridge_deposit_address = effective_bridge_address;

      if (auto *ccx = dynamic_cast<CcxAdapter *>(rt->adapter.get()))
        ccx->set_custody_address_string(effective_bridge_address);
    }
    else if (!rt->config.bridge_deposit_address.empty())
    {
      rt->adapter->set_deposit_address(rt->config.bridge_deposit_address);
      std::cerr << "warning: only 'destination_blob' is configured; "
                   "releases will fail because walletd requires a "
                   "base58 custody address. Set 'bridge_address' in "
                   "the config or pass --bridge-address.\n";
    }
    else if (rt->bridge_deposit_address.empty())
    {
      std::cerr << "warning: no bridge address configured; the "
                   "adapter will refuse to scan until one is set\n";
    }

    //  ---- Custody view key ----

    if (session.custody_view_key.has_value())
    {
      rt->adapter->set_deposit_ident_secret(*session.custody_view_key);
    }
    else
    {
      std::cerr << "warning: no --view-key-file configured; deposit "
                   "amounts may be wrong on multi-output transactions\n";
    }

    //  ---- CCX-specific: deposit-destination cache ----
    if (rt->adapter->source_chain_id() ==
        Core::CcxBridge::CCX_CHAIN_ID)
    {
      if (auto *ccx = dynamic_cast<CcxAdapter *>(rt->adapter.get()))
      {
        if (!rt->bridge_deposit_address.empty())
        {
          std::string parse_err;
          auto blob = ccx->parse_deposit_address(
              rt->bridge_deposit_address, &parse_err);
          if (blob.has_value() && blob->size() >= 32)
          {
            Crypto::PublicKey sp;
            std::memcpy(sp.data.data(), blob->data(), 32);
            rt->bridge_custody_spend_pub = sp;
          }
        }
        if (session.custody_view_key.has_value())
          rt->bridge_custody_view_priv = *session.custody_view_key;

        ccx->set_bridge_deposits_cache(
            &rt->bridge_deposits_by_spend);
      }
    }

    //  ---- Bitcoin custody ----
    if (is_btc_chain)
    {
      if (auto *btc = dynamic_cast<BitcoinAdapter *>(rt->adapter.get()))
      {
        if (!rt->config.raw_json.is_object() ||
            !rt->config.raw_json.contains("network") ||
            !rt->config.raw_json["network"].is_string())
        {
          std::cerr << "error: Bitcoin chain has no \"network\" field "
                       "in its config. Set it explicitly to one of "
                       "\"mainnet\", \"testnet\", or \"regtest\". "
                       "Refusing to start without it.\n";
          return;
        }

        const std::string net_name =
            rt->config.raw_json["network"].get<std::string>();
        Crypto::BitcoinNetwork net;
        if (net_name == "mainnet" || net_name == "main")
          net = Crypto::BitcoinNetwork::Mainnet;
        else if (net_name == "testnet" || net_name == "test")
          net = Crypto::BitcoinNetwork::Testnet;
        else if (net_name == "regtest" || net_name == "reg")
          net = Crypto::BitcoinNetwork::Regtest;
        else
        {
          std::cerr << "error: unknown Bitcoin network '" << net_name
                    << "' (expected mainnet|testnet|regtest)\n";
          return;
        }

        const std::string custody_dir =
            rt->config.state_subdir.empty()
                ? rt->chain_short_name()
                : rt->config.state_subdir;

        std::string custody_err;
        auto custody = BitcoinCustody::create_or_load(
            custody_dir,
            net,
            session.keystore_password,
            &custody_err);

        if (!custody)
        {
          std::cerr << "error: Bitcoin custody setup failed: "
                    << custody_err << "\n";
          return;
        }

        rt->btc_custody = std::move(custody);
        btc->set_custody(rt->btc_custody.get());
        btc->set_deposit_cache(&rt->btc_deposit_cache);
      }
    }

    //  ---- Wallet RPC (releases) ----
    if (rt->adapter->source_chain_id() ==
        Core::CcxBridge::CCX_CHAIN_ID)
    {
      if (!rt->config.wallet_rpc_host.empty() &&
          rt->config.wallet_rpc_port != 0)
      {
        rt->adapter->set_wallet_rpc_endpoint(
            rt->config.wallet_rpc_host,
            rt->config.wallet_rpc_port,
            rt->config.wallet_rpc_user,
            rt->config.wallet_rpc_password);
        std::cout << "Wallet RPC configured: "
                  << rt->config.wallet_rpc_host << ":"
                  << rt->config.wallet_rpc_port << "\n";
      }
      else
      {
        std::cout << "warning: no CCX wallet RPC configured; "
                     "withdrawals will not be released by this validator\n";
      }
    }

    rt->adapter->set_network_prefix(
        rt->config.ccx_network_prefix);

    if (rt->config.raw_json.is_object())
      rt->adapter->set_transport_config(rt->config.raw_json);

    //  ---- Cursor ----
    //
    //  Precedence:
    //
    //    1. Persisted cursor file, if it exists and is >= start_height - 1.
    //    2. start_height - 1 (which is 0 when start_height == 0,
    //       meaning "scan from genesis").
    //
    //  The persisted cursor wins over start_height: start_height is
    //  an initial "don't scan from genesis" hint, not a reset. To
    //  reset, delete the cursor file or use `rescan --from N`.
    //
    //  NOTE: this must happen *before* Scan::startScan, because the
    //  scan thread reads rt->last_source_height once at the top of
    //  its loop. Writing it after startScan races the scan thread.
    {
      const uint64_t config_floor =
          (rt->config.start_height == 0)
              ? 0
              : rt->config.start_height - 1;

      uint64_t persisted = 0;
      const bool have_persisted = readChainCursor(*rt, persisted);

      if (have_persisted && persisted >= config_floor)
      {
        rt->last_source_height = persisted;
        std::cout << "Resuming scan from persisted cursor at height "
                  << rt->last_source_height << "\n";
      }
      else
      {
        rt->last_source_height = config_floor;
        if (have_persisted && persisted < config_floor)
        {
          std::cout << "Persisted cursor (" << persisted
                    << ") is below start_height; using start_height - 1 ("
                    << config_floor << ")\n";
        }
        else if (rt->config.start_height != 0)
        {
          std::cout << "Starting scan from height "
                    << rt->config.start_height << " (from config)\n";
        }
      }
    }

    Scan::startScan(session, rt->chain_short_name());

    rt->running = true;
    rt->started_at = static_cast<int64_t>(std::time(nullptr));

    std::cout << "Started scan worker for " << rt->chain_short_name()
              << ".\n";
    std::cout << "Deposits will be attested on-chain and minted when a "
                 "quorum of validator attestations is present.\n";
    std::cout << "Withdrawals will be acked, released, and recorded "
                 "as they progress through the pipeline.\n";
  }

  void cmd_register_deposit(WatcherSession &session,
                            const std::vector<std::string> &args)
  {
    if (args.size() < 3)
    {
      std::cerr << "usage: register-deposit <chain> <rclrty-address>\n";
      return;
    }

    const std::string &chain_name = args[1];

    ChainRuntime *rt = session.findChain(chain_name);
    if (!rt)
    {
      std::cerr << "error: chain '" << chain_name
                << "' is not enabled\n";
      return;
    }
    if (!rt->adapter)
    {
      std::cerr << "error: chain has no adapter\n";
      return;
    }
    if (!session.hasKeystore() || !session.signer)
    {
      std::cerr << "error: an open keystore is required\n";
      return;
    }
    if (!session.clarity_rpc || !session.clarity_connected)
    {
      std::cerr << "error: Clarity RPC is not connected\n";
      return;
    }

    //  Parse the destination.
    auto dest = Wallet::decodeAddress(args[2], session.currentNetwork());
    if (!dest.has_value())
    {
      std::cerr << "error: '" << args[2]
                << "' is not a valid rclrty1... address for the "
                   "current network\n";
      return;
    }

    Wallet::BridgeRegisterDepositParams p;
    p.common.chain_id = session.keystore->chainId();
    p.common.nonce = Wallet::getNonce(
                         *session.clarity_rpc,
                         session.address_bech32m)
                         .value_or(0);
    p.common.fee = 100000;
    p.source_chain_id = rt->adapter->source_chain_id();
    p.destination = *dest;

    Wallet::WalletStatus build_st;
    auto tx = Wallet::buildBridgeRegisterDeposit(
        session.address.value(), p, &build_st);
    if (!tx.has_value())
    {
      std::cerr << "error: buildBridgeRegisterDeposit failed: "
                << (build_st.detail.empty()
                        ? Wallet::walletErrorMessage(build_st.code)
                        : build_st.detail)
                << "\n";
      return;
    }

    Wallet::WalletStatus sign_st;
    auto hash = Wallet::signTransaction(
        *tx, *session.signer, Wallet::clrtyPath(0, 0, 0), &sign_st);
    if (!hash.has_value())
    {
      std::cerr << "error: signTransaction failed: "
                << (sign_st.detail.empty()
                        ? Wallet::walletErrorMessage(sign_st.code)
                        : sign_st.detail)
                << "\n";
      return;
    }

    auto tx_bytes = tx->serialize();
    static const char HEX[] = "0123456789abcdef";
    std::string hex = "0x";
    hex.reserve(2 + tx_bytes.size() * 2);
    for (uint8_t b : tx_bytes)
    {
      hex.push_back(HEX[b >> 4]);
      hex.push_back(HEX[b & 0xF]);
    }

    std::string submit_err;
    auto txid = Wallet::sendRawTransaction(
        *session.clarity_rpc, hex, &submit_err);
    if (!txid.has_value())
    {
      std::cerr << "error: sendRawTransaction failed: "
                << submit_err << "\n";
      return;
    }

    std::cout << "Registration submitted: " << *txid << "\n";
    std::cout << "Chain:       " << chain_name << "\n";
    std::cout << "Destination: " << args[2] << "\n";
    std::cout << "\nOnce the transaction confirms, query the assigned "
                 "index with:\n";
    std::cout << "  getBridgeDepositsForAuthority("
              << "chain_id=0x" << std::hex
              << rt->adapter->source_chain_id()
              << ", address=" << session.address_bech32m
              << ")\n";
  }

  void cmd_register_chain(WatcherSession &session,
                          const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: register-chain <chain> "
                   "[--collect <idx>:0x<sig>] [--submit] "
                   "[--token-id <n>]\n";
      return;
    }

    const std::string &chain_name = args[1];

    ChainRuntime *rt = session.findChain(chain_name);
    if (!rt)
    {
      std::cerr << "error: chain '" << chain_name << "' is not enabled\n";
      return;
    }
    if (!rt->adapter)
    {
      std::cerr << "error: chain has no adapter\n";
      return;
    }
    if (!rt->adapter->supports_registration())
    {
      std::cerr << "error: adapter '" << chain_name
                << "' does not support registration (already "
                   "genesis-registered or not a bridge chain)\n";
      return;
    }
    if (!session.hasKeystore() || !session.signer)
    {
      std::cerr << "error: an open keystore is required to sign the "
                   "registration blob\n";
      return;
    }
    if (!session.clarity_rpc || !session.clarity_connected)
    {
      std::cerr << "error: Clarity RPC is not connected\n";
      return;
    }
    if (session.validator_id == 0)
    {
      std::cerr << "error: validator_id is unresolved; cannot determine "
                   "signer index\n";
      return;
    }

    const uint64_t source_chain_id = rt->adapter->source_chain_id();

    //  ---- Parse flags ----
    std::optional<std::pair<uint16_t, Crypto::Signature>> collect_sig;
    bool do_submit = false;
    std::optional<uint64_t> token_id_override;

    for (size_t i = 2; i < args.size(); ++i)
    {
      if (args[i] == "--submit")
      {
        do_submit = true;
      }
      else if (args[i] == "--token-id" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value() || *v == 0 || *v > 0xFFFFFFFFull)
        {
          std::cerr << "error: --token-id: invalid\n";
          return;
        }
        token_id_override = *v;
      }
      else if (args[i] == "--collect" && i + 1 < args.size())
      {
        const std::string spec = args[++i];
        const size_t colon = spec.find(':');
        if (colon == std::string::npos || colon == 0 ||
            colon + 1 >= spec.size())
        {
          std::cerr << "error: --collect: expected <idx>:0x<sig>\n";
          return;
        }
        std::string idx_str = spec.substr(0, colon);
        std::string sig_hex = spec.substr(colon + 1);

        //  Strip a 0x prefix from the index if one is present.
        if (idx_str.size() >= 2 && idx_str[0] == '0' &&
            (idx_str[1] == 'x' || idx_str[1] == 'X'))
          idx_str = idx_str.substr(2);

        errno = 0;
        char *end = nullptr;
        const unsigned long long idx =
            std::strtoull(idx_str.c_str(), &end, 16);
        if (errno != 0 || end == idx_str.c_str() || *end != '\0' ||
            idx > 0xFFFF)
        {
          std::cerr << "error: --collect: invalid signer index\n";
          return;
        }

        //  Strip an optional 0x from the signature hex, then parse
        //  to exactly 64 bytes.
        if (sig_hex.size() >= 2 && sig_hex[0] == '0' &&
            (sig_hex[1] == 'x' || sig_hex[1] == 'X'))
          sig_hex = sig_hex.substr(2);
        if (sig_hex.size() != 128)
        {
          std::cerr << "error: --collect: signature must be 64 bytes "
                       "(128 hex chars)\n";
          return;
        }
        auto sig_bytes = Common::decodeHex(sig_hex);
        if (!sig_bytes.has_value() || sig_bytes->size() != 64)
        {
          std::cerr << "error: --collect: signature is not valid hex\n";
          return;
        }
        Crypto::Signature sig;
        std::copy(sig_bytes->begin(), sig_bytes->end(),
                  sig.data.begin());
        collect_sig = std::make_pair(
            static_cast<uint16_t>(idx), sig);
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    //  ---- State file path ----
    //  Per-chain, per-session. The directory is created if missing.
    const std::filesystem::path reg_dir =
        std::filesystem::path(session.keystore_path)
                .parent_path()
                .empty()
            ? std::filesystem::current_path() / "register"
            : std::filesystem::path(session.keystore_path)
                      .parent_path() /
                  "register";
    std::error_code ec;
    std::filesystem::create_directories(reg_dir, ec);
    if (ec)
    {
      std::cerr << "error: cannot create registration dir "
                << reg_dir.string() << ": " << ec.message() << "\n";
      return;
    }
    const std::filesystem::path reg_file =
        reg_dir / (chain_name + ".json");

    //  ---- Load existing file, if any ----
    //  The file shape is:
    //    {
    //      "chain": "btc",
    //      "source_chain_id": "0x42544331",
    //      "wrapped_token_id": "0x2",
    //      "blob": "0x...",
    //      "signatures": [{"index": 0, "sig": "0x..."}, ...],
    //      "submitted_txid": "0x..."   // present once submitted
    //    }
    Common::Json state = Common::Json::object();
    bool have_state = false;
    {
      std::ifstream in(reg_file);
      if (in.good())
      {
        try
        {
          state = Common::Json::parse(in);
          have_state = state.is_object();
        }
        catch (const std::exception &e)
        {
          std::cerr << "error: could not parse existing registration file "
                    << reg_file.string() << ": " << e.what() << "\n";
          return;
        }
      }
    }

    if (!have_state)
    {
      //  Fresh build. Query for the next free token id.
      uint32_t chosen_token_id = 0;
      if (token_id_override.has_value())
      {
        chosen_token_id = static_cast<uint32_t>(*token_id_override);
      }
      else
      {
        std::string token_err;
        auto tokens_res = session.clarity_rpc->call(
            "getAllTokens",
            Common::Json::parse(
                "{\"limit\":\"0x3e8\",\"offset\":\"0x0\"}"));
        uint32_t max_id = 0;
        if (tokens_res.ok() && tokens_res.result.is_object() &&
            tokens_res.result.contains("tokens") &&
            tokens_res.result["tokens"].is_array())
        {
          for (const auto &t : tokens_res.result["tokens"])
          {
            if (!t.is_object() || !t.contains("id") ||
                !t["id"].is_string())
              continue;
            std::string id_hex = t["id"].get<std::string>();
            if (id_hex.size() >= 2 && id_hex[0] == '0' &&
                (id_hex[1] == 'x' || id_hex[1] == 'X'))
              id_hex = id_hex.substr(2);
            errno = 0;
            char *end = nullptr;
            const unsigned long v =
                std::strtoul(id_hex.c_str(), &end, 16);
            if (end == id_hex.c_str() || *end != '\0')
              continue;
            if (static_cast<uint32_t>(v) > max_id)
              max_id = static_cast<uint32_t>(v);
          }
        }
        chosen_token_id = max_id + 1;
        if (chosen_token_id == 0)
          chosen_token_id = 2; // id 0 is native; id 1 is genesis CCX
      }

      //  ---- Build the 55-byte blob ----
      //
      //  Layout (matches BridgeChainRegistration::serializeState):
      //    [0..8)    source_chain_id LE
      //    [8..12)   wrapped_token_id LE
      //    [12..44)  fingerprint
      //    [44]      source_decimals
      //    [45]      clarity_decimals
      //    [46..48)  confirmation_depth LE
      //    [48]      destination_blob_min_len
      //    [49]      destination_blob_max_len
      //    [50]      enabled
      //    [51..55)  active_validator_min LE
      std::vector<uint8_t> blob(55, 0);

      uint64_t scid = source_chain_id;
      for (int i = 0; i < 8; ++i)
        blob[i] = uint8_t(scid >> (i * 8));

      for (int i = 0; i < 4; ++i)
        blob[8 + i] = uint8_t(chosen_token_id >> (i * 8));

      const Crypto::Hash fp = rt->adapter->wrapped_token_fingerprint();
      std::copy(fp.data.begin(), fp.data.end(), blob.begin() + 12);

      blob[44] = rt->adapter->source_decimals();
      blob[45] = rt->adapter->source_decimals();

      const uint16_t depth = rt->config.confirmation_depth != 0
                                 ? rt->config.confirmation_depth
                                 : rt->adapter->default_confirmation_depth();
      blob[46] = uint8_t(depth);
      blob[47] = uint8_t(depth >> 8);

      const auto bounds = rt->adapter->registration_blob_bounds();
      blob[48] = bounds.first;
      blob[49] = bounds.second;
      blob[50] = 1; // enabled

      const uint32_t vmin =
          rt->adapter->registration_active_validator_min();
      for (int i = 0; i < 4; ++i)
        blob[51 + i] = uint8_t(vmin >> (i * 8));

      //  Sign the blob. Blake2b("brgr" || blob).
      std::vector<uint8_t> input = {'b', 'r', 'g', 'r'};
      input.insert(input.end(), blob.begin(), blob.end());
      Crypto::Hash signing_hash;
      Crypto::blake2b(input.data(), input.size(),
                      signing_hash.data.data(),
                      signing_hash.data.size());

      //  Sign with the consensus key if one is loaded, else the
      //  keystore's default account key. Consensus key is the
      //  right one: it's the key validatorKeyAtHeight resolves.
      std::optional<Crypto::Signature> sig;
      if (session.consensus_key.has_value())
      {
        sig = Crypto::sign(signing_hash, *session.consensus_key);
      }
      else
      {
        Wallet::WalletStatus sig_st;
        sig = session.signer->signAtPath(
            Wallet::clrtyPath(0, 0, 0), signing_hash, &sig_st);
      }
      if (!sig.has_value())
      {
        std::cerr << "error: could not sign the registration blob\n";
        return;
      }

      //  Resolve the signer's index in the active set (same logic
      //  the executor will use).
      std::string set_err;
      auto active = Wallet::getActiveSet(*session.clarity_rpc, &set_err);
      if (!active.has_value() || !active->is_object() ||
          !active->contains("ids") || !(*active)["ids"].is_array())
      {
        std::cerr << "error: getActiveSet failed: " << set_err << "\n";
        return;
      }
      std::vector<uint64_t> ids;
      ids.reserve((*active)["ids"].size());
      for (const auto &entry : (*active)["ids"])
      {
        if (!entry.is_string())
          continue;
        std::string s = entry.get<std::string>();
        if (s.size() >= 2 && s[0] == '0' &&
            (s[1] == 'x' || s[1] == 'X'))
          s = s.substr(2);
        errno = 0;
        char *end = nullptr;
        const unsigned long long v = std::strtoull(s.c_str(), &end, 16);
        if (end == s.c_str() || *end != '\0')
          continue;
        ids.push_back(static_cast<uint64_t>(v));
      }
      std::sort(ids.begin(), ids.end());
      uint16_t my_index = 0xFFFF;
      for (size_t i = 0; i < ids.size(); ++i)
      {
        if (ids[i] == session.validator_id)
        {
          my_index = static_cast<uint16_t>(i);
          break;
        }
      }
      if (my_index == 0xFFFF)
      {
        std::cerr << "error: this validator is not in the active set\n";
        return;
      }

      //  ---- Save state ----
      state["chain"] = chain_name;
      state["source_chain_id"] =
          "0x" + [&]
      {
        static const char hex[] = "0123456789abcdef";
        std::string s;
        uint64_t v = source_chain_id;
        if (v == 0)
          return std::string("0");
        while (v)
        {
          s.push_back(hex[v & 0xF]);
          v >>= 4;
        }
        std::reverse(s.begin(), s.end());
        return s;
      }();
      state["wrapped_token_id"] =
          "0x" + [&]
      {
        static const char hex[] = "0123456789abcdef";
        std::string s;
        uint32_t v = chosen_token_id;
        if (v == 0)
          return std::string("0");
        while (v)
        {
          s.push_back(hex[v & 0xF]);
          v >>= 4;
        }
        std::reverse(s.begin(), s.end());
        return s;
      }();
      state["blob"] = "0x" + [&]
      {
        static const char hex[] = "0123456789abcdef";
        std::string s;
        s.reserve(blob.size() * 2);
        for (uint8_t b : blob)
        {
          s.push_back(hex[b >> 4]);
          s.push_back(hex[b & 0xF]);
        }
        return s;
      }();
      state["signatures"] = Common::Json::array();
      state["signatures"].push_back(
          {{"index", my_index},
           {"sig", "0x" + [&]
                       {
                         static const char hex[] = "0123456789abcdef";
                         std::string s;
                         s.reserve(sig->data.size() * 2);
                         for (uint8_t b : sig->data)
                         {
                           s.push_back(hex[b >> 4]);
                           s.push_back(hex[b & 0xF]);
                         }
                         return s;
                       }()}});

      std::ofstream out(reg_file);
      if (!out)
      {
        std::cerr << "error: could not write " << reg_file.string() << "\n";
        return;
      }
      out << state.dump(2) << "\n";

      std::cout << "Registration blob written to "
                << reg_file.string() << "\n";
      std::cout << "Signer index: " << my_index << "\n";
      std::cout << "Signature:    "
                << state["signatures"][0]["sig"].get<std::string>()
                << "\n\n";
      std::cout << "Share the signature with the other validators. They "
                   "add it to their copy of the file with:\n"
                << "  register-chain " << chain_name << " --collect "
                << my_index << ":<signature-hex>\n";
      std::cout << "\nThen run:\n"
                << "  register-chain " << chain_name << " --submit\n";
      return;
    }

    //  ---- Self-sign if the file exists but this validator's
    //  signature isn't in it ----
    //
    //  This handles the case where the file was built by a peer
    //  (or by a previous run of this process from a different
    //  keystore) and the operator is now adding their own
    //  signature. Without this, `register-chain btc` on a second
    //  keystore would just report "Registration state" and never
    //  contribute a signature, leaving the operator with no CLI
    //  path to complete a two-validator registration.
    {
      //  Derive my_index from the active set.
      std::string set_err;
      auto active = Wallet::getActiveSet(*session.clarity_rpc, &set_err);
      if (!active.has_value() || !active->is_object() ||
          !active->contains("ids") || !(*active)["ids"].is_array())
      {
        std::cerr << "error: getActiveSet failed: " << set_err << "\n";
        return;
      }
      std::vector<uint64_t> ids;
      for (const auto &entry : (*active)["ids"])
      {
        if (!entry.is_string())
          continue;
        std::string s = entry.get<std::string>();
        if (s.size() >= 2 && s[0] == '0' &&
            (s[1] == 'x' || s[1] == 'X'))
          s = s.substr(2);
        errno = 0;
        char *end = nullptr;
        const unsigned long long v = std::strtoull(s.c_str(), &end, 16);
        if (end == s.c_str() || *end != '\0')
          continue;
        ids.push_back(static_cast<uint64_t>(v));
      }
      std::sort(ids.begin(), ids.end());
      uint16_t my_index = 0xFFFF;
      for (size_t i = 0; i < ids.size(); ++i)
        if (ids[i] == session.validator_id)
        {
          my_index = static_cast<uint16_t>(i);
          break;
        }
      if (my_index == 0xFFFF)
      {
        std::cerr << "error: this validator is not in the active set\n";
        return;
      }

      //  Is my signature already in the file?
      bool present = false;
      if (state.contains("signatures") &&
          state["signatures"].is_array())
      {
        for (const auto &s : state["signatures"])
        {
          if (s.is_object() && s.contains("index") &&
              s["index"].is_number_unsigned() &&
              s["index"].get<uint64_t>() == my_index)
          {
            present = true;
            break;
          }
        }
      }

      if (!present)
      {
        //  Recompute the hash and sign the stored blob.
        std::string blob_hex = state.value("blob", std::string(""));
        if (blob_hex.size() < 4)
        {
          std::cerr << "error: stored blob is missing or malformed\n";
          return;
        }
        auto blob_bytes = Common::decodeHex(blob_hex.substr(2));
        if (!blob_bytes.has_value() || blob_bytes->size() != 55)
        {
          std::cerr << "error: stored blob is not 55 bytes\n";
          return;
        }
        std::vector<uint8_t> input = {'b', 'r', 'g', 'r'};
        input.insert(input.end(), blob_bytes->begin(), blob_bytes->end());
        Crypto::Hash signing_hash;
        Crypto::blake2b(input.data(), input.size(),
                        signing_hash.data.data(),
                        signing_hash.data.size());

        std::optional<Crypto::Signature> sig;
        if (session.consensus_key.has_value())
          sig = Crypto::sign(signing_hash, *session.consensus_key);
        else
        {
          Wallet::WalletStatus sig_st;
          sig = session.signer->signAtPath(
              Wallet::clrtyPath(0, 0, 0), signing_hash, &sig_st);
        }
        if (!sig.has_value())
        {
          std::cerr << "error: could not sign the stored registration blob\n";
          return;
        }

        std::string sig_hex = "0x";
        {
          static const char hex[] = "0123456789abcdef";
          for (uint8_t b : sig->data)
          {
            sig_hex.push_back(hex[b >> 4]);
            sig_hex.push_back(hex[b & 0xF]);
          }
        }
        if (!state.contains("signatures") ||
            !state["signatures"].is_array())
          state["signatures"] = Common::Json::array();
        state["signatures"].push_back(
            {{"index", my_index}, {"sig", sig_hex}});

        std::ofstream out(reg_file);
        out << state.dump(2) << "\n";

        std::cout << "Added own signature (index " << my_index
                  << ") to existing registration file.\n";
        std::cout << "Signature: " << sig_hex << "\n";
        std::cout << "Total signatures: "
                  << state["signatures"].size() << "\n";
        return;
      }
    }

    //  ---- Existing state: collect or submit ----

    //  If --token-id was given and differs from the stored one,
    //  reject — the blob already carries the old id.
    if (token_id_override.has_value())
    {
      const std::string stored = state.value("wrapped_token_id",
                                             std::string("0x0"));
      std::string clean = stored;
      if (clean.size() >= 2 && clean[0] == '0' &&
          (clean[1] == 'x' || clean[1] == 'X'))
        clean = clean.substr(2);
      errno = 0;
      char *end = nullptr;
      const unsigned long long v = std::strtoull(clean.c_str(), &end, 16);
      if (end != clean.c_str() && *end == '\0' &&
          static_cast<uint64_t>(v) != *token_id_override)
      {
        std::cerr << "error: --token-id " << *token_id_override
                  << " conflicts with the blob's stored id "
                  << stored << "\n";
        return;
      }
    }

    if (collect_sig.has_value())
    {
      auto &sigs = state["signatures"];
      if (!sigs.is_array())
        sigs = Common::Json::array();

      //  Reject duplicate indices.
      for (const auto &s : sigs)
      {
        if (s.is_object() && s.contains("index") &&
            s["index"].is_number_unsigned() &&
            s["index"].get<uint64_t>() == collect_sig->first)
        {
          std::cerr << "error: signature with index "
                    << collect_sig->first << " is already recorded\n";
          return;
        }
      }

      std::string sig_hex = "0x";
      {
        static const char hex[] = "0123456789abcdef";
        for (uint8_t b : collect_sig->second.data)
        {
          sig_hex.push_back(hex[b >> 4]);
          sig_hex.push_back(hex[b & 0xF]);
        }
      }
      sigs.push_back({{"index", collect_sig->first},
                      {"sig", sig_hex}});

      std::ofstream out(reg_file);
      out << state.dump(2) << "\n";

      std::cout << "Collected signature from index "
                << collect_sig->first << ". "
                << "Total: " << sigs.size() << "\n";
      return;
    }

    if (do_submit)
    {
      const auto &sigs = state["signatures"];
      if (!sigs.is_array() || sigs.empty())
      {
        std::cerr << "error: no signatures collected\n";
        return;
      }

      //  Check quorum against the active set.
      std::string set_err;
      auto active = Wallet::getActiveSet(*session.clarity_rpc, &set_err);
      if (!active.has_value() || !active->is_object() ||
          !active->contains("size") || !(*active)["size"].is_string())
      {
        std::cerr << "error: getActiveSet failed: " << set_err << "\n";
        return;
      }
      std::string size_str = (*active)["size"].get<std::string>();
      if (size_str.size() >= 2 && size_str[0] == '0' &&
          (size_str[1] == 'x' || size_str[1] == 'X'))
        size_str = size_str.substr(2);
      errno = 0;
      char *end = nullptr;
      const unsigned long long set_size =
          std::strtoull(size_str.c_str(), &end, 16);
      if (end == size_str.c_str() || *end != '\0')
      {
        std::cerr << "error: malformed active-set size\n";
        return;
      }
      const size_t quorum = (set_size * 2) / 3 + 1;
      if (sigs.size() < quorum)
      {
        std::cerr << "error: need " << quorum << " signatures, have "
                  << sigs.size() << "\n";
        return;
      }

      //  Parse stored blob and signatures into the wire format.
      std::string blob_hex = state.value("blob", std::string(""));
      if (blob_hex.size() < 4)
      {
        std::cerr << "error: stored blob is missing or malformed\n";
        return;
      }
      auto blob_bytes = Common::decodeHex(blob_hex.substr(2));
      if (!blob_bytes.has_value() || blob_bytes->size() != 55)
      {
        std::cerr << "error: stored blob is not 55 bytes\n";
        return;
      }

      //  Signature block: [2 count LE] || count * [2 idx LE || 64 sig].
      std::vector<uint8_t> sig_block;
      const uint16_t count = static_cast<uint16_t>(sigs.size());
      sig_block.push_back(uint8_t(count));
      sig_block.push_back(uint8_t(count >> 8));
      for (const auto &s : sigs)
      {
        if (!s.is_object())
          continue;
        const uint16_t idx = static_cast<uint16_t>(
            s.value("index", 0u));
        sig_block.push_back(uint8_t(idx));
        sig_block.push_back(uint8_t(idx >> 8));
        std::string sig_hex = s.value("sig", std::string(""));
        if (sig_hex.size() >= 2 && sig_hex[0] == '0' &&
            (sig_hex[1] == 'x' || sig_hex[1] == 'X'))
          sig_hex = sig_hex.substr(2);
        auto sig_bytes = Common::decodeHex(sig_hex);
        if (!sig_bytes.has_value() || sig_bytes->size() != 64)
        {
          std::cerr << "error: stored signature is malformed\n";
          return;
        }
        sig_block.insert(sig_block.end(),
                         sig_bytes->begin(), sig_bytes->end());
      }

      //  Build + sign + submit.
      Wallet::BridgeRegisterChainParams p;
      p.common.chain_id = session.keystore->chainId();
      p.common.nonce =
          Wallet::getNonce(*session.clarity_rpc,
                           session.address_bech32m)
              .value_or(0);
      p.common.fee = 100000;
      p.registration_blob = *blob_bytes;
      p.signature_block = sig_block;

      Wallet::WalletStatus build_st;
      auto tx = Wallet::buildBridgeRegisterChain(
          session.address.value(), p, &build_st);
      if (!tx.has_value())
      {
        std::cerr << "error: buildBridgeRegisterChain failed: "
                  << (build_st.detail.empty()
                          ? Wallet::walletErrorMessage(build_st.code)
                          : build_st.detail)
                  << "\n";
        return;
      }

      Wallet::WalletStatus sign_st;
      auto signing_hash = Wallet::signTransaction(
          *tx, *session.signer, Wallet::clrtyPath(0, 0, 0), &sign_st);
      if (!signing_hash.has_value())
      {
        std::cerr << "error: signTransaction failed\n";
        return;
      }

      auto tx_bytes = tx->serialize();
      static const char hex[] = "0123456789abcdef";
      std::string hex_str = "0x";
      hex_str.reserve(2 + tx_bytes.size() * 2);
      for (uint8_t b : tx_bytes)
      {
        hex_str.push_back(hex[b >> 4]);
        hex_str.push_back(hex[b & 0xF]);
      }

      std::string submit_err;
      auto txid = Wallet::sendRawTransaction(
          *session.clarity_rpc, hex_str, &submit_err);
      if (!txid.has_value())
      {
        std::cerr << "error: sendRawTransaction failed: "
                  << submit_err << "\n";
        return;
      }

      state["submitted_txid"] = *txid;
      std::ofstream out(reg_file);
      out << state.dump(2) << "\n";

      std::cout << "Registration submitted: " << *txid << "\n";
      std::cout << "Wait for the block to commit, then run "
                   "`getBridgeChainRegistration` to confirm.\n";
      std::cout << "Deposits for this chain will be attested on the "
                   "next scan poll after the registration confirms.\n";
      return;
    }

    //  Neither --collect nor --submit: report the current file
    //  state so the operator knows where they are.
    std::cout << "Registration state for " << chain_name << ":\n";
    std::cout << "  file:       " << reg_file.string() << "\n";
    std::cout << "  blob:       "
              << state.value("blob", std::string("(none)")) << "\n";
    std::cout << "  token id:   "
              << state.value("wrapped_token_id", std::string("(none)"))
              << "\n";
    std::cout << "  signatures: "
              << (state.contains("signatures") &&
                          state["signatures"].is_array()
                      ? state["signatures"].size()
                      : 0)
              << "\n";
    if (state.contains("submitted_txid"))
      std::cout << "  submitted:  "
                << state.value("submitted_txid", std::string(""))
                << "\n";
  }

  void cmd_stop(WatcherSession &session,
                const std::vector<std::string> &args)
  {
    ChainRuntime *rt = nullptr;
    if (args.size() >= 2)
    {
      rt = session.findChain(args[1]);
      if (!rt)
      {
        std::cerr << "error: unknown chain '" << args[1] << "'\n";
        return;
      }
    }
    else
    {
      rt = requireCurrent(session, "stop");
    }
    if (!rt)
      return;

    if (!rt->running)
    {
      std::cout << rt->chain_short_name() << " is not running\n";
      return;
    }

    Scan::stopScan(rt->chain_short_name());
    rt->running = false;
    rt->started_at = 0;

    std::cout << "Stopped scan worker for " << rt->chain_short_name()
              << ".\n";
  }

  void cmd_rescan(WatcherSession &session,
                  const std::vector<std::string> &args)
  {
    ChainRuntime *rt = requireCurrent(session, "rescan");
    if (!rt)
      return;

    uint64_t from = 0;
    for (size_t i = 1; i < args.size(); ++i)
    {
      if (args[i] == "--from" && i + 1 < args.size())
      {
        auto v = parseU64(args[++i]);
        if (!v.has_value())
        {
          std::cerr << "error: --from: invalid\n";
          return;
        }
        from = *v;
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    if (rt->running)
    {
      std::cout << "Stopping scan worker for " << rt->chain_short_name()
                << "...\n";
      Scan::stopScan(rt->chain_short_name());
      rt->running = false;
      rt->started_at = 0;
    }

    rt->last_source_height = (from == 0) ? 0 : from - 1;

    std::cout << "Cursor for " << rt->chain_short_name()
              << " reset. Next scan will start at " << from << ".\n";
    std::cout << "Use 'start' to resume the scan worker, or "
                 "'deposits' for a one-shot scan.\n";
  }

  void cmd_state(WatcherSession &session,
                 const std::vector<std::string> &args)
  {
    std::string sub = (args.size() >= 2) ? args[1] : "";

    if (sub.empty() || sub == "watcher" || sub == "keystore")
    {
      std::cout << "Validator:\n";
      if (session.hasKeystore())
      {
        std::cout << " address: " << session.address_bech32m << "\n";
        std::cout << " network: "
                  << Wallet::networkName(session.currentNetwork())
                  << "\n";
        if (session.validator_id != 0)
          std::cout << " validator_id: " << session.validator_id << "\n";
        else
          std::cout << " validator_id: (unresolved — the keystore "
                       "address is not a registered validator)\n";
      }
      else
      {
        std::cout << " (no keystore open)\n";
      }

      std::cout << "\nClarity:\n";
      std::cout << " endpoint: " << session.clarity_endpoint.host
                << ":" << session.clarity_endpoint.port
                << (session.clarity_connected ? " [connected]"
                                              : " [offline]")
                << "\n";
      return;
    }

    if (sub == "chains")
    {
      if (session.chains.empty())
      {
        std::cout << "(no chains enabled)\n";
        return;
      }
      std::vector<std::string> names;
      names.reserve(session.chains.size());
      for (const auto &[name, rt] : session.chains)
      {
        if (rt.enabled)
          names.push_back(name);
      }
      std::sort(names.begin(), names.end());

      for (const auto &n : names)
      {
        const auto &rt = session.chains.at(n);
        std::cout << n << ":\n";
        std::cout << " last_source_height: " << rt.last_source_height
                  << "\n";
        std::cout << " last_clarity_height: " << rt.last_clarity_height
                  << "\n";
        std::cout << " pending_deposits: " << rt.pending_deposits
                  << "\n";
        std::cout << " pending_withdrawals: " << rt.pending_withdrawals
                  << "\n";
        std::cout << " state_dir: " << rt.config.state_subdir
                  << "\n";
      }
      return;
    }

    std::cerr << "usage: state [watcher|keystore|chains]\n";
  }

  void cmd_connect(WatcherSession &session,
                   const std::vector<std::string> &args)
  {
    if (args.size() < 3)
    {
      std::cerr << "usage: connect <chain> <host:port>\n";
      return;
    }

    const std::string &name = args[1];
    const std::string &spec = args[2];

    ChainRuntime *rt = session.findChain(name);
    if (!rt)
    {
      std::cerr << "error: unknown chain '" << name << "'\n";
      return;
    }

    std::string host;
    uint16_t port = 0;
    if (!parseEndpointSpec(spec, host, port))
    {
      std::cerr << "error: invalid host:port\n";
      return;
    }

    if (rt->running)
    {
      Scan::stopScan(name);
      rt->running = false;
      rt->started_at = 0;
    }

    rt->config.rpc_host = host;
    rt->config.rpc_port = port;
    rt->reconnect();

    std::cout << "Connecting " << name << " to "
              << host << ":" << port << "...\n";
    if (probeChain(*rt))
      std::cout << " Reachable.\n";
    else
      std::cout << " Not reachable. Check the daemon and try again.\n";
  }

  void cmd_open(WatcherSession &session,
                const std::vector<std::string> &args)
  {
    if (args.size() < 2)
    {
      std::cerr << "usage: open <path> [--password-file <path>]\n";
      return;
    }

    std::string path = args[1];
    std::string password_file;

    for (size_t i = 2; i < args.size(); ++i)
    {
      if (args[i] == "--password-file" && i + 1 < args.size())
      {
        password_file = args[++i];
      }
      else
      {
        std::cerr << "error: unknown argument '" << args[i] << "'\n";
        return;
      }
    }

    openKeystore(session, path, password_file);
  }

  void cmd_close(WatcherSession &session,
                 const std::vector<std::string> &args)
  {
    (void)args;
    closeKeystore(session);
  }

  void cmd_help(WatcherSession &session,
                const std::vector<std::string> &args)
  {
    (void)session;

    if (args.size() >= 2)
    {
      const Command *c = findCommand(args[1]);
      if (c == nullptr)
      {
        std::cerr << "error: no such command '" << args[1] << "'\n";
        return;
      }
      std::cout << c->usage << "\n\n"
                << c->help << "\n";
      return;
    }

    std::cout << "Commands:\n\n";
    for (const Command *c = commandTable(); c->name != nullptr; ++c)
    {
      if (std::string(c->name) == "quit")
        continue;
      std::cout << " " << c->usage << "\n";
    }
    std::cout << "\nType 'help <command>' for details.\n";
  }

  void cmd_exit(WatcherSession &session,
                const std::vector<std::string> &args)
  {
    (void)args;

    requestStopAllScans();

    session.running = false;
  }

} // namespace Bridge