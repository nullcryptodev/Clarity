// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Startup.h"

#include "ChainAdapter.h"
#include "WatcherConfig.h"
#include "Session.h"

#include "Common/PasswordPrompt.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/RpcClient.h"
#include "Wallet/WalletError.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace Bridge
{

  namespace fs = std::filesystem;

  // ===========================================================================
  // Input helpers
  // ===========================================================================

  namespace
  {
    // Read a line from stdin with a prompt on stderr. Runs before
    // the linenoise REPL starts; plain std::getline is used.
    // Returns std::nullopt on EOF (Ctrl+D).
    std::optional<std::string> readInput(const char *prompt)
    {
      std::fputs(prompt, stderr);
      std::fflush(stderr);

      std::string line;
      if (!std::getline(std::cin, line))
        return std::nullopt;
      return line;
    }

    std::string trim(const std::string &s)
    {
      size_t b = 0, e = s.size();
      while (b < e && (s[b] == ' ' || s[b] == '\t' ||
                       s[b] == '\r' || s[b] == '\n'))
        ++b;
      while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' ||
                       s[e - 1] == '\r' || s[e - 1] == '\n'))
        --e;
      return s.substr(b, e - b);
    }

    void printRule()
    {
      std::cout << "───────────────────────────────────────────────\n";
    }

    void section(const char *title)
    {
      std::cout << "\n"
                << title << "\n";
    }

    // "host:port" parser for interactive prompts. The CLI one lives
    // in Args.cpp; this is the wizard's version, returning
    // std::nullopt on any malformation.
    std::optional<std::pair<std::string, uint16_t>>
    parseEndpointSpec(const std::string &spec)
    {
      const size_t colon = spec.find(':');
      if (colon == std::string::npos || colon == 0 ||
          colon + 1 >= spec.size())
        return std::nullopt;

      const std::string host = spec.substr(0, colon);
      const std::string port_str = spec.substr(colon + 1);

      char *end = nullptr;
      const unsigned long port = std::strtoul(port_str.c_str(), &end, 10);
      if (end == port_str.c_str() || *end != '\0' ||
          port == 0 || port > 65535)
        return std::nullopt;

      return std::make_pair(host, static_cast<uint16_t>(port));
    }

    // Prompt for a chain list separated by spaces or commas. Returns
    // the trimmed, comma/space-split tokens. Empty input yields an
    // empty vector.
    std::vector<std::string> parseChainList(const std::string &s)
    {
      std::vector<std::string> out;
      size_t start = 0;
      while (start < s.size())
      {
        while (start < s.size() &&
               (s[start] == ' ' || s[start] == '\t' ||
                s[start] == ',' || s[start] == '\r' || s[start] == '\n'))
          ++start;
        size_t end = start;
        while (end < s.size() &&
               !(s[end] == ' ' || s[end] == '\t' ||
                 s[end] == ',' || s[end] == '\r' || s[end] == '\n'))
          ++end;
        if (end > start)
          out.push_back(s.substr(start, end - start));
        start = end;
      }
      return out;
    }
  } // anonymous namespace

  // ===========================================================================
  // Keystore discovery (same as Wallet::Startup)
  // ===========================================================================

  namespace
  {
    struct DiscoveredKeystore
    {
      std::string path;
      std::string address;
      Wallet::Network network;
    };

    enum class ProbeResult
    {
      Ok,
      NotFound,
      NotAKeystore,
    };

    ProbeResult probeKeystore(const std::string &path,
                              DiscoveredKeystore &out)
    {
      std::error_code ec;
      if (!fs::is_regular_file(path, ec) || ec)
        return ProbeResult::NotFound;

      const auto size = fs::file_size(path, ec);
      if (ec || size > 1024 * 1024)
        return ProbeResult::NotAKeystore;

      Wallet::WalletStatus st;
      auto ks = Wallet::EncryptedKeyStore::open(path, &st);
      if (!ks.has_value())
        return ProbeResult::NotAKeystore;

      out.path = path;
      out.address = (*ks)->address();
      out.network = (*ks)->network();
      return ProbeResult::Ok;
    }

    std::vector<DiscoveredKeystore> discoverKeystoresIn(
        const std::string &directory)
    {
      std::vector<DiscoveredKeystore> found;
      std::error_code ec;
      for (const auto &entry : fs::directory_iterator(directory, ec))
      {
        if (ec)
          break;
        if (!entry.is_regular_file())
          continue;

        DiscoveredKeystore dk;
        if (probeKeystore(entry.path().string(), dk) == ProbeResult::Ok)
          found.push_back(std::move(dk));
      }
      std::sort(found.begin(), found.end(),
                [](const DiscoveredKeystore &a, const DiscoveredKeystore &b)
                { return a.path < b.path; });
      return found;
    }

    std::vector<DiscoveredKeystore> discoverKeystores()
    {
      return discoverKeystoresIn(fs::current_path().string());
    }
  } // anonymous namespace

  // ===========================================================================
  // Clarity RPC connection
  // ===========================================================================

  namespace
  {
    bool probeClarity(Wallet::RpcClient &rpc)
    {
      Common::Json params = Common::Json::object();
      auto result = rpc.call("chainId", params);
      return result.ok();
    }

    // Step 1: Clarity RPC. Same prompt shape as the wallet's
    // stepConnect, with wording adapted for the bridge.
    bool stepConnectClarity(WatcherSession &session, const Args &args)
    {
      section("Clarity RPC");

      // If the CLI supplied an endpoint, use it. Otherwise the
      // session's default is 127.0.0.1:9633.
      session.clarity_endpoint.host = args.config.clarity_rpc_host;
      session.clarity_endpoint.port = args.config.clarity_rpc_port;
      session.clarity_endpoint.user = args.config.clarity_rpc_user;
      session.clarity_endpoint.password = args.config.clarity_rpc_password;
      session.clarity_rpc =
          std::make_unique<Wallet::RpcClient>(session.clarity_endpoint);

      while (true)
      {
        std::cout << "Connecting to "
                  << session.clarity_endpoint.host << ":"
                  << session.clarity_endpoint.port << "...\n";

        if (probeClarity(*session.clarity_rpc))
        {
          std::cout << " Connected.\n";
          session.clarity_connected = true;
          return true;
        }

        std::cout << " Could not connect.\n\n";
        std::cout << " [r] Retry\n";
        std::cout << " [c] Connect to a different endpoint\n";
        std::cout << " [s] Skip — continue offline\n";

        auto choice = readInput("Choice [r/c/s]: ");
        if (!choice.has_value())
          return false;

        std::string c = trim(*choice);
        if (c == "r" || c == "R" || c.empty())
          continue;

        if (c == "c" || c == "C")
        {
          auto line = readInput("Clarity endpoint (host:port): ");
          if (!line.has_value())
            return false;
          auto parsed = parseEndpointSpec(trim(*line));
          if (!parsed.has_value())
          {
            std::cerr << " Invalid format.\n";
            continue;
          }
          session.clarity_endpoint.host = parsed->first;
          session.clarity_endpoint.port = parsed->second;
          session.clarity_rpc =
              std::make_unique<Wallet::RpcClient>(session.clarity_endpoint);
          continue;
        }

        if (c == "s" || c == "S" || c == "skip")
        {
          std::cout << " Continuing offline. Use 'connect <host:port>' "
                       "when ready.\n";
          session.clarity_connected = false;
          return true;
        }

        std::cerr << " Unrecognized choice. Try again.\n";
      }
    }
  } // anonymous namespace

  // ===========================================================================
  // Chain selection
  //
  // Enumerate the adapters compiled into the binary (via the
  // registry). If the CLI already pre-selected chains, honor them
  // and skip the prompt; otherwise the operator picks a subset
  // by short_name.
  // ===========================================================================

  namespace
  {
    // Print the available adapter list, one per line, with its
    // short name (for typing) and full name.
    void listAdapters()
    {
      auto adapters = ChainAdapterRegistry::all();
      std::cout << "Available chain adapters (" << adapters.size()
                << "):\n\n";
      for (size_t i = 0; i < adapters.size(); ++i)
      {
        std::cout << " [" << (i + 1) << "] "
                  << adapters[i]->short_name()
                  << " — " << adapters[i]->name() << "\n";
        std::cout << " rpc: " << adapters[i]->default_rpc_endpoint()
                  << ", confirmations: "
                  << adapters[i]->default_confirmation_depth() << "\n";
      }
      std::cout << "\n";
    }

    // Prompt for chain selection. Returns the list of short_names
    // the operator chose. On EOF, returns nullopt.
    //
    // Empty input means "nothing enabled" — the operator can
    // still open a keystore, but the session will have no active
    // chains and status will say so. That's a valid state: a
    // watcher that is only there for the summary banner, or a
    // first-run operator who wants to see help before
    // committing to a chain.
    std::optional<std::vector<std::string>> promptChainSelection()
    {
      auto adapters = ChainAdapterRegistry::all();
      if (adapters.empty())
      {
        std::cout << "No chain adapters compiled into this binary.\n";
        std::cout << "(Rebuild with -DBRIDGE_ENABLE_CCX=ON or similar.)\n";
        return std::vector<std::string>{};
      }

      listAdapters();
      std::cout << " Enter one or more short names, space- or comma-"
                   "separated.\n";
      std::cout << " Press Enter to skip (no chains enabled).\n\n";

      auto line = readInput("Chains: ");
      if (!line.has_value())
        return std::nullopt;

      auto names = parseChainList(trim(*line));
      if (names.empty())
        return names;

      // Validate every name against the registry. If any is
      // unknown, print the bad name and reprompt once; a second
      // bad input is treated as "no chains".
      for (const auto &n : names)
      {
        if (!ChainAdapterRegistry::find(n))
        {
          std::cerr << " Unknown chain '" << n
                    << "'. Available: ";
          for (size_t i = 0; i < adapters.size(); ++i)
          {
            if (i > 0)
              std::cerr << ", ";
            std::cerr << adapters[i]->short_name();
          }
          std::cerr << "\n";
          return std::vector<std::string>{};
        }
      }
      return names;
    }

    // Apply the CLI-provided per-chain config to a ChainWatcherConfig.
    // The CLI's Args::cli_chain_configs is keyed implicitly by
    // position (each --chain produces one entry). We match by
    // chain_short_name.
    std::optional<ChainWatcherConfig> findCliChainConfig(
        const Args &args, const std::string &short_name)
    {
      for (const auto &c : args.cli_chain_configs)
      {
        if (c.chain_short_name == short_name)
          return c;
      }
      return std::nullopt;
    }
  } // anonymous namespace

  // ===========================================================================
  // Per-chain configuration
  //
  // For each selected chain, produce a complete ChainWatcherConfig.
  // Sources, in order of preference:
  //
  // 1. The CLI's --chain (with any --rpc, --confirmation-depth
  // overrides that came after it).
  // 2. The adapter's defaults, with prompts for the two fields
  // the operator can meaningfully adjust.
  // ===========================================================================

  namespace
  {
    std::optional<ChainWatcherConfig> configureOneChain(
        const std::string &short_name, const Args &args)
    {
      auto adapter = ChainAdapterRegistry::find(short_name);
      if (!adapter)
      {
        std::cerr << "error: unknown chain '" << short_name << "'\n";
        return std::nullopt;
      }

      section(("Configure " + adapter->name()).c_str());

      // Start from the CLI config if present; otherwise from the
      // adapter defaults.
      ChainWatcherConfig cfg;
      auto cli_cfg = findCliChainConfig(args, short_name);
      if (cli_cfg.has_value())
      {
        cfg = *cli_cfg;
        std::cout << " Using CLI defaults for " << short_name << ".\n";
      }
      else
      {
        cfg.chain_short_name = short_name;
        cfg.enabled = true;
      }

      // RPC endpoint: prompt only if still unset.
      if (cfg.rpc_host.empty() || cfg.rpc_port == 0)
      {
        const std::string default_ep = adapter->default_rpc_endpoint();
        const std::string prompt =
            " Source-chain RPC [" + default_ep + "]: ";
        auto line = readInput(prompt.c_str());
        if (!line.has_value())
          return std::nullopt;

        std::string spec = trim(*line);
        if (spec.empty())
          spec = default_ep;

        auto parsed = parseEndpointSpec(spec);
        if (!parsed.has_value())
        {
          std::cerr << " Invalid endpoint format. Using default.\n";
          parsed = parseEndpointSpec(default_ep);
          if (!parsed.has_value())
            return std::nullopt; // adapter default is broken
        }
        cfg.rpc_host = parsed->first;
        cfg.rpc_port = parsed->second;
      }
      else
      {
        std::cout << " RPC: " << cfg.rpc_host << ":" << cfg.rpc_port
                  << "\n";
      }

      // Confirmation depth: prompt only if still zero.
      if (cfg.confirmation_depth == 0)
      {
        const uint16_t default_depth = adapter->default_confirmation_depth();
        const std::string prompt =
            " Confirmations required [" +
            std::to_string(default_depth) + "]: ";
        auto line = readInput(prompt.c_str());
        if (!line.has_value())
          return std::nullopt;

        std::string s = trim(*line);
        if (s.empty())
        {
          cfg.confirmation_depth = default_depth;
        }
        else
        {
          char *end = nullptr;
          const unsigned long v = std::strtoul(s.c_str(), &end, 10);
          if (end == s.c_str() || *end != '\0' || v == 0 || v > 65535)
          {
            std::cerr << " Invalid depth. Using default.\n";
            cfg.confirmation_depth = default_depth;
          }
          else
          {
            cfg.confirmation_depth = static_cast<uint16_t>(v);
          }
        }
      }
      else
      {
        std::cout << " Confirmations: " << cfg.confirmation_depth << "\n";
      }

      // State subdir: derived from the root state dir + chain
      // short_name. The root is the CLI/session default unless
      // overridden; see step "state directory" below.
      cfg.state_subdir = short_name;

      // Fill any last gaps from the adapter. If the operator
      // skipped prompting (Ctrl+D handled above), the defaults
      // apply.
      applyAdapterDefaults(*adapter, cfg);

      // Final validation: make sure the config is complete. If it
      // still isn't, that's a programming error — bail.
      if (cfg.rpc_host.empty() || cfg.rpc_port == 0 ||
          cfg.confirmation_depth == 0)
      {
        std::cerr << "error: incomplete config for chain '"
                  << short_name << "'\n";
        return std::nullopt;
      }

      return cfg;
    }

    // Probe a configured chain's source RPC and report. Returns
    // true if reachable. A false result is not fatal; the wizard
    // continues and the runtime is marked not-connected.
    bool probeConfiguredChain(ChainWatcherConfig &cfg,
                              const ChainAdapter &adapter,
                              Wallet::RpcClient &rpc)
    {
      std::string err;
      if (adapter.probe_rpc(rpc, &err))
      {
        std::cout << " Connected.\n";
        return true;
      }
      std::cout << " Not reachable";
      if (!err.empty())
        std::cout << " (" << err << ")";
      std::cout << ". Use 'connect " << cfg.chain_short_name
                << " <host:port>' later.\n";
      return false;
    }
  } // anonymous namespace

  // ===========================================================================
  // Keystore selection / unlock (same shape as Wallet::Startup)
  // ===========================================================================

  namespace
  {
    std::optional<std::string> promptForKeystorePath()
    {
      auto line = readInput("Keystore path: ");
      if (!line.has_value())
        return std::nullopt;

      std::string path = expandHome(trim(*line));
      if (path.empty())
        return std::string();

      // Directory: scan inside.
      std::error_code ec;
      if (fs::is_directory(path, ec) && !ec)
      {
        auto found = discoverKeystoresIn(path);
        if (found.empty())
        {
          std::cerr << " No keystores found in " << path << "\n";
          return std::string();
        }
        if (found.size() == 1)
        {
          std::cout << " Found one keystore: " << found[0].path << "\n";
          return found[0].path;
        }

        std::cout << " Found " << found.size() << " keystores:\n\n";
        for (size_t i = 0; i < found.size(); ++i)
        {
          std::cout << " [" << (i + 1) << "] " << found[i].path << "\n";
          std::cout << " " << found[i].address << "\n";
        }
        std::cout << "\n";

        auto choice = readInput(" Choice: ");
        if (!choice.has_value())
          return std::nullopt;

        const std::string c = trim(*choice);
        char *end = nullptr;
        const unsigned long idx = std::strtoul(c.c_str(), &end, 10);
        if (end != c.c_str() && *end == '\0' &&
            idx >= 1 && idx <= found.size())
        {
          return found[idx - 1].path;
        }
        std::cerr << " Invalid choice.\n";
        return std::string();
      }
      return path;
    }

    std::optional<std::string> promptKeystoreChoice(
        const std::vector<DiscoveredKeystore> &found)
    {
      std::cout << "Found " << found.size() << " keystore"
                << (found.size() == 1 ? "" : "s") << " in "
                << fs::current_path().string() << ":\n\n";

      for (size_t i = 0; i < found.size(); ++i)
      {
        std::cout << " [" << (i + 1) << "] " << found[i].path << "\n";
        std::cout << " " << found[i].address
                  << " (" << Wallet::networkName(found[i].network)
                  << ")\n";
      }

      std::cout << "\n [o] Open a different path\n";
      std::cout << " [s] Skip — no keystore for now\n";

      auto line = readInput("Choice: ");
      if (!line.has_value())
        return std::nullopt;

      const std::string c = trim(*line);
      if (c.empty())
        return std::string();

      char *end = nullptr;
      const unsigned long idx = std::strtoul(c.c_str(), &end, 10);
      if (end != c.c_str() && *end == '\0' &&
          idx >= 1 && idx <= found.size())
        return found[idx - 1].path;

      if (c == "o" || c == "O")
        return promptForKeystorePath();

      if (c == "s" || c == "S" || c == "skip")
        return std::string();

      std::cerr << " Unrecognized choice.\n";
      return std::string();
    }

    std::optional<std::string> selectKeystore()
    {
      auto found = discoverKeystores();
      if (found.empty())
      {
        section("Keystore");
        std::cout << "No keystores found in "
                  << fs::current_path().string() << ".\n\n";
        std::cout << " [o] Open a keystore by path\n";
        std::cout << " [s] Skip — no keystore for now\n";

        auto line = readInput("Choice [o/s]: ");
        if (!line.has_value())
          return std::nullopt;

        const std::string c = trim(*line);
        if (c == "o" || c == "O" || c == "open")
          return promptForKeystorePath();
        if (c == "s" || c == "S" || c == "skip" || c.empty())
          return std::string();
        std::cerr << " Unrecognized choice.\n";
        return std::string();
      }

      section("Keystore");
      return promptKeystoreChoice(found);
    }

    std::optional<bool> confirmKeystore(const std::string &path)
    {
      DiscoveredKeystore dk;
      const ProbeResult r = probeKeystore(path, dk);
      switch (r)
      {
      case ProbeResult::NotFound:
      {
        std::error_code ec;
        if (fs::is_directory(path, ec) && !ec)
          std::cerr << " Path is a directory: " << path << "\n";
        else
          std::cerr << " No such file: " << path << "\n";
        return false;
      }
      case ProbeResult::NotAKeystore:
        std::cerr << " Not a valid keystore: " << path << "\n";
        return false;
      case ProbeResult::Ok:
        break;
      }

      std::cout << "\n";
      std::cout << " Path: " << dk.path << "\n";
      std::cout << " Address: " << dk.address << "\n";
      std::cout << " Network: " << Wallet::networkName(dk.network) << "\n";

      auto line = readInput("\nUse this keystore? [y/n]: ");
      if (!line.has_value())
        return std::nullopt;

      const std::string c = trim(*line);
      return (c == "y" || c == "Y" || c == "yes" || c.empty());
    }
  } // anonymous namespace

  // ===========================================================================
  // Watcher id prompt (only if the RPC-based resolution can't find it)
  // ===========================================================================

  namespace
  {
    // Ask the operator for the watcher id. The RPC method to
    // resolve it automatically doesn't exist yet, so this prompt
    // is the v1 path. An empty answer leaves watcher_id at 0
    // (unresolved); the operator can still use most commands.
    //
    // Returns std::nullopt on EOF, or the entered value (or 0).
    std::optional<uint64_t> promptWatcherId(uint64_t current)
    {
      std::cout << "\n";
      std::cout << " Watcher id on Clarity. You can find this in the\n";
      std::cout << " receipt of your RegisterBridgeWatcher transaction,\n";
      std::cout << " or ask the node operator. Leave blank to set it later.\n";
      std::cout << "\n";

      const std::string prompt =
          " Watcher id [" +
          (current != 0 ? std::to_string(current) : std::string("0")) +
          "]: ";
      auto line = readInput(prompt.c_str());
      if (!line.has_value())
        return std::nullopt;

      const std::string s = trim(*line);
      if (s.empty())
        return current;

      char *end = nullptr;
      const unsigned long long v = std::strtoull(s.c_str(), &end, 10);
      if (end == s.c_str() || *end != '\0')
      {
        std::cerr << " Invalid integer. Leaving unset.\n";
        return current;
      }
      return static_cast<uint64_t>(v);
    }
  } // anonymous namespace

  // ===========================================================================
  // Summary banner
  // ===========================================================================

  namespace
  {
    void printSummaryBanner(const WatcherSession &session)
    {
      std::cout << "\n";
      printRule();
      std::cout << "Clarity bridge app\n\n";

      if (session.hasKeystore())
      {
        std::cout << " Keystore: " << session.address_bech32m << "\n";
        if (session.watcher_id != 0)
          std::cout << " Watcher id: " << session.watcher_id << "\n";
        else
          std::cout << " Watcher id: (unresolved)\n";
      }
      else
      {
        std::cout << " Keystore: (none)\n";
      }

      if (session.clarity_connected)
      {
        std::cout << " Clarity: connected to "
                  << session.clarity_endpoint.host << ":"
                  << session.clarity_endpoint.port << "\n";
      }
      else
      {
        std::cout << " Clarity: offline\n";
      }

      std::cout << "\n Chains:\n";
      if (session.chains.empty())
      {
        std::cout << " (none enabled)\n";
      }
      else
      {
        // Sort for stable output.
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
          std::cout << " " << n << " (" << rt.chain_display_name()
                    << ")\n";
          std::cout << " rpc: " << rt.config.rpc_host
                    << ":" << rt.config.rpc_port;
          std::cout << (rt.connected ? " [reachable]"
                                     : " [not reachable]")
                    << "\n";
          std::cout << " confirmations: " << rt.config.confirmation_depth
                    << "\n";
          if (rt.running)
            std::cout << " status: running\n";
          else
            std::cout << " status: stopped\n";
        }
      }

      std::cout << "\nType 'help' for commands, 'exit' to quit.\n";
      printRule();
      std::cout << "\n";
    }
  } // anonymous namespace

  // ===========================================================================
  // The wizard
  // ===========================================================================

  bool runStartupWizard(WatcherSession &session, Args &args)
  {
    printRule();
    std::cout << "Clarity bridge — setup\n";

    // ---- Step 1: Clarity RPC ----
    if (!stepConnectClarity(session, args))
      return false;

    // ---- Step 2: chain selection ----
    //
    // If the CLI already enabled chains (via --chain), those are
    // authoritative — no prompt. Otherwise list the adapters and
    // ask. selected holds the short names the operator chose.
    std::vector<std::string> selected;

    if (!args.cli_chain_configs.empty())
    {
      section("Chains (from CLI)");
      for (const auto &c : args.cli_chain_configs)
      {
        std::cout << " " << c.chain_short_name << "\n";
        selected.push_back(c.chain_short_name);
      }
    }
    else
    {
      section("Chains");
      auto picked = promptChainSelection();
      if (!picked.has_value())
        return false;
      selected = std::move(*picked);
    }

    if (selected.empty())
    {
      std::cout << "\n No chains enabled. You can enable one later\n"
                << " with 'enable <chain>' at the prompt.\n";
    }

    // ---- Step 3: per-chain configuration ----
    //
    // Build the WatcherConfig here, then hand it to session.enableChain
    // for each chain in order. Config lives on the session (as
    // args.config) so later commands can read it.
    args.config.chains.clear();

    for (const auto &name : selected)
    {
      auto cfg = configureOneChain(name, args);
      if (!cfg.has_value())
        return false;
      args.config.chains.push_back(*cfg);
    }

    // ---- Step 4: state directory ----
    section("State directory");

    std::string state_dir = args.config.state_dir;
    if (state_dir.empty())
    {
      auto line = readInput("State directory [./bridge-state]: ");
      if (!line.has_value())
        return false;
      state_dir = trim(*line);
      if (state_dir.empty())
        state_dir = "./bridge-state";
    }
    else
    {
      std::cout << " Using CLI value: " << state_dir << "\n";
    }

    state_dir = expandHome(state_dir);
    if (!ensureStateRoot(state_dir))
      return false;
    args.config.state_dir = state_dir;

    // Now that the root is final, fill each chain's full path.
    for (auto &c : args.config.chains)
    {
      c.state_subdir = c.chain_short_name;
    }
    if (!ensureChainStateDirs(args.config))
      return false;

    std::cout << " Ready: " << state_dir << "\n";

    // ---- Step 5: enable the chains on the session ----
    //
    // enableChain creates the RPC client and inserts the runtime
    // into the map. We do this BEFORE probing so the runtime
    // exists to hold the connected flag.
    for (const auto &cfg : args.config.chains)
    {
      auto adapter = ChainAdapterRegistry::find(cfg.chain_short_name);
      if (!adapter)
      {
        std::cerr << "error: adapter vanished for '"
                  << cfg.chain_short_name << "'\n";
        return false;
      }
      auto *rt = session.enableChain(adapter, cfg);
      if (!rt)
      {
        std::cerr << "error: enableChain failed for '"
                  << cfg.chain_short_name << "'\n";
        return false;
      }
    }

    // Select the first enabled chain as current.
    if (session.current_chain.empty() && !session.chains.empty())
    {
      // Prefer the CLI's first --chain, if any.
      if (!args.cli_chain_configs.empty())
        session.current_chain = args.cli_chain_configs.front().chain_short_name;
      else
        session.current_chain = session.chains.begin()->first;
    }

    // ---- Step 6: probe each enabled chain ----
    if (!session.chains.empty())
    {
      section("Probing source chains");
      for (auto &[name, rt] : session.chains)
      {
        if (!rt.enabled)
          continue;
        std::cout << " " << name << " ("
                  << rt.chain_display_name() << ") at "
                  << rt.config.rpc_host << ":" << rt.config.rpc_port
                  << "...\n";
        probeChain(rt);
      }
    }

    // ---- Step 7: keystore ----
    //
    // If --keystore was supplied, open it directly (with retry on
    // wrong password). Otherwise discover + select + unlock with
    // the same shape as the wallet's wizard.
    if (!args.config.keystore_path.empty())
    {
      section("Keystore");
      std::cout << "Opening provided keystore: "
                << args.config.keystore_path << "\n";

      while (true)
      {
        if (openKeystore(session, args.config.keystore_path,
                         args.config.password_file))
          break;

        std::cout << "\n [r] Retry password\n";
        std::cout << " [a] Abort — continue without a keystore\n";

        auto line = readInput("Choice [r/a]: ");
        if (!line.has_value())
          return false;

        const std::string c = trim(*line);
        if (c == "a" || c == "A" || c == "abort")
        {
          std::cout << " Continuing without a keystore.\n";
          break;
        }
        // Retry is the default.
      }
    }
    else
    {
      section("Keystore");
      std::string chosen_path;
      while (true)
      {
        auto result = selectKeystore();
        if (!result.has_value())
          return false;
        chosen_path = *result;
        if (chosen_path.empty())
        {
          std::cout << "\n No keystore opened. Use 'open <path>' later.\n";
          break;
        }

        auto confirmed = confirmKeystore(chosen_path);
        if (!confirmed.has_value())
          return false;
        if (!*confirmed)
          continue;

        if (openKeystore(session, chosen_path, ""))
          break;

        std::cout << "\n [r] Retry password\n";
        std::cout << " [b] Back to keystore selection\n";

        auto line = readInput("Choice [r/b]: ");
        if (!line.has_value())
          return false;

        const std::string c = trim(*line);
        if (c == "b" || c == "B" || c == "back")
          continue;
        // Retry is the default; loop back and try again.
      }
    }

    // ---- Step 8: watcher id ----
    //
    // If the operator opened a keystore and the CLI didn't already
    // supply --watcher-id, and the RPC-based resolution didn't
    // find one (it can't yet — resolveWatcherId is stubbed), prompt.
    // Empty answer leaves watcher_id at 0.
    if (session.hasKeystore() && session.watcher_id == 0)
    {
      section("Watcher id");
      if (args.config.watcher_id != 0)
      {
        session.watcher_id = args.config.watcher_id;
        std::cout << " Using CLI value: " << session.watcher_id << "\n";
      }
      else
      {
        auto id = promptWatcherId(0);
        if (!id.has_value())
          return false;
        session.watcher_id = *id;
        if (session.watcher_id == 0)
          std::cout << " Left unset. Use 'state watcher' after your\n"
                    << " RegisterBridgeWatcher transaction confirms.\n";
      }
    }

    // ---- Step 9: summary ----
    printSummaryBanner(session);
    return true;
  }

  bool ensureStateRoot(const std::string &path)
  {
    std::error_code ec;
    if (fs::exists(path, ec))
    {
      if (!fs::is_directory(path, ec) || ec)
      {
        std::cerr << "error: state path exists but is not a directory: "
                  << path << "\n";
        return false;
      }
      return true;
    }
    fs::create_directories(path, ec);
    if (ec)
    {
      std::cerr << "error: cannot create state dir " << path
                << ": " << ec.message() << "\n";
      return false;
    }
    return true;
  }

  bool ensureChainStateDirs(const WatcherConfig &cfg)
  {
    for (const auto &c : cfg.chains)
    {
      const fs::path full =
          fs::path(cfg.state_dir) / c.state_subdir;
      std::error_code ec;
      fs::create_directories(full, ec);
      if (ec)
      {
        std::cerr << "error: cannot create chain state dir "
                  << full.string() << ": " << ec.message() << "\n";
        return false;
      }
    }
    return true;
  }

  std::string expandHome(const std::string &path)
  {
    if (path.empty() || path[0] != '~')
      return path;
    const char *home = std::getenv("HOME");
    if (!home)
      return path;
    return std::string(home) + path.substr(1);
  }
} // namespace Bridge