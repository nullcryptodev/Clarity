// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Startup.h"
#include "Args.h"
#include "Adapters/ChainAdapter.h"
#include "Config.h"
#include "WatcherConfig.h"
#include "Session/Session.h"

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
  // Keystore discovery
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

    bool stepConnectClarity(WatcherSession &session, const Args &args)
    {
      section("Clarity RPC");

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
  // ===========================================================================

  namespace
  {
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
            return std::nullopt;
        }
        cfg.rpc_host = parsed->first;
        cfg.rpc_port = parsed->second;
      }
      else
      {
        std::cout << " RPC: " << cfg.rpc_host << ":" << cfg.rpc_port
                  << "\n";
      }

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

      cfg.state_subdir = short_name;

      applyAdapterDefaults(*adapter, cfg);

      // Give the adapter a chance to interpret transport-
      // specific fields (transport, mempool_url, mempool_api_key).
      // This runs after applyAdapterDefaults because the
      // transport override may make the rpc_host/rpc_port
      // irrelevant (a mempool config uses a URL, not a
      // host:port), and it runs before the probe so the probe
      // uses the configured transport rather than the default
      // (BitcoindRpc).
      if (cfg.raw_json.is_object())
        adapter->set_transport_config(cfg.raw_json);

      if (cfg.rpc_host.empty() || cfg.rpc_port == 0 ||
          cfg.confirmation_depth == 0)
      {
        std::cerr << "error: incomplete config for chain '"
                  << short_name << "'\n";
        return std::nullopt;
      }

      return cfg;
    }

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
  // Keystore selection / unlock
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
  // Watcher id prompt
  // ===========================================================================

  namespace
  {
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
        if (session.validator_id != 0)
          std::cout << " Validator id: " << session.validator_id << "\n";
        else
          std::cout << " Validator id: (unresolved — not a registered "
                       "validator yet)\n";
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

    if (!stepConnectClarity(session, args))
      return false;

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

    args.config.chains.clear();

    for (const auto &name : selected)
    {
      auto cfg = configureOneChain(name, args);
      if (!cfg.has_value())
        return false;
      args.config.chains.push_back(*cfg);
    }

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

    for (auto &c : args.config.chains)
    {
      c.state_subdir = c.chain_short_name;
    }
    if (!ensureChainStateDirs(args.config))
      return false;

    std::cout << " Ready: " << state_dir << "\n";

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

      if (rt->config.raw_json.is_object())
        rt->adapter->set_transport_config(rt->config.raw_json);
    }

    if (session.current_chain.empty() && !session.chains.empty())
    {
      if (!args.cli_chain_configs.empty())
        session.current_chain = args.cli_chain_configs.front().chain_short_name;
      else
        session.current_chain = session.chains.begin()->first;
    }

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
      }
    }

    if (session.hasKeystore())
    {
      section("Validator identity");
      if (session.validator_id != 0)
      {
        std::cout << " Resolved validator id: "
                  << session.validator_id << "\n";
      }
      else
      {
        std::cout << " Not a registered validator (yet).\n";
        std::cout << " The daemon will not attest to bridge deposits\n"
                  << " until its reward address is in the active set.\n"
                  << " Send RegisterValidator and restart, or let it\n"
                  << " pick up the id on the next connect.\n";
      }
    }

    printSummaryBanner(session);
    return true;
  }

} // namespace Bridge