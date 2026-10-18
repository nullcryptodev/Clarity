// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Args.h"

#include "ChainAdapter.h"
#include "GlobalConfig.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

namespace Bridge
{
  namespace
  {
    void parseEndpoint(const std::string &spec, const char *flag,
                       std::string &host_out, uint16_t &port_out)
    {
      const size_t colon = spec.find(':');
      if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size())
        throw std::runtime_error(std::string(flag) +
                                 ": expected host:port, got '" + spec + "'");

      const std::string host = spec.substr(0, colon);
      const std::string port_str = spec.substr(colon + 1);

      char *end = nullptr;
      const unsigned long port = std::strtoul(port_str.c_str(), &end, 10);
      if (end == port_str.c_str() || *end != '\0' || port == 0 || port > 65535)
        throw std::runtime_error(std::string(flag) +
                                 ": invalid port '" + port_str + "'");

      host_out = host;
      port_out = static_cast<uint16_t>(port);
    }

    void requireValue(int i, int argc, const char *flag)
    {
      if (i + 1 >= argc)
        throw std::runtime_error(std::string(flag) + ": missing value");
    }
  } // anonymous namespace

  Args parseArgs(int argc, char **argv)
  {
    Args args;

    for (int i = 1; i < argc; ++i)
    {
      const std::string a = argv[i];

      if (a == "-h" || a == "--help")
      {
        args.show_help = true;
        return args;
      }
      if (a == "--version")
      {
        args.show_version = true;
        return args;
      }
      if (a == "--list-chains")
      {
        args.list_chains = true;
        continue;
      }
      if (a == "--print-config")
      {
        args.print_config = true;
        continue;
      }

      if (a == "--app")
      {
        requireValue(i, argc, "--app");
        args.config.app_name = argv[++i];
        continue;
      }

      if (a == "--chain")
      {
        //  --chain <name> enables one chain and pre-populates its
        //  config with the adapter's defaults. If the operator
        //  passes --chain more than once, multiple chains are
        //  enabled and each gets its own ChainWatcherConfig.
        requireValue(i, argc, "--chain");
        const std::string name = argv[++i];

        auto adapter = ChainAdapterRegistry::find(name);
        if (!adapter)
          throw std::runtime_error("--chain: unknown chain '" + name +
                                   "' (use --list-chains to see the "
                                   "available adapters)");

        //  Reject duplicates.
        for (const auto &c : args.cli_chain_configs)
        {
          if (c.chain_short_name == name)
            throw std::runtime_error("--chain: chain '" + name +
                                     "' specified more than once");
        }

        ChainWatcherConfig cc;
        cc.chain_short_name = name;
        cc.enabled = true;
        cc.confirmation_depth = adapter->default_confirmation_depth();

        //  Parse the adapter's default RPC endpoint, which is
        //  "host:port" (the same shape the CLI accepts).
        std::string host;
        uint16_t port = 0;
        parseEndpoint(adapter->default_rpc_endpoint(), "--chain",
                      host, port);
        cc.rpc_host = host;
        cc.rpc_port = port;

        args.cli_chain_configs.push_back(std::move(cc));
        continue;
      }

      if (a == "--rpc-clarity")
      {
        requireValue(i, argc, "--rpc-clarity");
        parseEndpoint(argv[++i], "--rpc-clarity",
                      args.config.clarity_rpc_host,
                      args.config.clarity_rpc_port);
        continue;
      }

      if (a == "--rpc")
      {
        //  Per-chain RPC override. Requires a preceding --chain
        //  so the override has a target.
        requireValue(i, argc, "--rpc");
        if (args.cli_chain_configs.empty())
          throw std::runtime_error(
              "--rpc: must follow a --chain to identify which chain "
              "the RPC is for");
        parseEndpoint(argv[++i], "--rpc",
                      args.cli_chain_configs.back().rpc_host,
                      args.cli_chain_configs.back().rpc_port);
        continue;
      }

      if (a == "--confirmation-depth")
      {
        //  Per-chain override.
        requireValue(i, argc, "--confirmation-depth");
        if (args.cli_chain_configs.empty())
          throw std::runtime_error(
              "--confirmation-depth: must follow a --chain");
        char *end = nullptr;
        const unsigned long v = std::strtoul(argv[++i], &end, 10);
        if (end == argv[i] || *end != '\0' || v == 0 || v > 65535)
          throw std::runtime_error("--confirmation-depth: invalid value");
        args.cli_chain_configs.back().confirmation_depth =
            static_cast<uint16_t>(v);
        continue;
      }

      if (a == "--keystore")
      {
        requireValue(i, argc, "--keystore");
        args.config.keystore_path = argv[++i];
        continue;
      }

      if (a == "--password-file")
      {
        requireValue(i, argc, "--password-file");
        args.config.password_file = argv[++i];
        continue;
      }

      if (a == "--state-dir")
      {
        requireValue(i, argc, "--state-dir");
        args.config.state_dir = argv[++i];
        continue;
      }

      if (a == "--watcher-id")
      {
        requireValue(i, argc, "--watcher-id");
        char *end = nullptr;
        const unsigned long long v =
            std::strtoull(argv[++i], &end, 10);
        if (end == argv[i] || *end != '\0')
          throw std::runtime_error("--watcher-id: invalid value");
        args.config.watcher_id = static_cast<uint64_t>(v);
        continue;
      }

      if (a == "--log-level")
      {
        requireValue(i, argc, "--log-level");
        const std::string level = argv[++i];
        if (level != "trace" && level != "debug" && level != "info" &&
            level != "warn" && level != "error")
          throw std::runtime_error("--log-level: invalid level '" +
                                   level + "'");
        args.log_level = level;
        continue;
      }

      if (a == "--log-file")
      {
        requireValue(i, argc, "--log-file");
        args.log_file = argv[++i];
        continue;
      }

      throw std::runtime_error("unknown argument '" + a + "'");
    }

    return args;
  }

  void printVersion()
  {
    std::printf("%s %s\n",
                GlobalConfig::PROJECT_NAME,
                GlobalConfig::CLIENT_VERSION);
    std::printf("bridge app\n");
  }

  void printHelp(const char *argv0)
  {
    std::printf(
        "Usage: %s [options]\n"
        "\n"
        "Starts the Clarity bridge app. With no --chain flags, the\n"
        "startup wizard lists every compiled-in chain adapter and\n"
        "prompts you to enable one or more.\n"
        "\n"
        "Global options:\n"
        "  --app <name>                App name (default: clarity-bridge)\n"
        "  --rpc-clarity <host:port>   Clarity node RPC (default:\n"
        "                              127.0.0.1:9633)\n"
        "  --keystore <path>           Watcher keystore, shared across\n"
        "                              all enabled chains\n"
        "  --password-file <path>      Read keystore password from file\n"
        "  --state-dir <path>          Root state directory (default:\n"
        "                              ./bridge-state). Each chain's\n"
        "                              state is under <path>/<chain>/\n"
        "  --watcher-id <n>            Watcher id on Clarity; 0 means\n"
        "                              resolve from the keystore\n"
        "\n"
        "Per-chain options (each must follow its --chain):\n"
        "  --chain <name>              Enable a chain adapter. Repeat\n"
        "                              to enable multiple chains.\n"
        "  --rpc <host:port>           Source-chain daemon RPC for the\n"
        "                              preceding --chain\n"
        "  --confirmation-depth <n>    Override the adapter's default\n"
        "                              confirmation depth for the\n"
        "                              preceding --chain\n"
        "\n"
        "Discovery:\n"
        "  --list-chains               List every chain adapter compiled\n"
        "                              into this binary and exit\n"
        "\n"
        "Daemon options:\n"
        "  --log-level <level>         trace|debug|info|warn|error\n"
        "  --log-file <path>           Log to file instead of stderr\n"
        "  --print-config              Print resolved configuration and\n"
        "                              exit\n"
        "  -h, --help                  This message\n"
        "  --version                   Version information\n"
        "\n"
        "Once running, type 'help' at the prompt for commands.\n",
        argv0);
  }

  void printConfig(const Args &a)
  {
    std::printf("Bridge configuration:\n");
    std::printf("  app:                 %s\n", a.config.app_name.c_str());
    std::printf("  clarity rpc:         %s:%u\n",
                a.config.clarity_rpc_host.c_str(),
                a.config.clarity_rpc_port);
    std::printf("  keystore:            %s\n",
                a.config.keystore_path.empty()
                    ? "(none — wizard will prompt)"
                    : a.config.keystore_path.c_str());
    std::printf("  state dir:           %s\n", a.config.state_dir.c_str());
    std::printf("  watcher id:          %llu\n",
                static_cast<unsigned long long>(a.config.watcher_id));
    std::printf("  log level:           %s\n", a.log_level.c_str());
    std::printf("  log file:            %s\n",
                a.log_file.empty() ? "(stderr)" : a.log_file.c_str());

    std::printf("  chains:\n");
    if (a.cli_chain_configs.empty())
    {
      std::printf("    (none — wizard will prompt)\n");
    }
    else
    {
      for (const auto &c : a.cli_chain_configs)
      {
        std::printf("    %s:\n", c.chain_short_name.c_str());
        std::printf("      rpc:               %s:%u\n",
                    c.rpc_host.c_str(), c.rpc_port);
        std::printf("      confirmation:      %u\n",
                    static_cast<unsigned>(c.confirmation_depth));
      }
    }
  }

} // namespace Bridge