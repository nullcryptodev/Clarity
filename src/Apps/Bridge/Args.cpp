// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Args.h"

#include "ChainAdapter.h"
#include "Commands.h"
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

    //  Read a password file and trim a single trailing newline.
    //  Password files are almost always written by `echo` or an
    //  editor, both of which add one; operators always trip on
    //  it if we don't strip it. Only one trailing newline (or
    //  CRLF) is stripped — embedded newlines stay, so a
    //  multi-line passphrase still works.
    std::string readPasswordFile(const std::string &path, const char *flag)
    {
      std::FILE *f = std::fopen(path.c_str(), "rb");
      if (!f)
        throw std::runtime_error(std::string(flag) +
                                 ": cannot open '" + path + "'");

      std::string contents;
      char buf[256];
      size_t n;
      while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        contents.append(buf, n);
      std::fclose(f);

      while (!contents.empty() &&
             (contents.back() == '\n' || contents.back() == '\r'))
        contents.pop_back();

      return contents;
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
      if (a == "--no-wizard")
      {
        args.no_wizard = true;
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

      // todo remove
      if (a == "--mint-destination")
      {
        requireValue(i, argc, "--mint-destination");
        args.config.mint_destination = argv[++i];
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

      if (a == "--clarity-rpc-user")
      {
        requireValue(i, argc, "--clarity-rpc-user");
        args.config.clarity_rpc_user = argv[++i];
        continue;
      }

      if (a == "--clarity-rpc-password-file")
      {
        requireValue(i, argc, "--clarity-rpc-password-file");
        args.config.clarity_rpc_password =
            readPasswordFile(argv[++i], "--clarity-rpc-password-file");
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

      if (a == "--rpc-user")
      {
        requireValue(i, argc, "--rpc-user");
        if (args.cli_chain_configs.empty())
          throw std::runtime_error(
              "--rpc-user: must follow a --chain to identify which "
              "chain the credentials are for");
        args.cli_chain_configs.back().rpc_user = argv[++i];
        continue;
      }

      if (a == "--rpc-password-file")
      {
        requireValue(i, argc, "--rpc-password-file");
        if (args.cli_chain_configs.empty())
          throw std::runtime_error(
              "--rpc-password-file: must follow a --chain");
        args.cli_chain_configs.back().rpc_password =
            readPasswordFile(argv[++i], "--rpc-password-file");
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

      //  ---- --consensus-key-file ----
      //
      //  Loads the validator's consensus signing key from a
      //  file. The file contains a single 32-byte secret key as
      //  64 hex characters (optionally 0x-prefixed, whitespace-
      //  trimmed). Used by SubmitAttestation to sign BridgeAttest
      //  transactions.
      //
      //  Required when the validator's registered consensus key
      //  differs from the keystore's default-path (0/0/0) key.
      //  When absent, the bridge falls back to the keystore's
      //  default-path key — which only produces a valid
      //  attestation signature if that is the same key.
      if (a == "--consensus-key-file")
      {
        requireValue(i, argc, "--consensus-key-file");
        args.config.consensus_key_file = argv[++i];
        continue;
      }

      //  ---- --view-key-file ----
      //
      //  Loads the custody wallet's private view key from a file.
      //  Same format as --consensus-key-file: 64 hex chars,
      //  optional 0x prefix, optional trailing newline.
      //
      //  Used by CcxAdapter to compute the per-tx shared secret
      //  (Crypto::generateKeyDerivation) and thereby identify
      //  which vout of a scanned deposit pays to the custody
      //  address. Without it, scan_deposits falls back to
      //  sum-of-outputs and mints the wrong amount.
      //
      //  The corresponding spend pubkey is not a flag: it's the
      //  first 32 bytes of the decoded --bridge-address, so the
      //  adapter derives it from the address it already has.
      if (a == "--view-key-file")
      {
        requireValue(i, argc, "--view-key-file");
        args.config.view_key_file = argv[++i];
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

      if (a == "--command")
      {
        requireValue(i, argc, "--command");
        const std::string name = argv[++i];

        //  Validate against the command table now so a typo
        //  fails fast, before any RPC probe or keystore prompt.
        //  A service manager should not see the daemon "start"
        //  and then discover the command was garbage.
        if (!findCommand(name))
          throw std::runtime_error(
              "--command: unknown command '" + name +
              "' (use the REPL 'help' to list commands)");

        args.command = name;
        continue;
      }

      //  Positional token, only meaningful when --command has
      //  been seen. Collected as command_args in order. Anything
      //  that doesn't start with "--" and arrives after
      //  "--command <name>" ends up here.
      if (a.rfind("--", 0) != 0 && !args.command.empty())
      {
        args.command_args.push_back(a);
        continue;
      }

      throw std::runtime_error("unknown argument '" + a + "'");
    }

    //  Validate mode combinations at the end, after every flag
    //  has been seen. This lets --command appear before or after
    //  --no-wizard without ordering mattering.

    if (args.no_wizard)
    {
      //  Read-only one-shot commands (status, chains, deposits,
      //  withdrawals, pending, help, version) don't need a
      //  keystore or a chain — they just report what's already in
      //  the session, which may be empty. `start` and the default
      //  REPL case do need both.
      const bool read_only_command =
          !args.command.empty() && args.command != "start";

      if (!read_only_command)
      {
        if (args.config.keystore_path.empty())
          throw std::runtime_error(
              "--no-wizard: --keystore is required");
        if (args.cli_chain_configs.empty())
          throw std::runtime_error(
              "--no-wizard: at least one --chain is required");
      }
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
        "  --consensus-key-file <path> Load the validator's consensus\n"
        "                              signing key from <path>. The file\n"
        "                              must contain a single 32-byte\n"
        "                              Ed25519 secret key as 64 hex chars\n"
        "                              (0x prefix and trailing newline\n"
        "                              are allowed). Required when the\n"
        "                              validator's registered consensus\n"
        "                              key differs from the keystore's\n"
        "                              default-path key. Without it, the\n"
        "                              bridge falls back to the keystore's\n"
        "                              0/0/0 key — which only signs a valid\n"
        "                              attestation if that is the same key.\n"
        "  --view-key-file <path>      Load the custody wallet's private\n"
        "                              view key from <path>. Same format\n"
        "                              as --consensus-key-file (64 hex\n"
        "                              chars, optional 0x prefix, whitespace\n"
        "                              trimmed). Used by the CCX adapter to\n"
        "                              identify which vout of a deposit\n"
        "                              pays to the custody address. Without\n"
        "                              it, the bridge falls back to a\n"
        "                              sum-of-outputs approximation and\n"
        "                              mints an incorrect (too-large)\n"
        "                              amount for each deposit.\n"
        "  --state-dir <path>          Root state directory (default:\n"
        "                              ./bridge-state). Each chain's\n"
        "                              state is under <path>/<chain>/\n"
        "  --watcher-id <n>            Watcher id on Clarity; 0 means\n"
        "                              resolve from the keystore\n"
        "  --clarity-rpc-user <user>   Optional Basic auth user for the\n"
        "                              Clarity RPC\n"
        "  --clarity-rpc-password-file <path>\n"
        "                              Read the Clarity RPC password\n"
        "                              from a file (trailing newline\n"
        "                              is trimmed)\n"
        "  TLS: clarity-bridge speaks plain HTTP to its RPC\n"
        "      endpoints. To reach a remote node over TLS, run a\n"
        "      reverse proxy (nginx, Caddy, haproxy) in front of\n"
        "      the node's RPC and point --rpc-clarity / --rpc at\n"
        "      the proxy's loopback listener.\n"
        "\n"
        "Per-chain options (each must follow its --chain):\n"
        "  --chain <name>              Enable a chain adapter. Repeat\n"
        "                              to enable multiple chains.\n"
        "  --rpc <host:port>           Source-chain daemon RPC for the\n"
        "                              preceding --chain\n"
        "  --confirmation-depth <n>    Override the adapter's default\n"
        "                              confirmation depth for the\n"
        "                              preceding --chain\n"
        "  --rpc-user <user>           Optional Basic auth user for the\n"
        "                              preceding --chain's RPC\n"
        "  --rpc-password-file <path>  Read the preceding --chain's RPC\n"
        "                              password from a file\n"
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
        "  --no-wizard                 Skip the interactive wizard; all\n"
        "                              required fields must be on the\n"
        "                              command line (--keystore and\n"
        "                              at least one --chain), unless a\n"
        "                              read-only --command is also set\n"
        "  --command <name> [args...]  Run one command and exit. Use\n"
        "                              'start' to run as a foreground\n"
        "                              service (blocks until SIGINT or\n"
        "                              SIGTERM). All other commands run\n"
        "                              once and exit. Implies non-\n"
        "                              interactive mode.\n"
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
    if (!a.config.clarity_rpc_user.empty())
      std::printf("  clarity rpc user:    %s\n",
                  a.config.clarity_rpc_user.c_str());
    std::printf("  keystore:            %s\n",
                a.config.keystore_path.empty()
                    ? "(none — wizard will prompt)"
                    : a.config.keystore_path.c_str());
    std::printf("  consensus key file:  %s\n",
                a.config.consensus_key_file.empty()
                    ? "(none — using keystore 0/0/0)"
                    : a.config.consensus_key_file.c_str());
    std::printf("  view key file:       %s\n",
                a.config.view_key_file.empty()
                    ? "(none — sum-of-outputs fallback)"
                    : a.config.view_key_file.c_str());
    std::printf("  state dir:           %s\n", a.config.state_dir.c_str());
    std::printf("  watcher id:          %llu\n",
                static_cast<unsigned long long>(a.config.watcher_id));
    std::printf("  log level:           %s\n", a.log_level.c_str());
    std::printf("  log file:            %s\n",
                a.log_file.empty() ? "(stderr)" : a.log_file.c_str());

    if (!a.command.empty())
    {
      std::printf("  command:             %s", a.command.c_str());
      for (const auto &arg : a.command_args)
        std::printf(" %s", arg.c_str());
      std::printf("\n");
    }
    else
    {
      std::printf("  command:             (REPL)\n");
    }

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
        if (!c.rpc_user.empty())
          std::printf("      rpc user:          %s\n",
                      c.rpc_user.c_str());
        std::printf("      confirmation:      %u\n",
                    static_cast<unsigned>(c.confirmation_depth));
      }
    }
  }

} // namespace Bridge