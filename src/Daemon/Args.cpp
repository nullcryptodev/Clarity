// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Args.h"

#include "Common/StringTools.h"

#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace Daemon
{
  namespace
  {
    // Parse a network name into the enum.
    Node::Network parseNetwork(const std::string &s)
    {
      if (s == "mainnet" || s == "main")
        return Node::Network::Mainnet;
      if (s == "testnet" || s == "test")
        return Node::Network::Testnet;
      if (s == "regtest" || s == "reg")
        return Node::Network::Regtest;
      throw std::runtime_error("unknown network: " + s);
    }

    // Parse an unsigned integer with optional 0x prefix.
    uint64_t parseU64(const std::string &s)
    {
      uint64_t value = 0;
      try
      {
        size_t consumed = 0;
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        {
          value = std::stoull(s.substr(2), &consumed, 16);
        }
        else
        {
          value = std::stoull(s, &consumed, 10);
        }
        if (consumed != s.size())
        {
          throw std::runtime_error("trailing characters");
        }
      }
      catch (const std::exception &)
      {
        throw std::runtime_error("invalid number: " + s);
      }
      return value;
    }

    // Parse a hex-encoded 32-byte secret key.
    Crypto::SecretKey parseSecretKey(const std::string &hex)
    {
      if (hex.size() != 64)
      {
        throw std::runtime_error(
            "secret key must be 64 hex characters (32 bytes)");
      }
      Crypto::SecretKey sk;
      for (size_t i = 0; i < 32; ++i)
      {
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
        int hi = nib(hex[i * 2]);
        int lo = nib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
          throw std::runtime_error("secret key contains non-hex characters");
        }
        sk.data[i] = static_cast<uint8_t>((hi << 4) | lo);
      }
      return sk;
    }

    // Split a comma-separated list into a vector.
    std::vector<std::string> splitComma(const std::string &s)
    {
      std::vector<std::string> result;
      std::string current;
      for (char c : s)
      {
        if (c == ',')
        {
          if (!current.empty())
          {
            result.push_back(current);
            current.clear();
          }
        }
        else
        {
          current.push_back(c);
        }
      }
      if (!current.empty())
        result.push_back(current);
      return result;
    }
  } // anonymous namespace

  Args parseArgs(int argc, char **argv)
  {
    Args args;

    for (int i = 1; i < argc; ++i)
    {
      std::string arg = argv[i];

      auto next = [&]() -> std::string
      {
        if (i + 1 >= argc)
        {
          throw std::runtime_error("missing value for " + arg);
        }
        return argv[++i];
      };

      if (arg == "-h" || arg == "--help")
      {
        args.show_help = true;
        return args;
      }
      if (arg == "-v" || arg == "--version")
      {
        args.show_version = true;
        return args;
      }

      // ---- Network ----
      if (arg == "--network")
      {
        args.node.network = parseNetwork(next());
        continue;
      }

      // ---- Data directory ----
      if (arg == "--data-dir")
      {
        args.node.data_dir = next();
        continue;
      }

      // ---- P2P ----
      if (arg == "--p2p-port")
      {
        args.node.p2p_port = static_cast<uint16_t>(parseU64(next()));
        continue;
      }
      if (arg == "--seed")
      {
        // Single seed "host:port". Can be repeated.
        args.node.seeds.push_back(next());
        continue;
      }
      if (arg == "--seeds")
      {
        // Comma-separated list.
        auto list = splitComma(next());
        for (auto &s : list)
          args.node.seeds.push_back(s);
        continue;
      }

      // ---- Validator ----
      if (arg == "--validator-id")
      {
        args.node.validator_id = parseU64(next());
        continue;
      }
      if (arg == "--validator-key")
      {
        args.node.validator_secret_key = parseSecretKey(next());
        continue;
      }

      // ---- Consensus tuning ----
      if (arg == "--max-block-bytes")
      {
        args.node.max_block_bytes = parseU64(next());
        continue;
      }
      if (arg == "--max-block-txs")
      {
        args.node.max_block_txs = parseU64(next());
        continue;
      }
      if (arg == "--consensus-poll-ms")
      {
        args.node.consensus_poll_ms = parseU64(next());
        continue;
      }

      // ---- Storage ----
      if (arg == "--state-map-size")
      {
        args.node.state_map_size = parseU64(next());
        continue;
      }
      if (arg == "--chain-map-size")
      {
        args.node.chain_map_size = parseU64(next());
        continue;
      }

      // ---- Genesis ----
      if (arg == "--no-genesis")
      {
        args.node.apply_genesis_on_start = false;
        continue;
      }

      // ---- Logging ----
      if (arg == "--log-level")
      {
        args.log_level = next();
        continue;
      }
      if (arg == "--log-file")
      {
        args.log_file = next();
        continue;
      }
      if (arg == "--log-consensus")
      {
        args.node.log_consensus_state = true;
        continue;
      }

      // ---- Diagnostics ----
      if (arg == "--print-config")
      {
        args.print_config = true;
        continue;
      }

      // ---- Unknown ----
      throw std::runtime_error("unknown argument: " + arg);
    }

    return args;
  }

  void printHelp(const char *argv0)
  {
    std::cout
        << "Clarity daemon " << "\n"
        << "Usage: " << argv0 << " [options]\n"
        << "\n"
        << "Network:\n"
        << "  --network <name>           mainnet | testnet | regtest (default: regtest)\n"
        << "\n"
        << "Storage:\n"
        << "  --data-dir <path>          Data directory (required)\n"
        << "  --state-map-size <bytes>   State DB map size (default: 16 GiB)\n"
        << "  --chain-map-size <bytes>   Chain DB map size (default: 16 GiB)\n"
        << "\n"
        << "P2P:\n"
        << "  --p2p-port <port>          Listen port (0 = don't listen)\n"
        << "  --seed <host:port>         Add a seed peer (repeatable)\n"
        << "  --seeds <list>             Comma-separated seeds\n"
        << "\n"
        << "Validator:\n"
        << "  --validator-id <N>         Validator ID (0 = not a validator)\n"
        << "  --validator-key <hex>      Ed25519 secret key (64 hex chars)\n"
        << "\n"
        << "Consensus:\n"
        << "  --max-block-bytes <bytes>  Max block size (default: 262144)\n"
        << "  --max-block-txs <count>    Max txs per block (default: 5000)\n"
        << "  --consensus-poll-ms <ms>   Consensus timer poll (default: 100)\n"
        << "\n"
        << "Logging:\n"
        << "  --log-level <level>        trace|debug|info|warn|error (default: info)\n"
        << "  --log-file <path>          Write logs to file (default: stderr)\n"
        << "  --log-consensus            Log consensus state changes\n"
        << "\n"
        << "Diagnostics:\n"
        << "  --print-config             Print resolved config and exit\n"
        << "  -h, --help                 Show this help\n"
        << "  -v, --version              Show version\n"
        << "\n";
  }

  void printVersion()
  {
    std::cout << "Clarity daemon 1.0.0\n";
    std::cout << "Protocol version: 1\n";
    std::cout << "Chain IDs: mainnet=0x434C5254 testnet=0x434C5454 regtest=0x434C5247\n";
  }

  void printConfig(const Args &args)
  {
    const auto &n = args.node;

    std::cout << "Resolved configuration:\n";
    std::cout << "  network:              " << Node::networkName(n.network) << "\n";
    std::cout << "  chain_id:             0x" << std::hex << n.chain_id << std::dec << "\n";
    std::cout << "  data_dir:             " << n.data_dir << "\n";
    std::cout << "  state_map_size:       " << n.state_map_size << "\n";
    std::cout << "  chain_map_size:       " << n.chain_map_size << "\n";
    std::cout << "  p2p_port:             " << n.p2p_port << "\n";
    std::cout << "  seeds:                ";
    for (size_t i = 0; i < n.seeds.size(); ++i)
    {
      if (i > 0)
        std::cout << ", ";
      std::cout << n.seeds[i];
    }
    std::cout << "\n";
    std::cout << "  validator_id:         " << n.validator_id << "\n";
    std::cout << "  validator_key:        "
              << (n.validator_secret_key.isNull() ? "(none)" : "(set)") << "\n";
    std::cout << "  max_block_bytes:      " << n.max_block_bytes << "\n";
    std::cout << "  max_block_txs:        " << n.max_block_txs << "\n";
    std::cout << "  consensus_poll_ms:    " << n.consensus_poll_ms << "\n";
    std::cout << "  apply_genesis:        "
              << (n.apply_genesis_on_start ? "yes" : "no") << "\n";
    std::cout << "  log_level:            " << args.log_level << "\n";
    std::cout << "  log_file:             "
              << (args.log_file.empty() ? "(stderr)" : args.log_file) << "\n";
    std::cout << "  log_consensus_state:  "
              << (n.log_consensus_state ? "yes" : "no") << "\n";
  }

} // namespace Daemon