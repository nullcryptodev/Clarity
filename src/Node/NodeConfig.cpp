// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "NodeConfig.h"
#include "GlobalConfig.h"

#include "P2P/MessageTypes.h"

#include <stdexcept>

namespace Node
{

  const char *networkName(Network n) noexcept
  {
    switch (n)
    {
    case Network::Mainnet:
      return "mainnet";
    case Network::Testnet:
      return "testnet";
    case Network::Regtest:
      return "regtest";
    }
    return "unknown";
  }

  uint64_t chainIdForNetwork(Network n) noexcept
  {
    switch (n)
    {
    case Network::Mainnet:
      return GlobalConfig::CHAIN_ID; // 'CLRT'
    case Network::Testnet:
      return GlobalConfig::TESTNET_CHAIN_ID; // 'CLTT'
    case Network::Regtest:
      return GlobalConfig::REGNET_CHAIN_ID; // 'CLRG'
    }
    return 0;
  }

  void validateConfig(NodeConfig &config)
  {
    if (config.data_dir.empty())
    {
      config.data_dir = ".";
    }

    // Fill in chain_id from network if not explicitly set.
    if (config.chain_id == 0)
    {
      config.chain_id = chainIdForNetwork(config.network);
    }

    // Sanity bounds.
    if (config.max_block_bytes < 1024)
    {
      throw std::runtime_error("node: max_block_bytes too small");
    }
    if (config.max_block_bytes > 16 * 1024 * 1024)
    {
      throw std::runtime_error("node: max_block_bytes too large");
    }
    if (config.max_block_txs == 0)
    {
      throw std::runtime_error("node: max_block_txs must be > 0");
    }
    if (config.consensus_poll_ms < 10 || config.consensus_poll_ms > 5000)
    {
      throw std::runtime_error("node: consensus_poll_ms out of range");
    }

    // Validator sanity.
    if (config.validator_id != 0)
    {
      if (!config.consensus_key_file.empty() && config.validator_id == 0)
      {
        throw std::runtime_error(
            "node: consensus_key_file was set but validator_id is 0; a "
            "consensus key is only meaningful on a validator");
      }

      // Raw-hex key on the command line is a regtest-only convenience:
      // the secret is visible in `ps`, shell history, and any process
      // listing. Enforced here rather than in the arg parser so it is
      // independent of flag ordering (see Args.cpp).
      if (!config.consensus_secret_key.isNull() &&
          config.network != Network::Regtest)
      {
        throw std::runtime_error(
            "node: consensus_secret_key (the raw-hex form) is a regtest-only "
            "development convenience; use consensus_key_file on mainnet and "
            "testnet");
      }

      // A validator must have a key, but "a key source was specified" is
      // enough at this stage — loadSecrets() runs after validateConfig()
      // and is what turns a path into a loaded key. Requiring the key to
      // be non-null here would reject every file-based config, because
      // the file hasn't been read yet.
      if (config.validator_id != 0 &&
          config.consensus_secret_key.isNull() &&
          config.consensus_key_file.empty())
      {
        throw std::runtime_error(
            "node: validator_id set but no consensus key was provided "
            "(use --consensus-key-file or --consensus-key)");
      }
    }
  }
} // namespace Node