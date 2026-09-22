// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "NodeConfig.h"

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
      return 0x434C5254; // 'CLRT'
    case Network::Testnet:
      return 0x434C5454; // 'CLTT'
    case Network::Regtest:
      return 0x434C5247; // 'CLRG'
    }
    return 0;
  }

  void validateConfig(NodeConfig &config)
  {
    if (config.data_dir.empty())
    {
      throw std::runtime_error("node: data_dir must be set");
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
      if (config.validator_secret_key.isNull())
      {
        throw std::runtime_error(
            "node: validator_id set but validator_secret_key is null");
      }
    }
  }
} // namespace Node