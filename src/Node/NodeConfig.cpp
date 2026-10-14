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
      return GlobalConfig::CHAIN_ID;
    case Network::Testnet:
      return GlobalConfig::TESTNET_CHAIN_ID;
    case Network::Regtest:
      return GlobalConfig::REGNET_CHAIN_ID;
    }
    return 0;
  }

  //  Resolve the SMT history window default from GlobalConfig, chosen
  //  by network. See the comment on NodeConfig::smt_history_blocks for
  //  the rationale on the specific values.
  static uint64_t smtHistoryDefaultForNetwork(Network n) noexcept
  {
    switch (n)
    {
    case Network::Mainnet:
      return GlobalConfig::MAINNET_SMT_HISTORY_BLOCKS;
    case Network::Testnet:
      return GlobalConfig::TESTNET_SMT_HISTORY_BLOCKS;
    case Network::Regtest:
      return GlobalConfig::REGTEST_SMT_HISTORY_BLOCKS;
    }
    return GlobalConfig::REGTEST_SMT_HISTORY_BLOCKS;
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

    // Resolve smt_history_blocks from the network default if the
    // caller left it at 0. An explicit non-zero value is honored
    // verbatim: it is how a node operator opts into a different window.
    if (config.smt_history_blocks == 0)
    {
      config.smt_history_blocks = smtHistoryDefaultForNetwork(config.network);
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

      // Raw-hex key on the command line is a regtest-only convenience.
      if (!config.consensus_secret_key.isNull() &&
          config.network != Network::Regtest)
      {
        throw std::runtime_error(
            "node: consensus_secret_key (the raw-hex form) is a regtest-only "
            "development convenience; use consensus_key_file on mainnet and "
            "testnet");
      }

      // A validator must have a key, either inline or via file. The
      // file hasn't been read yet at this stage — loadSecrets() does
      // that after validateConfig — so "a source was specified" is
      // the correct check.
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