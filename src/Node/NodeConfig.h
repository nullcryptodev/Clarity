// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Crypto/Types.h"
#include "Core/Genesis.h"

namespace Node
{
  enum class Network : uint8_t
  {
    Mainnet = 0,
    Testnet = 1,
    Regtest = 2,
  };

  const char *networkName(Network n) noexcept;

  struct NodeConfig
  {
    // ---- Network ----
    Network network{Network::Regtest};
    uint64_t chain_id{0};

    // ---- Storage ----
    std::string data_dir;
    size_t state_map_size{1ULL << 34};
    size_t chain_map_size{1ULL << 34};

    // ---- P2P ----
    uint16_t p2p_port{0};
    std::vector<std::string> seeds;

    // ---- P2P enable/disable ----
    // Set to false for headless / offline mode. When false, the node
    // skips P2P initialization entirely and does not open sockets.
    // Consensus still works, proposals and votes are simply not
    // broadcasted. Useful for tests and for single-node "private chain"
    // setups.
    bool enable_p2p{true};

    // ---- Validator identity ----
    uint64_t validator_id{0};
    Crypto::SecretKey validator_secret_key{};

    // ---- Consensus ----
    uint64_t max_block_bytes{256 * 1024};
    uint64_t max_block_txs{5'000};
    uint64_t consensus_poll_ms{100};

    // ---- Genesis ----
    bool apply_genesis_on_start{true};

    // ---- Diagnostics ----
    bool log_consensus_state{false};

    std::optional<Core::GenesisConfig> test_genesis_override;
  };

  void validateConfig(NodeConfig &config);

  uint64_t chainIdForNetwork(Network n) noexcept;

  uint32_t p2pMagicForNetwork(Network n) noexcept;
} // namespace Node