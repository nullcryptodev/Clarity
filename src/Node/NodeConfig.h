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
    Crypto::SecretKey consensus_secret_key{};

    // ---- Node identity (P2P auth) ----
    //
    // Every node that speaks P2P needs a stable identity key to sign
    // the Auth exchange. This is NOT the validator key: a non-validator
    // node has no validator key, but it still authenticates to peers
    // so the ban list and per-peer reputation have something to bind
    // to.
    //
    // If this is null (the default), Node::initP2P() loads it from
    // <data_dir>/node_key, generating and persisting a fresh key on
    // first run. Set it explicitly only for tests that need a fixed
    // identity.
    //
    // On a validator, this may be the same key as consensus_secret_key
    // or different — either works. The auth protocol doesn't require
    // the node key to match the validator key; the validator binding
    // is a separate lookup by reward address in verifyPeerAuth().
    Crypto::SecretKey node_secret_key{};

    // ---- Consensus ----
    uint64_t max_block_bytes{256 * 1024};
    uint64_t max_block_txs{5'000};
    uint64_t consensus_poll_ms{100};

    //  Number of blocks in the rolling fee window. Used by
    //  getFeeStats to answer "fees in the last 24 hours" without
    //  walking the whole window on every call.
    //
    //  Default: 86,400 blocks (24 hours at NOMINAL_BLOCK_SECONDS = 1).
    //  On a test chain with a smaller window, set this lower so the
    //  value is populated quickly.
    uint64_t fee_window_blocks{86'400};

    //  Number of recent versions of the SMT to retain. Older
    //  versions are pruned after each block commit. Zero disables
    //  pruning entirely (unbounded growth).
    //
    //  Default: 10,000 blocks. On a chain with meaningful state
    //  traffic, the historical SMT is the dominant storage consumer;
    //  keeping this bounded is what keeps disk usage predictable.
    //
    //  Pruning happens in a background pass after block commit, at
    //  most once every HISTORY_PRUNE_INTERVAL_BLOCKS blocks, so the
    //  cost is amortized.
    uint64_t smt_history_blocks{10'000};

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