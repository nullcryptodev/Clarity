// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
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

    // Path to a file containing the validator's consensus secret key,
    // as 64 hex characters. Mutually exclusive with
    // consensus_secret_key (the raw-hex form, which is dev-only and
    // gated on network == regtest). Loaded by Daemon::loadSecrets()
    // after config validation and before the node is constructed.
    std::string consensus_key_file;

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
    Crypto::SecretKey node_secret_key{};

    // ---- Consensus ----
    uint64_t max_block_bytes{256 * 1024};
    uint64_t max_block_txs{5'000};
    uint64_t consensus_poll_ms{100};

    //  Number of blocks in the rolling fee window. Used by
    //  getFeeStats to answer "fees in the last 24 hours" without
    //  walking the whole window on every call.
    uint64_t fee_window_blocks{86'400};

    //  Number of recent versions of the SMT to retain. Older
    //  versions are pruned after each block commit. Zero disables
    //  pruning entirely (unbounded growth).
    //
    //  A value of 0 here means "use the network default", which
    //  validateConfig() resolves from GlobalConfig:
    //
    //    mainnet:  2048  (~68 minutes at 1s blocks)
    //    testnet:   512  (~8 minutes)
    //    regtest:    64  (~1 minute)
    //
    //  Set an explicit non-zero value to override the network default.
    //  The override is what an operator uses when running a dedicated
    //  indexer node that wants deep history.
    //
    //  Rationale for the small defaults: since the consensus layer is
    //  BFT with immediate finality, there are no reorgs and no
    //  fork-choice that needs historical state. Historical queries are
    //  a block-explorer convenience; a node that wants more history
    //  than the default window should run an indexer that scrapes
    //  blocks and maintains its own state.
    uint64_t smt_history_blocks{0};

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