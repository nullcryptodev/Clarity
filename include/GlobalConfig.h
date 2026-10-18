#pragma once

#include <cstdint>

namespace
{
  using Height = uint64_t;
  using Amount = uint64_t;
  using Round = uint32_t;
  using Id = uint64_t;
  using Version = uint16_t;
  using Index = uint16_t;
  using Bps = uint16_t;

  inline constexpr uint64_t INVALID_ID = 0;
  inline constexpr uint16_t INVALID_INDEX = 0xFFFF;
  inline constexpr uint64_t NATIVE_TOKEN_ID = 0;
  inline constexpr uint16_t MAX_BPS = 10'000;
}

namespace GlobalConfig
{
  // Identity

  inline constexpr const char *PROJECT_NAME = "Clarity";
  inline constexpr const char *PROJECT_SYMBOL = "CLRTY";
  inline constexpr const char *PROJECT_AGENT_STRING = "/Clarity:1.0.0/";
  inline constexpr const char *CLIENT_VERSION = "clrty/v1.0.0";

  inline constexpr Id CHAIN_ID = 0x434C5254;         // 'CLRT'
  inline constexpr Id TESTNET_CHAIN_ID = 0x434C5454; // 'CLTT'
  inline constexpr Id REGNET_CHAIN_ID = 0x434C5247;  // 'CLRG'

  inline constexpr const char *MAINNET_HRP = "clrty";
  inline constexpr const char *TESTNET_HRP = "tclrty";
  inline constexpr const char *REGTEST_HRP = "rclrty";

  // Version

  inline constexpr Version CURRENT_BLOCK_VERSION = 1;
  inline constexpr Version CURRENT_TRANSACTION_VERSION = 1;
  inline constexpr Version CURRENT_PROTOCOL_VERSION = 1;
  inline constexpr Version MIN_PROTOCOL_VERSION = 1;

  // Currency

  inline constexpr uint8_t DECIMALS = 5;
  inline constexpr Amount ATOMIC_UNITS_PER_COIN = 100'000;           // 1 full coin
  inline constexpr Amount BLOCK_REWARD = ATOMIC_UNITS_PER_COIN * 1;  // 1 $CLRTY

  // Split percentages in basis points
  inline constexpr Bps STAKER_SHARE_BPS = 4000;    // 40%
  inline constexpr Bps VALIDATOR_SHARE_BPS = 6000; // 60%
  inline constexpr Bps PRODUCER_BONUS_BPS = 2000;  // 20%
  inline constexpr Bps SET_SHARE_BPS = 8000;       // 80%

  static_assert(STAKER_SHARE_BPS + VALIDATOR_SHARE_BPS == MAX_BPS, "Block reward share percentages must sum to 100%");
  static_assert(PRODUCER_BONUS_BPS + SET_SHARE_BPS == MAX_BPS, "Validator distribution must sum to 100%");

  // Validator set

  inline constexpr uint32_t INITIAL_SET_SIZE = 2; // should match seed node count

  inline constexpr Amount VALIDATOR_MIN_STAKE = 10ULL * ATOMIC_UNITS_PER_COIN; // 10 CLRTY

  inline constexpr uint64_t ACTIVE_SET_MIN = 2;   // BFT minimum (2 of 2)
  inline constexpr uint64_t ACTIVE_SET_MAX = 100; // BFT ceiling
  inline constexpr uint64_t ACTIVE_SET_DEFAULT = 11;

  static_assert(ACTIVE_SET_MIN >= 2, "BFT needs at least 2 validators");
  static_assert(ACTIVE_SET_MIN <= ACTIVE_SET_DEFAULT, "Default must be >= minimum");
  static_assert(ACTIVE_SET_DEFAULT <= ACTIVE_SET_MAX, "Default must be <= maximum");
  static_assert(INITIAL_SET_SIZE <= ACTIVE_SET_MIN, "Seeds must fit within the minimum active set");

  // Genesis

  inline constexpr uint64_t GENESIS_TIMESTAMP_MS = 1767225600000ULL;

  // The genesis supply gets split multiple addresses
  // Current config splits 250k into 3 addresses.
  // 98k to "treasury", 1k to each each seed to pay VALIDATOR_MIN_STAKE.
  inline constexpr Amount GENESIS_SUPPLY = ATOMIC_UNITS_PER_COIN * 250'000; // 250k

  inline constexpr const char *TREASURY_FUND_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001";  // address
  inline constexpr Amount TREASURY_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 249'980; // pay seed validators

  // Genesis block hashes, one per network. Computed once and pinned.
  // If a change to genesis construction produces a different hash,
  // these checks fail at node startup with a clear "genesis mismatch"
  // error, instead of silently diverging from other nodes on the same
  // network.
  // When creating new hashes, rotate the addresses too.
  inline constexpr const char *MAINNET_GENESIS_HASH = "877684213774ccb31963923827281bb640bed151d4f733ab3d9b520b5caec958";
  inline constexpr const char *TESTNET_GENESIS_HASH = "1e5e5376f78aac8a819445fd8f3d4abc2c259dac2c62ae17fb85d81462ab9447";
  inline constexpr const char *REGTEST_GENESIS_HASH = "30d2a74b4477e1a6f0ec5fec2bae6492fb3a9e64cebf47fad6e591a583d1d5c9";

  // Seed validators.
  //
  // Each seed has two keys derived from a single BIP-39 mnemonic:
  //
  //   SEED_ADDRESS_*    — the reward address. One bech32m string per
  //                       network, because the HRP differs. Same
  //                       underlying pubkey for all three networks.
  //
  //   SEED_NODE[_TWO]   — the consensus public key. A raw 32-byte
  //                       Ed25519 key, identical across all three
  //                       networks because it doesn't carry an HRP.
  //
  // The corresponding consensus *secret* is what the daemon reads
  // via --consensus-key. It is NOT in this config: secrets don't
  // belong in source. Retrieve it with:
  //   ./address --show <keystore> --show-secret

  // Seed validator 1
  inline constexpr const char *SEED_ADDRESS_MAINNET = "clrty1qzjrjdw68zqmxa744ewv7sstgdstlxw9yx7llhtz9nwmf5r74fetufge6dx";  // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TESTNET = "tclrty1qzjrjdw68zqmxa744ewv7sstgdstlxw9yx7llhtz9nwmf5r74fetu2nznlq"; // address as bech32m
  inline constexpr const char *SEED_ADDRESS_REGTEST = "rclrty1qzjrjdw68zqmxa744ewv7sstgdstlxw9yx7llhtz9nwmf5r74fetumsykpj"; // address as bech32m
  inline constexpr Amount SEED_FUND_AMOUNT = VALIDATOR_MIN_STAKE;                                                           // just fund the seed as to be a validator

  // Seed validator 2
  inline constexpr const char *SEED_ADDRESS_TWO_MAINNET = "clrty1qpk4v84rlhjtm69uawqrjgslwtdfnteghx0tgyxa77p56ha4xjk8u97md5r";  // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TWO_TESTNET = "tclrty1qpk4v84rlhjtm69uawqrjgslwtdfnteghx0tgyxa77p56ha4xjk8ux9qyx9"; // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TWO_REGTEST = "rclrty1qpk4v84rlhjtm69uawqrjgslwtdfnteghx0tgyxa77p56ha4xjk8uhxxpch"; // address as bech32m
  inline constexpr Amount SEED_FUND_AMOUNT_TWO = VALIDATOR_MIN_STAKE;                                                           // just fund the seed as to be a validator

  // Consensus keys are identical across all three networks
  inline constexpr const char *SEED_NODE = "d86279aa29ef25512105c8fd7f667146e6171d0cc404ebd2ba45070c3dcbd2e8";     // consensus pubkey
  inline constexpr const char *SEED_NODE_TWO = "521a1a4ecacd27962aa79e6def79ff8797b61e43d31960d18d20b3e7a6fad532"; // consensus pubkey

  inline constexpr uint64_t SEED_NODES_COUNT = INITIAL_SET_SIZE; // active seeds amount

  // Staking

  inline constexpr Amount AUTO_STAKE_THRESHOLD = 1ULL * ATOMIC_UNITS_PER_COIN;    // 1 CLRTY
  inline constexpr Bps APY_BASE_BPS = 300;                                        // 3.00% (gov)
  inline constexpr Bps APY_ACTIVITY_MAX_BPS = 300;                                // +3.00% max
  inline constexpr Bps APY_POT_BONUS_MAX_BPS = 300;                               // +3.00% max

  // Balance bonus: stakers holding >= threshold get +3% weight
  inline constexpr Bps BALANCE_BONUS_BPS = 300;                                      // 3.00%
  inline constexpr Amount BALANCE_BONUS_THRESHOLD = 1000ULL * ATOMIC_UNITS_PER_COIN; // 1000 CLRTY

  //  SMT history retention
  //  The number of historical versions the node retains in the SMT
  //  historical tables. Rows for versions older than
  //  (current_height - smt_history_blocks) are pruned on every block
  //  commit inside the same transaction.
  //  Since consensus is BFT with immediate finality, there are no
  //  reorgs: historical state queries are a block-explorer convenience
  //  and a light-client-proof feature, not a consensus requirement.
  //  The default is deliberately small. Operators who want deeper
  //  history run an indexer, which scrapes blocks and maintains its
  //  own state.
  //  These values are the defaults a fresh node uses when opening an
  //  existing DB. Changing them on an existing DB takes effect at the
  //  next prune. Set to 0 to disable pruning entirely (the historical
  //  tables grow without bound).

  inline constexpr uint64_t MAINNET_SMT_HISTORY_BLOCKS = 2048;
  inline constexpr uint64_t TESTNET_SMT_HISTORY_BLOCKS = 512;
  inline constexpr uint64_t REGTEST_SMT_HISTORY_BLOCKS = 64;
}