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
  inline constexpr Amount BLOCK_REWARD = ATOMIC_UNITS_PER_COIN * 10; // 10 $CLRTY

  // Split percentages in basis points
  inline constexpr Bps STAKER_SHARE_BPS = 4000;    // 40%
  inline constexpr Bps VALIDATOR_SHARE_BPS = 6000; // 60%
  inline constexpr Bps PRODUCER_BONUS_BPS = 2000;  // 20%
  inline constexpr Bps SET_SHARE_BPS = 8000;       // 80%

  static_assert(STAKER_SHARE_BPS + VALIDATOR_SHARE_BPS == MAX_BPS, "Block reward share percentages must sum to 100%");
  static_assert(PRODUCER_BONUS_BPS + SET_SHARE_BPS == MAX_BPS, "Validator distribution must sum to 100%");

  // Genesis

  inline constexpr uint64_t GENESIS_TIMESTAMP_MS = 1767225600000ULL;

  // The genesis supply gets split multiple addresses
  // Current config splits 100k into 3 addresses.
  // 98k to "treasury", 1k to each each seed to pay VALIDATOR_MIN_STAKE.
  inline constexpr Amount GENESIS_SUPPLY = ATOMIC_UNITS_PER_COIN * 100'000; // 100k

  inline constexpr const char *TREASURY_FUND_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001";  // address
  inline constexpr Amount TREASURY_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 98'000; // pay seed validators

  // Genesis block hashes, one per network. Computed once and pinned.
  // If a change to genesis construction produces a different hash,
  // these checks fail at node startup with a clear "genesis mismatch"
  // error, instead of silently diverging from other nodes on the same
  // network.
  // When creating new hashes, rotate the addresses too.
  inline constexpr const char *MAINNET_GENESIS_HASH = "3191aa8830769b5e45aee264cb95564b733743a4647d899554c07d8cbf6b5587";
  inline constexpr const char *TESTNET_GENESIS_HASH = "4a9ea3b334d4a09c50cb2d71d19719fc935bd1e06a0ad3affe52ac24d28ae990";
  inline constexpr const char *REGTEST_GENESIS_HASH = "894142fdfed4d4761f459ce71cc9a77929bb3f5fe452f1d22614db20cd79fadf";

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
  inline constexpr const char *SEED_ADDRESS_MAINNET = "clrty1qpk2acd8m5tfnpgnsdmx70hed9vnsklt23wpn45dcy9qvx3540sww4antx5";  // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TESTNET = "tclrty1qpk2acd8m5tfnpgnsdmx70hed9vnsklt23wpn45dcy9qvx3540swwkxgz5j"; // address as bech32m
  inline constexpr const char *SEED_ADDRESS_REGTEST = "rclrty1qpk2acd8m5tfnpgnsdmx70hed9vnsklt23wpn45dcy9qvx3540sww89w82q"; // address as bech32m
  inline constexpr Amount SEED_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 1'000;                                                 // just fund the seed as to be a validator

  // Seed validator 2
  inline constexpr const char *SEED_ADDRESS_TWO_MAINNET = "clrty1qqgazw56gxw7q27wdsnv926e0sfwk67zfq65kdkatnzv3g77k8cawav2th3";  // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TWO_TESTNET = "tclrty1qqgazw56gxw7q27wdsnv926e0sfwk67zfq65kdkatnzv3g77k8caw7h3z9h"; // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TWO_REGTEST = "rclrty1qqgazw56gxw7q27wdsnv926e0sfwk67zfq65kdkatnzv3g77k8caw05h8m9"; // address as bech32m
  inline constexpr Amount SEED_FUND_AMOUNT_TWO = ATOMIC_UNITS_PER_COIN * 1'000;                                                 // just fund the seed as to be a validator

  // Consensus keys are identical across all three networks
  inline constexpr const char *SEED_NODE = "e22c47a21f70ff67035ff850fef2bc48d915105a883e1c7a9bb21b307e68b83f";     // consensus pubkey
  inline constexpr const char *SEED_NODE_TWO = "18f812fb6dbde89e54c02458416bbf884151476ab5925eae30091d958ee0a5e8"; // consensus pubkey

  inline constexpr uint32_t INITIAL_SET_SIZE = 2; // should match seed node count
  inline constexpr uint64_t SEED_NODES_COUNT = 2; // active seeds amount

  // Validator set

  inline constexpr Amount VALIDATOR_MIN_STAKE = 1000ULL * ATOMIC_UNITS_PER_COIN; // 1000 CLRTY

  inline constexpr uint64_t ACTIVE_SET_MIN = SEED_NODES_COUNT; // BFT minimum (2 of 2)
  inline constexpr uint64_t ACTIVE_SET_MAX = 100;              // BFT ceiling
  inline constexpr uint64_t ACTIVE_SET_DEFAULT = 11;

  static_assert(ACTIVE_SET_MIN >= 2, "BFT needs at least 2 validators");
  static_assert(ACTIVE_SET_MIN <= ACTIVE_SET_DEFAULT, "Default must be >= minimum");
  static_assert(ACTIVE_SET_DEFAULT <= ACTIVE_SET_MAX, "Default must be <= maximum");
  static_assert(SEED_NODES_COUNT <= ACTIVE_SET_MIN, "Seeds must fit within the minimum active set");

  // Staking

  inline constexpr Amount AUTO_STAKE_THRESHOLD = 100ULL * ATOMIC_UNITS_PER_COIN;  // 100 CLRTY
  inline constexpr Bps APY_BASE_BPS = 500;                                        // 5.00% (gov)
  inline constexpr Bps APY_ACTIVITY_MAX_BPS = 500;                                // +5.00% max
  inline constexpr Bps APY_POT_BONUS_MAX_BPS = 300;                               // +3.00% max

  // Balance bonus: stakers holding >= threshold get +3% weight
  inline constexpr Bps BALANCE_BONUS_BPS = 300;                                      // 3.00%
  inline constexpr Amount BALANCE_BONUS_THRESHOLD = 1000ULL * ATOMIC_UNITS_PER_COIN; // 1000 CLRTY
}