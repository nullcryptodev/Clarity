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
  inline constexpr const char *MAINNET_GENESIS_HASH = "9def9871496416713c277544592e6409e372cc4577593062910604143ad1f2b0";
  inline constexpr const char *TESTNET_GENESIS_HASH = "b735c17969ea1c76d8823ab6132f8396ba26a1913f7465269aea77a1c805e75a";
  inline constexpr const char *REGTEST_GENESIS_HASH = "39225b762030873e38dfda67bfd811e2e208ecc78f3b9770e94d684ec947662e";

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
  inline constexpr const char *SEED_ADDRESS_MAINNET = "clrty1qpt8lfr2rds5q2dxt2ng56y6mu9a6x7x3lh0napgekukp8a9ce3t2szumup";  // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TESTNET = "tclrty1qpt8lfr2rds5q2dxt2ng56y6mu9a6x7x3lh0napgekukp8a9ce3t2ne8jw8"; // address as bech32m
  inline constexpr const char *SEED_ADDRESS_REGTEST = "rclrty1qpt8lfr2rds5q2dxt2ng56y6mu9a6x7x3lh0napgekukp8a9ce3t2z6phs4"; // address as bech32m
  inline constexpr Amount SEED_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 1'000;                                                 // just fund the seed as to be a validator

  // Seed validator 2
  inline constexpr const char *SEED_ADDRESS_TWO_MAINNET = "clrty1qqwpcjfxlvnhwk4j907rdtnka00ywc03tw0drzt6f8c68h5dyrw56j50g7d";  // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TWO_TESTNET = "tclrty1qqwpcjfxlvnhwk4j907rdtnka00ywc03tw0drzt6f8c68h5dyrw56305pvt"; // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TWO_REGTEST = "rclrty1qqwpcjfxlvnhwk4j907rdtnka00ywc03tw0drzt6f8c68h5dyrw56qvjyje"; // address as bech32m
  inline constexpr Amount SEED_FUND_AMOUNT_TWO = ATOMIC_UNITS_PER_COIN * 1'000;                                                 // just fund the seed as to be a validator

  // Consensus keys are identical across all three networks
  inline constexpr const char *SEED_NODE = "84efa7717ca8286de2331fb0cff419f02f830486501f1d3748d387067b610ff1";     // consensus pubkey
  inline constexpr const char *SEED_NODE_TWO = "1051bde916098cb2a55d806ace794d384de0dd78f5bbad3ef6cf8304da5183e6"; // consensus pubkey

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
  //  Values are per-network because a regtest that runs thousands of
  //  blocks per hour should not retain the same window as a mainnet.

  inline constexpr uint64_t MAINNET_SMT_HISTORY_BLOCKS = 2048;
  inline constexpr uint64_t TESTNET_SMT_HISTORY_BLOCKS = 512;
  inline constexpr uint64_t REGTEST_SMT_HISTORY_BLOCKS = 64;
}