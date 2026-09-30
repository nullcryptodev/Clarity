#pragma once

#include <cstdint>

namespace
{
  using Height      = uint64_t;
  using Amount      = uint64_t;
  using Round       = uint32_t;
  using Id          = uint64_t;
  using Version     = uint16_t;
  using Index       = uint16_t;
  using Bps         = uint16_t;

  inline constexpr uint64_t INVALID_ID = 0;
  inline constexpr uint16_t INVALID_INDEX = 0xFFFF;
  inline constexpr uint64_t NATIVE_TOKEN_ID = 0;
  inline constexpr uint16_t MAX_BPS = 10'000;
}

namespace GlobalConfig
{
  // Identity

  inline constexpr const char *PROJECT_NAME         = "Clarity";
  inline constexpr const char *PROJECT_SYMBOL       = "CLRTY";
  inline constexpr const char *PROJECT_AGENT_STRING = "/Clarity:1.0.0/";

  inline constexpr Id CHAIN_ID         = 0x434C5254; // 'CLRT'
  inline constexpr Id TESTNET_CHAIN_ID = 0x434C5454; // 'CLTT'
  inline constexpr Id REGNET_CHAIN_ID  = 0x434C5247; // 'CLRG'

  inline constexpr const char *MAINNET_HRP = "clrty";
  inline constexpr const char *TESTNET_HRP = "tclrty";
  inline constexpr const char *REGTEST_HRP = "rclrty";

  // Version

  inline constexpr Version CURRENT_BLOCK_VERSION       = 1;
  inline constexpr Version CURRENT_TRANSACTION_VERSION = 1;
  inline constexpr Version CURRENT_PROTOCOL_VERSION    = 1;
  inline constexpr Version MIN_PROTOCOL_VERSION        = 1;

  // Currency

  inline constexpr uint8_t DECIMALS = 5;
  inline constexpr Amount ATOMIC_UNITS_PER_COIN = 100'000;           // 1 full coin
  inline constexpr Amount BLOCK_REWARD = ATOMIC_UNITS_PER_COIN * 10; // 10 $CLRTY

  // Split percentages in basis points
  inline constexpr Bps STAKER_SHARE_BPS    = 4000; // 40%
  inline constexpr Bps VALIDATOR_SHARE_BPS = 6000; // 60%
  inline constexpr Bps PRODUCER_BONUS_BPS  = 2000; // 20%
  inline constexpr Bps SET_SHARE_BPS       = 8000; // 80%

  static_assert(STAKER_SHARE_BPS + VALIDATOR_SHARE_BPS == MAX_BPS, "Block reward share percentages must sum to 100%");
  static_assert(PRODUCER_BONUS_BPS + SET_SHARE_BPS == MAX_BPS, "Validator distribution must sum to 100%");

  // Genesis

  inline constexpr uint64_t GENESIS_TIMESTAMP_MS = 1767225600000ULL;

  // The genesis supply gets split multiple addresses
  // Current config splits 100k into 3 addresses, 60k to "treasury", 20k into "community"
  // and 20k to the first seed. The seed can go without this reward, but funds could be
  // used to bootstrap the network 
  inline constexpr Amount GENESIS_SUPPLY = ATOMIC_UNITS_PER_COIN * 100'000; // 100k

  inline constexpr const char *COMMUNITY_FUND_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001"; // address
  inline constexpr const char *TREASURY_FUND_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001";  // address

  inline constexpr Amount COMMUNITY_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 40'000;
  inline constexpr Amount TREASURY_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 58'000; // pay for seed validator

  // Genesis block hashes, one per network. Computed once and pinned.
  // If a change to genesis construction produces a different hash,
  // these checks fail at node startup with a clear "genesis mismatch"
  // error, instead of silently diverging from other nodes on the same
  // network.
  inline constexpr const char *MAINNET_GENESIS_HASH = "b2b3730c1ec92cb6be0670ee961b13d7e0108e122e7cf97bcb675e6b709793c3";
  inline constexpr const char *TESTNET_GENESIS_HASH = "08e5b2658d69f0853a87e0d165d705fb79392443ba8d367004dec3b0ffd079fd";
  inline constexpr const char *REGTEST_GENESIS_HASH = "3e80bff4887f7e1aff5423ad6d59e6f4dfced21a7c55f5d296f6b03059ffc063";

  // Seed

  inline constexpr const char *SEED_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001"; // address
  inline constexpr Amount SEED_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 1'000;                                       // just fund the seed as to be a validator
  inline constexpr const char *SEED_ADDRESS_TWO = "0000000000000000000000000000000000000000000000000000000000000001"; // address
  inline constexpr Amount SEED_FUND_AMOUNT_TWO = ATOMIC_UNITS_PER_COIN * 1'000;                                       // just fund the seed as to be a validator

  inline constexpr const char *SEED_NODE = "1111111111111111111111111111111111111111111111111111111111111111"; // pubkey
  inline constexpr const char *SEED_NODE_TWO = "1111111111111111111111111111111111111111111111111111111111111111"; // pubkey
  inline constexpr uint32_t INITIAL_SET_SIZE = 1;

  // Validator set

  inline constexpr uint64_t VALIDATOR_MIN_STAKE = 1000ULL * ATOMIC_UNITS_PER_COIN; // 1000 CLRTY

  inline constexpr uint64_t SEED_NODES_COUNT = 2;              // always active
  inline constexpr uint64_t ACTIVE_SET_MIN = SEED_NODES_COUNT; // BFT minimum (2 of 2)
  inline constexpr uint64_t ACTIVE_SET_MAX = 100;              // BFT ceiling
  inline constexpr uint64_t ACTIVE_SET_DEFAULT = 11;

  static_assert(ACTIVE_SET_MIN >= 2, "BFT needs at least 2 validators");
  static_assert(ACTIVE_SET_MIN <= ACTIVE_SET_DEFAULT, "Default must be >= minimum");
  static_assert(ACTIVE_SET_DEFAULT <= ACTIVE_SET_MAX, "Default must be <= maximum");
  static_assert(SEED_NODES_COUNT <= ACTIVE_SET_MIN, "Seeds must fit within the minimum active set");

  // Staking

  inline constexpr uint64_t AUTO_STAKE_THRESHOLD = 100ULL * ATOMIC_UNITS_PER_COIN; // 100 CLRTY
  inline constexpr uint16_t APY_BASE_BPS = 500;                                    // 5.00% (gov)
  inline constexpr uint16_t APY_ACTIVITY_MAX_BPS = 500;                            // +5.00% max
  inline constexpr uint16_t APY_POT_BONUS_MAX_BPS = 300;                           // +3.00% max

  // Balance bonus: stakers holding >= threshold get +3% weight
  inline constexpr uint16_t BALANCE_BONUS_BPS = 300;                                   // 3.00%
  inline constexpr uint64_t BALANCE_BONUS_THRESHOLD = 1000ULL * ATOMIC_UNITS_PER_COIN; // 1000 CLRTY
}