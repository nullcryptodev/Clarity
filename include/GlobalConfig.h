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
  inline constexpr Amount GENESIS_SUPPLY = ATOMIC_UNITS_PER_COIN * 100'000; // 100k

  inline constexpr const char *COMMUNITY_FUND_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001"; // address
  inline constexpr const char *TREASURY_FUND_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001";  // address

  inline constexpr Amount COMMUNITY_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 20'000;
  inline constexpr Amount TREASURY_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 60'000;

  // Seed

  inline constexpr const char *SEED_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001"; // address
  inline constexpr Amount SEED_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 20'000;

  inline constexpr const char *SEED_NODE = "1111111111111111111111111111111111111111111111111111111111111111"; // pubkey
  inline constexpr uint32_t INITIAL_SET_SIZE = 1;
}