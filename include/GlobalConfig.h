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
  // Current config splits 100k into 3 addresses, 60k to "treasury", 20k into "community"
  // and 20k to the first seed.
  // The seed can go without this reward, but funds are used to bootstrap the network
  // and ensure both seeds "afford" to be network validators
  inline constexpr Amount GENESIS_SUPPLY = ATOMIC_UNITS_PER_COIN * 100'000; // 100k

  inline constexpr const char *COMMUNITY_FUND_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001"; // address
  inline constexpr const char *TREASURY_FUND_ADDRESS = "0000000000000000000000000000000000000000000000000000000000000001";  // address

  inline constexpr Amount COMMUNITY_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 40'000;
  inline constexpr Amount TREASURY_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 58'000; // pay seed validators

  // Genesis block hashes, one per network. Computed once and pinned.
  // If a change to genesis construction produces a different hash,
  // these checks fail at node startup with a clear "genesis mismatch"
  // error, instead of silently diverging from other nodes on the same
  // network.
  inline constexpr const char *MAINNET_GENESIS_HASH = "92b083df282f1bc6ca0bd9311fa0facee430ba79bda767d3bc0578341046b8bb";
  inline constexpr const char *TESTNET_GENESIS_HASH = "c0ba640301b056cf1b5eb0834ad45ad1a95870e85fd1a344fd38dd31e5e500b0";
  inline constexpr const char *REGTEST_GENESIS_HASH = "285ef00240dca3a9ba620cd0603ee4336406db660ccc7ca08a02ce042e0a57f0";

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
  inline constexpr const char *SEED_ADDRESS_MAINNET = "clrty1qqktjn87xfapx3tepuserag2pknlnkq35vkdza3pmvasqjjz202zyzszaum";  // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TESTNET = "tclrty1qqktjn87xfapx3tepuserag2pknlnkq35vkdza3pmvasqjjz202zypte5wa"; // address as bech32m
  inline constexpr const char *SEED_ADDRESS_REGTEST = "rclrty1qqktjn87xfapx3tepuserag2pknlnkq35vkdza3pmvasqjjz202zysgl3s0"; // address as bech32m
  inline constexpr Amount SEED_FUND_AMOUNT = ATOMIC_UNITS_PER_COIN * 1'000;                                                 // just fund the seed as to be a validator

  // Seed validator 2
  inline constexpr const char *SEED_ADDRESS_TWO_MAINNET = "clrty1qq7pdm0ugjqk47zqr58t8zkju4rafacaq73yjr7kxxqxg5tmledm7k6e0c7";  // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TWO_TESTNET = "tclrty1qq7pdm0ugjqk47zqr58t8zkju4rafacaq73yjr7kxxqxg5tmledm74pzx2c"; // address as bech32m
  inline constexpr const char *SEED_ADDRESS_TWO_REGTEST = "rclrty1qq7pdm0ugjqk47zqr58t8zkju4rafacaq73yjr7kxxqxg5tmledm7yzyr52"; // address as bech32m
  inline constexpr Amount SEED_FUND_AMOUNT_TWO = ATOMIC_UNITS_PER_COIN * 1'000;                                                 // just fund the seed as to be a validator

  // Consensus keys are identical across all three networks
  inline constexpr const char *SEED_NODE = "5cab747984018f73c3dac5979254b35591477fd06e15707fed28f67dfcd9b02e";     // consensus pubkey
  inline constexpr const char *SEED_NODE_TWO = "bcd90de479cabb39f01475775fb03289128c46d1966d056d64c637659fef31c9"; // consensus pubkey

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