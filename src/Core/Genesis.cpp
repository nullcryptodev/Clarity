// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Genesis.h"

#include "Account.h"
#include "GlobalState.h"
#include "RewardTypes.h"
#include "TokenTypes.h"
#include "ValidatorTypes.h"
#include "GlobalConfig.h"

#include "Common/StringTools.h"

#include "State/StateAccess.h"
#include "State/StateDB.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/WalletTypes.h"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <stdexcept>

namespace
{
  // Parse a 64-character hex string into a Crypto::Hash. Throws if
  // the input is malformed (wrong length, non-hex characters). The
  // pinned genesis hash constants are compile-time-defined 64-char
  // hex strings, so a throw here means the constants themselves are
  // wrong, not that runtime data is bad.
  Crypto::Hash hashFromHex(const char *hex)
  {
    Crypto::Hash h;
    std::vector<uint8_t> bytes = Common::fromHex(std::string(hex));
    if (bytes.size() != 32)
      throw std::runtime_error("hashFromHex: expected 64 hex chars");
    std::memcpy(h.data.data(), bytes.data(), 32);
    return h;
  }

  //  Resolve an address from a GlobalConfig constant.
  //
  //  The config may hold either a bech32m address (the normal case,
  //  e.g. "rclrty1qpmfjm75...") or a 64-character hex string (the
  //  legacy form, used for the community and treasury fund
  //  placeholders). This helper accepts both and throws on anything
  //  else, so a misconfigured constant fails loudly at genesis
  //  construction rather than silently producing a garbage address.
  //
  //  Detection:
  //    - exactly 64 characters, all hex digits → parse as hex
  //    - decodes as a bech32m address for the expected network → use it
  //    - anything else → throw
  //
  //  The expected network is passed explicitly because the three
  //  genesis configs share this code path but use different HRPs.
  //  A mainnet address in a regtest config is a hard error rather
  //  than a silent misparse.
  Crypto::Address addressFromConfig(const char *value,
                                    Wallet::Network expected_network,
                                    const char *label)
  {
    const std::string s(value);

    auto isHex64 = [](const std::string &str) -> bool
    {
      if (str.size() != 64)
        return false;
      for (char c : str)
      {
        const bool hex =
            (c >= '0' && c <= '9') ||
            (c >= 'a' && c <= 'f') ||
            (c >= 'A' && c <= 'F');
        if (!hex)
          return false;
      }
      return true;
    };

    //  Hex form. Preserves the existing behaviour for the fund
    //  addresses, which are still placeholder hex constants.
    if (isHex64(s))
      return Crypto::addrFromHex(value);

    //  Bech32m form. The decoder validates the HRP against
    //  `expected_network`, so a mainnet HRP in a regtest config is
    //  rejected rather than silently accepted.
    const auto decoded = Wallet::decodeAddress(s, expected_network);
    if (!decoded.has_value())
    {
      throw std::runtime_error(
          std::string("genesis: ") + label +
          ": failed to decode address '" + s +
          "' (expected bech32m for the configured network, "
          "or 64-character hex)");
    }

    return *decoded;
  }
} // anonymous namespace

namespace Core
{
  GenesisConfig mainnetGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::CHAIN_ID;
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    constexpr Wallet::Network net = Wallet::Network::Mainnet;

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::COMMUNITY_FUND_ADDRESS, net, "community fund"),
                            GlobalConfig::COMMUNITY_FUND_AMOUNT,
                            "community fund"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::TREASURY_FUND_ADDRESS, net, "treasury"),
                            GlobalConfig::TREASURY_FUND_AMOUNT,
                            "treasury"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::SEED_ADDRESS_MAINNET, net, "seed validator 1"),
                            GlobalConfig::SEED_FUND_AMOUNT,
                            "seed validator 1"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::SEED_ADDRESS_TWO_MAINNET, net, "seed validator 2"),
                            GlobalConfig::SEED_FUND_AMOUNT_TWO,
                            "seed validator 2"});

    //  Seed validators.
    //
    //  The consensus key is set explicitly to SEED_NODE. If it were
    //  left null, applyGenesis would fall back to the reward address,
    //  and the daemon's signing key would not match the validator
    //  record — every vote would fail verification.
    //
    //  Brace-init order is {id, reward_address, node_key, is_seed,
    //  consensus_key}. The consensus_key field is at the END of
    //  GenesisValidator so that earlier configs which do not set it
    //  continue to compile and get the fallback behaviour.
    cfg.validators.push_back({1,
                              addressFromConfig(GlobalConfig::SEED_ADDRESS_MAINNET, net, "seed validator 1 reward"),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE),
                              true,
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE)});

    cfg.validators.push_back({2,
                              addressFromConfig(GlobalConfig::SEED_ADDRESS_TWO_MAINNET, net, "seed validator 2 reward"),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE_TWO),
                              true,
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE_TWO)});

    cfg.initial_total_supply = GlobalConfig::GENESIS_SUPPLY;
    cfg.initial_active_set_size = GlobalConfig::INITIAL_SET_SIZE;

    return cfg;
  }

  GenesisConfig testnetGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::TESTNET_CHAIN_ID; // 'CLTT'
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    constexpr Wallet::Network net = Wallet::Network::Testnet;

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::COMMUNITY_FUND_ADDRESS, net, "community fund"),
                            GlobalConfig::COMMUNITY_FUND_AMOUNT,
                            "community fund"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::TREASURY_FUND_ADDRESS, net, "treasury"),
                            GlobalConfig::TREASURY_FUND_AMOUNT,
                            "treasury"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::SEED_ADDRESS_TESTNET, net, "seed validator 1"),
                            GlobalConfig::SEED_FUND_AMOUNT,
                            "seed validator 1"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::SEED_ADDRESS_TWO_TESTNET, net, "seed validator 2"),
                            GlobalConfig::SEED_FUND_AMOUNT_TWO,
                            "seed validator 2"});

    cfg.validators.push_back({1,
                              addressFromConfig(GlobalConfig::SEED_ADDRESS_TESTNET, net, "seed validator 1 reward"),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE),
                              true,
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE)});

    cfg.validators.push_back({2,
                              addressFromConfig(GlobalConfig::SEED_ADDRESS_TWO_TESTNET, net, "seed validator 2 reward"),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE_TWO),
                              true,
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE_TWO)});

    cfg.initial_total_supply = GlobalConfig::GENESIS_SUPPLY;
    cfg.initial_active_set_size = GlobalConfig::INITIAL_SET_SIZE;

    return cfg;
  }

  GenesisConfig regtestGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::REGNET_CHAIN_ID;
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    constexpr Wallet::Network net = Wallet::Network::Regtest;

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::COMMUNITY_FUND_ADDRESS, net, "community fund"),
                            GlobalConfig::COMMUNITY_FUND_AMOUNT,
                            "community fund"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::TREASURY_FUND_ADDRESS, net, "treasury"),
                            GlobalConfig::TREASURY_FUND_AMOUNT,
                            "treasury"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::SEED_ADDRESS_REGTEST, net, "seed validator 1"),
                            GlobalConfig::SEED_FUND_AMOUNT,
                            "seed validator 1"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::SEED_ADDRESS_TWO_REGTEST, net, "seed validator 2"),
                            GlobalConfig::SEED_FUND_AMOUNT_TWO,
                            "seed validator 2"});

    cfg.validators.push_back({1,
                              addressFromConfig(GlobalConfig::SEED_ADDRESS_REGTEST, net, "seed validator 1 reward"),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE),
                              true,
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE)});

    cfg.validators.push_back({2,
                              addressFromConfig(GlobalConfig::SEED_ADDRESS_TWO_REGTEST, net, "seed validator 2 reward"),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE_TWO),
                              true,
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE_TWO)});

    cfg.initial_total_supply = GlobalConfig::GENESIS_SUPPLY;
    cfg.initial_active_set_size = GlobalConfig::INITIAL_SET_SIZE;

    return cfg;
  }

  // ============================================================================
  //  Application
  // ============================================================================

  namespace
  {
    std::vector<uint8_t> u64Bytes(uint64_t v)
    {
      std::vector<uint8_t> out(8);
      for (int i = 0; i < 8; ++i)
        out[i] = uint8_t(v >> (i * 8));
      return out;
    }
  } // anonymous namespace

  void applyGenesis(State::StateAccess &state, const GenesisConfig &config)
  {
    // ---- Initial accounts ----
    for (const auto &acc : config.accounts)
    {
      Account a;
      a.balance = acc.balance_atomic;
      a.nonce = 0;
      a.staking_opted_out = false;
      a.created_at_height = 0;
      a.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
      state.putAccount(acc.address, a);
    }

    // ---- Seed validators ----
    //
    // For each seed, write the validator record and the index entry
    // that maps its reward_address back to its id. The index is what
    // the reward distributor uses to identify the block proposer, and
    // what any caller with only an address uses to find the validator.
    for (const auto &v : config.validators)
    {
      ValidatorInfo vi;
      vi.id = v.id;
      vi.reward_address = v.reward_address;

      //  Consensus key: use whatever the genesis config declares.
      //  The genesis builders above always set it explicitly, so the
      //  fallback is only reachable from a custom GenesisConfig that
      //  doesn't populate the field.
      vi.consensus_key = v.consensus_key.isNull() ? v.reward_address
                                                  : v.consensus_key;

      vi.node_key = v.node_key;
      vi.owner = v.reward_address;
      vi.registered_at_height = 0;
      vi.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
      vi.uptime_score = 10'000;
      vi.is_seed = v.is_seed;
      vi.is_active = true;
      vi.became_active_at = 0;
      vi.last_active_at = 0;
      vi.last_seen_height = 0;
      vi.reward_multiplier = REWARD_MULTIPLIER_START;
      vi.infraction_count = 0;
      vi.last_infraction_height = 0;

      // ---- Stats (all default to 0, but explicit here for clarity) ----
      vi.pings_responded_this_epoch = 0;
      vi.pings_sent_this_epoch = 0;
      vi.total_blocks_produced = 0;
      vi.total_rewards_earned = 0;
      vi.epochs_active = 0;

      state.putValidator(vi);

      state.putValidatorByAddress(v.reward_address, v.id);
    }

    // ---- Active set as global state ----
    {
      std::vector<uint8_t> set_bytes;
      for (const auto &v : config.validators)
      {
        if (!v.is_seed)
          continue;
        auto b = u64Bytes(v.id);
        set_bytes.insert(set_bytes.end(), b.begin(), b.end());
      }
      state.putGlobal("active_set", set_bytes);
    }

    uint64_t max_seed_id = 0;
    for (const auto &v : config.validators)
    {
      if (v.is_seed && v.id > max_seed_id)
        max_seed_id = v.id;
    }

    // ---- Global state ----
    state.putGlobal("chain_id", u64Bytes(config.chain_id));
    state.putGlobal("total_supply", u64Bytes(config.initial_total_supply));
    state.putGlobal("total_staked", u64Bytes(0));
    state.putGlobal("pot", u64Bytes(0));
    state.putGlobal("epoch_number", u64Bytes(0));
    state.putGlobal("staker_count", u64Bytes(0));
    state.putGlobal("next_validator_id", u64Bytes(max_seed_id + 1));
    state.putGlobal("next_token_id", u64Bytes(1));
    state.putGlobal("next_order_id", u64Bytes(1));
    state.putGlobal("next_pool_id", u64Bytes(1));
    state.putGlobal("next_position_id", u64Bytes(1));
    state.putGlobal("last_rotation_height", u64Bytes(0));
    state.putGlobal("apy_activity_bps", u64Bytes(0));
    state.putGlobal("apy_pot_bps", u64Bytes(0));

    state.putGlobal("active_set_size",
                    u64Bytes(config.initial_active_set_size));

    // ---- Native token metadata ----
    {
      TokenInfo native;
      native.id = INVALID_ID;
      native.name = GlobalConfig::PROJECT_NAME;
      native.symbol = GlobalConfig::PROJECT_SYMBOL;
      native.decimals = GlobalConfig::DECIMALS;
      native.creator = Crypto::Address{};
      native.backing = BackingModel::Unbacked;
      native.maxSupply = 0;
      native.royaltyBps = 0;
      state.putToken(native);
    }
  }

  // ============================================================================
  //  Genesis header
  // ============================================================================

  BlockHeader makeGenesisHeader(const GenesisConfig &config)
  {
    BlockHeader hdr;
    hdr.version = 1;
    hdr.chain_id = config.chain_id;
    hdr.height = 0;
    hdr.parent_hash = Crypto::NULL_HASH;
    hdr.timestamp_ms = config.timestamp_ms;
    hdr.proposer = Crypto::Address{};
    hdr.epoch = 0;
    hdr.rotation_index = 0;
    hdr.state_root = Crypto::NULL_HASH;
    hdr.tx_root = Crypto::NULL_HASH;
    hdr.receipts_root = Crypto::NULL_HASH;
    hdr.validator_set_root = Crypto::NULL_HASH;
    hdr.total_fees = 0;
    hdr.tx_count = 0;
    hdr.active_validator_count = static_cast<uint32_t>(config.validators.size());
    return hdr;
  }

  Block makeGenesisBlock(State::StateAccess &state, const GenesisConfig &config)
  {
    Block b;
    b.header = makeGenesisHeader(config);

    std::vector<Id> active_ids;
    for (const auto &v : config.validators)
    {
      if (v.is_seed)
        active_ids.push_back(v.id);
    }

    b.header.validator_set_root = computeValidatorSetRoot(active_ids);
    b.header.state_root = state.stateRoot();

    b.transactions.clear();
    b.quorum_signatures.clear();
    b.participants.clear();

    return b;
  }

  // ============================================================================
  //  Verification
  // ============================================================================

  Crypto::Hash computeGenesisStateRoot(const GenesisConfig &config)
  {
    namespace fs = std::filesystem;

    auto temp_dir = fs::temp_directory_path() / "clrty_genesis_tmp";
    fs::remove_all(temp_dir);

    try
    {
      State::StateDB db(temp_dir.string(), 64ULL * 1024 * 1024);
      State::StateAccess state(db, /*version=*/0);
      applyGenesis(state, config);
      Crypto::Hash root = state.stateRoot();
      db.close();
      fs::remove_all(temp_dir);
      return root;
    }
    catch (...)
    {
      fs::remove_all(temp_dir);
      throw;
    }
  }

  bool verifyGenesis(State::StateAccess &state, const GenesisConfig &config)
  {
    Crypto::Hash expected = computeGenesisStateRoot(config);
    return state.stateRoot() == expected;
  }

  Crypto::Hash expectedGenesisHash(const GenesisConfig &config) noexcept
  {
    try
    {
      switch (config.chain_id)
      {
      case GlobalConfig::CHAIN_ID:
        return hashFromHex(GlobalConfig::MAINNET_GENESIS_HASH);
      case GlobalConfig::TESTNET_CHAIN_ID:
        return hashFromHex(GlobalConfig::TESTNET_GENESIS_HASH);
      case GlobalConfig::REGNET_CHAIN_ID:
        return hashFromHex(GlobalConfig::REGTEST_GENESIS_HASH);
      }
    }
    catch (...)
    {
      return Crypto::Hash{};
    }
    return Crypto::Hash{};
  }
} // namespace Core