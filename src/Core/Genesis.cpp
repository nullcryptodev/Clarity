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

#include "State/StateAccess.h"
#include "State/StateDB.h"

#include <chrono>
#include <filesystem>

namespace Core
{
  GenesisConfig mainnetGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::CHAIN_ID;
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::COMMUNITY_FUND_ADDRESS),
                            GlobalConfig::COMMUNITY_FUND_AMOUNT,
                            "community fund"});

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::TREASURY_FUND_ADDRESS),
                            GlobalConfig::TREASURY_FUND_AMOUNT,
                            "treasury"});

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::SEED_ADDRESS),
                            GlobalConfig::SEED_FUND_AMOUNT,
                            "seed validator 1"});

    // Add more if needed
    //cfg.accounts.push_back({
    // GlobalConfig::SEED_ADDRESS_TWO
    // GlobalConfig::SEED_FUND_AMOUNT_TWO,
    // "seed validator 2"
    //});

    cfg.validators.push_back({1,
                              Crypto::addrFromHex(GlobalConfig::SEED_ADDRESS),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE),
                              true});

    // Add more if needed
    //cfg.validators.push_back({
    //  2,
    //  GlobalConfig::SEED_ADDRESS_TWO,
    //  GlobalConfig::SEED_NODE_TWO,
    //  true
    //});

    cfg.initial_total_supply = GlobalConfig::GENESIS_SUPPLY;
    cfg.initial_active_set_size = GlobalConfig::INITIAL_SET_SIZE;

    return cfg;
  }

  GenesisConfig testnetGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::TESTNET_CHAIN_ID; // 'CLTT'
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::COMMUNITY_FUND_ADDRESS),
                            GlobalConfig::COMMUNITY_FUND_AMOUNT,
                            "community fund"});

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::TREASURY_FUND_ADDRESS),
                            GlobalConfig::TREASURY_FUND_AMOUNT,
                            "treasury"});

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::SEED_ADDRESS),
                            GlobalConfig::SEED_FUND_AMOUNT,
                            "seed validator 1"});

    // Add more if needed
    // cfg.accounts.push_back({
    // GlobalConfig::SEED_ADDRESS_TWO
    // GlobalConfig::SEED_FUND_AMOUNT_TWO,
    // "seed validator 2"
    //});

    cfg.validators.push_back({1,
                              Crypto::addrFromHex(GlobalConfig::SEED_ADDRESS),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE),
                              true});

    // Add more if needed
    // cfg.validators.push_back({
    //  2,
    //  GlobalConfig::SEED_ADDRESS_TWO,
    //  GlobalConfig::SEED_NODE_TWO,
    //  true
    //});

    cfg.initial_total_supply = GlobalConfig::GENESIS_SUPPLY;
    cfg.initial_active_set_size = GlobalConfig::INITIAL_SET_SIZE;

    return cfg;
  }

  GenesisConfig regtestGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::REGNET_CHAIN_ID;
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::COMMUNITY_FUND_ADDRESS),
                            GlobalConfig::COMMUNITY_FUND_AMOUNT,
                            "community fund"});

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::TREASURY_FUND_ADDRESS),
                            GlobalConfig::TREASURY_FUND_AMOUNT,
                            "treasury"});

    cfg.accounts.push_back({Crypto::addrFromHex(GlobalConfig::SEED_ADDRESS),
                            GlobalConfig::SEED_FUND_AMOUNT,
                            "seed validator 1"});

    // Add more if needed
    // cfg.accounts.push_back({
    // GlobalConfig::SEED_ADDRESS_TWO
    // GlobalConfig::SEED_FUND_AMOUNT_TWO,
    // "seed validator 2"
    //});

    cfg.validators.push_back({1,
                              Crypto::addrFromHex(GlobalConfig::SEED_ADDRESS),
                              Crypto::pubkeyFromHex(GlobalConfig::SEED_NODE),
                              true});

    // Add more if needed
    // cfg.validators.push_back({
    //  2,
    //  GlobalConfig::SEED_ADDRESS_TWO,
    //  GlobalConfig::SEED_NODE_TWO,
    //  true
    //});

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
      a.recalculateStaked(AUTO_STAKE_THRESHOLD);
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
      vi.node_key = v.node_key;
      vi.owner = v.reward_address;
      vi.registered_at_height = 0;
      vi.stake = VALIDATOR_MIN_STAKE;
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

      // NEW: validator-by-address index.
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

    // Derive next_validator_id from the highest seed id rather
    // than assuming exactly two seeds with ids {1, 2}. The previous
    // hardcoded value would collide with a third seed if a network
    // ever added one.
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
    state.putGlobal("next_token_id", u64Bytes(1)); // 0 is native CLRTY
    state.putGlobal("next_order_id", u64Bytes(1));
    state.putGlobal("next_pool_id", u64Bytes(1));
    state.putGlobal("next_position_id", u64Bytes(1));
    state.putGlobal("last_rotation_height", u64Bytes(0));
    state.putGlobal("apy_activity_bps", u64Bytes(0));
    state.putGlobal("apy_pot_bps", u64Bytes(0));

    // Initial active set size. Written explicitly so a fresh node
    // reads it from state rather than falling back to a compile-time
    // default in the rotation logic.
    state.putGlobal("active_set_size",
                    u64Bytes(config.initial_active_set_size));

    // ---- Native token metadata ----
    {
      TokenInfo native;
      native.id = INVALID_ID;
      native.name = GlobalConfig::PROJECT_NAME;
      native.symbol = GlobalConfig::PROJECT_SYMBOL;
      native.decimals = GlobalConfig::DECIMALS;
      native.creator = Crypto::Address{}; // zero = native token
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
    hdr.version = 1; // Genesis will always be version 1
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

    // Collect seed validator IDs.
    std::vector<Id> active_ids;
    for (const auto &v : config.validators)
    {
      if (v.is_seed)
        active_ids.push_back(v.id);
    }

    // Root of the seed validator set.
    b.header.validator_set_root = computeValidatorSetRoot(active_ids);

    // The state root after applying genesis.
    b.header.state_root = state.stateRoot();

    // No transactions, no quorum signatures, no participants.
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

} // namespace Core