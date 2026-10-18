// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Genesis.h"

#include "Account.h"
#include "BridgeTypes.h"
#include "BridgeWatcherTypes.h"
#include "Bridge/ConcealCCX.h"
#include "GlobalState.h"
#include "KeyRotation.h"
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
  Crypto::Hash hashFromHex(const char *hex)
  {
    Crypto::Hash h;
    std::vector<uint8_t> bytes = Common::fromHex(std::string(hex));
    if (bytes.size() != 32)
      throw std::runtime_error("hashFromHex: expected 64 hex chars");
    std::memcpy(h.data.data(), bytes.data(), 32);
    return h;
  }

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

    if (isHex64(s))
      return Crypto::addrFromHex(value);

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

  std::vector<uint8_t> u64Bytes(uint64_t v)
  {
    std::vector<uint8_t> out(8);
    for (int i = 0; i < 8; ++i)
      out[i] = uint8_t(v >> (i * 8));
    return out;
  }
} // anonymous namespace

namespace Core
{
  //  =========================================================================
  //  Network configurations
  //  =========================================================================

  GenesisConfig mainnetGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::CHAIN_ID;
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    constexpr Wallet::Network net = Wallet::Network::Mainnet;

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::TREASURY_FUND_ADDRESS, net, "treasury"),
                            GlobalConfig::TREASURY_FUND_AMOUNT,
                            "treasury"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::SEED_ADDRESS_MAINNET, net, "seed validator 1"),
                            GlobalConfig::SEED_FUND_AMOUNT,
                            "seed validator 1"});

    cfg.accounts.push_back({addressFromConfig(GlobalConfig::SEED_ADDRESS_TWO_MAINNET, net, "seed validator 2"),
                            GlobalConfig::SEED_FUND_AMOUNT_TWO,
                            "seed validator 2"});

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

    cfg.bridge.enabled = true;
    cfg.bridge.ccx_chain_id = BRIDGE_CCX_CHAIN_ID;

    return cfg;
  }

  GenesisConfig testnetGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::TESTNET_CHAIN_ID;
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    constexpr Wallet::Network net = Wallet::Network::Testnet;

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

    cfg.bridge.enabled = true;
    cfg.bridge.ccx_chain_id = BRIDGE_CCX_CHAIN_ID;

    return cfg;
  }

  GenesisConfig regtestGenesis()
  {
    GenesisConfig cfg;
    cfg.chain_id = GlobalConfig::REGNET_CHAIN_ID;
    cfg.timestamp_ms = GlobalConfig::GENESIS_TIMESTAMP_MS;

    constexpr Wallet::Network net = Wallet::Network::Regtest;

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

    cfg.bridge.enabled = true;
    cfg.bridge.ccx_chain_id = BRIDGE_CCX_CHAIN_ID;

    return cfg;
  }

  // ============================================================================
  //  Application
  // ============================================================================

  void applyGenesis(State::StateAccess &state, const GenesisConfig &config)
  {
    //  =====================================================================
    //  Idempotency contract
    //
    //  This function must be safe to call more than once on the same
    //  state and produce the same resulting root each time. That is
    //  *not* the same as "every write is an assignment":
    //
    //    - putAccount() maintains the globals `total_staked` and
    //      `staker_count` by an *incremental* update:
    //          total += copy.staked - old.staked
    //      On a fresh DB old.staked == 0 so this adds the full
    //      amount; on a second call old.staked already equals the
    //      new staked amount, so it adds zero. If we simply wrote
    //      `0` to those globals at the top and relied on putAccount
    //      to rebuild them, the second call would leave them at 0
    //      while the first left them at sum-of-genesis-stakes —
    //      different roots, broken idempotency.
    //
    //    - The bridge block needs a deterministic wrapped-token id
    //      regardless of whatever `next_token_id` happens to be in
    //      the DB. At genesis, that id is always 1 (nothing else
    //      has been minted yet), so we hard-code it as a local
    //      constant rather than reading the global back.
    //
    //  So: every write here is either a plain assignment derived
    //  from `config`, or an incremental update whose final value
    //  we then overwrite with the correct config-derived total.
    //  =====================================================================

    // ---- Global state ----

    uint64_t max_seed_id = 0;
    for (const auto &v : config.validators)
    {
      if (v.is_seed && v.id > max_seed_id)
        max_seed_id = v.id;
    }

    state.putGlobal("chain_id", u64Bytes(config.chain_id));
    state.putGlobal("total_supply", u64Bytes(config.initial_total_supply));
    state.putGlobal("pot", u64Bytes(0));
    state.putGlobal("epoch_number", u64Bytes(0));
    state.putGlobal("next_validator_id", u64Bytes(max_seed_id + 1));
    state.putGlobal("next_token_id", u64Bytes(1));
    state.putGlobal("next_order_id", u64Bytes(1));
    state.putGlobal("next_pool_id", u64Bytes(1));
    state.putGlobal("next_position_id", u64Bytes(1));
    state.putGlobal("next_collection_id", u64Bytes(1));
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

    // ---- Initial accounts ----
    //
    //  putAccount maintains `total_staked` and `staker_count` as a
    //  side-effect. On a fresh DB that side-effect produces the
    //  correct totals; on a second call it produces zero. To make
    //  the function idempotent we recompute the totals directly
    //  from `config.accounts` and overwrite the globals once the
    //  loop has finished.

    uint64_t genesis_total_staked = 0;
    uint64_t genesis_staker_count = 0;

    for (const auto &acc : config.accounts)
    {
      Account a;
      a.balance = acc.balance_atomic;
      a.nonce = 0;
      a.staking_opted_out = false;
      a.created_at_height = 0;
      a.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
      state.putAccount(acc.address, a);

      genesis_total_staked += a.staked;
      if (a.staked > 0)
        ++genesis_staker_count;
    }

    state.putGlobal("total_staked", u64Bytes(genesis_total_staked));
    state.putGlobal("staker_count", u64Bytes(genesis_staker_count));

    // ---- Seed validators ----

    for (const auto &v : config.validators)
    {
      ValidatorInfo vi;
      vi.id = v.id;
      vi.reward_address = v.reward_address;

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

      vi.pings_responded_this_epoch = 0;
      vi.pings_sent_this_epoch = 0;
      vi.total_blocks_produced = 0;
      vi.total_rewards_earned = 0;
      vi.epochs_active = 0;

      state.putValidator(vi);

      state.putValidatorByAddress(v.reward_address, v.id);

      {
        std::vector<KeyRotation> history;
        KeyRotation entry;
        entry.key = vi.effectiveConsensusKey();
        entry.valid_from_height = 0;
        entry.valid_until_height = 0;
        history.push_back(entry);
        state.putValidatorKeyHistory(v.id, history);
      }
    }

    // ---- Bridge ----

    if (config.bridge.enabled)
    {
      const Id wrapped_token_id = 1;

      {
        TokenInfo wrapped;
        wrapped.id = wrapped_token_id;
        wrapped.name = std::string(CcxBridge::CCX_WRAPPED_NAME);
        wrapped.symbol = std::string(CcxBridge::CCX_WRAPPED_SYMBOL);
        wrapped.decimals = CcxBridge::CCX_WRAPPED_DECIMALS;
        wrapped.creator = Crypto::Address{};
        wrapped.backing = BackingModel::Backed;
        wrapped.maxSupply = 0;
        wrapped.royaltyBps = 0;
        wrapped.fingerprint = CcxBridge::wrappedTokenFingerprint();

        state.putToken(wrapped);
        state.putTokenSupply(wrapped_token_id, 0);
      }

      state.putGlobal(
          "next_token_id",
          u64Bytes(static_cast<uint64_t>(wrapped_token_id) + 1));

      {
        BridgeChainRegistration reg;
        reg.source_chain_id = config.bridge.ccx_chain_id;
        reg.wrapped_token_id = static_cast<uint32_t>(wrapped_token_id);
        reg.fingerprint = CcxBridge::wrappedTokenFingerprint();
        reg.source_decimals = CcxBridge::CCX_SOURCE_DECIMALS;
        reg.clarity_decimals = CcxBridge::CCX_CLARITY_DECIMALS;
        reg.confirmation_depth = CcxBridge::CCX_CONFIRMATION_DEPTH;
        reg.destination_blob_min_len =
            static_cast<uint8_t>(CcxBridge::CCX_DESTINATION_MIN_BYTES);
        reg.destination_blob_max_len =
            static_cast<uint8_t>(CcxBridge::CCX_DESTINATION_MAX_BYTES);
        reg.enabled = true;
        reg.active_watcher_min = BRIDGE_CCX_ACTIVE_WATCHER_MIN;

        if (!reg.isWellFormed())
          throw std::runtime_error(
              "genesis: bridge chain registration is ill-formed");

        state.putBridgeChainRegistration(reg);
      }

      uint64_t next_watcher_id = 1;
      for (const auto &v : config.validators)
      {
        BridgeWatcherInfo w;
        w.id = next_watcher_id++;
        w.validator_id = v.id;
        w.source_chain_id = config.bridge.ccx_chain_id;
        w.reward_address = v.reward_address;
        w.registered_at_height = 0;
        w.stake = BRIDGE_WATCHER_MIN_STAKE;
        w.last_seen_height = 0;
        w.is_active = true;
        w.became_active_at = 0;
        w.last_active_at = 0;

        if (!w.isWellFormed())
          throw std::runtime_error(
              "genesis: bridge watcher record for seed is ill-formed");

        state.putBridgeWatcher(w);
      }

      state.putGlobal("bridge_paused", u64Bytes(0));
      state.putGlobal("bridge_next_withdrawal_id", u64Bytes(1));
      state.putGlobal("bridge_withdrawals_pending", u64Bytes(0));
      state.putGlobal("bridge_consumed_count", u64Bytes(0));
      state.putGlobal("bridge_next_watcher_id", u64Bytes(next_watcher_id));
    }

    // ---- Active set ----

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
      state.setHistoryWindow(GlobalConfig::REGTEST_SMT_HISTORY_BLOCKS);
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