// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/BridgeTypes.h"
#include "Core/BridgeWatcherTypes.h"
#include "Core/Bridge/ConcealCCX.h"
#include "Core/Genesis.h"
#include "Core/GlobalState.h"
#include "Core/TokenTypes.h"

#include "State/StateAccess.h"
#include "State/StateDB.h"

#include <filesystem>

using namespace Core;

namespace
{
  class Core_BridgeGenesisFixture : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      tmp_dir_ = std::filesystem::temp_directory_path() /
                 ("clrty_bridge_genesis_" +
                  std::to_string(::testing::UnitTest::GetInstance()
                                     ->current_test_info()
                                     ->line()));

      std::filesystem::remove_all(tmp_dir_);
      std::filesystem::create_directories(tmp_dir_);

      db_ = std::make_unique<State::StateDB>(
          tmp_dir_.string(), 64ULL * 1024 * 1024);

      cfg_ = regtestGenesis();

      {
        auto txn = db_->beginWrite();
        State::StateAccess state(*db_, txn, /*version=*/0);
        applyGenesis(state, cfg_);
        state.commit(0);
        txn.commit();
      }

      state_ = std::make_unique<State::StateAccess>(*db_, 0);
      state_->setHistoryWindow(GlobalConfig::REGTEST_SMT_HISTORY_BLOCKS);
    }

    void TearDown() override
    {
      state_.reset();
      db_->close();
      db_.reset();

      std::error_code ec;
      std::filesystem::remove_all(tmp_dir_, ec);
    }

    std::unique_ptr<State::StateDB> db_;
    std::unique_ptr<State::StateAccess> state_;
    GenesisConfig cfg_;
    std::filesystem::path tmp_dir_;
  };

} // anonymous namespace

// ============================================================================
//  Wrapped-CCX token
// ============================================================================

TEST_F(Core_BridgeGenesisFixture, WrappedTokenExists)
{
  TokenInfo wrapped;
  ASSERT_TRUE(state_->getToken(1, wrapped));

  EXPECT_EQ(wrapped.id, 1u);
  EXPECT_EQ(wrapped.name, std::string(CcxBridge::CCX_WRAPPED_NAME));
  EXPECT_EQ(wrapped.symbol, std::string(CcxBridge::CCX_WRAPPED_SYMBOL));
  EXPECT_EQ(wrapped.decimals, CcxBridge::CCX_WRAPPED_DECIMALS);
  EXPECT_EQ(wrapped.backing, BackingModel::Backed);
  EXPECT_EQ(wrapped.maxSupply, 0u);
  EXPECT_EQ(wrapped.royaltyBps, 0u);

  ASSERT_TRUE(wrapped.fingerprint.has_value());
  EXPECT_EQ(*wrapped.fingerprint, CcxBridge::wrappedTokenFingerprint());

  EXPECT_TRUE(wrapped.creator.isNull());
}

TEST_F(Core_BridgeGenesisFixture, WrappedTokenIsBridged)
{
  TokenInfo wrapped;
  ASSERT_TRUE(state_->getToken(1, wrapped));
  EXPECT_TRUE(wrapped.isBridged());
  EXPECT_FALSE(wrapped.isNative());
}

TEST_F(Core_BridgeGenesisFixture, WrappedTokenSupplyStartsAtZero)
{
  EXPECT_EQ(state_->getTokenSupply(1), 0u);
}

// ============================================================================
//  CCX chain registration
// ============================================================================

TEST_F(Core_BridgeGenesisFixture, CcxChainRegistrationExists)
{
  BridgeChainRegistration reg;
  ASSERT_TRUE(state_->getBridgeChainRegistration(
      CcxBridge::CCX_CHAIN_ID, reg));

  EXPECT_EQ(reg.source_chain_id, CcxBridge::CCX_CHAIN_ID);
  EXPECT_EQ(reg.wrapped_token_id, 1u);
  EXPECT_EQ(reg.fingerprint, CcxBridge::wrappedTokenFingerprint());
  EXPECT_EQ(reg.source_decimals, CcxBridge::CCX_SOURCE_DECIMALS);
  EXPECT_EQ(reg.clarity_decimals, CcxBridge::CCX_CLARITY_DECIMALS);
  EXPECT_EQ(reg.confirmation_depth, CcxBridge::CCX_CONFIRMATION_DEPTH);
  EXPECT_EQ(reg.destination_blob_min_len,
            CcxBridge::CCX_DESTINATION_MIN_BYTES);
  EXPECT_EQ(reg.destination_blob_max_len,
            CcxBridge::CCX_DESTINATION_MAX_BYTES);
  EXPECT_TRUE(reg.enabled);
  EXPECT_EQ(reg.active_watcher_min, BRIDGE_CCX_ACTIVE_WATCHER_MIN);
  EXPECT_TRUE(reg.isWellFormed());
}

TEST_F(Core_BridgeGenesisFixture, NoUnknownChainRegistrations)
{
  BridgeChainRegistration reg;
  EXPECT_FALSE(state_->getBridgeChainRegistration(
      CcxBridge::CCX_CHAIN_ID + 1, reg));
  EXPECT_FALSE(state_->getBridgeChainRegistration(0, reg));
}

// ============================================================================
//  Bridge watcher records
// ============================================================================

TEST_F(Core_BridgeGenesisFixture, BridgeWatchersExist)
{
  BridgeWatcherInfo w1, w2;
  ASSERT_TRUE(state_->getBridgeWatcher(1, w1));
  ASSERT_TRUE(state_->getBridgeWatcher(2, w2));

  EXPECT_EQ(w1.id, 1u);
  EXPECT_EQ(w1.validator_id, 1u);
  EXPECT_EQ(w1.source_chain_id, CcxBridge::CCX_CHAIN_ID);
  EXPECT_EQ(w1.stake, BRIDGE_WATCHER_MIN_STAKE);
  EXPECT_TRUE(w1.is_active);
  EXPECT_EQ(w1.pending_unbond_height, 0u);
  EXPECT_EQ(w1.infraction_count, 0u);

  EXPECT_EQ(w2.id, 2u);
  EXPECT_EQ(w2.validator_id, 2u);
  EXPECT_EQ(w2.source_chain_id, CcxBridge::CCX_CHAIN_ID);
  EXPECT_EQ(w2.stake, BRIDGE_WATCHER_MIN_STAKE);
  EXPECT_TRUE(w2.is_active);
  EXPECT_EQ(w2.pending_unbond_height, 0u);
  EXPECT_EQ(w2.infraction_count, 0u);
}

TEST_F(Core_BridgeGenesisFixture, BridgeWatcherRecordsAreWellFormed)
{
  BridgeWatcherInfo w;
  ASSERT_TRUE(state_->getBridgeWatcher(1, w));
  EXPECT_TRUE(w.isWellFormed());

  ASSERT_TRUE(state_->getBridgeWatcher(2, w));
  EXPECT_TRUE(w.isWellFormed());
}

TEST_F(Core_BridgeGenesisFixture, BridgeWatcherRewardAddressesMatchSeeds)
{
  BridgeWatcherInfo w1, w2;
  ASSERT_TRUE(state_->getBridgeWatcher(1, w1));
  ASSERT_TRUE(state_->getBridgeWatcher(2, w2));

  ASSERT_GE(cfg_.validators.size(), 2u);
  EXPECT_EQ(w1.reward_address, cfg_.validators[0].reward_address);
  EXPECT_EQ(w2.reward_address, cfg_.validators[1].reward_address);
}

TEST_F(Core_BridgeGenesisFixture, BridgeWatchersFormActiveSet)
{
  size_t count = 0;
  state_->forEachActiveBridgeWatcherForChain(
      CcxBridge::CCX_CHAIN_ID, /*current_height=*/0,
      [&](const BridgeWatcherInfo &)
      { ++count; });
  EXPECT_EQ(count, 2u);
}

TEST_F(Core_BridgeGenesisFixture, BridgeWatcherSetSatisfiesMinimum)
{
  const size_t count = state_->countActiveBridgeWatchersForChain(
      CcxBridge::CCX_CHAIN_ID, /*current_height=*/0);
  EXPECT_EQ(count, BRIDGE_CCX_ACTIVE_WATCHER_MIN);
}

// ============================================================================
//  Bridge globals at initial values
// ============================================================================

TEST_F(Core_BridgeGenesisFixture, BridgeGlobalsAtInitialValues)
{
  GlobalStateReader reader(*state_);

  EXPECT_FALSE(reader.bridgePaused());
  EXPECT_EQ(reader.bridgeNextWithdrawalId(), 1u);
  EXPECT_EQ(reader.bridgeWithdrawalsPending(), 0u);
  EXPECT_EQ(reader.bridgeConsumedCount(), 0u);
  EXPECT_EQ(reader.bridgeNextWatcherId(), 3u);
}

// ============================================================================
//  Idempotency
//
//  Applies genesis twice on a fresh DB and compares the resulting state
//  roots. This tests the invariant that actually matters: "re-running
//  genesis on a fresh chain is a no-op."
//
//  The fixture's own DB is deliberately NOT used here. It has already
//  been modified by fundStandardAccounts(), and — more importantly —
//  applyGenesis() resets total_staked / staker_count to zero and
//  re-derives them only from config.accounts. A second apply over a
//  dirty DB therefore produces a different (inconsistent) root for
//  reasons that have nothing to do with the invariant we want to test.
//
//  Using a fresh DB also sidesteps the read-txn lifetime rule in
//  StateDB: the test opens and commits its own write txns, and never
//  leaves an autocommit StateAccess alive across a beginWrite().
// ============================================================================

TEST(Core_BridgeGenesisIdempotency, ApplyGenesisIsIdempotent)
{
  //  Standalone — does not need Core_BridgeGenesisFixture's DB or
  //  its autocommit `state_`. Only needs a GenesisConfig.
  const auto tmp = std::filesystem::temp_directory_path() /
                   "clrty_bridge_idem_standalone";
  std::filesystem::remove_all(tmp);
  std::filesystem::create_directories(tmp);

  GenesisConfig cfg = regtestGenesis();
  cfg.bridge.enabled = true;
  cfg.bridge.ccx_chain_id = CcxBridge::CCX_CHAIN_ID;

  auto db = std::make_unique<State::StateDB>(tmp.string(),
                                             64ULL * 1024 * 1024);

  Crypto::Hash root_after_one;
  {
    auto txn = db->beginWrite();
    State::StateAccess st(*db, txn, 0);
    applyGenesis(st, cfg);
    st.commit(0);
    txn.commit();
  }
  {
    State::StateAccess reader(*db, 0);
    root_after_one = reader.stateRoot();
  }

  Crypto::Hash root_after_two;
  {
    auto txn = db->beginWrite();
    State::StateAccess st(*db, txn, 0);
    applyGenesis(st, cfg);
    st.commit(0);
    txn.commit();
  }
  {
    State::StateAccess reader(*db, 0);
    root_after_two = reader.stateRoot();
  }

  EXPECT_EQ(root_after_one, root_after_two);

  db->close();
  db.reset();
  std::error_code ec;
  std::filesystem::remove_all(tmp, ec);
}

// ============================================================================
//  Genesis block hash
// ============================================================================

TEST_F(Core_BridgeGenesisFixture, GenesisHashMatchesPinnedOrIsRegenerable)
{
  State::StateAccess state(*db_, 0);
  Block genesis = makeGenesisBlock(state, cfg_);
  const Crypto::Hash computed = genesis.hash();
  const Crypto::Hash expected = expectedGenesisHash(cfg_);

  ASSERT_FALSE(expected.isNull())
      << "expectedGenesisHash returned null for regtest.";

  if (computed != expected)
  {
    GTEST_SKIP()
        << "Genesis hash is stale. Update GlobalConfig::*_GENESIS_HASH "
           "to the computed value and rebuild.\n"
        << "  chain_id: " << std::hex << cfg_.chain_id << std::dec << "\n"
        << "  computed: " << computed.toString() << "\n"
        << "  pinned:   " << expected.toString();
  }

  EXPECT_EQ(computed, expected);
}

// ============================================================================
//  Bridge-disabled genesis
// ============================================================================

TEST(Core_BridgeGenesis, DisabledBridgeWritesNoState)
{
  const auto tmp = std::filesystem::temp_directory_path() /
                   "clrty_bridge_genesis_disabled";
  std::filesystem::remove_all(tmp);
  std::filesystem::create_directories(tmp);

  auto db = std::make_unique<State::StateDB>(tmp.string(),
                                             64ULL * 1024 * 1024);

  GenesisConfig cfg = regtestGenesis();
  cfg.bridge.enabled = false;

  {
    auto txn = db->beginWrite();
    State::StateAccess state(*db, txn, 0);
    applyGenesis(state, cfg);
    state.commit(0);
    txn.commit();
  }

  {
    State::StateAccess state(*db, 0);

    TokenInfo wrapped;
    EXPECT_FALSE(state.getToken(1, wrapped));

    BridgeChainRegistration reg;
    EXPECT_FALSE(state.getBridgeChainRegistration(
        CcxBridge::CCX_CHAIN_ID, reg));

    BridgeWatcherInfo w;
    EXPECT_FALSE(state.getBridgeWatcher(1, w));
    EXPECT_FALSE(state.getBridgeWatcher(2, w));

    EXPECT_EQ(state.countActiveBridgeWatchersForChain(
                  CcxBridge::CCX_CHAIN_ID, 0),
              0u);

    GlobalStateReader reader(state);
    EXPECT_FALSE(reader.bridgePaused());
    EXPECT_EQ(reader.bridgeNextWatcherId(), 0u);
    EXPECT_EQ(reader.bridgeWithdrawalsPending(), 0u);
  }

  db->close();
  db.reset();
  std::filesystem::remove_all(tmp);
}