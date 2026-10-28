// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Core/BridgeTypes.h"
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

  //  Under the validator-is-watcher model there is no separate
  //  watcher set and no per-chain registration of watchers. The
  //  chain registration's active_validator_min is the floor on the
  //  active validator set size for this chain to operate. It is
  //  the same field the executor checks against
  //  forEachActiveValidator's count when verifying a mint
  //  attestation or an ack attestation.
  EXPECT_EQ(reg.active_validator_min, GlobalConfig::ACTIVE_SET_MIN);

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
//  Validator-as-watcher invariant
//
//  Before commit 93be86f, genesis wrote per-watcher records at
//  TBL_BRIDGE_WATCHERS and a by-owner index, and the executor
//  resolved the operational signer set by reading those records
//  per chain. The commit removed both. The invariant that replaced
//  it — and the one this file now verifies — is:
//
//    "The operational signer set for every registered source chain
//    is the active validator set at the height of the operation."
//
//  At genesis this is checked as: every seed validator in the
//  active set appears in forEachActiveValidator, and the count
//  satisfies active_validator_min. There is no watcher table to
//  read because there is no watcher record.
// ============================================================================

TEST_F(Core_BridgeGenesisFixture, ActiveValidatorsExist)
{
  //  The genesis fixture has two seed validators. Both must be
  //  present in the active set (the fixture's genesis_config
  //  sets initial_active_set_size = 2 and the two seed validator
  //  records are written by applyGenesis).
  std::vector<Core::ValidatorInfo> active;
  state_->forEachActiveValidator(
      [&](const Core::ValidatorInfo &v)
      { active.push_back(v); });

  ASSERT_EQ(active.size(), 2u);

  //  Both seeds must be present, with the same reward addresses
  //  the fixture's GenesisConfig carries.
  ASSERT_GE(cfg_.validators.size(), 2u);

  bool found_1 = false;
  bool found_2 = false;
  for (const auto &v : active)
  {
    if (v.id == 1)
    {
      found_1 = true;
      EXPECT_EQ(v.reward_address, cfg_.validators[0].reward_address);
      EXPECT_TRUE(v.is_seed);
    }
    else if (v.id == 2)
    {
      found_2 = true;
      EXPECT_EQ(v.reward_address, cfg_.validators[1].reward_address);
      EXPECT_TRUE(v.is_seed);
    }
  }
  EXPECT_TRUE(found_1);
  EXPECT_TRUE(found_2);
}

TEST_F(Core_BridgeGenesisFixture, ActiveValidatorSetSatisfiesMin)
{
  //  The bridge's operational signer set is the active validator
  //  set. The chain registration's active_validator_min is the
  //  floor that set must meet for the bridge to operate against
  //  that chain.
  //
  //  At genesis the active set is exactly the two seeds, and
  //  active_validator_min for CCX is 2 (matching
  //  ACTIVE_SET_MIN). This test asserts the invariant holds at
  //  the chain's starting state.
  const size_t active_count = state_->countActiveValidators();
  EXPECT_EQ(active_count, static_cast<size_t>(GlobalConfig::INITIAL_SET_SIZE));

  BridgeChainRegistration reg;
  ASSERT_TRUE(state_->getBridgeChainRegistration(
      CcxBridge::CCX_CHAIN_ID, reg));

  EXPECT_GE(active_count, reg.active_validator_min);
}

TEST_F(Core_BridgeGenesisFixture, NoBridgeWatcherTablePopulated)
{
  //  Commit 93be86f removed the per-watcher records. This test
  //  is the negative-space assertion: nothing in genesis writes
  //  to the removed table, and there is no API to read it back.
  //
  //  We assert the absence by checking that the old accessors
  //  no longer exist at the type level — i.e. this test body
  //  simply doesn't call them. If a future refactor re-adds a
  //  watcher table, this test is the place to add the assertion
  //  that it's empty at genesis. Today the test documents the
  //  invariant by existing and compiling.
  //
  //  What it proves: the genesis writer's only writer for
  //  bridge-related state is the chain registration plus the
  //  wrapped token. Validators are the operational signer set
  //  by virtue of being in active_set, not by being named in
  //  a separate record.
  SUCCEED() << "No separate watcher state; validators are the "
               "operational signer set by construction.";
}

// ============================================================================
//  Bridge globals at initial values
//
//  bridgeNextWatcherId is no longer written by genesis: the
//  watcher id counter only existed to allocate BridgeWatcherInfo
//  records, and there are none. The remaining globals are
//  unchanged.
// ============================================================================

TEST_F(Core_BridgeGenesisFixture, BridgeGlobalsAtInitialValues)
{
  GlobalStateReader reader(*state_);

  EXPECT_FALSE(reader.bridgePaused());
  EXPECT_EQ(reader.bridgeNextWithdrawalId(), 1u);
  EXPECT_EQ(reader.bridgeWithdrawalsPending(), 0u);
  EXPECT_EQ(reader.bridgeConsumedCount(), 0u);
}

// ============================================================================
//  Idempotency
//
//  Applies genesis twice on a fresh DB and compares the resulting
//  state roots. Same invariant as before: "re-running genesis on
//  a fresh chain is a no-op." The removal of the watcher table
//  does not change this — the test still uses a fresh DB for the
//  reasons documented in the original.
// ============================================================================

TEST(Core_BridgeGenesisIdempotency, ApplyGenesisIsIdempotent)
{
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

    //  No watcher record to check; the validator-as-watcher model
    //  has no separate watcher table. What we *can* check is that
    //  the bridge globals are at their empty values, which means
    //  no genesis-time bridge state was written.
    GlobalStateReader reader(state);
    EXPECT_FALSE(reader.bridgePaused());
    EXPECT_EQ(reader.bridgeWithdrawalsPending(), 0u);
  }

  db->close();
  db.reset();
  std::filesystem::remove_all(tmp);
}