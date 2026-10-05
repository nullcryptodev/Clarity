// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fixtures.h"

#include "State/StateAccess.h"

#include "Core/Account.h"
#include "Core/AmmPool.h"
#include "Core/AmmPosition.h"
#include "Core/Order.h"
#include "Core/Receipt.h"
#include "Core/RewardTypes.h"
#include "Core/TokenTypes.h"
#include "Core/ValidatorTypes.h"

using namespace State;
using namespace Tests;

// ============================================================================
//  A. Accounts
// ============================================================================

TEST_F(State_StateAccessFixture, AccountRoundTrip)
{
  auto addr = makeAddress(1);

  Core::Account acct;
  acct.balance = 12'345;
  acct.nonce = 7;
  acct.pending_rewards = 42;
  acct.created_at_height = 3;
  acct.staking_opted_out = false;

  s().putAccount(addr, acct);

  Core::Account got = s().getAccount(addr);
  EXPECT_EQ(got.balance, 12'345u);
  EXPECT_EQ(got.nonce, 7u);
  EXPECT_EQ(got.pending_rewards, 42u);
  EXPECT_EQ(got.created_at_height, 3u);
}

TEST_F(State_StateAccessFixture, MissingAccountIsEmpty)
{
  auto addr = makeAddress(123);
  Core::Account got = s().getAccount(addr);
  EXPECT_TRUE(got.isEmpty());
  EXPECT_EQ(got.balance, 0u);
  EXPECT_EQ(got.nonce, 0u);
}

TEST_F(State_StateAccessFixture, AccountExistsReflectsWrites)
{
  auto addr = makeAddress(1);

  EXPECT_FALSE(s().accountExists(addr));

  Core::Account acct;
  acct.balance = 100;
  s().putAccount(addr, acct);

  EXPECT_TRUE(s().accountExists(addr));
}

TEST_F(State_StateAccessFixture, DeleteAccountRemovesIt)
{
  auto addr = makeAddress(1);

  Core::Account acct;
  acct.balance = 500;
  s().putAccount(addr, acct);
  ASSERT_TRUE(s().accountExists(addr));

  s().deleteAccount(addr);
  EXPECT_FALSE(s().accountExists(addr));
  EXPECT_TRUE(s().getAccount(addr).isEmpty());
}

TEST_F(State_StateAccessFixture, MultipleAccountsIndependent)
{
  auto a = makeAddress(1);
  auto b = makeAddress(2);
  auto c = makeAddress(3);

  Core::Account acct_a;
  acct_a.balance = 100;
  Core::Account acct_b;
  acct_b.balance = 200;
  Core::Account acct_c;
  acct_c.balance = 300;

  s().putAccount(a, acct_a);
  s().putAccount(b, acct_b);
  s().putAccount(c, acct_c);

  EXPECT_EQ(s().getAccount(a).balance, 100u);
  EXPECT_EQ(s().getAccount(b).balance, 200u);
  EXPECT_EQ(s().getAccount(c).balance, 300u);
}

TEST_F(State_StateAccessFixture, UpdatingAccountOverwrites)
{
  auto addr = makeAddress(1);

  Core::Account acct;
  acct.balance = 100;
  s().putAccount(addr, acct);

  acct.balance = 999;
  s().putAccount(addr, acct);

  EXPECT_EQ(s().getAccount(addr).balance, 999u);
}

// ============================================================================
//  A2. Staker totals
//
//  putAccount maintains three global counters in response to account
//  writes: total_staked (sum of every account's staked), staker_count
//  (number of accounts with staked > 0), and the staker index. These
//  tests verify the maintenance logic directly.
// ============================================================================

TEST_F(State_StateAccessFixture, PutAccountMaintainsTotalStaked)
{
  auto a = makeAddress(0xAA);

  // Below auto-stake threshold: no stake, no contribution to total.
  {
    Core::Account acct;
    acct.balance = GlobalConfig::AUTO_STAKE_THRESHOLD - 1;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    s().putAccount(a, acct);
    EXPECT_EQ(readU64Global(s(), "total_staked"), 0u);
  }

  // At threshold: becomes a staker, total picks up the full balance.
  {
    Core::Account acct;
    acct.balance = GlobalConfig::AUTO_STAKE_THRESHOLD;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    s().putAccount(a, acct);
    EXPECT_EQ(readU64Global(s(), "total_staked"),
              GlobalConfig::AUTO_STAKE_THRESHOLD);
  }

  // Increase balance: total grows by the delta.
  {
    Core::Account acct;
    acct.balance = GlobalConfig::AUTO_STAKE_THRESHOLD * 3;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    s().putAccount(a, acct);
    EXPECT_EQ(readU64Global(s(), "total_staked"),
              GlobalConfig::AUTO_STAKE_THRESHOLD * 3);
  }

  // Opt out: no longer a staker, total drops to 0.
  {
    Core::Account acct;
    acct.balance = GlobalConfig::AUTO_STAKE_THRESHOLD * 3;
    acct.staking_opted_out = true;
    acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
    s().putAccount(a, acct);
    EXPECT_EQ(readU64Global(s(), "total_staked"), 0u);
  }
}

TEST_F(State_StateAccessFixture, PutAccountMaintainsStakerCount)
{
  auto a = makeAddress(0xAA);
  auto b = makeAddress(0xBB);

  Core::Account acct;
  acct.balance = GlobalConfig::AUTO_STAKE_THRESHOLD;
  acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);

  s().putAccount(a, acct);
  EXPECT_EQ(readU64Global(s(), "staker_count"), 1u);

  s().putAccount(b, acct);
  EXPECT_EQ(readU64Global(s(), "staker_count"), 2u);

  // Writing the same account twice doesn't double-count.
  s().putAccount(a, acct);
  EXPECT_EQ(readU64Global(s(), "staker_count"), 2u);

  // Opting out decrements.
  acct.staking_opted_out = true;
  acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
  s().putAccount(a, acct);
  EXPECT_EQ(readU64Global(s(), "staker_count"), 1u);
}

TEST_F(State_StateAccessFixture, PutAccountSetsStakerSinceHeight)
{
  setVersion(500);

  auto a = makeAddress(0xAA);

  Core::Account acct;
  acct.balance = GlobalConfig::AUTO_STAKE_THRESHOLD;
  acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);

  s().putAccount(a, acct);
  EXPECT_EQ(s().getAccount(a).staker_since_height, 500u);

  acct.balance = GlobalConfig::AUTO_STAKE_THRESHOLD * 2;
  acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
  s().putAccount(a, acct);
  EXPECT_EQ(s().getAccount(a).staker_since_height, 500u);

  acct.staking_opted_out = true;
  acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
  s().putAccount(a, acct);
  EXPECT_EQ(s().getAccount(a).staker_since_height, 0u);
}

// ============================================================================
//  B. Token balances
// ============================================================================

TEST_F(State_StateAccessFixture, TokenBalanceRoundTrip)
{
  auto addr = makeAddress(1);
  Id token = 42;

  EXPECT_EQ(s().getTokenBalance(addr, token), 0u);

  s().putTokenBalance(addr, token, 12'345);
  EXPECT_EQ(s().getTokenBalance(addr, token), 12'345u);
}

TEST_F(State_StateAccessFixture, TokenBalanceZeroDeletes)
{
  auto addr = makeAddress(1);
  Id token = 42;

  s().putTokenBalance(addr, token, 100);
  ASSERT_EQ(s().getTokenBalance(addr, token), 100u);

  s().putTokenBalance(addr, token, 0);
  EXPECT_EQ(s().getTokenBalance(addr, token), 0u);
}

TEST_F(State_StateAccessFixture, DeleteTokenBalanceExplicit)
{
  auto addr = makeAddress(1);
  Id token = 42;

  s().putTokenBalance(addr, token, 100);
  s().deleteTokenBalance(addr, token);
  EXPECT_EQ(s().getTokenBalance(addr, token), 0u);
}

TEST_F(State_StateAccessFixture, MultipleTokensPerAddress)
{
  auto addr = makeAddress(1);

  s().putTokenBalance(addr, 10, 1000);
  s().putTokenBalance(addr, 20, 2000);
  s().putTokenBalance(addr, 30, 3000);

  EXPECT_EQ(s().getTokenBalance(addr, 10), 1000u);
  EXPECT_EQ(s().getTokenBalance(addr, 20), 2000u);
  EXPECT_EQ(s().getTokenBalance(addr, 30), 3000u);
  EXPECT_EQ(s().getTokenBalance(addr, 40), 0u);
}

TEST_F(State_StateAccessFixture, SameTokenDifferentAddresses)
{
  auto a = makeAddress(1);
  auto b = makeAddress(2);
  Id token = 42;

  s().putTokenBalance(a, token, 100);
  s().putTokenBalance(b, token, 200);

  EXPECT_EQ(s().getTokenBalance(a, token), 100u);
  EXPECT_EQ(s().getTokenBalance(b, token), 200u);
}

// ============================================================================
//  C. Token metadata
// ============================================================================

TEST_F(State_StateAccessFixture, TokenMetadataRoundTrip)
{
  Core::TokenInfo token;
  token.id = 100;
  token.name = "Gold";
  token.symbol = "GLD";
  token.decimals = 8;
  token.creator = makeAddress(1);
  token.backing = Core::BackingModel::Unbacked;
  token.maxSupply = 1'000'000;
  token.royaltyBps = 50;

  s().putToken(token);

  Core::TokenInfo got;
  ASSERT_TRUE(s().getToken(100, got));
  EXPECT_EQ(got.id, 100u);
  EXPECT_EQ(got.name, "Gold");
  EXPECT_EQ(got.symbol, "GLD");
  EXPECT_EQ(got.decimals, 8);
  EXPECT_EQ(got.creator, token.creator);
  EXPECT_EQ(got.maxSupply, 1'000'000u);
  EXPECT_EQ(got.royaltyBps, 50);
}

TEST_F(State_StateAccessFixture, MissingTokenReturnsFalse)
{
  Core::TokenInfo got;
  EXPECT_FALSE(s().getToken(999, got));
}

TEST_F(State_StateAccessFixture, TokenWithFingerprint)
{
  Core::TokenInfo token;
  token.id = 100;
  token.name = "Bridged";
  token.symbol = "BRG";
  token.decimals = 8;
  token.creator = makeAddress(1);
  token.fingerprint = makeHash(77);

  s().putToken(token);

  Core::TokenInfo got;
  ASSERT_TRUE(s().getToken(100, got));
  ASSERT_TRUE(got.fingerprint.has_value());
  EXPECT_EQ(*got.fingerprint, makeHash(77));
}

// ============================================================================
//  D. Validators
// ============================================================================

TEST_F(State_StateAccessFixture, ValidatorRoundTrip)
{
  Core::ValidatorInfo v;
  v.id = 5;
  v.reward_address = makeAddress(1);
  v.owner = makeAddress(1);
  v.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
  v.uptime_score = 9'500;
  v.is_active = true;

  s().putValidator(v);

  Core::ValidatorInfo got;
  ASSERT_TRUE(s().getValidator(5, got));
  EXPECT_EQ(got.id, 5u);
  EXPECT_EQ(got.reward_address, v.reward_address);
  EXPECT_EQ(got.stake, GlobalConfig::VALIDATOR_MIN_STAKE);
  EXPECT_EQ(got.uptime_score, 9'500);
  EXPECT_TRUE(got.is_active);
}

TEST_F(State_StateAccessFixture, MissingValidatorReturnsFalse)
{
  Core::ValidatorInfo got;
  EXPECT_FALSE(s().getValidator(999, got));
}

// ============================================================================
//  E. Orders
// ============================================================================

TEST_F(State_StateAccessFixture, OrderRoundTrip)
{
  Core::Order o;
  o.id = 7;
  o.owner = makeAddress(1);
  o.mode = Core::OrderExecutionMode::Passive;
  o.sell_token = 0;
  o.buy_token = 100;
  o.sell_amount = 500;
  o.min_buy_amount = 100;

  s().putOrder(o);

  Core::Order got;
  ASSERT_TRUE(s().getOrder(7, got));
  EXPECT_EQ(got.id, 7u);
  EXPECT_EQ(got.owner, o.owner);
  EXPECT_EQ(got.sell_amount, 500u);
  EXPECT_EQ(got.buy_token, 100u);
}

TEST_F(State_StateAccessFixture, DeleteOrderRemovesIt)
{
  Core::Order o;
  o.id = 7;
  o.owner = makeAddress(1);
  o.sell_token = 0;
  o.buy_token = 100;
  o.sell_amount = 500;
  o.min_buy_amount = 100;

  s().putOrder(o);
  ASSERT_TRUE(s().getOrder(7, o));

  s().deleteOrder(7);

  Core::Order got;
  EXPECT_FALSE(s().getOrder(7, got));
}

// ============================================================================
//  F. AMM pools
// ============================================================================

TEST_F(State_StateAccessFixture, AmmPoolRoundTrip)
{
  Core::AmmPool p;
  p.id = 1;
  p.creator = makeAddress(1);
  p.token_a = 0;
  p.token_b = 100;
  p.reserve_a = 1000;
  p.reserve_b = 1000;
  p.total_liquidity = 1000;
  p.fee_bps = 30;
  p.active = true;

  s().putAmmPool(p);

  Core::AmmPool got;
  ASSERT_TRUE(s().getAmmPool(1, got));
  EXPECT_EQ(got.id, 1u);
  EXPECT_EQ(got.token_a, 0u);
  EXPECT_EQ(got.token_b, 100u);
  EXPECT_EQ(got.reserve_a, 1000u);
  EXPECT_EQ(got.reserve_b, 1000u);
  EXPECT_EQ(got.fee_bps, 30);
  EXPECT_TRUE(got.active);
}

TEST_F(State_StateAccessFixture, MissingPoolReturnsFalse)
{
  Core::AmmPool got;
  EXPECT_FALSE(s().getAmmPool(999, got));
}

// ============================================================================
//  G. AMM positions
// ============================================================================

TEST_F(State_StateAccessFixture, AmmPositionRoundTrip)
{
  Core::AmmPosition pos;
  pos.id = 3;
  pos.owner = makeAddress(1);
  pos.pool_id = 1;
  pos.liquidity = 500;
  pos.created_at_height = 10;

  s().putAmmPosition(pos);

  Core::AmmPosition got;
  ASSERT_TRUE(s().getAmmPosition(3, got));
  EXPECT_EQ(got.id, 3u);
  EXPECT_EQ(got.owner, pos.owner);
  EXPECT_EQ(got.pool_id, 1u);
  EXPECT_EQ(got.liquidity, 500u);
}

TEST_F(State_StateAccessFixture, DeleteAmmPosition)
{
  Core::AmmPosition pos;
  pos.id = 3;
  pos.owner = makeAddress(1);
  pos.pool_id = 1;
  pos.liquidity = 500;

  s().putAmmPosition(pos);
  s().deleteAmmPosition(3);

  Core::AmmPosition got;
  EXPECT_FALSE(s().getAmmPosition(3, got));
}

// ============================================================================
//  H. Receipts
// ============================================================================

TEST_F(State_StateAccessFixture, ReceiptRoundTrip)
{
  auto hash = makeHash(999);
  Core::Receipt r;
  r.status = Core::ReceiptStatus::Success;
  r.fee_paid = 42;

  s().putReceipt(hash, r);

  Core::Receipt got;
  ASSERT_TRUE(s().getReceipt(hash, got));
  EXPECT_EQ(got.status, Core::ReceiptStatus::Success);
  EXPECT_EQ(got.fee_paid, 42u);
}

TEST_F(State_StateAccessFixture, MissingReceiptReturnsFalse)
{
  Core::Receipt got;
  EXPECT_FALSE(s().getReceipt(makeHash(1), got));
}

// ============================================================================
//  I. Global state
// ============================================================================

TEST_F(State_StateAccessFixture, GlobalRoundTrip)
{
  std::vector<uint8_t> value = {1, 2, 3, 4, 5};
  s().putGlobal("test_key", value);

  std::vector<uint8_t> got;
  ASSERT_TRUE(s().getGlobal("test_key", got));
  EXPECT_EQ(got, value);
}

TEST_F(State_StateAccessFixture, MissingGlobalReturnsFalse)
{
  std::vector<uint8_t> got;
  EXPECT_FALSE(s().getGlobal("nonexistent", got));
}

TEST_F(State_StateAccessFixture, GlobalOverwrites)
{
  s().putGlobal("k", {1, 2});
  s().putGlobal("k", {3, 4, 5});

  std::vector<uint8_t> got;
  ASSERT_TRUE(s().getGlobal("k", got));
  EXPECT_EQ(got, std::vector<uint8_t>({3, 4, 5}));
}

TEST_F(State_StateAccessFixture, MultipleGlobals)
{
  s().putGlobal("a", {1});
  s().putGlobal("b", {2});
  s().putGlobal("c", {3});

  std::vector<uint8_t> got;
  ASSERT_TRUE(s().getGlobal("a", got));
  EXPECT_EQ(got, std::vector<uint8_t>({1}));
  ASSERT_TRUE(s().getGlobal("b", got));
  EXPECT_EQ(got, std::vector<uint8_t>({2}));
  ASSERT_TRUE(s().getGlobal("c", got));
  EXPECT_EQ(got, std::vector<uint8_t>({3}));
}

// ============================================================================
//  J. Raw SMT access
// ============================================================================

TEST_F(State_StateAccessFixture, RawRoundTrip)
{
  auto key = makeHash(42);
  std::vector<uint8_t> value = {9, 8, 7};

  s().putRaw(key, value);

  auto got = s().getRaw(key);
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(*got, value);
}

TEST_F(State_StateAccessFixture, RawDelete)
{
  auto key = makeHash(42);
  s().putRaw(key, {1, 2, 3});
  s().deleteRaw(key);
  EXPECT_FALSE(s().getRaw(key).has_value());
}

// ============================================================================
//  K. State root
// ============================================================================

TEST_F(State_StateAccessFixture, StateRootChangesOnWrite)
{
  auto before = s().stateRoot();

  Core::Account acct;
  acct.balance = 100;
  s().putAccount(makeAddress(1), acct);

  auto after = s().stateRoot();
  EXPECT_NE(before, after);
}

TEST_F(State_StateAccessFixture, StateRootIsDeterministicForSameWrites)
{
  auto addr = makeAddress(1);

  Core::Account acct;
  acct.balance = 100;
  s().putAccount(addr, acct);
  auto root1 = s().stateRoot();

  s().putAccount(addr, acct);
  auto root2 = s().stateRoot();
  EXPECT_EQ(root1, root2);
}

// ============================================================================
//  L. Autocommit mode
// ============================================================================

namespace
{
  class AutocommitState_StateAccessFixture : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      access_ = std::make_unique<StateAccess>(db_.db(), 0);
    }

    void TearDown() override { access_.reset(); }

    StateAccess &s() { return *access_; }

    TempDB db_;
    std::unique_ptr<StateAccess> access_;
  };
} // anonymous namespace

TEST_F(AutocommitState_StateAccessFixture, AccountRoundTripInAutocommit)
{
  auto addr = makeAddress(1);

  Core::Account acct;
  acct.balance = 5000;
  acct.nonce = 3;
  s().putAccount(addr, acct);

  Core::Account got = s().getAccount(addr);
  EXPECT_EQ(got.balance, 5000u);
  EXPECT_EQ(got.nonce, 3u);
}

TEST_F(AutocommitState_StateAccessFixture, GlobalRoundTripInAutocommit)
{
  s().putGlobal("k", {1, 2, 3});

  std::vector<uint8_t> got;
  ASSERT_TRUE(s().getGlobal("k", got));
  EXPECT_EQ(got, std::vector<uint8_t>({1, 2, 3}));
}

// ============================================================================
//  M. Staker index
// ============================================================================

TEST_F(State_StateAccessFixture, StakerIndexRoundTrip)
{
  auto a = makeAddress(1);
  auto b = makeAddress(2);

  s().indexStaker(a);
  s().indexStaker(b);

  std::vector<Crypto::Address> found;
  s().forEachStaker([&](const Crypto::Address &addr)
                    { found.push_back(addr); });

  ASSERT_EQ(found.size(), 2u);

  bool has_a = false, has_b = false;
  for (const auto &addr : found)
  {
    if (addr == a)
      has_a = true;
    if (addr == b)
      has_b = true;
  }
  EXPECT_TRUE(has_a);
  EXPECT_TRUE(has_b);
}

TEST_F(State_StateAccessFixture, UnindexStakerRemoves)
{
  auto a = makeAddress(1);
  auto b = makeAddress(2);

  s().indexStaker(a);
  s().indexStaker(b);
  s().unindexStaker(a);

  std::vector<Crypto::Address> found;
  s().forEachStaker([&](const Crypto::Address &addr)
                    { found.push_back(addr); });

  ASSERT_EQ(found.size(), 1u);
  EXPECT_EQ(found[0], b);
}

// ============================================================================
//  Versioned reads through StateAccess.
//
//  These tests use State_SmtPersistenceFixture, which gives explicit
//  control over txn commit/abort and DB open/close. The
//  State_StateAccessFixture aborts on setVersion, which is the right
//  behavior for single-version tests but wrong for multi-version ones.
// ============================================================================

TEST_F(State_SmtPersistenceFixture, AccountAtVersion)
{
  auto addr = makeAddress(0xAA);

  // Version 1: balance 1000.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 1);

    Core::Account a;
    a.balance = 1000;
    access.putAccount(addr, a);
    access.commit(1);
    txn.commit();
    db->close();
  }

  // Version 2: balance 2000.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 2);

    Core::Account a = access.getAccount(addr);
    a.balance = 2000;
    access.putAccount(addr, a);
    access.commit(2);
    txn.commit();
    db->close();
  }

  // Read at both versions through a fresh handle.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 2);

    // Current read.
    EXPECT_EQ(access.getAccount(addr).balance, 2000u);

    // Historical reads.
    EXPECT_EQ(access.getAccountAtVersion(addr, 1).balance, 1000u);
    EXPECT_EQ(access.getAccountAtVersion(addr, 2).balance, 2000u);

    txn.abort();
    db->close();
  }
}

TEST_F(State_SmtPersistenceFixture, GlobalAtVersion)
{
  // Version 1.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 1);

    std::vector<uint8_t> v1 = {1, 2, 3};
    access.putGlobal("test", v1);
    access.commit(1);
    txn.commit();
    db->close();
  }

  // Version 2.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 2);

    std::vector<uint8_t> v2 = {4, 5, 6, 7};
    access.putGlobal("test", v2);
    access.commit(2);
    txn.commit();
    db->close();
  }

  // Read both.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 2);

    std::vector<uint8_t> got;
    ASSERT_TRUE(access.getGlobalAtVersion("test", 1, got));
    EXPECT_EQ(got, std::vector<uint8_t>({1, 2, 3}));

    ASSERT_TRUE(access.getGlobalAtVersion("test", 2, got));
    EXPECT_EQ(got, std::vector<uint8_t>({4, 5, 6, 7}));

    txn.abort();
    db->close();
  }
}

TEST_F(State_SmtPersistenceFixture, ValidatorAtVersion)
{
  constexpr uint64_t VID = 5;

  // Version 1.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 1);

    Core::ValidatorInfo v;
    v.id = VID;
    v.reward_address = makeAddress(1);
    v.stake = 1'000'000;
    access.putValidator(v);
    access.commit(1);
    txn.commit();
    db->close();
  }

  // Version 2: stake increased.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 2);

    Core::ValidatorInfo v;
    ASSERT_TRUE(access.getValidator(VID, v));
    v.stake = 2'000'000;
    access.putValidator(v);
    access.commit(2);
    txn.commit();
    db->close();
  }

  // Read both.
  {
    auto db = openDB();
    auto txn = db->beginWrite();
    StateAccess access(*db, txn, 2);

    Core::ValidatorInfo v;
    ASSERT_TRUE(access.getValidatorAtVersion(VID, 1, v));
    EXPECT_EQ(v.stake, 1'000'000u);

    ASSERT_TRUE(access.getValidatorAtVersion(VID, 2, v));
    EXPECT_EQ(v.stake, 2'000'000u);

    txn.abort();
    db->close();
  }
}