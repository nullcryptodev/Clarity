// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fixtures.h"
#include "Tests/State/Fixtures.h"

#include "Core/Account.h"
#include "Core/GlobalState.h"
#include "Core/Receipt.h"
#include "Core/RewardTypes.h"
#include "Core/TransactionExecutor.h"
#include "Core/ValidatorTypes.h"

#include "State/StateAccess.h"

using namespace State;
using namespace Tests;

namespace
{
  // Insert a validator under a fixed id. Defaults produce a healthy,
  // non-seed validator at the given stake, ready to be slashed.
  void seedValidator(StateAccess &s,
                     uint64_t id,
                     uint64_t stake,
                     bool is_seed = false)
  {
    Core::ValidatorInfo v;
    v.id = id;
    v.stake = stake;
    v.is_seed = is_seed;
    v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
    v.uptime_score = 10'000;
    s.putValidator(v);
  }

  Core::TxExecutionContext ctxAt(uint64_t height)
  {
    Core::TxExecutionContext ctx;
    ctx.current_height = height;
    ctx.chain_id = EXEC_CHAIN_ID;
    ctx.tx_index_in_block = 0;
    return ctx;
  }
} // anonymous namespace

// ============================================================================
//  Happy path
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_ValidProof_ReducesStakeAndMultiplier)
{
  seedValidator(s(), 1, 1000ULL * 100'000ULL);

  auto r = Core::TransactionExecutor::executeSystemSlash(
      s(), 1, 42, ctxAt(42));
  ASSERT_EQ(r.status, Core::ReceiptStatus::Success);

  Core::ValidatorInfo v;
  ASSERT_TRUE(s().getValidator(1, v));
  EXPECT_EQ(v.stake, 950ULL * 100'000ULL);
  EXPECT_EQ(v.reward_multiplier, 8000);
  EXPECT_EQ(v.infraction_count, 1);
  EXPECT_EQ(v.last_infraction_height, 42u);

  EXPECT_EQ(readU64GlobalSV(s(), Core::GLOBAL_POT), 50ULL * 100'000ULL);
}

// ============================================================================
//  Eligibility gates
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_SeedExempt_Rejected)
{
  seedValidator(s(), 1, 1000ULL * 100'000ULL, /*is_seed=*/true);

  auto r = Core::TransactionExecutor::executeSystemSlash(
      s(), 1, 42, ctxAt(42));
  EXPECT_EQ(r.status, Core::ReceiptStatus::Failure);

  Core::ValidatorInfo v;
  ASSERT_TRUE(s().getValidator(1, v));
  EXPECT_EQ(v.stake, 1000ULL * 100'000ULL);
  EXPECT_EQ(v.reward_multiplier, Core::REWARD_MULTIPLIER_START);
  EXPECT_EQ(v.infraction_count, 0);

  EXPECT_EQ(readU64GlobalSV(s(), Core::GLOBAL_POT), 0u);
}

TEST_F(State_StateAccessFixture, SystemSlash_UnregisteredValidator_Rejected)
{
  auto r = Core::TransactionExecutor::executeSystemSlash(
      s(), 999, 42, ctxAt(42));
  EXPECT_EQ(r.status, Core::ReceiptStatus::Failure);

  EXPECT_EQ(readU64GlobalSV(s(), Core::GLOBAL_POT), 0u);
}

// ============================================================================
//  Edge cases: nothing to slash, or already at floor
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_ZeroStake_RecordsInfractionOnly)
{
  seedValidator(s(), 1, /*stake=*/0);

  auto r = Core::TransactionExecutor::executeSystemSlash(
      s(), 1, 42, ctxAt(42));
  EXPECT_EQ(r.status, Core::ReceiptStatus::Success);

  Core::ValidatorInfo v;
  ASSERT_TRUE(s().getValidator(1, v));
  EXPECT_EQ(v.stake, 0u);
  EXPECT_EQ(v.reward_multiplier, 8000);
  EXPECT_EQ(v.infraction_count, 1);

  EXPECT_EQ(readU64GlobalSV(s(), Core::GLOBAL_POT), 0u);
}

TEST_F(State_StateAccessFixture, SystemSlash_AtFloorMultiplier_ClampsAtFloor)
{
  seedValidator(s(), 1, 1000ULL * 100'000ULL);

  // Drop the multiplier to the floor before slashing.
  {
    Core::ValidatorInfo v;
    ASSERT_TRUE(s().getValidator(1, v));
    v.reward_multiplier = Core::REWARD_MULTIPLIER_FLOOR;
    s().putValidator(v);
  }

  auto r = Core::TransactionExecutor::executeSystemSlash(
      s(), 1, 42, ctxAt(42));
  EXPECT_EQ(r.status, Core::ReceiptStatus::Success);

  Core::ValidatorInfo v;
  ASSERT_TRUE(s().getValidator(1, v));
  EXPECT_EQ(v.reward_multiplier, Core::REWARD_MULTIPLIER_FLOOR);
  EXPECT_EQ(v.infraction_count, 1);
}

// ============================================================================
//  Accumulation across multiple slashes
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_MultipleSlashes_Accumulate)
{
  seedValidator(s(), 1, 1000ULL * 100'000ULL);

  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 1, ctxAt(1))
                .status,
            Core::ReceiptStatus::Success);
  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 2, ctxAt(2))
                .status,
            Core::ReceiptStatus::Success);
  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 3, ctxAt(3))
                .status,
            Core::ReceiptStatus::Success);

  Core::ValidatorInfo v;
  ASSERT_TRUE(s().getValidator(1, v));

  // Each slash removes applyBps(stake, 500) = 5% of the current stake.
  // applyBps operates on atomic units and floors, so the sequence is
  // exact at every step:
  //   100,000,000 -> 95,000,000 -> 90,250,000 -> 85,737,500
  // i.e. 1000 -> 950 -> 902.5 -> 857.375 CLRTY.
  EXPECT_EQ(v.stake, 85'737'500ULL);
  EXPECT_EQ(v.reward_multiplier, 4000);
  EXPECT_EQ(v.infraction_count, 3);
  EXPECT_EQ(v.last_infraction_height, 3u);

  // The invariant that matters: the pot received exactly what the
  // stake lost. Deriving the expectation from the validator record
  // (rather than restating 856) keeps this test from silently
  // breaking if SLASH_AMOUNT_BPS or applyBps ever changes.
  EXPECT_EQ(readU64GlobalSV(s(), Core::GLOBAL_POT),
            100'000'000ULL - v.stake);
}

// ============================================================================
//  Interaction with canBeActive
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_DropsBelowMinStake_CannotBeActive)
{
  seedValidator(s(), 1, Core::VALIDATOR_MIN_STAKE);

  Core::ValidatorInfo before;
  ASSERT_TRUE(s().getValidator(1, before));
  EXPECT_TRUE(before.canBeActive());

  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 1, ctxAt(1))
                .status,
            Core::ReceiptStatus::Success);

  Core::ValidatorInfo after;
  ASSERT_TRUE(s().getValidator(1, after));
  EXPECT_FALSE(after.meetsStakeRequirement());
  EXPECT_FALSE(after.canBeActive());
}

// ============================================================================
//  Pot accounting
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_PotAccounting_PreservesExistingPot)
{
  // Pre-seed the pot via the same global-state encoding the rest of
  // the code uses.
  {
    std::vector<uint8_t> bytes(8);
    uint64_t v = 12345;
    for (int i = 0; i < 8; ++i)
      bytes[i] = uint8_t(v >> (i * 8));
    s().putGlobal(std::string(Core::GLOBAL_POT), bytes);
  }

  seedValidator(s(), 1, 1000ULL * 100'000ULL);

  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 1, ctxAt(1))
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(readU64GlobalSV(s(), Core::GLOBAL_POT),
            12345u + 50ULL * 100'000ULL);
}

TEST_F(State_StateAccessFixture, SystemSlash_PotMissing_InitializesFromZero)
{
  // No pot key written.
  seedValidator(s(), 1, 1000ULL * 100'000ULL);

  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 1, ctxAt(1))
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(readU64GlobalSV(s(), Core::GLOBAL_POT), 50ULL * 100'000ULL);
}

// ============================================================================
//  Balance vs. stake separation
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_DoesNotTouchOwnerAccountBalance)
{
  auto owner = makeAddress(0xAB);

  // Owner's account starts with a balance independent of the
  // validator's stake. The slash must not move funds between them.
  {
    Core::Account acct;
    acct.balance = 777;
    acct.nonce = 5;
    s().putAccount(owner, acct);
  }

  {
    Core::ValidatorInfo v;
    v.id = 1;
    v.owner = owner;
    v.reward_address = owner;
    v.stake = 1000ULL * 100'000ULL;
    v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
    v.uptime_score = 10'000;
    s().putValidator(v);
  }

  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 1, ctxAt(1))
                .status,
            Core::ReceiptStatus::Success);

  Core::ValidatorInfo v;
  ASSERT_TRUE(s().getValidator(1, v));
  EXPECT_EQ(v.stake, 950ULL * 100'000ULL);

  Core::Account after = s().getAccount(owner);
  EXPECT_EQ(after.balance, 777u);
  EXPECT_EQ(after.nonce, 5u);
}

// ============================================================================
//  Nonce / fee bypass
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_DoesNotChargeFeeOrBumpNonce)
{
  auto owner = makeAddress(0xCD);

  {
    Core::Account acct;
    acct.balance = 5000;
    acct.nonce = 11;
    s().putAccount(owner, acct);
  }

  {
    Core::ValidatorInfo v;
    v.id = 1;
    v.owner = owner;
    v.reward_address = owner;
    v.stake = 1000ULL * 100'000ULL;
    v.reward_multiplier = Core::REWARD_MULTIPLIER_START;
    v.uptime_score = 10'000;
    s().putValidator(v);
  }

  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 1, ctxAt(1))
                .status,
            Core::ReceiptStatus::Success);

  Core::Account after = s().getAccount(owner);
  EXPECT_EQ(after.balance, 5000u);
  EXPECT_EQ(after.nonce, 11u);
}

// ============================================================================
//  State-root neutrality check
//
//  A slash is NOT root-neutral: it writes to the validator record and
//  to the pot, both of which are part of the SMT. This test asserts
//  the write actually happened at the root level — a regression that
//  routed the slash through a read-only path would fail it.
// ============================================================================

TEST_F(State_StateAccessFixture, SystemSlash_ChangesStateRoot)
{
  seedValidator(s(), 1, 1000ULL * 100'000ULL);

  Crypto::Hash before = s().stateRoot();

  ASSERT_EQ(Core::TransactionExecutor::executeSystemSlash(
                s(), 1, 1, ctxAt(1))
                .status,
            Core::ReceiptStatus::Success);

  Crypto::Hash after = s().stateRoot();
  EXPECT_NE(before, after);
}