// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Fixtures.h"

#include "Core/BlockProcessor.h"
#include "Core/TransactionExecutor.h"
#include "Core/ValidatorTypes.h"

using namespace Core;
using namespace Tests;

// ============================================================================
//  Unbonding lifecycle.
//
//  Unregister retains the validator record, removes the validator
//  from the active set, and stamps pending_unbond_height. The record
//  and stake are only released at expiry, by
//  BlockProcessor::processUnbondExpiries, which runs as part of
//  applyBlock.
//
//  Both tests pick EXPIRY well away from the OFFLINE_CHECK_INTERVAL
//  (10) and ROTATION_INTERVAL (60) boundaries, so the only side
//  effects of applying the block are the reward distribution and
//  the global-state bookkeeping. Neither touches the target's
//  record or the owner's balance, so the assertions are isolated to
//  the behavior under test.
// ============================================================================

TEST_F(Core_BlockProcessorFixture, UnbondExpiryReleasesRecordAndStake)
{
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;
  constexpr uint64_t TARGET_STAKE = 1'000'000'000ULL;
  constexpr uint64_t EXPIRY = 5;

  registerValidatorWithKey(TARGET_ID, target_key, TARGET_STAKE);

  //  Stamp the pending unbond directly. This is what
  //  executeUnregisterValidator does under the new behavior; going
  //  through the tx path would require signing and funding, which is
  //  not what this test is about.
  withState([&](State::StateAccess &s)
            {
    ValidatorInfo v;
    ASSERT_TRUE(s.getValidator(TARGET_ID, v));
    v.is_active = false;
    v.pending_unbond_height = EXPIRY;
    s.putValidator(v); });

  const Crypto::Address owner = addressOf(target_key);
  const uint64_t owner_before = balanceOf(owner);

  //  Apply an empty block at the expiry height. processUnbondExpiries
  //  runs inside applyBlock, before rewards and before rotation.
  BlockResult r = applyBlock(EXPIRY, makeHash(EXPIRY), {},
                             /*dry_run=*/false, {1, 2});
  ASSERT_TRUE(r.valid) << r.error;

  //  Record released.
  ValidatorInfo after;
  EXPECT_FALSE(readValidator(TARGET_ID, after));

  //  Address index released.
  uint64_t id = 0;
  readState([&](State::StateAccess &s)
            { EXPECT_FALSE(s.getValidatorByAddress(owner, id)); });

  //  Stake returned to the owner.
  EXPECT_EQ(balanceOf(owner), owner_before + TARGET_STAKE);
}

TEST_F(Core_BlockProcessorFixture, UnbondBeforeExpiryKeepsRecord)
{
  auto target_key = Crypto::generateKeyPair();
  constexpr Id TARGET_ID = 100;
  constexpr uint64_t TARGET_STAKE = 1'000'000'000ULL;
  constexpr uint64_t EXPIRY = 5;

  registerValidatorWithKey(TARGET_ID, target_key, TARGET_STAKE);

  withState([&](State::StateAccess &s)
            {
    ValidatorInfo v;
    ASSERT_TRUE(s.getValidator(TARGET_ID, v));
    v.pending_unbond_height = EXPIRY;
    s.putValidator(v); });

  const Crypto::Address owner = addressOf(target_key);
  const uint64_t owner_before = balanceOf(owner);

  //  Apply at EXPIRY - 1: one block early.
  BlockResult r = applyBlock(EXPIRY - 1,
                             makeHash(EXPIRY - 1), {},
                             /*dry_run=*/false, {1, 2});
  ASSERT_TRUE(r.valid) << r.error;

  //  Record and stake both still present.
  ValidatorInfo v;
  ASSERT_TRUE(readValidator(TARGET_ID, v));
  EXPECT_EQ(v.pending_unbond_height, EXPIRY);
  EXPECT_EQ(v.stake, TARGET_STAKE);

  //  Address index still present.
  uint64_t id = 0;
  readState([&](State::StateAccess &s)
            { EXPECT_TRUE(s.getValidatorByAddress(owner, id)); });
  EXPECT_EQ(id, TARGET_ID);

  //  Stake not returned.
  EXPECT_EQ(balanceOf(owner), owner_before);
}