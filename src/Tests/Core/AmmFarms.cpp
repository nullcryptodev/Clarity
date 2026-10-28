// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Fixtures.h"

#include "Core/AmmFarmTypes.h"
#include "Core/AmmPool.h"
#include "Core/AmmPosition.h"
#include "Core/TokenTypes.h"

#include "State/Keys.h"
#include "State/StateAccess.h"
#include "State/SparseMerkleTree.h"

using namespace Core;
using namespace State;
using namespace Tests;

namespace
{
  // ===================================================================
  //  Record sample builders
  // ===================================================================

  AmmFarmSchedule makeFarm(uint64_t pool_id, Id reward_token)
  {
    AmmFarmSchedule f;
    f.pool_id = pool_id;
    f.creator = Crypto::addrFromHex(
        "1111111111111111111111111111111111111111111111111111111111111111");
    f.reward_token_id = reward_token;
    f.reward_rate_per_epoch = 100;
    f.reward_escrow_remaining = 10000;
    f.reward_paused = false;
    f.rps_per_share = 0;
    f.created_at_height = 50;
    return f;
  }

  AmmPositionAccrual makeAccrual(uint64_t position_id, uint64_t last_rps)
  {
    AmmPositionAccrual a;
    a.position_id = position_id;
    a.last_rps = last_rps;
    return a;
  }

  // ===================================================================
  //  Executor payload encoders
  // ===================================================================

  void appendU32(std::vector<uint8_t> &p, uint32_t v)
  {
    for (int i = 0; i < 4; ++i)
      p.push_back(uint8_t(v >> (i * 8)));
  }

  void appendU64(std::vector<uint8_t> &p, uint64_t v)
  {
    for (int i = 0; i < 8; ++i)
      p.push_back(uint8_t(v >> (i * 8)));
  }

  std::vector<uint8_t> encodeCreateAmmFarmPayload(
      uint64_t pool_id, Id reward_token_id, uint64_t rate, uint64_t escrow)
  {
    std::vector<uint8_t> p;
    appendU64(p, pool_id);
    appendU32(p, reward_token_id);
    appendU64(p, rate);
    appendU64(p, escrow);
    return p;
  }

  std::vector<uint8_t> encodeUpdateAmmFarmPayload(
      uint64_t pool_id, uint64_t new_rate)
  {
    std::vector<uint8_t> p;
    appendU64(p, pool_id);
    appendU64(p, new_rate);
    return p;
  }

  std::vector<uint8_t> encodePoolIdPayload(uint64_t pool_id)
  {
    std::vector<uint8_t> p;
    appendU64(p, pool_id);
    return p;
  }

  std::vector<uint8_t> encodeRefillAmmFarmPayload(
      uint64_t pool_id, uint64_t amount)
  {
    std::vector<uint8_t> p;
    appendU64(p, pool_id);
    appendU64(p, amount);
    return p;
  }

  // ===================================================================
  //  Test helpers
  // ===================================================================

  void seedFarmEscrow(State::StateAccess &state,
                      const Crypto::Address &creator,
                      Id reward_token_id,
                      uint64_t pool_id,
                      uint64_t amount)
  {
    if (reward_token_id == NATIVE_TOKEN_ID)
    {
      Core::Account acct = state.getAccount(creator);
      if (acct.balance < amount)
        return;
      acct.balance -= amount;
      state.putAccount(creator, acct);

      Core::Account custody = state.getAccount(
          State::Keys::ammFarmAddress(pool_id));
      custody.balance += amount;
      state.putAccount(State::Keys::ammFarmAddress(pool_id), custody);
    }
    else
    {
      const uint64_t cur = state.getTokenBalance(creator, reward_token_id);
      if (cur < amount)
        return;
      state.putTokenBalance(creator, reward_token_id, cur - amount);

      const Crypto::Address custody = State::Keys::ammFarmAddress(pool_id);
      const uint64_t custody_cur = state.getTokenBalance(custody, reward_token_id);
      state.putTokenBalance(custody, reward_token_id, custody_cur + amount);
    }
  }

  uint64_t custodyBalance(State::StateAccess &state,
                          uint64_t pool_id,
                          Id reward_token_id)
  {
    const Crypto::Address custody = State::Keys::ammFarmAddress(pool_id);
    if (reward_token_id == NATIVE_TOKEN_ID)
      return state.getAccount(custody).balance;
    return state.getTokenBalance(custody, reward_token_id);
  }

  void seedFarmAndPosition(State::StateAccess &state,
                           uint64_t pool_id,
                           const Crypto::Address &owner,
                           uint64_t position_id,
                           uint64_t liquidity,
                           Id reward_token_id,
                           uint64_t rate,
                           uint64_t escrow,
                           uint64_t current_height)
  {
    Core::AmmPool pool;
    pool.id = pool_id;
    pool.creator = owner;
    pool.token_a = NATIVE_TOKEN_ID;
    pool.token_b = 100;
    pool.reserve_a = 1'000'000;
    pool.reserve_b = 1'000'000;
    pool.total_liquidity = liquidity;
    pool.fee_bps = Core::AMM_DEFAULT_FEE_BPS;
    pool.created_at_height = 1;
    pool.active = true;
    state.putAmmPool(pool);

    Core::AmmPosition pos;
    pos.id = position_id;
    pos.owner = owner;
    pos.pool_id = pool_id;
    pos.liquidity = liquidity;
    pos.created_at_height = 1;
    state.putAmmPosition(pos);
    state.putPositionIndex(owner, pool_id, position_id);

    Core::AmmFarmSchedule farm;
    farm.pool_id = pool_id;
    farm.creator = owner;
    farm.reward_token_id = reward_token_id;
    farm.reward_rate_per_epoch = rate;
    farm.reward_escrow_remaining = escrow;
    farm.reward_paused = false;
    farm.rps_per_share = 0;
    farm.created_at_height = 1;
    state.putAmmFarm(farm);

    seedFarmEscrow(state, owner, reward_token_id, pool_id, escrow);
  }
}

// =====================================================================
//  AmmFarmSchedule codec
// =====================================================================

TEST(Core_AmmFarmSchedule, DefaultIsInvalid)
{
  AmmFarmSchedule f;
  EXPECT_EQ(f.pool_id, INVALID_ID);
  EXPECT_FALSE(f.isValid());
}

TEST(Core_AmmFarmSchedule, ValidFarm)
{
  AmmFarmSchedule f = makeFarm(7, NATIVE_TOKEN_ID);
  EXPECT_TRUE(f.isValid());
  EXPECT_TRUE(f.hasEmission());
  EXPECT_TRUE(f.isActive());
}

TEST(Core_AmmFarmSchedule, NativeTokenRewardIsValid)
{
  AmmFarmSchedule f = makeFarm(7, NATIVE_TOKEN_ID);
  EXPECT_EQ(f.reward_token_id, NATIVE_TOKEN_ID);
  EXPECT_TRUE(f.isValid());
}

TEST(Core_AmmFarmSchedule, RejectsNullCreator)
{
  AmmFarmSchedule f = makeFarm(7, 0);
  f.creator = Crypto::Address{};
  EXPECT_FALSE(f.isValid());
}

TEST(Core_AmmFarmSchedule, RejectsZeroPool)
{
  AmmFarmSchedule f = makeFarm(0, 0);
  EXPECT_FALSE(f.isValid());
}

TEST(Core_AmmFarmSchedule, RejectsZeroRateAndZeroEscrow)
{
  AmmFarmSchedule f = makeFarm(7, 0);
  f.reward_rate_per_epoch = 0;
  f.reward_escrow_remaining = 0;
  EXPECT_FALSE(f.isValid());
}

TEST(Core_AmmFarmSchedule, ZeroRateWithEscrowIsValid)
{
  AmmFarmSchedule f = makeFarm(7, 0);
  f.reward_rate_per_epoch = 0;
  f.reward_escrow_remaining = 1000;
  EXPECT_TRUE(f.isValid());
  EXPECT_FALSE(f.hasEmission());
  EXPECT_FALSE(f.isActive());
}

TEST(Core_AmmFarmSchedule, ZeroEscrowWithRateIsValid)
{
  AmmFarmSchedule f = makeFarm(7, 0);
  f.reward_escrow_remaining = 0;
  EXPECT_TRUE(f.isValid());
  EXPECT_TRUE(f.hasEmission());
  EXPECT_FALSE(f.isActive());
}

TEST(Core_AmmFarmSchedule, PausedIsNotActive)
{
  AmmFarmSchedule f = makeFarm(7, 0);
  f.reward_paused = true;
  EXPECT_TRUE(f.isValid());
  EXPECT_TRUE(f.hasEmission());
  EXPECT_FALSE(f.isActive());
}

TEST(Core_AmmFarmSchedule, StateRoundTrip)
{
  AmmFarmSchedule original = makeFarm(7, 42);
  original.rps_per_share = 12345;
  original.reward_paused = true;
  original.created_at_height = 100;

  auto bytes = original.serializeState();

  AmmFarmSchedule restored;
  ASSERT_TRUE(AmmFarmSchedule::deserializeState(
      bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.pool_id, original.pool_id);
  EXPECT_EQ(restored.creator.toString(), original.creator.toString());
  EXPECT_EQ(restored.reward_token_id, original.reward_token_id);
  EXPECT_EQ(restored.reward_rate_per_epoch,
            original.reward_rate_per_epoch);
  EXPECT_EQ(restored.reward_escrow_remaining,
            original.reward_escrow_remaining);
  EXPECT_EQ(restored.reward_paused, original.reward_paused);
  EXPECT_EQ(restored.rps_per_share, original.rps_per_share);
  EXPECT_EQ(restored.created_at_height, original.created_at_height);
}

TEST(Core_AmmFarmSchedule, StateSizeIsSeventySeven)
{
  EXPECT_EQ(AmmFarmSchedule::STATE_SIZE, 77u);
  AmmFarmSchedule f = makeFarm(7, 42);
  EXPECT_EQ(f.serializeState().size(), AmmFarmSchedule::STATE_SIZE);
}

TEST(Core_AmmFarmSchedule, DeserializeRejectsShortInput)
{
  AmmFarmSchedule f = makeFarm(7, 42);
  auto bytes = f.serializeState();

  AmmFarmSchedule restored;
  EXPECT_FALSE(AmmFarmSchedule::deserializeState(
      bytes.data(), bytes.size() - 1, restored));
}

TEST(Core_AmmFarmSchedule, DeserializeRejectsLongInput)
{
  AmmFarmSchedule f = makeFarm(7, 42);
  auto bytes = f.serializeState();
  bytes.push_back(0xFF);

  AmmFarmSchedule restored;
  EXPECT_FALSE(AmmFarmSchedule::deserializeState(
      bytes.data(), bytes.size(), restored));
}

// =====================================================================
//  AmmPositionAccrual codec
// =====================================================================

TEST(Core_AmmPositionAccrual, DefaultIsInvalid)
{
  AmmPositionAccrual a;
  EXPECT_EQ(a.position_id, INVALID_ID);
  EXPECT_FALSE(a.isValid());
}

TEST(Core_AmmPositionAccrual, Valid)
{
  AmmPositionAccrual a = makeAccrual(42, 100);
  EXPECT_TRUE(a.isValid());
}

TEST(Core_AmmPositionAccrual, StateRoundTrip)
{
  AmmPositionAccrual original = makeAccrual(42, 987654321);
  auto bytes = original.serializeState();

  AmmPositionAccrual restored;
  ASSERT_TRUE(AmmPositionAccrual::deserializeState(
      bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.position_id, original.position_id);
  EXPECT_EQ(restored.last_rps, original.last_rps);
}

TEST(Core_AmmPositionAccrual, StateSizeIsSixteen)
{
  EXPECT_EQ(AmmPositionAccrual::STATE_SIZE, 16u);
}

TEST(Core_AmmPositionAccrual, DeserializeRejectsShortInput)
{
  AmmPositionAccrual a = makeAccrual(42, 100);
  auto bytes = a.serializeState();

  AmmPositionAccrual restored;
  EXPECT_FALSE(AmmPositionAccrual::deserializeState(
      bytes.data(), bytes.size() - 1, restored));
}

// =====================================================================
//  State layer
// =====================================================================

TEST_F(Core_ExecutorFixture, State_PutGetAmmFarmRoundTrip)
{
  AmmFarmSchedule f = makeFarm(1, NATIVE_TOKEN_ID);
  f.creator = alice_.publicKey;
  state_->putAmmFarm(f);

  AmmFarmSchedule out;
  ASSERT_TRUE(state_->getAmmFarm(1, out));
  EXPECT_EQ(out.pool_id, 1);
  EXPECT_EQ(out.reward_rate_per_epoch, f.reward_rate_per_epoch);
  EXPECT_EQ(out.reward_escrow_remaining, f.reward_escrow_remaining);
}

TEST_F(Core_ExecutorFixture, State_DeleteAmmFarmRemovesRecord)
{
  AmmFarmSchedule f = makeFarm(1, NATIVE_TOKEN_ID);
  f.creator = alice_.publicKey;
  state_->putAmmFarm(f);
  state_->deleteAmmFarm(1);

  AmmFarmSchedule out;
  EXPECT_FALSE(state_->getAmmFarm(1, out));
}

TEST_F(Core_ExecutorFixture, State_ForEachAmmFarmEnumeratesAll)
{
  for (uint64_t i = 1; i <= 3; ++i)
  {
    AmmFarmSchedule f = makeFarm(i, NATIVE_TOKEN_ID);
    f.creator = alice_.publicKey;
    state_->putAmmFarm(f);
  }

  uint64_t count = 0;
  state_->forEachAmmFarm([&](const AmmFarmSchedule &)
                         { ++count; });
  EXPECT_EQ(count, 3u);
}

TEST_F(Core_ExecutorFixture, State_PutGetAmmPositionAccrualRoundTrip)
{
  AmmPositionAccrual a = makeAccrual(42, 777);
  state_->putAmmPositionAccrual(a);

  AmmPositionAccrual out;
  ASSERT_TRUE(state_->getAmmPositionAccrual(42, out));
  EXPECT_EQ(out.position_id, 42);
  EXPECT_EQ(out.last_rps, 777);
}

TEST_F(Core_ExecutorFixture, State_GetAmmPositionAccrualAbsentReturnsFalse)
{
  AmmPositionAccrual out;
  EXPECT_FALSE(state_->getAmmPositionAccrual(999, out));
}

TEST_F(Core_ExecutorFixture, State_DeleteAmmPositionAccrualRemovesRecord)
{
  AmmPositionAccrual a = makeAccrual(42, 777);
  state_->putAmmPositionAccrual(a);
  state_->deleteAmmPositionAccrual(42);

  AmmPositionAccrual out;
  EXPECT_FALSE(state_->getAmmPositionAccrual(42, out));
}

// =====================================================================
//  Executor: CreateAmmFarm
// =====================================================================

TEST_F(Core_ExecutorFixture, CreateAmmFarm_FundsEscrowFromCreator)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  const uint64_t alice_before = balanceOf(alice_.publicKey);

  //  createPool used nonce 0. Alice's next tx is nonce 1.
  Core::Receipt r = run(TransactionBuilder()
                            .type(Core::TxType::CreateAmmFarm)
                            .from(alice_)
                            .to(Crypto::Address{})
                            .amount(0)
                            .fee(1)
                            .nonce(1)
                            .chainId(EXEC_CHAIN_ID)
                            .payload(encodeCreateAmmFarmPayload(
                                pool_id, NATIVE_TOKEN_ID,
                                /*rate=*/10, /*escrow=*/500))
                            .build());
  ASSERT_EQ(r.status, Core::ReceiptStatus::Success);

  AmmFarmSchedule farm;
  ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
  EXPECT_EQ(farm.reward_token_id, NATIVE_TOKEN_ID);
  EXPECT_EQ(farm.reward_rate_per_epoch, 10);
  EXPECT_EQ(farm.reward_escrow_remaining, 500);
  EXPECT_FALSE(farm.reward_paused);
  EXPECT_EQ(farm.rps_per_share, 0);

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 500 - 1);
  EXPECT_EQ(custodyBalance(*state_, pool_id, NATIVE_TOKEN_ID), 500);
}

TEST_F(Core_ExecutorFixture, CreateAmmFarm_RejectsMissingPool)
{
  Core::Receipt r = run(TransactionBuilder()
                            .type(Core::TxType::CreateAmmFarm)
                            .from(alice_)
                            .to(Crypto::Address{})
                            .amount(0)
                            .fee(1)
                            .nonce(0)
                            .chainId(EXEC_CHAIN_ID)
                            .payload(encodeCreateAmmFarmPayload(
                                /*pool_id=*/999, NATIVE_TOKEN_ID, 10, 500))
                            .build());
  EXPECT_EQ(r.status, Core::ReceiptStatus::Failure);

  AmmFarmSchedule farm;
  EXPECT_FALSE(state_->getAmmFarm(999, farm));
}

TEST_F(Core_ExecutorFixture, CreateAmmFarm_RejectsSecondFarmOnSamePool)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 20, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, CreateAmmFarm_RejectsZeroRate)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, /*rate=*/0, /*escrow=*/500))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, CreateAmmFarm_RejectsZeroEscrow)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, /*rate=*/10, /*escrow=*/0))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, CreateAmmFarm_RejectsInsufficientEscrowFunds)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  setBalance(alice_.publicKey, 10);

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  AmmFarmSchedule farm;
  EXPECT_FALSE(state_->getAmmFarm(pool_id, farm));
}

TEST_F(Core_ExecutorFixture, CreateAmmFarm_NonNativeRewardToken)
{
  const Id reward_token = createTokenDirect(alice_, "Reward", "RWD",
                                            /*max_supply=*/0, /*token_id=*/80);
  setTokenBalance(alice_.publicKey, reward_token, 5000);

  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, reward_token, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  AmmFarmSchedule farm;
  ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
  EXPECT_EQ(farm.reward_token_id, reward_token);

  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, reward_token), 4500);
  EXPECT_EQ(custodyBalance(*state_, pool_id, reward_token), 500);
}

// =====================================================================
//  Executor: UpdateAmmFarm
// =====================================================================

TEST_F(Core_ExecutorFixture, UpdateAmmFarm_ChangesRate)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateAmmFarmPayload(pool_id, 25))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  AmmFarmSchedule farm;
  ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
  EXPECT_EQ(farm.reward_rate_per_epoch, 25);
  EXPECT_EQ(farm.reward_escrow_remaining, 500);
}

TEST_F(Core_ExecutorFixture, UpdateAmmFarm_RejectsZeroRate)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateAmmFarmPayload(pool_id, 0))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  AmmFarmSchedule farm;
  ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
  EXPECT_EQ(farm.reward_rate_per_epoch, 10);
}

TEST_F(Core_ExecutorFixture, UpdateAmmFarm_NonCreatorRejected)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Bob's first tx is nonce 0 (independent of Alice).
  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::UpdateAmmFarm)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeUpdateAmmFarmPayload(pool_id, 25))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);

  AmmFarmSchedule farm;
  ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
  EXPECT_EQ(farm.reward_rate_per_epoch, 10);
}

// =====================================================================
//  Executor: PauseAmmFarm
// =====================================================================

TEST_F(Core_ExecutorFixture, PauseAmmFarm_SetsPausedFlag)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::PauseAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodePoolIdPayload(pool_id))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  AmmFarmSchedule farm;
  ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
  EXPECT_TRUE(farm.reward_paused);
}

TEST_F(Core_ExecutorFixture, PauseAmmFarm_NonCreatorRejected)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::PauseAmmFarm)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodePoolIdPayload(pool_id))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

// =====================================================================
//  Executor: RefillAmmFarm
// =====================================================================

TEST_F(Core_ExecutorFixture, RefillAmmFarm_AddsEscrowAndUnpauses)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  {
    AmmFarmSchedule farm;
    ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
    farm.reward_escrow_remaining = 0;
    farm.reward_paused = true;
    state_->putAmmFarm(farm);

    const Crypto::Address custody = State::Keys::ammFarmAddress(pool_id);
    const uint64_t bal = state_->getAccount(custody).balance;
    if (bal > 0)
    {
      Core::Account c = state_->getAccount(custody);
      c.balance = 0;
      state_->putAccount(custody, c);
      Core::Account a = state_->getAccount(alice_.publicKey);
      a.balance += bal;
      state_->putAccount(alice_.publicKey, a);
    }
  }

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::RefillAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeRefillAmmFarmPayload(pool_id, 1000))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  AmmFarmSchedule farm;
  ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
  EXPECT_EQ(farm.reward_escrow_remaining, 1000);
  EXPECT_FALSE(farm.reward_paused);

  EXPECT_EQ(custodyBalance(*state_, pool_id, NATIVE_TOKEN_ID), 1000);
}

TEST_F(Core_ExecutorFixture, RefillAmmFarm_NonCreatorRejected)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::RefillAmmFarm)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeRefillAmmFarmPayload(pool_id, 1000))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

// =====================================================================
//  Executor: CloseAmmFarm
// =====================================================================

TEST_F(Core_ExecutorFixture, CloseAmmFarm_RejectsLivePool)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CloseAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodePoolIdPayload(pool_id))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, CloseAmmFarm_RejectsUnpausedFarm)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  {
    AmmPool pool;
    ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
    pool.reserve_a = 0;
    pool.reserve_b = 0;
    pool.total_liquidity = 0;
    state_->putAmmPool(pool);
  }

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CloseAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodePoolIdPayload(pool_id))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, CloseAmmFarm_RefundsAndDeletesWhenPaused)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::PauseAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodePoolIdPayload(pool_id))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  {
    AmmPool pool;
    ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
    pool.reserve_a = 0;
    pool.reserve_b = 0;
    pool.total_liquidity = 0;
    state_->putAmmPool(pool);
  }

  const uint64_t alice_before = balanceOf(alice_.publicKey);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CloseAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(3)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodePoolIdPayload(pool_id))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  AmmFarmSchedule farm;
  EXPECT_FALSE(state_->getAmmFarm(pool_id, farm));

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before + 500 - 1);
  EXPECT_EQ(custodyBalance(*state_, pool_id, NATIVE_TOKEN_ID), 0);
}

TEST_F(Core_ExecutorFixture, CloseAmmFarm_NonCreatorRejected)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, 10, 500))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::PauseAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodePoolIdPayload(pool_id))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  {
    AmmPool pool;
    ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
    pool.reserve_a = 0;
    pool.reserve_b = 0;
    pool.total_liquidity = 0;
    state_->putAmmPool(pool);
  }

  EXPECT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CloseAmmFarm)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodePoolIdPayload(pool_id))
                    .build())
                .status,
            Core::ReceiptStatus::Failure);
}

// =====================================================================
//  Executor: ClaimAmmFarmRewards
// =====================================================================

TEST_F(Core_ExecutorFixture, ClaimAmmFarmRewards_EmptyPayloadRequired)
{
  Core::Transaction tx = TransactionBuilder()
                             .type(Core::TxType::ClaimAmmFarmRewards)
                             .from(alice_)
                             .to(Crypto::Address{})
                             .amount(0)
                             .fee(1)
                             .nonce(0)
                             .chainId(EXEC_CHAIN_ID)
                             .payload({0x00})
                             .build();

  EXPECT_EQ(run(tx).status, Core::ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, ClaimAmmFarmRewards_AccruesIntoPending)
{
  const uint64_t pool_id = 1;
  const uint64_t position_id = 1;
  const uint64_t liquidity = 1000;
  const Id reward_token = NATIVE_TOKEN_ID;

  seedFarmAndPosition(*state_, pool_id, alice_.publicKey,
                      position_id, liquidity,
                      reward_token, /*rate=*/100, /*escrow=*/100000,
                      /*current_height=*/1);

  {
    AmmFarmSchedule farm;
    ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
    farm.rps_per_share = 10'000'000'000ULL;
    state_->putAmmFarm(farm);
  }

  const uint64_t alice_before = state_->getAccount(alice_.publicKey).pending_rewards;

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::ClaimAmmFarmRewards)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload({})
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  const uint64_t alice_after = state_->getAccount(alice_.publicKey).pending_rewards;
  EXPECT_EQ(alice_after, alice_before + 1000);

  AmmPositionAccrual acc;
  ASSERT_TRUE(state_->getAmmPositionAccrual(position_id, acc));
  EXPECT_EQ(acc.last_rps, 10'000'000'000ULL);

  const uint64_t alice_before_second = alice_after;
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::ClaimAmmFarmRewards)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload({})
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(state_->getAccount(alice_.publicKey).pending_rewards,
            alice_before_second);
}

TEST_F(Core_ExecutorFixture, ClaimAmmFarmRewards_NoFarmNoOp)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);

  ASSERT_NE(createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                       other_token, 1'000'000),
            0u);

  const uint64_t alice_before =
      state_->getAccount(alice_.publicKey).pending_rewards;

  //  createPool used nonce 0. Claim uses nonce 1.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::ClaimAmmFarmRewards)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload({})
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(state_->getAccount(alice_.publicKey).pending_rewards, alice_before);
}

// =====================================================================
//  Executor: RemoveLiquidity settles accrual
// =====================================================================

TEST_F(Core_ExecutorFixture, RemoveLiquidity_SettlesAccrual)
{
  const uint64_t pool_id = 1;
  const uint64_t position_id = 1;
  const uint64_t liquidity = 1000;
  const Id reward_token = NATIVE_TOKEN_ID;

  seedFarmAndPosition(*state_, pool_id, alice_.publicKey,
                      position_id, liquidity,
                      reward_token, /*rate=*/100, /*escrow=*/100000,
                      /*current_height=*/1);

  {
    AmmFarmSchedule farm;
    ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
    farm.rps_per_share = 10'000'000'000ULL;
    state_->putAmmFarm(farm);
  }

  const uint64_t alice_pending_before =
      state_->getAccount(alice_.publicKey).pending_rewards;

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::RemoveLiquidity)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload([&]
                             {
                        std::vector<uint8_t> p;
                        appendU64(p, position_id);
                        appendU64(p, 0); // 0 = remove all
                        return p; }())
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(state_->getAccount(alice_.publicKey).pending_rewards,
            alice_pending_before + 1000);

  AmmPositionAccrual acc;
  EXPECT_FALSE(state_->getAmmPositionAccrual(position_id, acc));
}

// =====================================================================
//  Block processor: epoch-boundary emission
// =====================================================================

TEST_F(Core_BlockProcessorFixture, AmmFarm_EpochBoundaryEmits)
{
  const uint64_t pool_id = 1;
  const uint64_t position_id = 1;
  const uint64_t liquidity = 1000;

  withState([&](State::StateAccess &s)
            { seedFarmAndPosition(s, pool_id, alice_.publicKey,
                                  position_id, liquidity,
                                  NATIVE_TOKEN_ID, 100, 100000, 1); });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/false);
  Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
  ASSERT_TRUE(r.valid) << r.error;

  AmmFarmSchedule in_txn;
  ASSERT_TRUE(s.getAmmFarm(pool_id, in_txn));

  EXPECT_EQ(in_txn.rps_per_share, 1'000'000'000ULL);
  EXPECT_EQ(in_txn.reward_escrow_remaining, 100000 - 100);

  s.commit(0);
  t.commit();

  AmmFarmSchedule after;
  readState([&](State::StateAccess &s2)
            { ASSERT_TRUE(s2.getAmmFarm(pool_id, after)); });
  EXPECT_EQ(after.rps_per_share, 1'000'000'000ULL);
  EXPECT_EQ(after.reward_escrow_remaining, 100000 - 100);
}

TEST_F(Core_BlockProcessorFixture, AmmFarm_EscrowExhaustionPauses)
{
  const uint64_t pool_id = 1;
  const uint64_t position_id = 1;
  const uint64_t liquidity = 1000;
  const uint64_t escrow = 50;

  withState([&](State::StateAccess &s)
            { seedFarmAndPosition(s, pool_id, alice_.publicKey,
                                  position_id, liquidity,
                                  NATIVE_TOKEN_ID, /*rate=*/100, escrow, 1); });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/false);
  Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
  ASSERT_TRUE(r.valid) << r.error;

  AmmFarmSchedule in_txn;
  ASSERT_TRUE(s.getAmmFarm(pool_id, in_txn));
  EXPECT_EQ(in_txn.reward_escrow_remaining, 0u);
  EXPECT_TRUE(in_txn.reward_paused);

  EXPECT_EQ(in_txn.rps_per_share, 500'000'000ULL);

  s.commit(0);
  t.commit();
}

TEST_F(Core_BlockProcessorFixture, AmmFarm_PausedFarmDoesNotEmit)
{
  const uint64_t pool_id = 1;
  const uint64_t position_id = 1;
  const uint64_t liquidity = 1000;

  withState([&](State::StateAccess &s)
            {
              seedFarmAndPosition(s, pool_id, alice_.publicKey,
                                  position_id, liquidity,
                                  NATIVE_TOKEN_ID, 100, 10000, 1);

              AmmFarmSchedule farm;
              ASSERT_TRUE(s.getAmmFarm(pool_id, farm));
              farm.reward_paused = true;
              s.putAmmFarm(farm); });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/false);
  Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
  ASSERT_TRUE(r.valid) << r.error;

  AmmFarmSchedule in_txn;
  ASSERT_TRUE(s.getAmmFarm(pool_id, in_txn));
  EXPECT_EQ(in_txn.rps_per_share, 0u);
  EXPECT_EQ(in_txn.reward_escrow_remaining, 10000);
  EXPECT_TRUE(in_txn.reward_paused);

  s.commit(0);
  t.commit();
}

TEST_F(Core_BlockProcessorFixture, AmmFarm_ZeroLiquiditySkipsEmission)
{
  const uint64_t pool_id = 1;

  withState([&](State::StateAccess &s)
            { seedFarmAndPosition(s, pool_id, alice_.publicKey,
                                  /*position_id=*/1, /*liquidity=*/0,
                                  NATIVE_TOKEN_ID, 100, 10000, 1); });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  auto t = db_->beginWrite();
  State::StateAccess s(*db_, t, 0);
  Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/false);
  Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
  ASSERT_TRUE(r.valid) << r.error;

  AmmFarmSchedule in_txn;
  ASSERT_TRUE(s.getAmmFarm(pool_id, in_txn));
  EXPECT_EQ(in_txn.rps_per_share, 0u);
  EXPECT_EQ(in_txn.reward_escrow_remaining, 10000);

  s.commit(0);
  t.commit();
}

// =====================================================================
//  THE CANARY: simulate and apply produce the same root
// =====================================================================

TEST_F(Core_BlockProcessorFixture, AmmFarm_SimulateAndApplyProduceSameRoot)
{
  withState([&](State::StateAccess &s)
            { seedFarmAndPosition(s, /*pool_id=*/1, alice_.publicKey,
                                  /*position_id=*/1, /*liquidity=*/1000,
                                  NATIVE_TOKEN_ID, /*rate=*/100,
                                  /*escrow=*/10000, /*current_height=*/1); });

  const uint64_t boundary_height = Core::ROTATION_INTERVAL - 1;
  Core::Block b = makeProcessableBlock(
      boundary_height, genesis_hash_, {}, activeSet());

  Crypto::Hash simulated_root;
  {
    auto txn = db_->beginWrite();
    State::StateAccess s(*db_, txn, 0);
    Core::BlockContext ctx = makeContext(boundary_height, /*dry_run=*/true);
    Core::BlockResult r = Core::BlockProcessor::applyBlock(s, b, ctx);
    ASSERT_TRUE(r.valid) << r.error;
    simulated_root = r.new_state_root;
    txn.abort();
  }

  Core::BlockResult applied = applyPrebuiltBlock(b);
  ASSERT_TRUE(applied.valid) << applied.error;

  EXPECT_EQ(currentStateRoot(), simulated_root);
}

// =====================================================================
//  THE CORRECTNESS TEST: mid-epoch liquidity changes
// =====================================================================

TEST_F(Core_ExecutorFixture, AmmFarm_RpsAccountingUnderMidEpochLiquidityChange)
{
  //  Two positions on the same farmed pool: Alice has 1000 shares,
  //  Bob has 3000. Farm rate is 100 per epoch, so the per-epoch
  //  emission splits 25% / 75%.
  //
  //  Pool reserves seeded at 4000 / 4000, total_liquidity 4000.
  //  AddLiquidity(2000, 2000) mints 2000 new shares (ratio is 1:1),
  //  so after the add Alice has 3000 and the pool has 6000.
  //
  //  Alice's AddLiquidity must settle her accrual from epoch 1
  //  first: 1000 shares * 10^10 / 10^10 = 1000 shares credited, and
  //  her last_rps becomes 10^10. Otherwise her epoch 1 accrual would
  //  be retroactively computed at 3000 shares and come out wrong.
  //
  //  Epoch 2 inc = 100 * 10^10 / 6000 = 166,666,666.
  //    Alice (3000 shares): 166,666,666 * 3000 / 10^10 = 49.
  //    Bob (3000 shares):   166,666,666 * 3000 / 10^10 = 49.
  //  Alice total = 1000 + 49 = 1049; Bob total = 3000 + 49 = 3049.

  const uint64_t pool_id = 1;
  const uint64_t alice_pos_id = 1;
  const uint64_t bob_pos_id = 2;

  {
    State::StateAccess &s = *state_;

    const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                             /*max_supply=*/0, /*token_id=*/100);
    setTokenBalance(alice_.publicKey, other_token, 10'000'000);

    AmmPool pool;
    pool.id = pool_id;
    pool.creator = alice_.publicKey;
    pool.token_a = NATIVE_TOKEN_ID;
    pool.token_b = other_token;
    pool.reserve_a = 4000;
    pool.reserve_b = 4000;
    pool.total_liquidity = 4000;
    pool.fee_bps = Core::AMM_DEFAULT_FEE_BPS;
    pool.created_at_height = 1;
    pool.active = true;
    s.putAmmPool(pool);

    AmmPosition ap;
    ap.id = alice_pos_id;
    ap.owner = alice_.publicKey;
    ap.pool_id = pool_id;
    ap.liquidity = 1000;
    ap.created_at_height = 1;
    s.putAmmPosition(ap);
    s.putPositionIndex(alice_.publicKey, pool_id, alice_pos_id);
    AmmPositionAccrual aa;
    aa.position_id = alice_pos_id;
    aa.last_rps = 0;
    s.putAmmPositionAccrual(aa);

    AmmPosition bp;
    bp.id = bob_pos_id;
    bp.owner = bob_.publicKey;
    bp.pool_id = pool_id;
    bp.liquidity = 3000;
    bp.created_at_height = 1;
    s.putAmmPosition(bp);
    s.putPositionIndex(bob_.publicKey, pool_id, bob_pos_id);
    AmmPositionAccrual ba;
    ba.position_id = bob_pos_id;
    ba.last_rps = 0;
    s.putAmmPositionAccrual(ba);

    AmmFarmSchedule farm;
    farm.pool_id = pool_id;
    farm.creator = alice_.publicKey;
    farm.reward_token_id = NATIVE_TOKEN_ID;
    farm.reward_rate_per_epoch = 100;
    farm.reward_escrow_remaining = 10000;
    farm.reward_paused = false;
    farm.rps_per_share = 0;
    farm.created_at_height = 1;
    s.putAmmFarm(farm);

    seedFarmEscrow(s, alice_.publicKey, NATIVE_TOKEN_ID,
                   pool_id, 10000);
  }

  //  Simulate epoch 1 emission by setting rps directly.
  {
    AmmFarmSchedule farm;
    ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
    farm.rps_per_share = 10'000'000'000ULL;
    state_->putAmmFarm(farm);
  }

  //  Alice adds 2000 more of each side. The existing-position branch
  //  settles her epoch-1 accrual (1000) and bumps her liquidity to
  //  3000. Alice's nonce is 0 (fixture starts each account at 0).
  {
    ASSERT_EQ(run(TransactionBuilder()
                      .type(Core::TxType::AddLiquidity)
                      .from(alice_)
                      .to(Crypto::Address{})
                      .amount(2000)
                      .fee(1)
                      .nonce(0)
                      .tokenId(NATIVE_TOKEN_ID)
                      .chainId(EXEC_CHAIN_ID)
                      .payload([&]
                               {
                          std::vector<uint8_t> p;
                          appendU64(p, pool_id);
                          appendU64(p, 2000);
                          return p; }())
                      .build())
                  .status,
              Core::ReceiptStatus::Success);

    AmmPosition ap;
    ASSERT_TRUE(state_->getAmmPosition(alice_pos_id, ap));
    EXPECT_EQ(ap.liquidity, 3000u);

    //  Epoch-1 accrual was settled into pending_rewards and last_rps
    //  was advanced to 10^10.
    const uint64_t alice_pending =
        state_->getAccount(alice_.publicKey).pending_rewards;
    EXPECT_EQ(alice_pending, 1000u);

    AmmPositionAccrual aa;
    ASSERT_TRUE(state_->getAmmPositionAccrual(alice_pos_id, aa));
    EXPECT_EQ(aa.last_rps, 10'000'000'000ULL);
  }

  //  Simulate epoch 2 emission. Pool total is now 6000.
  {
    AmmFarmSchedule farm;
    ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
    const uint64_t emission = 100;
    AmmPool pool;
    ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
    EXPECT_EQ(pool.total_liquidity, 6000u);
    const __uint128_t inc_128 =
        static_cast<__uint128_t>(emission) * FARM_RPS_SCALE /
        pool.total_liquidity;
    farm.rps_per_share += static_cast<uint64_t>(inc_128);
    state_->putAmmFarm(farm);
  }

  //  Snapshot the baseline AFTER the add's settle, so the assertion
  //  measures only the epoch-2 accrual.
  const uint64_t alice_pending_before =
      state_->getAccount(alice_.publicKey).pending_rewards; // 1000
  const uint64_t bob_pending_before =
      state_->getAccount(bob_.publicKey).pending_rewards; // 0

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::ClaimAmmFarmRewards)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload({})
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::ClaimAmmFarmRewards)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(0)
                    .chainId(EXEC_CHAIN_ID)
                    .payload({})
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Alice's total credited (settle during add + claim of epoch 2)
  //  is 1000 + 49 = 1049. Since her baseline already includes the
  //  1000 from the add's settle, the claim alone credits 49.
  const uint64_t alice_credited =
      state_->getAccount(alice_.publicKey).pending_rewards -
      alice_pending_before;
  const uint64_t bob_credited =
      state_->getAccount(bob_.publicKey).pending_rewards -
      bob_pending_before;

  //  Claim-only amounts. Alice: 49 (epoch 2 at 3000 shares).
  //  Bob: 3049 (epoch 1 at 3000 shares + epoch 2 at 3000 shares).
  EXPECT_EQ(alice_credited, 49u);
  EXPECT_EQ(bob_credited, 3049u);

  //  Alice's total pending_rewards now includes the settle from
  //  AddLiquidity (1000) plus the claim (49) = 1049.
  EXPECT_EQ(state_->getAccount(alice_.publicKey).pending_rewards, 1049u);

  AmmFarmSchedule farm;
  ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));

  AmmPositionAccrual aa;
  ASSERT_TRUE(state_->getAmmPositionAccrual(alice_pos_id, aa));
  EXPECT_EQ(aa.last_rps, farm.rps_per_share);

  AmmPositionAccrual ba;
  ASSERT_TRUE(state_->getAmmPositionAccrual(bob_pos_id, ba));
  EXPECT_EQ(ba.last_rps, farm.rps_per_share);
}

// =====================================================================
//  Executor: full lifecycle
// =====================================================================

TEST_F(Core_ExecutorFixture, AmmFarm_FullLifecycle)
{
  const Id other_token = createTokenDirect(alice_, "PoolToken", "PTK",
                                           /*max_supply=*/0, /*token_id=*/100);
  setTokenBalance(alice_.publicKey, other_token, 10'000'000);
  const uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                      other_token, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  //  createPool used nonce 0. CreateAmmFarm uses nonce 1.
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::CreateAmmFarm)
                    .from(alice_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload(encodeCreateAmmFarmPayload(
                        pool_id, NATIVE_TOKEN_ID, /*rate=*/10, /*escrow=*/1000))
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  //  Bob has never transacted; his nonce is 0.
  setTokenBalance(bob_.publicKey, other_token, 10'000'000);
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::AddLiquidity)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(1000)
                    .fee(1)
                    .nonce(0)
                    .tokenId(NATIVE_TOKEN_ID)
                    .chainId(EXEC_CHAIN_ID)
                    .payload([&]
                             {
                        std::vector<uint8_t> p;
                        appendU64(p, pool_id);
                        appendU64(p, 1000);
                        return p; }())
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  {
    AmmFarmSchedule farm;
    ASSERT_TRUE(state_->getAmmFarm(pool_id, farm));
    farm.rps_per_share = 1'000'000'000ULL;
    state_->putAmmFarm(farm);
  }

  const uint64_t bob_before = state_->getAccount(bob_.publicKey).pending_rewards;
  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::ClaimAmmFarmRewards)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(1)
                    .chainId(EXEC_CHAIN_ID)
                    .payload({})
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_GT(state_->getAccount(bob_.publicKey).pending_rewards, bob_before);

  const uint64_t bob_balance_before = state_->getAccount(bob_.publicKey).balance;
  const uint64_t bob_pending = state_->getAccount(bob_.publicKey).pending_rewards;

  ASSERT_EQ(run(TransactionBuilder()
                    .type(Core::TxType::ClaimRewards)
                    .from(bob_)
                    .to(Crypto::Address{})
                    .amount(0)
                    .fee(1)
                    .nonce(2)
                    .chainId(EXEC_CHAIN_ID)
                    .payload({})
                    .build())
                .status,
            Core::ReceiptStatus::Success);

  EXPECT_EQ(state_->getAccount(bob_.publicKey).balance,
            bob_balance_before + bob_pending - 1);
  EXPECT_EQ(state_->getAccount(bob_.publicKey).pending_rewards, 0u);
}