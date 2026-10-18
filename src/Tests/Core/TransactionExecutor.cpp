// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Fixtures.h"

using namespace Core;
using namespace Tests;

// Common validation (applies to every tx type)

TEST_F(Core_ExecutorFixture, RejectsMalformedTx)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(0)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  Receipt r = run(tx);
  EXPECT_EQ(r.status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RejectsWrongChainId)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID + 1)
                       .build();

  uint64_t before = balanceOf(alice_.publicKey);
  Receipt r = run(tx);
  EXPECT_EQ(r.status, ReceiptStatus::Failure);
  EXPECT_EQ(balanceOf(alice_.publicKey), before);
}

TEST_F(Core_ExecutorFixture, RejectsBadSignature)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  tx.signature.data[0] ^= 0xFF;

  uint64_t before = balanceOf(alice_.publicKey);
  Receipt r = run(tx);
  EXPECT_EQ(r.status, ReceiptStatus::Failure);
  EXPECT_EQ(balanceOf(alice_.publicKey), before);
}

TEST_F(Core_ExecutorFixture, RejectsExpiredTx)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .expiry(50)
                       .build();

  Receipt r = run(tx, /*height=*/100);
  EXPECT_EQ(r.status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RejectsLowNonce)
{
  for (uint64_t n = 0; n < 5; ++n)
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::Transfer)
                         .from(alice_)
                         .to(bob_.publicKey)
                         .amount(1)
                         .fee(1)
                         .nonce(n)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  Transaction stale = TransactionBuilder()
                          .type(TxType::Transfer)
                          .from(alice_)
                          .to(bob_.publicKey)
                          .amount(1)
                          .fee(1)
                          .nonce(3)
                          .chainId(EXEC_CHAIN_ID)
                          .build();

  EXPECT_EQ(run(stale).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RejectsHighNonce)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(1)
                       .fee(1)
                       .nonce(1)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RejectsInsufficientFee)
{
  setBalance(alice_.publicKey, 5);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(1)
                       .fee(10)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, BumpsNonceOnSuccess)
{
  ASSERT_EQ(nonceOf(alice_.publicKey), 0u);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(nonceOf(alice_.publicKey), 1u);
}

TEST_F(Core_ExecutorFixture, DoesNotBumpNonceOnFailure)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(1)
                       .nonce(1)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Failure);
  EXPECT_EQ(nonceOf(alice_.publicKey), 0u);
}

TEST_F(Core_ExecutorFixture, ChargesFeeOnSuccess)
{
  uint64_t before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(7)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  Receipt r = run(tx);
  ASSERT_EQ(r.status, ReceiptStatus::Success);
  EXPECT_EQ(r.fee_paid, 7u);
  EXPECT_EQ(balanceOf(alice_.publicKey), before - 100 - 7);
}

// Transfer

TEST_F(Core_ExecutorFixture, NativeTransfer)
{
  uint64_t a_before = balanceOf(alice_.publicKey);
  uint64_t b_before = balanceOf(bob_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(500)
                       .fee(3)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(balanceOf(alice_.publicKey), a_before - 500 - 3);
  EXPECT_EQ(balanceOf(bob_.publicKey), b_before + 500);
}

TEST_F(Core_ExecutorFixture, SelfTransfer)
{
  uint64_t before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(alice_.publicKey)
                       .amount(500)
                       .fee(3)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(balanceOf(alice_.publicKey), before - 3);
}

TEST_F(Core_ExecutorFixture, TransferExactBalance)
{
  setBalance(alice_.publicKey, 100 + 5);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(5)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(balanceOf(alice_.publicKey), 0u);
}

TEST_F(Core_ExecutorFixture, TransferInsufficientFunds)
{
  setBalance(alice_.publicKey, 50);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, TransferZeroAmountRejected)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(0)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, TransferNullRecipientRejected)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, TokenTransfer)
{
  const Id token = 42;
  state_->putTokenBalance(alice_.publicKey, token, 1000);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Transfer)
                       .from(alice_)
                       .to(bob_.publicKey)
                       .amount(250)
                       .fee(2)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  uint64_t a_native_before = balanceOf(alice_.publicKey);
  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token), 750u);
  EXPECT_EQ(state_->getTokenBalance(bob_.publicKey, token), 250u);
  EXPECT_EQ(balanceOf(alice_.publicKey), a_native_before - 2);
}

// Staking

TEST_F(Core_ExecutorFixture, OptInClearsOptOut)
{
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::OptOutStaking)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(0)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  EXPECT_TRUE(state_->getAccount(alice_.publicKey).staking_opted_out);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::OptInStaking)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  EXPECT_FALSE(state_->getAccount(alice_.publicKey).staking_opted_out);
}

TEST_F(Core_ExecutorFixture, OptOutSetsFlag)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::OptOutStaking)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_TRUE(state_->getAccount(alice_.publicKey).staking_opted_out);
}

TEST_F(Core_ExecutorFixture, OptOutDoesNotMoveFunds)
{
  uint64_t before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::OptOutStaking)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(4)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(balanceOf(alice_.publicKey), before - 4);
}

// Register validator

TEST_F(Core_ExecutorFixture, RegistersBelowMinimum)
{
  Core::Account acct = state_->getAccount(alice_.publicKey);
  acct.balance = GlobalConfig::VALIDATOR_MIN_STAKE - 1;
  state_->putAccount(alice_.publicKey, acct);

  Transaction tx = TransactionBuilder()
                       .type(TxType::RegisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeRegisterValidatorPayload())
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RegistersSuccessfully)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::RegisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeRegisterValidatorPayload())
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  bool found = false;
  for (uint64_t id = 1; id <= 5; ++id)
  {
    ValidatorInfo v;
    if (state_->getValidator(id, v) && v.owner == alice_.publicKey)
    {
      found = true;
      EXPECT_EQ(v.reward_address, alice_.publicKey);
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST_F(Core_ExecutorFixture, RejectsEmptyPayload)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::RegisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

// Create token

TEST_F(Core_ExecutorFixture, CreatesNativeStyleToken)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateTokenPayload("Gold", "GLD"))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  bool found = false;
  for (Id id = 1; id <= 5; ++id)
  {
    TokenInfo t;
    if (state_->getToken(id, t) && t.creator == alice_.publicKey)
    {
      found = true;
      EXPECT_EQ(t.name, "Gold");
      EXPECT_EQ(t.symbol, "GLD");
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST_F(Core_ExecutorFixture, CreateTokenRespectsMaxSupply)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateTokenPayload("Capped", "CAP", 8, 0, 1'000'000))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  bool found = false;
  for (Id id = 1; id <= 5; ++id)
  {
    TokenInfo t;
    if (state_->getToken(id, t) && t.creator == alice_.publicKey)
    {
      found = true;
      EXPECT_EQ(t.maxSupply, 1'000'000u);
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST_F(Core_ExecutorFixture, CreateTokenRejectsInvalidSymbol)
{
  std::string long_symbol(64, 'X');

  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateTokenPayload("Name", long_symbol))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, CreateTokenRejectsMalformedPayload)
{
  std::vector<uint8_t> truncated = {8, 0, 4};

  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::move(truncated))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, CreateTokenRejectsShortSymbol)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateTokenPayload("Name", "AB"))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

// Mint / Burn

TEST_F(Core_ExecutorFixture, OnlyCreatorCanMint)
{
  const Id token = createTokenDirect(alice_, "Gold", "GLD");

  Transaction tx = TransactionBuilder()
                       .type(TxType::MintToken)
                       .from(bob_)
                       .to(bob_.publicKey)
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  EXPECT_EQ(state_->getTokenBalance(bob_.publicKey, token), 0u);
}

TEST_F(Core_ExecutorFixture, MintRespectsMaxSupply)
{
  const Id token =
      createTokenDirect(alice_, "Capped", "CAP", /*max_supply=*/1000);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::MintToken)
                         .from(alice_)
                         .to(alice_.publicKey)
                         .amount(1000)
                         .fee(1)
                         .nonce(0)
                         .tokenId(token)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
    EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token), 1000u);
  }

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::MintToken)
                         .from(alice_)
                         .to(alice_.publicKey)
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .tokenId(token)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  }
}

TEST_F(Core_ExecutorFixture, BurnReducesBalance)
{
  const Id token = createTokenDirect(alice_, "Gold", "GLD");
  state_->putTokenBalance(alice_.publicKey, token, 500);

  Transaction tx = TransactionBuilder()
                       .type(TxType::BurnToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(200)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token), 300u);
}

TEST_F(Core_ExecutorFixture, BurnInsufficientBalance)
{
  const Id token = createTokenDirect(alice_, "Gold", "GLD");
  state_->putTokenBalance(alice_.publicKey, token, 50);

  Transaction tx = TransactionBuilder()
                       .type(TxType::BurnToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token), 50u);
}

// AMM
//
// Every AMM amount below is in atomic units under the current
// `GlobalConfig::DECIMALS`. The original tests used 1000/1000 pools
// sized for `DECIMALS = 8`; under `DECIMALS = 5` that is 0.01 CLRTY
// per side, well below `MIN_POOL_LIQUIDITY`. Every amount has been
// scaled by 1000× so the tests keep exercising the same economic
// magnitudes, at a reserve large enough to satisfy the floor.

TEST_F(Core_ExecutorFixture, CreatePool)
{
  const Id token_a = NATIVE_TOKEN_ID;
  const Id token_b = 100;

  state_->putTokenBalance(alice_.publicKey, token_b, 10'000'000);

  const uint64_t amount_a = 1'000'000;
  const uint64_t amount_b = 1'000'000;

  uint64_t pool_id = createPool(alice_, token_a, amount_a, token_b, amount_b);
  ASSERT_NE(pool_id, 0u);

  AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
  EXPECT_EQ(pool.token_a, std::min(token_a, token_b));
  EXPECT_EQ(pool.token_b, std::max(token_a, token_b));
  EXPECT_EQ(pool.reserve_a, amount_a);
  EXPECT_EQ(pool.reserve_b, amount_b);
  EXPECT_EQ(pool.total_liquidity, expectedInitialLiquidity(amount_a, amount_b));
  EXPECT_EQ(pool.creator, alice_.publicKey);
  EXPECT_TRUE(pool.active);

  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token_b), 9'000'000u);
}

TEST_F(Core_ExecutorFixture, CreatePoolLiquidityIsSqrt)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 1'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 100'000,
                                token_b, 100'000);
  ASSERT_NE(pool_id, 0u);

  AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
  EXPECT_EQ(pool.total_liquidity, 100'000u);
}

TEST_F(Core_ExecutorFixture, CreatePoolRejectsSameTokens)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::CreatePool)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1'000'000)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreatePoolPayload(
                           static_cast<uint32_t>(NATIVE_TOKEN_ID),
                           1'000'000, AMM_DEFAULT_FEE_BPS))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, AddLiquidity)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  AmmPool before;
  ASSERT_TRUE(state_->getAmmPool(pool_id, before));

  Transaction tx = TransactionBuilder()
                       .type(TxType::AddLiquidity)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(500'000)
                       .fee(1)
                       .nonce(1)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeAddLiquidityPayload(pool_id, 500'000))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  AmmPool after;
  ASSERT_TRUE(state_->getAmmPool(pool_id, after));
  EXPECT_EQ(after.reserve_a, before.reserve_a + 500'000);
  EXPECT_EQ(after.reserve_b, before.reserve_b + 500'000);
  EXPECT_GT(after.total_liquidity, before.total_liquidity);
}

TEST_F(Core_ExecutorFixture, RemoveLiquidity)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  uint64_t position_id = 0;
  for (uint64_t pid = 1; pid <= 8; ++pid)
  {
    AmmPosition pos;
    if (state_->getAmmPosition(pid, pos) &&
        pos.owner == alice_.publicKey &&
        pos.pool_id == pool_id)
    {
      position_id = pid;
      break;
    }
  }
  ASSERT_NE(position_id, 0u);

  AmmPosition pos_before;
  ASSERT_TRUE(state_->getAmmPosition(position_id, pos_before));
  ASSERT_GT(pos_before.liquidity, 0u);

  AmmPool pool_before;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool_before));

  uint64_t alice_native_before = balanceOf(alice_.publicKey);
  uint64_t alice_token_before = state_->getTokenBalance(alice_.publicKey, token_b);

  Transaction tx = TransactionBuilder()
                       .type(TxType::RemoveLiquidity)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(1)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeRemoveLiquidityPayload(position_id))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  //  The pool record is gone. Alice was the only LP, so her full
  //  removal drained the pool and triggered the auto-close.
  AmmPool pool_after;
  EXPECT_FALSE(state_->getAmmPool(pool_id, pool_after));

  //  Alice got her share of both reserves back, minus the fee.
  EXPECT_EQ(balanceOf(alice_.publicKey),
            alice_native_before + pool_before.reserve_a - 1);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token_b),
            alice_token_before + pool_before.reserve_b);

  //  The position is zeroed. The record itself is retained.
  AmmPosition pos_after;
  ASSERT_TRUE(state_->getAmmPosition(position_id, pos_after));
  EXPECT_EQ(pos_after.liquidity, 0u);

  //  The position index entry is gone.
  uint64_t idx = 0;
  EXPECT_FALSE(state_->getPositionIndex(alice_.publicKey, pool_id, idx));
}

TEST_F(Core_ExecutorFixture, SwapXForY)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  const uint64_t amount_in = 10'000;
  const uint64_t expected_out =
      expectedSwapOutput(1'000'000, 1'000'000, amount_in, AMM_DEFAULT_FEE_BPS);

  // Hand-computed anchor for the Uniswap V2 formula:
  //   in_with_fee = 10'000 * 9970 / 10'000 = 9'970
  //   out = 1'000'000 * 9'970 / (1'000'000 + 9'970)
  //       = 9'970'000'000 / 1'009'970
  //       = 9'871 (integer division)
  //
  // The anchor is computed by hand above; the EXPECT below confirms
  // that `expectedSwapOutput` agrees with it. If either changes, this
  // will fail loudly rather than drift.
  EXPECT_EQ(expected_out, 9'871u);

  uint64_t alice_native_before = balanceOf(alice_.publicKey);
  uint64_t alice_token_before = state_->getTokenBalance(alice_.publicKey, token_b);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Swap)
                       .from(alice_)
                       .to(alice_.publicKey)
                       .amount(amount_in)
                       .fee(1)
                       .nonce(1)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeSwapPayload(pool_id, /*min_amount_out=*/1))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  EXPECT_EQ(balanceOf(alice_.publicKey),
            alice_native_before - amount_in - 1);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token_b),
            alice_token_before + expected_out);

  AmmPool pool_after;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool_after));
  EXPECT_EQ(pool_after.reserve_a, 1'000'000u + amount_in);
  EXPECT_EQ(pool_after.reserve_b, 1'000'000u - expected_out);
}

TEST_F(Core_ExecutorFixture, SwapSlippageExceeded)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  uint64_t alice_native_before = balanceOf(alice_.publicKey);
  uint64_t alice_token_before = state_->getTokenBalance(alice_.publicKey, token_b);

  AmmPool pool_before;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool_before));

  Transaction tx = TransactionBuilder()
                       .type(TxType::Swap)
                       .from(alice_)
                       .to(alice_.publicKey)
                       .amount(10'000)
                       .fee(1)
                       .nonce(1)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeSwapPayload(pool_id, /*min_amount_out=*/100'000))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_native_before - 1);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token_b), alice_token_before);

  AmmPool pool_after;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool_after));
  EXPECT_EQ(pool_after.reserve_a, pool_before.reserve_a);
  EXPECT_EQ(pool_after.reserve_b, pool_before.reserve_b);
}

TEST_F(Core_ExecutorFixture, SwapUnknownPool)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::Swap)
                       .from(alice_)
                       .to(alice_.publicKey)
                       .amount(10)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeSwapPayload(/*pool_id=*/999, 1))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

// Orders

TEST_F(Core_ExecutorFixture, CreateOrderLocksFunds)
{
  const Id buy_token = 200;

  uint64_t alice_native_before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateOrder)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(500)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateOrderPayload(
                           static_cast<uint32_t>(buy_token),
                           /*min_buy_amount=*/100,
                           static_cast<uint8_t>(OrderExecutionMode::Passive),
                           /*expires_at=*/0))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_native_before - 500 - 1);

  bool found = false;
  for (uint64_t oid = 1; oid <= 8; ++oid)
  {
    Order o;
    if (state_->getOrder(oid, o) && o.owner == alice_.publicKey)
    {
      found = true;
      EXPECT_EQ(o.sell_amount, 500u);
      EXPECT_EQ(o.sell_token, NATIVE_TOKEN_ID);
      EXPECT_EQ(o.buy_token, buy_token);
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST_F(Core_ExecutorFixture, CreateOrderRejectsSameTokens)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateOrder)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(500)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateOrderPayload(
                           static_cast<uint32_t>(NATIVE_TOKEN_ID),
                           100, static_cast<uint8_t>(OrderExecutionMode::Passive), 0))
                       .build();

  uint64_t alice_before = balanceOf(alice_.publicKey);
  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 1);
}

TEST_F(Core_ExecutorFixture, CreateOrderRejectsInvalidMode)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateOrder)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(500)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateOrderPayload(
                           /*buy_token=*/200, 100, /*mode=*/99, /*expires_at=*/0))
                       .build();

  uint64_t alice_before = balanceOf(alice_.publicKey);
  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 1);
}

TEST_F(Core_ExecutorFixture, CancelOrderRefunds)
{
  uint64_t alice_before = balanceOf(alice_.publicKey);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::CreateOrder)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(500)
                         .fee(1)
                         .nonce(0)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeCreateOrderPayload(
                             /*buy_token=*/200, 100,
                             static_cast<uint8_t>(OrderExecutionMode::Passive), 0))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  uint64_t order_id = 0;
  for (uint64_t oid = 1; oid <= 8; ++oid)
  {
    Order o;
    if (state_->getOrder(oid, o) && o.owner == alice_.publicKey)
    {
      order_id = oid;
      break;
    }
  }
  ASSERT_NE(order_id, 0u);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::CancelOrder)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeCancelOrderPayload(order_id))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 2);

  Order o;
  EXPECT_FALSE(state_->getOrder(order_id, o));
}

TEST_F(Core_ExecutorFixture, CancelOrderWrongOwner)
{
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::CreateOrder)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(500)
                         .fee(1)
                         .nonce(0)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeCreateOrderPayload(
                             /*buy_token=*/200, 100,
                             static_cast<uint8_t>(OrderExecutionMode::Passive), 0))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  uint64_t order_id = 0;
  for (uint64_t oid = 1; oid <= 8; ++oid)
  {
    Order o;
    if (state_->getOrder(oid, o) && o.owner == alice_.publicKey)
    {
      order_id = oid;
      break;
    }
  }
  ASSERT_NE(order_id, 0u);

  Transaction tx = TransactionBuilder()
                       .type(TxType::CancelOrder)
                       .from(bob_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCancelOrderPayload(order_id))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);

  Order o;
  EXPECT_TRUE(state_->getOrder(order_id, o));
}

TEST_F(Core_ExecutorFixture, CancelOrderUnknown)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::CancelOrder)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCancelOrderPayload(/*order_id=*/999))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

// Integration

TEST_F(Core_ExecutorFixture, FullTransferSequence)
{
  uint64_t alice_before = balanceOf(alice_.publicKey);
  uint64_t bob_before = balanceOf(bob_.publicKey);

  const uint64_t amount = 100;
  const uint64_t fee = 2;

  for (uint64_t n = 0; n < 5; ++n)
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::Transfer)
                         .from(alice_)
                         .to(bob_.publicKey)
                         .amount(amount)
                         .fee(fee)
                         .nonce(n)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success) << "nonce " << n;
  }

  EXPECT_EQ(balanceOf(alice_.publicKey),
            alice_before - 5 * (amount + fee));
  EXPECT_EQ(balanceOf(bob_.publicKey),
            bob_before + 5 * amount);
  EXPECT_EQ(nonceOf(alice_.publicKey), 5u);
}

TEST_F(Core_ExecutorFixture, AMMSwapAfterCreate)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  const uint64_t amount_in = 100'000;
  const uint64_t expected_out =
      expectedSwapOutput(1'000'000, 1'000'000, amount_in, AMM_DEFAULT_FEE_BPS);

  Transaction tx = TransactionBuilder()
                       .type(TxType::Swap)
                       .from(alice_)
                       .to(alice_.publicKey)
                       .amount(amount_in)
                       .fee(1)
                       .nonce(1)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeSwapPayload(pool_id, /*min_amount_out=*/1))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
  EXPECT_EQ(pool.reserve_a, 1'000'000u + amount_in);
  EXPECT_EQ(pool.reserve_b, 1'000'000u - expected_out);

  // k grew (fees accumulate) or stayed equal (no fee). It must never shrink.
  __uint128_t k_before = static_cast<__uint128_t>(1'000'000) * 1'000'000;
  __uint128_t k_after = pool.k();
  EXPECT_GE(k_after, k_before);
}

TEST_F(Core_ExecutorFixture, OrderLifecycle)
{
  uint64_t alice_before = balanceOf(alice_.publicKey);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::CreateOrder)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(500)
                         .fee(1)
                         .nonce(0)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeCreateOrderPayload(
                             /*buy_token=*/200, 100,
                             static_cast<uint8_t>(OrderExecutionMode::Passive), 0))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  uint64_t order_id = 0;
  for (uint64_t oid = 1; oid <= 8; ++oid)
  {
    Order o;
    if (state_->getOrder(oid, o) && o.owner == alice_.publicKey)
    {
      order_id = oid;
      break;
    }
  }
  ASSERT_NE(order_id, 0u);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::CancelOrder)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeCancelOrderPayload(order_id))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  EXPECT_EQ(balanceOf(alice_.publicKey), alice_before - 2);
  EXPECT_EQ(nonceOf(alice_.publicKey), 2u);
}

TEST_F(Core_ExecutorFixture, MintAfterTransferRespectsMaxSupply)
{
  const Id token =
      createTokenDirect(alice_, "Capped", "CAP", /*max_supply=*/1000);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::MintToken)
                         .from(alice_)
                         .to(alice_.publicKey)
                         .amount(1000)
                         .fee(1)
                         .nonce(0)
                         .tokenId(token)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  EXPECT_EQ(state_->getTokenSupply(token), 1000u);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::Transfer)
                         .from(alice_)
                         .to(bob_.publicKey)
                         .amount(500)
                         .fee(1)
                         .nonce(1)
                         .tokenId(token)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token), 500u);
  EXPECT_EQ(state_->getTokenBalance(bob_.publicKey, token), 500u);
  EXPECT_EQ(state_->getTokenSupply(token), 1000u);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::MintToken)
                         .from(alice_)
                         .to(alice_.publicKey)
                         .amount(1)
                         .fee(1)
                         .nonce(2)
                         .tokenId(token)
                         .chainId(EXEC_CHAIN_ID)
                         .build();
    EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  }

  EXPECT_EQ(state_->getTokenSupply(token), 1000u);
}

TEST_F(Core_ExecutorFixture, MintIncreasesTokenSupply)
{
  const Id token = createTokenDirect(alice_, "Gold", "GLD");

  EXPECT_EQ(state_->getTokenSupply(token), 0u);

  Transaction tx = TransactionBuilder()
                       .type(TxType::MintToken)
                       .from(alice_)
                       .to(alice_.publicKey)
                       .amount(250)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(state_->getTokenSupply(token), 250u);
}

TEST_F(Core_ExecutorFixture, BurnReducesTokenSupply)
{
  const Id token = createTokenDirect(alice_, "Gold", "GLD");
  state_->putTokenBalance(alice_.publicKey, token, 500);
  state_->putTokenSupply(token, 500);

  Transaction tx = TransactionBuilder()
                       .type(TxType::BurnToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(200)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(state_->getTokenSupply(token), 300u);
}

TEST_F(Core_ExecutorFixture, BurnBelowTrackedSupplyClampsAtZero)
{
  const Id token = createTokenDirect(alice_, "Gold", "GLD");
  state_->putTokenBalance(alice_.publicKey, token, 100);
  state_->putTokenSupply(token, 50);

  Transaction tx = TransactionBuilder()
                       .type(TxType::BurnToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(100)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  EXPECT_EQ(state_->getTokenSupply(token), 0u);
}

TEST_F(Core_ExecutorFixture, MintNativeTokenRejected)
{
  uint64_t native_before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::MintToken)
                       .from(alice_)
                       .to(alice_.publicKey)
                       .amount(1000)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  EXPECT_EQ(balanceOf(alice_.publicKey), native_before - 1);
}

TEST_F(Core_ExecutorFixture, BurnNativeTokenRejected)
{
  uint64_t native_before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::BurnToken)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1000)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  EXPECT_EQ(balanceOf(alice_.publicKey), native_before - 1);
}

// LP position index

TEST_F(Core_ExecutorFixture, AddLiquidityMergesIntoExistingPosition)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  uint64_t pos_id = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id, pos_id));

  AmmPosition pos_before;
  ASSERT_TRUE(state_->getAmmPosition(pos_id, pos_before));

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::AddLiquidity)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(500'000)
                         .fee(1)
                         .nonce(1)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeAddLiquidityPayload(pool_id, 500'000))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  uint64_t pos_id_after = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id, pos_id_after));
  EXPECT_EQ(pos_id_after, pos_id);

  AmmPosition pos_after;
  ASSERT_TRUE(state_->getAmmPosition(pos_id, pos_after));
  EXPECT_GT(pos_after.liquidity, pos_before.liquidity);
  EXPECT_EQ(pos_after.created_at_height, pos_before.created_at_height);
}

TEST_F(Core_ExecutorFixture, AddLiquidityFromDifferentOwnerCreatesNewPosition)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);
  state_->putTokenBalance(bob_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::AddLiquidity)
                         .from(bob_)
                         .to(Crypto::Address{})
                         .amount(500'000)
                         .fee(1)
                         .nonce(0)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeAddLiquidityPayload(pool_id, 500'000))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  uint64_t alice_pos = 0;
  uint64_t bob_pos = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id, alice_pos));
  ASSERT_TRUE(state_->getPositionIndex(bob_.publicKey, pool_id, bob_pos));
  EXPECT_NE(alice_pos, bob_pos);
}

TEST_F(Core_ExecutorFixture, RemoveLiquidityClearsPositionIndex)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  uint64_t pos_id = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id, pos_id));

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::RemoveLiquidity)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeRemoveLiquidityPayload(pos_id))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  uint64_t pos_after = 0;
  EXPECT_FALSE(state_->getPositionIndex(alice_.publicKey, pool_id, pos_after));

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::AddLiquidity)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(500'000)
                         .fee(1)
                         .nonce(2)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeAddLiquidityPayload(pool_id, 500'000))
                         .build();
    // The pool is empty after full removal, so this must fail with
    // the "empty pool" precondition.
    EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
  }
}

// Validator address index

TEST_F(Core_ExecutorFixture, RegisterValidatorWritesAddressIndex)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::RegisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeRegisterValidatorPayload())
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  uint64_t vid = 0;
  ASSERT_TRUE(state_->getValidatorByAddress(alice_.publicKey, vid));

  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(vid, v));
  EXPECT_EQ(v.reward_address, alice_.publicKey);
  EXPECT_EQ(v.owner, alice_.publicKey);
}

TEST_F(Core_ExecutorFixture, UnregisterRetainsAddressIndexUntilExpiry)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UnregisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  uint64_t id = 0;
  EXPECT_TRUE(state_->getValidatorByAddress(alice_.publicKey, id));
  EXPECT_EQ(id, 5u);
}

// Order expiry index

TEST_F(Core_ExecutorFixture, CreateOrderAddsToExpiryIndex)
{
  const Id buy_token = 200;
  const uint64_t expires_at = 500;

  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateOrder)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(500)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateOrderPayload(
                           static_cast<uint32_t>(buy_token),
                           /*min_buy_amount=*/100,
                           static_cast<uint8_t>(OrderExecutionMode::Passive),
                           expires_at))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  uint64_t order_id = 0;
  for (uint64_t oid = 1; oid <= 8; ++oid)
  {
    Order o;
    if (state_->getOrder(oid, o))
    {
      order_id = oid;
      break;
    }
  }
  ASSERT_NE(order_id, 0u);

  auto expiring = state_->getOrdersExpiringAt(expires_at);
  ASSERT_EQ(expiring.size(), 1u);
  EXPECT_EQ(expiring[0], order_id);
}

TEST_F(Core_ExecutorFixture, CreateOrderWithZeroExpiryIsNotIndexed)
{
  const Id buy_token = 200;

  Transaction tx = TransactionBuilder()
                       .type(TxType::CreateOrder)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(500)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreateOrderPayload(
                           static_cast<uint32_t>(buy_token),
                           /*min_buy_amount=*/100,
                           static_cast<uint8_t>(OrderExecutionMode::Passive),
                           /*expires_at=*/0))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  EXPECT_TRUE(state_->getOrdersExpiringAt(0).empty());
  EXPECT_TRUE(state_->getOrdersExpiringAt(1).empty());
  EXPECT_TRUE(state_->getOrdersExpiringAt(500).empty());
}

TEST_F(Core_ExecutorFixture, CancelOrderRemovesFromExpiryIndex)
{
  const Id buy_token = 200;
  const uint64_t expires_at = 500;

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::CreateOrder)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(500)
                         .fee(1)
                         .nonce(0)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeCreateOrderPayload(
                             static_cast<uint32_t>(buy_token),
                             100,
                             static_cast<uint8_t>(OrderExecutionMode::Passive),
                             expires_at))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  uint64_t order_id = 0;
  for (uint64_t oid = 1; oid <= 8; ++oid)
  {
    Order o;
    if (state_->getOrder(oid, o))
    {
      order_id = oid;
      break;
    }
  }
  ASSERT_NE(order_id, 0u);
  ASSERT_EQ(state_->getOrdersExpiringAt(expires_at).size(), 1u);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::CancelOrder)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeCancelOrderPayload(order_id))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  EXPECT_TRUE(state_->getOrdersExpiringAt(expires_at).empty());
}

// Claim Rewards

TEST_F(Core_ExecutorFixture, ClaimMovesRewardsToBalance)
{
  setPendingRewards(alice_.publicKey, 500);

  uint64_t before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::ClaimRewards)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  EXPECT_EQ(balanceOf(alice_.publicKey), before + 500 - 2);
  EXPECT_EQ(state_->getAccount(alice_.publicKey).pending_rewards, 0u);
}

TEST_F(Core_ExecutorFixture, ClaimZeroRewardsSucceeds)
{
  uint64_t before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::ClaimRewards)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  EXPECT_EQ(balanceOf(alice_.publicKey), before - 2);
}

TEST_F(Core_ExecutorFixture, ClaimPreservesTotalValue)
{
  setPendingRewards(alice_.publicKey, 1000);

  Core::Account before = state_->getAccount(alice_.publicKey);
  uint64_t total_before = before.balance + before.pending_rewards;

  Transaction tx = TransactionBuilder()
                       .type(TxType::ClaimRewards)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(3)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  Core::Account after = state_->getAccount(alice_.publicKey);
  uint64_t total_after = after.balance + after.pending_rewards;

  EXPECT_EQ(total_after + 3, total_before);
}

TEST_F(Core_ExecutorFixture, ClaimRecomputesStaked)
{
  Core::Account acct = state_->getAccount(alice_.publicKey);
  acct.balance = GlobalConfig::AUTO_STAKE_THRESHOLD - 100;
  acct.pending_rewards = 500;
  acct.recalculateStaked(GlobalConfig::AUTO_STAKE_THRESHOLD);
  state_->putAccount(alice_.publicKey, acct);

  EXPECT_EQ(state_->getAccount(alice_.publicKey).staked, 0u);

  Transaction tx = TransactionBuilder()
                       .type(TxType::ClaimRewards)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  Core::Account after = state_->getAccount(alice_.publicKey);
  EXPECT_GT(after.balance, GlobalConfig::AUTO_STAKE_THRESHOLD);
  EXPECT_EQ(after.staked, after.balance);
}

// Unregister Validator

TEST_F(Core_ExecutorFixture, UnregisterStartsUnbondingInsteadOfReturningStake)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  uint64_t before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UnregisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  EXPECT_EQ(balanceOf(alice_.publicKey), before - 2);

  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(5, v));
  EXPECT_EQ(v.pending_unbond_height,
            100 + UNBONDING_PERIOD);
  EXPECT_FALSE(v.canBeActive());
}

TEST_F(Core_ExecutorFixture, UnregisterRejectsSeed)
{
  seedValidator(alice_, /*id=*/1, /*is_seed=*/true);
  bumpNextValidatorId(2);

  uint64_t before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UnregisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);

  EXPECT_EQ(balanceOf(alice_.publicKey), before - 2);
}

TEST_F(Core_ExecutorFixture, UnregisterRejectsUnknown)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::UnregisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, UnregisterTwiceIsRejected)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  auto make_unreg = [&](uint64_t nonce)
  {
    return TransactionBuilder()
        .type(TxType::UnregisterValidator)
        .from(alice_)
        .to(Crypto::Address{})
        .amount(1)
        .fee(2)
        .nonce(nonce)
        .chainId(EXEC_CHAIN_ID)
        .build();
  };

  ASSERT_EQ(run(make_unreg(0)).status, ReceiptStatus::Success);

  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(5, v));
  const uint64_t first_stamp = v.pending_unbond_height;
  ASSERT_NE(first_stamp, 0u);

  EXPECT_EQ(run(make_unreg(1)).status, ReceiptStatus::Failure);

  ASSERT_TRUE(state_->getValidator(5, v));
  EXPECT_EQ(v.pending_unbond_height, first_stamp);
}

TEST_F(Core_ExecutorFixture, UnregisterRejectsWhenAlreadyUnbonding)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  {
    ValidatorInfo v;
    ASSERT_TRUE(state_->getValidator(5, v));
    v.pending_unbond_height = 500;
    state_->putValidator(v);
  }

  Transaction tx = TransactionBuilder()
                       .type(TxType::UnregisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, UnregisterRetainsRecordAndIndex)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UnregisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(5, v));
  EXPECT_EQ(v.pending_unbond_height,
            100u + UNBONDING_PERIOD);

  uint64_t id = 0;
  ASSERT_TRUE(state_->getValidatorByAddress(alice_.publicKey, id));
  EXPECT_EQ(id, 5u);
}

TEST_F(Core_ExecutorFixture, UnregisterRemovesFromActiveSet)
{
  seedValidator(alice_, /*id=*/1, /*is_seed=*/true, /*is_active=*/true);
  seedValidator(bob_, /*id=*/2, /*is_seed=*/false, /*is_active=*/true);
  bumpNextValidatorId(3);

  std::vector<Id> active = {1, 2};
  for (uint64_t id = 3; id <= GlobalConfig::ACTIVE_SET_MIN + 1; ++id)
  {
    ValidatorInfo v;
    v.id = id;
    v.reward_address = Crypto::Address{};
    v.reward_address.data[0] = uint8_t(id);
    v.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
    v.uptime_score = 10'000;
    v.is_seed = false;
    v.is_active = true;
    state_->putValidator(v);
    active.push_back(id);
  }
  setActiveSet(active);
  bumpNextValidatorId(GlobalConfig::ACTIVE_SET_MIN + 2);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UnregisterValidator)
                       .from(bob_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  std::vector<uint8_t> set_bytes;
  ASSERT_TRUE(state_->getGlobal("active_set", set_bytes));
  std::vector<uint64_t> ids;
  for (size_t i = 0; i < set_bytes.size(); i += 8)
  {
    uint64_t id = 0;
    for (int j = 0; j < 8; ++j)
      id |= uint64_t(set_bytes[i + j]) << (j * 8);
    ids.push_back(id);
  }
  EXPECT_EQ(std::find(ids.begin(), ids.end(), 2u), ids.end());
  EXPECT_EQ(ids.size(), GlobalConfig::ACTIVE_SET_MIN);
}

TEST_F(Core_ExecutorFixture, UnregisterRejectsIfSetWouldDropBelowMin)
{
  std::vector<Id> active;
  for (uint64_t id = 1; id <= GlobalConfig::ACTIVE_SET_MIN; ++id)
  {
    Crypto::KeyPair kp = (id == 1) ? alice_ : bob_;
    ValidatorInfo v;
    v.id = id;
    v.reward_address = kp.publicKey;
    if (id > 2)
    {
      v.reward_address = Crypto::Address{};
      v.reward_address.data[0] = uint8_t(id);
    }
    v.stake = GlobalConfig::VALIDATOR_MIN_STAKE;
    v.uptime_score = 10'000;
    v.is_seed = false;
    v.is_active = true;
    state_->putValidator(v);
    active.push_back(id);
  }
  setActiveSet(active);
  bumpNextValidatorId(GlobalConfig::ACTIVE_SET_MIN + 1);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UnregisterValidator)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

// Update Reward Address

TEST_F(Core_ExecutorFixture, UpdateRewardAddressMovesIndex)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateRewardAddress)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(bob_.publicKey.data.begin(),
                                                     bob_.publicKey.data.end()))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  uint64_t id = 0;
  EXPECT_FALSE(state_->getValidatorByAddress(alice_.publicKey, id));

  ASSERT_TRUE(state_->getValidatorByAddress(bob_.publicKey, id));
  EXPECT_EQ(id, 5u);

  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(5, v));
  EXPECT_EQ(v.reward_address, bob_.publicKey);
  EXPECT_EQ(v.owner, bob_.publicKey);
}

TEST_F(Core_ExecutorFixture, UpdateRewardAddressRejectsCollision)
{
  seedValidator(alice_, /*id=*/5);
  seedValidator(bob_, /*id=*/6);
  bumpNextValidatorId(7);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateRewardAddress)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(bob_.publicKey.data.begin(),
                                                     bob_.publicKey.data.end()))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, UpdateRewardAddressRejectsNonValidator)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateRewardAddress)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(bob_.publicKey.data.begin(),
                                                     bob_.publicKey.data.end()))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, UpdateRewardAddressRejectsNull)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateRewardAddress)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(32, 0))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, UpdateRewardAddressRejectsWrongPayloadSize)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateRewardAddress)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(2)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(16, 0xAA))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

// Update Token Meta

TEST_F(Core_ExecutorFixture, UpdateTokenMetaChangesName)
{
  const Id token =
      createTokenDirect(alice_, "Gold", "GLD");

  std::vector<uint8_t> payload;
  payload.push_back(3);
  payload.insert(payload.end(), {'B', 'a', 'r'});
  payload.push_back(0);
  payload.push_back(0);
  payload.push_back(0);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateTokenMeta)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(payload)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  TokenInfo t;
  ASSERT_TRUE(state_->getToken(token, t));
  EXPECT_EQ(t.name, "Bar");
  EXPECT_EQ(t.symbol, "GLD");
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaChangesSymbol)
{
  const Id token =
      createTokenDirect(alice_, "Gold", "GLD");

  std::vector<uint8_t> payload;
  payload.push_back(0);
  payload.push_back(3);
  payload.insert(payload.end(), {'B', 'A', 'R'});
  payload.push_back(0);
  payload.push_back(0);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateTokenMeta)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(payload)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  TokenInfo t;
  ASSERT_TRUE(state_->getToken(token, t));
  EXPECT_EQ(t.name, "Gold");
  EXPECT_EQ(t.symbol, "BAR");
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaChangesRoyalty)
{
  const Id token =
      createTokenDirect(alice_, "Gold", "GLD");

  std::vector<uint8_t> payload;
  payload.push_back(0);
  payload.push_back(0);
  payload.push_back(250);
  payload.push_back(0);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateTokenMeta)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(payload)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  TokenInfo t;
  ASSERT_TRUE(state_->getToken(token, t));
  EXPECT_EQ(t.royaltyBps, 250u);
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaEmptyMeansNoChange)
{
  const Id token =
      createTokenDirect(alice_, "Gold", "GLD");

  std::vector<uint8_t> payload = {0, 0, 0, 0};

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateTokenMeta)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(payload)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  TokenInfo t;
  ASSERT_TRUE(state_->getToken(token, t));
  EXPECT_EQ(t.name, "Gold");
  EXPECT_EQ(t.symbol, "GLD");
  EXPECT_EQ(t.royaltyBps, 0u);
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaRejectsNonCreator)
{
  const Id token =
      createTokenDirect(alice_, "Gold", "GLD");

  std::vector<uint8_t> payload = {3, 'B', 'a', 'r', 0, 0, 0};

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateTokenMeta)
                       .from(bob_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(payload)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaRejectsNative)
{
  std::vector<uint8_t> payload = {3, 'B', 'a', 'r', 0, 0, 0};

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateTokenMeta)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(payload)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaRejectsInvalidSymbol)
{
  const Id token =
      createTokenDirect(alice_, "Gold", "GLD");

  std::vector<uint8_t> payload;
  payload.push_back(0);
  payload.push_back(2);
  payload.insert(payload.end(), {'A', 'B'});
  payload.push_back(0);
  payload.push_back(0);

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateTokenMeta)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(payload)
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaDoesNotChangeMaxSupply)
{
  const Id token =
      createTokenDirect(alice_, "Capped", "CAP", /*max_supply=*/1000);

  std::vector<uint8_t> payload = {3, 'B', 'a', 'r', 0, 0, 0};

  Transaction tx = TransactionBuilder()
                       .type(TxType::UpdateTokenMeta)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .tokenId(token)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(payload)
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  TokenInfo t;
  ASSERT_TRUE(state_->getToken(token, t));
  EXPECT_EQ(t.maxSupply, 1000u);
}

TEST_F(Core_ExecutorFixture, RemoveLastLiquidityClosesPool)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  uint64_t position_id = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id,
                                       position_id));

  AmmPosition pos_before;
  ASSERT_TRUE(state_->getAmmPosition(position_id, pos_before));
  ASSERT_GT(pos_before.liquidity, 0u);

  Transaction tx = TransactionBuilder()
                       .type(TxType::RemoveLiquidity)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(1)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeRemoveLiquidityPayload(position_id))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  AmmPool pool;
  EXPECT_FALSE(state_->getAmmPool(pool_id, pool));
}

TEST_F(Core_ExecutorFixture, ClosedPoolRejectsSwap)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  uint64_t position_id = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id,
                                       position_id));

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::RemoveLiquidity)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeRemoveLiquidityPayload(position_id))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  Transaction swap = TransactionBuilder()
                         .type(TxType::Swap)
                         .from(alice_)
                         .to(alice_.publicKey)
                         .amount(10'000)
                         .fee(1)
                         .nonce(2)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeSwapPayload(pool_id, /*min_out=*/1))
                         .build();

  EXPECT_EQ(run(swap).status, ReceiptStatus::Failure);

  Transaction add = TransactionBuilder()
                        .type(TxType::AddLiquidity)
                        .from(alice_)
                        .to(Crypto::Address{})
                        .amount(500'000)
                        .fee(1)
                        .nonce(3)
                        .tokenId(NATIVE_TOKEN_ID)
                        .chainId(EXEC_CHAIN_ID)
                        .payload(makeAddLiquidityPayload(pool_id, 500'000))
                        .build();

  EXPECT_EQ(run(add).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, PartialRemovalDoesNotClosePool)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000'000);
  state_->putTokenBalance(bob_.publicKey, token_b, 100'000'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1'000'000,
                                token_b, 1'000'000);
  ASSERT_NE(pool_id, 0u);

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::AddLiquidity)
                         .from(bob_)
                         .to(Crypto::Address{})
                         .amount(500'000)
                         .fee(1)
                         .nonce(0)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeAddLiquidityPayload(pool_id, 500'000))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  uint64_t alice_pos = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id,
                                       alice_pos));

  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::RemoveLiquidity)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeRemoveLiquidityPayload(alice_pos))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
  EXPECT_GT(pool.total_liquidity, 0u);
  EXPECT_GT(pool.reserve_a, 0u);
  EXPECT_GT(pool.reserve_b, 0u);

  Transaction swap = TransactionBuilder()
                         .type(TxType::Swap)
                         .from(alice_)
                         .to(alice_.publicKey)
                         .amount(10'000)
                         .fee(1)
                         .nonce(2)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeSwapPayload(pool_id, /*min_out=*/1))
                         .build();

  EXPECT_EQ(run(swap).status, ReceiptStatus::Success);
}

//  PartialRemovalWithReservesThatOverflowU64 is unchanged: it writes
//  the pool and position directly, bypassing MIN_POOL_LIQUIDITY, and
//  its numbers are chosen for the uint128 promotion, not for the
//  current DECIMALS.
TEST_F(Core_ExecutorFixture, PartialRemovalWithReservesThatOverflowU64)
{
  const Id token_b = 100;
  const uint64_t total_liquidity = uint64_t(1) << 40;
  const uint64_t reserve = uint64_t(1) << 40;
  const uint64_t remove_amount = uint64_t(1) << 39;

  AmmPool pool;
  pool.id = 77;
  pool.token_a = NATIVE_TOKEN_ID;
  pool.token_b = token_b;
  pool.reserve_a = reserve;
  pool.reserve_b = reserve;
  pool.total_liquidity = total_liquidity;
  pool.fee_bps = AMM_DEFAULT_FEE_BPS;
  pool.creator = alice_.publicKey;
  pool.created_at_height = 1;
  pool.active = true;
  state_->putAmmPool(pool);

  AmmPosition pos;
  pos.id = 88;
  pos.owner = alice_.publicKey;
  pos.pool_id = pool.id;
  pos.liquidity = remove_amount;
  pos.created_at_height = 1;
  state_->putAmmPosition(pos);
  state_->putPositionIndex(alice_.publicKey, pool.id, pos.id);

  state_->putTokenBalance(alice_.publicKey, token_b, 0);

  const uint64_t alice_native_before = balanceOf(alice_.publicKey);

  Transaction tx = TransactionBuilder()
                       .type(TxType::RemoveLiquidity)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeRemoveLiquidityPayload(pos.id, remove_amount))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  const uint64_t expected_share = remove_amount;

  EXPECT_EQ(balanceOf(alice_.publicKey),
            alice_native_before + expected_share - 1);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token_b),
            expected_share);

  AmmPool pool_after;
  ASSERT_TRUE(state_->getAmmPool(pool.id, pool_after));
  EXPECT_EQ(pool_after.reserve_a, reserve - expected_share);
  EXPECT_EQ(pool_after.reserve_b, reserve - expected_share);
  EXPECT_EQ(pool_after.total_liquidity, total_liquidity - remove_amount);

  AmmPosition pos_after;
  ASSERT_TRUE(state_->getAmmPosition(pos.id, pos_after));
  EXPECT_EQ(pos_after.liquidity, 0u);

  uint64_t idx = 0;
  EXPECT_TRUE(state_->getPositionIndex(alice_.publicKey, pool.id, idx));
  EXPECT_EQ(idx, pos.id);
}