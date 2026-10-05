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

TEST_F(Core_ExecutorFixture, CreatePool)
{
  const Id token_a = NATIVE_TOKEN_ID;
  const Id token_b = 100;

  state_->putTokenBalance(alice_.publicKey, token_b, 10'000);

  const uint64_t amount_a = 1000;
  const uint64_t amount_b = 1000;

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

  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token_b), 9'000u);
}

TEST_F(Core_ExecutorFixture, CreatePoolLiquidityIsSqrt)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 1000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 100,
                                token_b, 100);
  ASSERT_NE(pool_id, 0u);

  AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
  EXPECT_EQ(pool.total_liquidity, 100u);
}

TEST_F(Core_ExecutorFixture, CreatePoolRejectsSameTokens)
{
  Transaction tx = TransactionBuilder()
                       .type(TxType::CreatePool)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1000)
                       .fee(1)
                       .nonce(0)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeCreatePoolPayload(
                           static_cast<uint32_t>(NATIVE_TOKEN_ID),
                           1000, AMM_DEFAULT_FEE_BPS))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, AddLiquidity)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  AmmPool before;
  ASSERT_TRUE(state_->getAmmPool(pool_id, before));

  Transaction tx = TransactionBuilder()
                       .type(TxType::AddLiquidity)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(500)
                       .fee(1)
                       .nonce(1)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeAddLiquidityPayload(pool_id, 500))
                       .build();

  ASSERT_EQ(run(tx).status, ReceiptStatus::Success);

  AmmPool after;
  ASSERT_TRUE(state_->getAmmPool(pool_id, after));
  EXPECT_EQ(after.reserve_a, before.reserve_a + 500);
  EXPECT_EQ(after.reserve_b, before.reserve_b + 500);
  EXPECT_GT(after.total_liquidity, before.total_liquidity);
}

TEST_F(Core_ExecutorFixture, RemoveLiquidity)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
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
  //  removal drained the pool and triggered the auto-close. Under
  //  the old behavior the record survived with zero reserves; that
  //  assertion was removed along with the old behavior — the close
  //  is now the observable post-condition.
  AmmPool pool_after;
  EXPECT_FALSE(state_->getAmmPool(pool_id, pool_after));

  //  Alice got her share of both reserves back, minus the fee.
  EXPECT_EQ(balanceOf(alice_.publicKey),
            alice_native_before + pool_before.reserve_a - 1);
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token_b),
            alice_token_before + pool_before.reserve_b);

  //  The position is zeroed. The record itself is retained (it's
  //  unreachable from the position index, which was removed, so it's
  //  inert), but its liquidity is zero.
  AmmPosition pos_after;
  ASSERT_TRUE(state_->getAmmPosition(position_id, pos_after));
  EXPECT_EQ(pos_after.liquidity, 0u);

  //  The position index entry is gone, so a future AddLiquidity would
  //  create a fresh position rather than merge into the zeroed one.
  //  (In practice there's no pool to add to — see the closed-pool
  //  test — but the index cleanup is worth asserting separately.)
  uint64_t idx = 0;
  EXPECT_FALSE(state_->getPositionIndex(alice_.publicKey, pool_id, idx));
}

TEST_F(Core_ExecutorFixture, SwapXForY)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  const uint64_t amount_in = 10;
  const uint64_t expected_out =
      expectedSwapOutput(1000, 1000, amount_in, AMM_DEFAULT_FEE_BPS);

  // Hand-computed anchor for the Uniswap V2 formula:
  //   in_with_fee = 10 * 9970 / 10000 = 9
  //   out = 1000 * 9 / (1000 + 9) = 9000 / 1009 = 8 (integer division)
  EXPECT_EQ(expected_out, 8u);

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

  // Native decreases by amount_in + fee. No native comes back —
  // the output is token_b.
  EXPECT_EQ(balanceOf(alice_.publicKey),
            alice_native_before - amount_in - 1);
  // token_b increases by the swap output.
  EXPECT_EQ(state_->getTokenBalance(alice_.publicKey, token_b),
            alice_token_before + expected_out);

  AmmPool pool_after;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool_after));
  EXPECT_EQ(pool_after.reserve_a, 1000u + amount_in);
  EXPECT_EQ(pool_after.reserve_b, 1000u - expected_out);
}

TEST_F(Core_ExecutorFixture, SwapSlippageExceeded)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  uint64_t alice_native_before = balanceOf(alice_.publicKey);
  uint64_t alice_token_before = state_->getTokenBalance(alice_.publicKey, token_b);

  AmmPool pool_before;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool_before));

  Transaction tx = TransactionBuilder()
                       .type(TxType::Swap)
                       .from(alice_)
                       .to(alice_.publicKey)
                       .amount(10)
                       .fee(1)
                       .nonce(1)
                       .tokenId(NATIVE_TOKEN_ID)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(makeSwapPayload(pool_id, /*min_amount_out=*/100))
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
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  const uint64_t amount_in = 100;
  const uint64_t expected_out =
      expectedSwapOutput(1000, 1000, amount_in, AMM_DEFAULT_FEE_BPS);

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
  EXPECT_EQ(pool.reserve_a, 1000u + amount_in);
  EXPECT_EQ(pool.reserve_b, 1000u - expected_out);

  // k grew (fees accumulate) or stayed equal (no fee). It must never shrink.
  __uint128_t k_before = static_cast<__uint128_t>(1000) * 1000;
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
  // The bug that the supply counter fixes: mint to cap, transfer
  // tokens away, mint again. The old code checked the minter's
  // balance, so transferring away reduced the apparent usage and
  // allowed minting past the cap.
  const Id token =
      createTokenDirect(alice_, "Capped", "CAP", /*max_supply=*/1000);

  // Mint the full cap to Alice.
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

  // Transfer half to Bob. Alice's balance is now 500, but the token's
  // total supply is still 1000.
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

  // Now try to mint 1 more. With the old balance-based check, Alice's
  // balance (500) + 1 <= 1000 would pass. With the supply-based check,
  // supply (1000) + 1 > 1000 fails.
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
  // Defensive: if burn exceeds the tracked supply (inconsistent state
  // that shouldn't be reachable), the counter clamps at zero rather
  // than underflowing.
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
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  // Create pool: Alice gets one position.
  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  // Find Alice's initial position via the index.
  uint64_t pos_id = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id, pos_id));

  AmmPosition pos_before;
  ASSERT_TRUE(state_->getAmmPosition(pos_id, pos_before));

  // Add more liquidity. Should merge into the same position.
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::AddLiquidity)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(500)
                         .fee(1)
                         .nonce(1)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeAddLiquidityPayload(pool_id, 500))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  // The index must still point at the same position_id.
  uint64_t pos_id_after = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id, pos_id_after));
  EXPECT_EQ(pos_id_after, pos_id);

  // The position's liquidity should have grown, and created_at_height
  // should be unchanged (the original creation height, not the merge).
  AmmPosition pos_after;
  ASSERT_TRUE(state_->getAmmPosition(pos_id, pos_after));
  EXPECT_GT(pos_after.liquidity, pos_before.liquidity);
  EXPECT_EQ(pos_after.created_at_height, pos_before.created_at_height);
}

TEST_F(Core_ExecutorFixture, AddLiquidityFromDifferentOwnerCreatesNewPosition)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);
  state_->putTokenBalance(bob_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  // Bob adds liquidity. He has no position yet, so a new one is created.
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::AddLiquidity)
                         .from(bob_)
                         .to(Crypto::Address{})
                         .amount(500)
                         .fee(1)
                         .nonce(0)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeAddLiquidityPayload(pool_id, 500))
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
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  uint64_t pos_id = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id, pos_id));

  // Remove all liquidity.
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

  // The index must be gone.
  uint64_t pos_after = 0;
  EXPECT_FALSE(state_->getPositionIndex(alice_.publicKey, pool_id, pos_after));

  // Re-adding liquidity creates a fresh position with a new ID.
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::AddLiquidity)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(500)
                         .fee(1)
                         .nonce(2)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeAddLiquidityPayload(pool_id, 500))
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

  // The validator-by-address index should now map Alice's address to
  // her newly assigned validator ID.
  uint64_t vid = 0;
  ASSERT_TRUE(state_->getValidatorByAddress(alice_.publicKey, vid));

  // And the validator record should exist under that ID.
  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(vid, v));
  EXPECT_EQ(v.reward_address, alice_.publicKey);
  EXPECT_EQ(v.owner, alice_.publicKey);
}

TEST_F(Core_ExecutorFixture, UnregisterRetainsAddressIndexUntilExpiry)
{
  // The address index must survive unregister so an equivocation
  // proof against the validator can still resolve the signer. It's
  // only removed at unbond expiry.
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

  // Find the new order ID.
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

  // No entry at height 0 (or anywhere).
  EXPECT_TRUE(state_->getOrdersExpiringAt(0).empty());
  EXPECT_TRUE(state_->getOrdersExpiringAt(1).empty());
  EXPECT_TRUE(state_->getOrdersExpiringAt(500).empty());
}

TEST_F(Core_ExecutorFixture, CancelOrderRemovesFromExpiryIndex)
{
  const Id buy_token = 200;
  const uint64_t expires_at = 500;

  // Create an indexed order.
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

  // Cancel it.
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

  // The index entry must be gone.
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

  // Balance gained 500 (rewards), lost 2 (fee).
  EXPECT_EQ(balanceOf(alice_.publicKey), before + 500 - 2);

  // Pending is cleared.
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

  // Only the fee moves.
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

  // The only delta is the fee.
  EXPECT_EQ(total_after + 3, total_before);
}

TEST_F(Core_ExecutorFixture, ClaimRecomputesStaked)
{
  // Set balance just below auto-stake threshold, with a reward that
  // pushes it above.
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

  // Balance is now (AUTO_STAKE_THRESHOLD - 100) + 500 - 1, above the
  // threshold. staked should equal balance.
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

  // Only the fee left the balance. The stake is still held in the
  // validator record.
  EXPECT_EQ(balanceOf(alice_.publicKey), before - 2);

  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(5, v));
  EXPECT_EQ(v.pending_unbond_height,
            100 + UNBONDING_PERIOD); // run() uses height 100
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

  // Only the fee is taken.
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
  // The first unregister stamps pending_unbond_height. The second
  // must be rejected — otherwise a caller could reset the clock and
  // extend the slashable window indefinitely, or starve the stake
  // return.
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

  // Second attempt, different nonce so it passes the nonce check.
  EXPECT_EQ(run(make_unreg(1)).status, ReceiptStatus::Failure);

  // The stamp is unchanged.
  ASSERT_TRUE(state_->getValidator(5, v));
  EXPECT_EQ(v.pending_unbond_height, first_stamp);
}

TEST_F(Core_ExecutorFixture, UnregisterRejectsWhenAlreadyUnbonding)
{
  // Same as above but the pending_unbond_height is set directly, so
  // the test doesn't depend on the unregister path having run first.
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

  // The record is retained until the unbond expires. `run()` uses
  // height 100 by default, so the stamp is 100 + UNBONDING_PERIOD.
  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(5, v));
  EXPECT_EQ(v.pending_unbond_height,
            100u + UNBONDING_PERIOD);

  // The address index is retained too — otherwise an equivocation
  // proof landing between now and expiry couldn't resolve the signer.
  uint64_t id = 0;
  ASSERT_TRUE(state_->getValidatorByAddress(alice_.publicKey, id));
  EXPECT_EQ(id, 5u);
}

TEST_F(Core_ExecutorFixture, UnregisterRemovesFromActiveSet)
{
  // Set up: two named validators (Alice seed, Bob non-seed) plus
  // enough synthetic validators that removing Bob leaves the set at
  // exactly ACTIVE_SET_MIN, which is the floor.
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

  // Bob unregisters.
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

  // Bob's ID must not appear in the active set.
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
  EXPECT_EQ(ids.size(), GlobalConfig::ACTIVE_SET_MIN); // 2, the floor
}

TEST_F(Core_ExecutorFixture, UnregisterRejectsIfSetWouldDropBelowMin)
{
  // Set up: exactly ACTIVE_SET_MIN validators, all active. Removing
  // any one would drop below the minimum.
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

  // Alice (id=1) tries to unregister.
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

  // Old address no longer resolves.
  uint64_t id = 0;
  EXPECT_FALSE(state_->getValidatorByAddress(alice_.publicKey, id));

  // New address resolves to the same validator.
  ASSERT_TRUE(state_->getValidatorByAddress(bob_.publicKey, id));
  EXPECT_EQ(id, 5u);

  // The record itself reflects the new address.
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

  // Payload: [1] name_len=3, "Bar", [1] sym_len=0, [2] royalty=0
  std::vector<uint8_t> payload;
  payload.push_back(3);
  payload.insert(payload.end(), {'B', 'a', 'r'});
  payload.push_back(0); // symbol unchanged
  payload.push_back(0); // royalty low byte
  payload.push_back(0); // royalty high byte

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
  EXPECT_EQ(t.symbol, "GLD"); // unchanged
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaChangesSymbol)
{
  const Id token =
      createTokenDirect(alice_, "Gold", "GLD");

  std::vector<uint8_t> payload;
  payload.push_back(0); // name unchanged
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
  EXPECT_EQ(t.name, "Gold"); // unchanged
  EXPECT_EQ(t.symbol, "BAR");
}

TEST_F(Core_ExecutorFixture, UpdateTokenMetaChangesRoyalty)
{
  const Id token =
      createTokenDirect(alice_, "Gold", "GLD");

  std::vector<uint8_t> payload;
  payload.push_back(0);   // name unchanged
  payload.push_back(0);   // symbol unchanged
  payload.push_back(250); // royalty low byte (250 bps = 2.5%)
  payload.push_back(0);   // royalty high byte

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

  // All fields empty: name, symbol, royalty = 0
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

  // Symbol "AB" is too short (min is 3).
  std::vector<uint8_t> payload;
  payload.push_back(0); // name unchanged
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

  // A payload that only changes the name.
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
  EXPECT_EQ(t.maxSupply, 1000u); // unchanged
}

TEST_F(Core_ExecutorFixture, RemoveLastLiquidityClosesPool)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  //  Find Alice's position — the one created by createPool.
  uint64_t position_id = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id,
                                       position_id));

  AmmPosition pos_before;
  ASSERT_TRUE(state_->getAmmPosition(position_id, pos_before));
  ASSERT_GT(pos_before.liquidity, 0u);

  //  Alice removes her full share. She's the only LP, so the pool
  //  drains completely.
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

  //  The pool record must be gone. This is the auto-close.
  AmmPool pool;
  EXPECT_FALSE(state_->getAmmPool(pool_id, pool));
}

TEST_F(Core_ExecutorFixture, ClosedPoolRejectsSwap)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);

  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  uint64_t position_id = 0;
  ASSERT_TRUE(state_->getPositionIndex(alice_.publicKey, pool_id,
                                       position_id));

  //  Drain and close.
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

  //  A swap against the closed pool fails at the "pool not found"
  //  check, because getAmmPool returns false for a deleted record.
  //  This is what makes the close observable to users: the pool is
  //  not just inert, it's absent.
  Transaction swap = TransactionBuilder()
                         .type(TxType::Swap)
                         .from(alice_)
                         .to(alice_.publicKey)
                         .amount(10)
                         .fee(1)
                         .nonce(2)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeSwapPayload(pool_id, /*min_out=*/1))
                         .build();

  EXPECT_EQ(run(swap).status, ReceiptStatus::Failure);

  //  And so does adding liquidity to it.
  Transaction add = TransactionBuilder()
                        .type(TxType::AddLiquidity)
                        .from(alice_)
                        .to(Crypto::Address{})
                        .amount(500)
                        .fee(1)
                        .nonce(3)
                        .tokenId(NATIVE_TOKEN_ID)
                        .chainId(EXEC_CHAIN_ID)
                        .payload(makeAddLiquidityPayload(pool_id, 500))
                        .build();

  EXPECT_EQ(run(add).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, PartialRemovalDoesNotClosePool)
{
  const Id token_b = 100;
  state_->putTokenBalance(alice_.publicKey, token_b, 100'000);
  state_->putTokenBalance(bob_.publicKey, token_b, 100'000);

  //  Alice creates the pool.
  uint64_t pool_id = createPool(alice_, NATIVE_TOKEN_ID, 1000,
                                token_b, 1000);
  ASSERT_NE(pool_id, 0u);

  //  Bob adds liquidity. Now the pool has two LPs.
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::AddLiquidity)
                         .from(bob_)
                         .to(Crypto::Address{})
                         .amount(500)
                         .fee(1)
                         .nonce(0)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeAddLiquidityPayload(pool_id, 500))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  //  Alice removes her full share. Bob still has liquidity, so the
  //  pool has not drained.
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

  //  The pool record must still exist, with Bob's liquidity.
  AmmPool pool;
  ASSERT_TRUE(state_->getAmmPool(pool_id, pool));
  EXPECT_GT(pool.total_liquidity, 0u);
  EXPECT_GT(pool.reserve_a, 0u);
  EXPECT_GT(pool.reserve_b, 0u);

  //  And a swap should still succeed.
  Transaction swap = TransactionBuilder()
                         .type(TxType::Swap)
                         .from(alice_)
                         .to(alice_.publicKey)
                         .amount(10)
                         .fee(1)
                         .nonce(2)
                         .tokenId(NATIVE_TOKEN_ID)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(makeSwapPayload(pool_id, /*min_out=*/1))
                         .build();

  EXPECT_EQ(run(swap).status, ReceiptStatus::Success);
}