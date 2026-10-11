// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Fixtures.h"

#include "Core/KeyRotation.h"

using namespace Core;
using namespace Tests;

// =================================================================
//  KeyRotation codec
// =================================================================

TEST(Core_KeyRotationCodec, EmptyRoundTrip)
{
  std::vector<KeyRotation> in;
  auto bytes = encodeKeyHistory(in);
  ASSERT_EQ(bytes.size(), 4u);

  std::vector<KeyRotation> out;
  ASSERT_TRUE(decodeKeyHistory(bytes.data(), bytes.size(), out));
  ASSERT_TRUE(out.empty());
}

TEST(Core_KeyRotationCodec, SingleEntryRoundTrip)
{
  KeyRotation e;
  e.key.data[0] = 0xAB;
  e.valid_from_height = 100;
  e.valid_until_height = 0;

  std::vector<KeyRotation> in{e};
  auto bytes = encodeKeyHistory(in);
  ASSERT_EQ(bytes.size(), 4u + KEY_ROTATION_WIRE_SIZE);

  std::vector<KeyRotation> out;
  ASSERT_TRUE(decodeKeyHistory(bytes.data(), bytes.size(), out));
  ASSERT_EQ(out.size(), 1u);
  ASSERT_EQ(out[0].key, e.key);
  ASSERT_EQ(out[0].valid_from_height, 100u);
  ASSERT_EQ(out[0].valid_until_height, 0u);
}

TEST(Core_KeyRotationCodec, MultiEntryRoundTrip)
{
  std::vector<KeyRotation> in;
  for (int i = 0; i < 3; ++i)
  {
    KeyRotation e;
    e.key.data[0] = uint8_t(i + 1);
    e.valid_from_height = 100 * (i + 1);
    e.valid_until_height = 0;
    if (i < 2)
      e.valid_until_height = 100 * (i + 2);
    in.push_back(e);
  }

  auto bytes = encodeKeyHistory(in);
  std::vector<KeyRotation> out;
  ASSERT_TRUE(decodeKeyHistory(bytes.data(), bytes.size(), out));
  ASSERT_EQ(out.size(), 3u);
  for (size_t i = 0; i < in.size(); ++i)
  {
    ASSERT_EQ(out[i].key, in[i].key);
    ASSERT_EQ(out[i].valid_from_height, in[i].valid_from_height);
    ASSERT_EQ(out[i].valid_until_height, in[i].valid_until_height);
  }
}

TEST(Core_KeyRotationCodec, RejectsTruncated)
{
  KeyRotation e;
  std::vector<KeyRotation> in{e};
  auto bytes = encodeKeyHistory(in);

  std::vector<KeyRotation> out;
  ASSERT_FALSE(decodeKeyHistory(bytes.data(), bytes.size() - 1, out));
}

TEST(Core_KeyRotationCodec, RejectsTrailingBytes)
{
  KeyRotation e;
  std::vector<KeyRotation> in{e};
  auto bytes = encodeKeyHistory(in);
  bytes.push_back(0x00);

  std::vector<KeyRotation> out;
  ASSERT_FALSE(decodeKeyHistory(bytes.data(), bytes.size(), out));
}

TEST(Core_KeyRotationCodec, RejectsAbsurdCount)
{
  uint8_t buf[4] = {0xFF, 0xFF, 0xFF, 0xFF};
  std::vector<KeyRotation> out;
  ASSERT_FALSE(decodeKeyHistory(buf, sizeof(buf), out));
}

// =================================================================
//  StateAccess lookups
// =================================================================

TEST_F(Core_ExecutorFixture, ValidatorKeyAtHeightSingleEntry)
{
  seedValidator(alice_, /*id=*/5);
  bumpNextValidatorId(6);

  std::vector<KeyRotation> history;
  KeyRotation entry;
  entry.key = alice_.publicKey;
  entry.valid_from_height = 1;
  entry.valid_until_height = 0;
  history.push_back(entry);

  state_->putValidatorKeyHistory(5, history);

  auto k1 = state_->validatorKeyAtHeight(5, 1);
  ASSERT_TRUE(k1.has_value());
  ASSERT_EQ(*k1, alice_.publicKey);

  auto k2 = state_->validatorKeyAtHeight(5, 1000);
  ASSERT_TRUE(k2.has_value());
  ASSERT_EQ(*k2, alice_.publicKey);

  auto k3 = state_->validatorKeyAtHeight(5, 0);
  ASSERT_FALSE(k3.has_value())
      << "height before valid_from_height should have no key";
}

TEST_F(Core_ExecutorFixture, ValidatorKeyAtHeightMultiEntry)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  Crypto::KeyPair k1 = Crypto::generateKeyPair();
  Crypto::KeyPair k2 = Crypto::generateKeyPair();
  Crypto::KeyPair k3 = Crypto::generateKeyPair();

  std::vector<KeyRotation> history;
  history.push_back({k1.publicKey, 1, 100});
  history.push_back({k2.publicKey, 100, 200});
  history.push_back({k3.publicKey, 200, 0});

  state_->putValidatorKeyHistory(5, history);

  //  Height 50 is in [1, 100) → k1.
  auto a = state_->validatorKeyAtHeight(5, 50);
  ASSERT_TRUE(a.has_value());
  ASSERT_EQ(*a, k1.publicKey);

  //  Height 100 is the boundary, in [100, 200) → k2.
  auto b = state_->validatorKeyAtHeight(5, 100);
  ASSERT_TRUE(b.has_value());
  ASSERT_EQ(*b, k2.publicKey);

  //  Height 199 is in [100, 200) → k2.
  auto c = state_->validatorKeyAtHeight(5, 199);
  ASSERT_TRUE(c.has_value());
  ASSERT_EQ(*c, k2.publicKey);

  //  Height 200 is the boundary, in [200, 0) → k3.
  auto d = state_->validatorKeyAtHeight(5, 200);
  ASSERT_TRUE(d.has_value());
  ASSERT_EQ(*d, k3.publicKey);

  //  Height beyond 200 is still k3.
  auto e = state_->validatorKeyAtHeight(5, 10'000);
  ASSERT_TRUE(e.has_value());
  ASSERT_EQ(*e, k3.publicKey);
}

TEST_F(Core_ExecutorFixture, ValidatorKeyAtHeightNoHistoryFallsBackToRecord)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  //  No history written. The fallback should resolve to the
  //  record's effectiveConsensusKey, which for a record created
  //  by seedValidator is the reward_address (== alice_.publicKey).
  auto k = state_->validatorKeyAtHeight(5, 100);
  ASSERT_TRUE(k.has_value());
  ASSERT_EQ(*k, alice_.publicKey);
}

TEST_F(Core_ExecutorFixture, ValidatorKeyAtHeightUnknownValidator)
{
  auto k = state_->validatorKeyAtHeight(999, 100);
  ASSERT_FALSE(k.has_value());
}

// =================================================================
//  RotateConsensusKey transaction
// =================================================================

TEST_F(Core_ExecutorFixture, RotateConsensusKeySucceeds)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  Crypto::KeyPair new_key = Crypto::generateKeyPair();

  //  Build a signed RotateConsensusKey transaction.
  Transaction tx = TransactionBuilder()
                       .type(TxType::RotateConsensusKey)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(
                           new_key.publicKey.data.begin(),
                           new_key.publicKey.data.end()))
                       .build();

  Receipt r = run(tx);
  ASSERT_EQ(r.status, ReceiptStatus::Success);

  ValidatorInfo v;
  ASSERT_TRUE(state_->getValidator(5, v));
  ASSERT_EQ(v.consensus_key, new_key.publicKey);

  std::vector<KeyRotation> history;
  ASSERT_TRUE(state_->getValidatorKeyHistory(5, history));
  ASSERT_EQ(history.size(), 2u);

  //  The first entry is now sealed at the rotation height.
  ASSERT_EQ(history[0].valid_from_height, 1u);
  ASSERT_EQ(history[0].valid_until_height, 100u); // run() height

  //  The second entry is the new key.
  ASSERT_EQ(history[1].key, new_key.publicKey);
  ASSERT_EQ(history[1].valid_from_height, 100u);
  ASSERT_EQ(history[1].valid_until_height, 0u);

  //  Lookup by height works.
  auto old = state_->validatorKeyAtHeight(5, 50);
  ASSERT_TRUE(old.has_value());
  ASSERT_EQ(*old, alice_.publicKey);

  auto fresh = state_->validatorKeyAtHeight(5, 100);
  ASSERT_TRUE(fresh.has_value());
  ASSERT_EQ(*fresh, new_key.publicKey);
}

TEST_F(Core_ExecutorFixture, RotateConsensusKeyRejectsNonOwner)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  Crypto::KeyPair new_key = Crypto::generateKeyPair();

  Transaction tx = TransactionBuilder()
                       .type(TxType::RotateConsensusKey)
                       .from(bob_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(
                           new_key.publicKey.data.begin(),
                           new_key.publicKey.data.end()))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RotateConsensusKeyRejectsSameKey)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  Transaction tx = TransactionBuilder()
                       .type(TxType::RotateConsensusKey)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(
                           alice_.publicKey.data.begin(),
                           alice_.publicKey.data.end()))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RotateConsensusKeyRejectsWrongPayloadSize)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  Transaction tx = TransactionBuilder()
                       .type(TxType::RotateConsensusKey)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(16, 0xAA))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RotateConsensusKeyRejectsNullKey)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  Transaction tx = TransactionBuilder()
                       .type(TxType::RotateConsensusKey)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(32, 0))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RotateConsensusKeyRejectsUnbonding)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  {
    ValidatorInfo v;
    ASSERT_TRUE(state_->getValidator(5, v));
    v.pending_unbond_height = 500;
    state_->putValidator(v);
  }

  Crypto::KeyPair new_key = Crypto::generateKeyPair();

  Transaction tx = TransactionBuilder()
                       .type(TxType::RotateConsensusKey)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(
                           new_key.publicKey.data.begin(),
                           new_key.publicKey.data.end()))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RotateConsensusKeyRejectsUnknownValidator)
{
  Crypto::KeyPair new_key = Crypto::generateKeyPair();

  Transaction tx = TransactionBuilder()
                       .type(TxType::RotateConsensusKey)
                       .from(alice_)
                       .to(Crypto::Address{})
                       .amount(1)
                       .fee(1)
                       .nonce(0)
                       .chainId(EXEC_CHAIN_ID)
                       .payload(std::vector<uint8_t>(
                           new_key.publicKey.data.begin(),
                           new_key.publicKey.data.end()))
                       .build();

  EXPECT_EQ(run(tx).status, ReceiptStatus::Failure);
}

TEST_F(Core_ExecutorFixture, RotateConsensusKeyTwiceAppendsTwoEntries)
{
  seedValidator(alice_, 5);
  bumpNextValidatorId(6);

  Crypto::KeyPair key_a = Crypto::generateKeyPair();
  Crypto::KeyPair key_b = Crypto::generateKeyPair();

  //  First rotation.
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::RotateConsensusKey)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(0)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(std::vector<uint8_t>(
                             key_a.publicKey.data.begin(),
                             key_a.publicKey.data.end()))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  //  Second rotation.
  {
    Transaction tx = TransactionBuilder()
                         .type(TxType::RotateConsensusKey)
                         .from(alice_)
                         .to(Crypto::Address{})
                         .amount(1)
                         .fee(1)
                         .nonce(1)
                         .chainId(EXEC_CHAIN_ID)
                         .payload(std::vector<uint8_t>(
                             key_b.publicKey.data.begin(),
                             key_b.publicKey.data.end()))
                         .build();
    ASSERT_EQ(run(tx).status, ReceiptStatus::Success);
  }

  std::vector<KeyRotation> history;
  ASSERT_TRUE(state_->getValidatorKeyHistory(5, history));
  ASSERT_EQ(history.size(), 3u);

  //  First entry: alice, [1, 100).
  ASSERT_EQ(history[0].key, alice_.publicKey);
  ASSERT_EQ(history[0].valid_from_height, 1u);
  ASSERT_EQ(history[0].valid_until_height, 100u);

  //  Second entry: key_a, [100, 100). Wait — both rotations
  //  happen at height 100 because run() defaults to 100. That's
  //  a corner case: two rotations in one block. The gapless
  //  invariant is preserved by the append: the second entry
  //  gets sealed at height 100 and the third starts at 100, so
  //  the range [100, 100) is empty. That's a zero-width interval
  //  in the middle of the history, which is fine — the height
  //  never falls in it.
  //
  //  In practice two rotations in the same block would be two
  //  transactions in the same block, which the block processor
  //  handles sequentially. The history is still well-formed.
  ASSERT_EQ(history[1].key, key_a.publicKey);
  ASSERT_EQ(history[1].valid_from_height, 100u);
  ASSERT_EQ(history[1].valid_until_height, 100u);

  //  Third entry: key_b, current.
  ASSERT_EQ(history[2].key, key_b.publicKey);
  ASSERT_EQ(history[2].valid_from_height, 100u);
  ASSERT_EQ(history[2].valid_until_height, 0u);

  //  Lookup by height: at 100, the general-case scan finds the
  //  first entry whose range contains 100. history[0] has
  //  until=100, so 100 is NOT in it. history[1] has from=100,
  //  until=100, so 100 is NOT in it either. history[2] has
  //  from=100, until=0, so 100 IS in it. The lookup returns
  //  key_b.
  auto k = state_->validatorKeyAtHeight(5, 100);
  ASSERT_TRUE(k.has_value());
  ASSERT_EQ(*k, key_b.publicKey);
}