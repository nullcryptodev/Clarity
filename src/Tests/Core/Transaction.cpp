// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Core/Transaction.h"
#include "Core/TransactionTypes.h"
#include "Crypto/Ed25519.h"

using namespace Core;
using namespace Tests;

// Well-formedness

TEST(Core_Transaction, WellFormedBaseline)
{
  EXPECT_TRUE(makeTransaction().isWellFormed());
}

TEST(Core_Transaction, RejectsWrongVersion)
{
  Transaction tx = makeTransaction();
  tx.version = 999;
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Core_Transaction, RejectsZeroChainId)
{
  Transaction tx = makeTransaction();
  tx.chain_id = 0;
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Core_Transaction, RejectsInvalidTxType)
{
  Transaction tx = makeTransaction();
  tx.tx_type = TxType::Invalid;
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Core_Transaction, RejectsNullSender)
{
  Transaction tx = makeTransaction();
  tx.from = Crypto::Address{};
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Core_Transaction, RejectsOversizePayload)
{
  Transaction tx = makeTransaction();
  tx.payload.assign(TX_MAX_PAYLOAD_SIZE + 1, 0xAA);
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Core_Transaction, AcceptsMaxSizePayload)
{
  Transaction tx = makeTransaction();
  tx.payload.assign(TX_MAX_PAYLOAD_SIZE, 0xAA);
  EXPECT_TRUE(tx.isWellFormed());
}

TEST(Core_Transaction, RejectsCompletelyEmpty)
{
  Transaction tx = makeTransaction();
  tx.amount = 0;
  tx.fee = 0;
  tx.payload.clear();
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Core_Transaction, AcceptsZeroAmountWithFee)
{
  Transaction tx = makeTransaction();
  tx.amount = 0;
  tx.fee = 500;
  EXPECT_TRUE(tx.isWellFormed());
}

// Serialization round-trip

TEST(Core_Transaction, SerializeRoundTrip)
{
  Transaction original = makeTransaction();
  original.payload = {0x01, 0x02, 0x03, 0x04, 0x05};

  // Fill the signature with test bytes so serialization covers it.
  for (size_t i = 0; i < 64; ++i)
  {
    original.signature.data[i] = static_cast<uint8_t>(i);
  }

  auto bytes = original.serialize();
  ASSERT_FALSE(bytes.empty());

  Transaction restored;
  ASSERT_TRUE(Transaction::deserialize(bytes.data(), bytes.size(), restored));

  EXPECT_EQ(restored.version, original.version);
  EXPECT_EQ(restored.chain_id, original.chain_id);
  EXPECT_EQ(restored.tx_type, original.tx_type);
  EXPECT_EQ(restored.nonce, original.nonce);
  EXPECT_EQ(restored.valid_until_height, original.valid_until_height);
  EXPECT_EQ(restored.from.toString(), original.from.toString());
  EXPECT_EQ(restored.to.toString(), original.to.toString());
  EXPECT_EQ(restored.token_id, original.token_id);
  EXPECT_EQ(restored.amount, original.amount);
  EXPECT_EQ(restored.fee, original.fee);
  EXPECT_EQ(restored.payload, original.payload);
  EXPECT_EQ(restored.signature.toString(), original.signature.toString());
}

TEST(Core_Transaction, SerializeEmptyPayloadRoundTrip)
{
  Transaction original = makeTransaction();
  original.payload.clear();

  for (size_t i = 0; i < 64; ++i)
  {
    original.signature.data[i] = 0xAB;
  }

  auto bytes = original.serialize();
  Transaction restored;
  ASSERT_TRUE(Transaction::deserialize(bytes.data(), bytes.size(), restored));

  EXPECT_TRUE(restored.payload.empty());
  EXPECT_EQ(restored.signature.toString(), original.signature.toString());
}

TEST(Core_Transaction, SerializeDeterministic)
{
  Transaction tx = makeTransaction();
  tx.payload = {0xAA, 0xBB, 0xCC};

  auto a = tx.serialize();
  auto b = tx.serialize();
  EXPECT_EQ(a, b);
}

TEST(Core_Transaction, DeserializeRejectsTruncated)
{
  Transaction tx = makeTransaction();
  auto bytes = tx.serialize();

  // Truncate at various points and confirm deserialization fails.
  for (size_t len : {size_t(5), size_t(20), size_t(100), bytes.size() - 1})
  {
    Transaction restored;
    EXPECT_FALSE(Transaction::deserialize(bytes.data(), len, restored))
        << "should fail at len=" << len;
  }
}

TEST(Core_Transaction, SerializedSizeMatchesActual)
{
  Transaction tx = makeTransaction();
  tx.payload = {1, 2, 3, 4, 5};

  EXPECT_EQ(tx.serialize().size(), tx.serializedSize());
}

// Hash / signing

TEST(Core_Transaction, SigningHashExcludesSignature)
{
  Transaction tx1 = makeTransaction();
  Transaction tx2 = makeTransaction();

  // Same everything except signature.
  tx1.signature = Crypto::Signature{};
  for (size_t i = 0; i < 64; ++i)
    tx2.signature.data[i] = 0xAA;

  EXPECT_EQ(tx1.signingHash().toString(), tx2.signingHash().toString());
}

TEST(Core_Transaction, SigningHashCoversAllFields)
{
  Transaction tx1 = makeTransaction();
  Crypto::Hash h1 = tx1.signingHash();

  // Change one field.
  Transaction tx2 = tx1;
  tx2.amount += 1;

  EXPECT_NE(h1.toString(), tx2.signingHash().toString());
}

TEST(Core_Transaction, SigningHashDeterministic)
{
  Transaction tx = makeTransaction();
  EXPECT_EQ(tx.signingHash().toString(), tx.signingHash().toString());
}

TEST(Core_Transaction, TxidEqualsSigningHash)
{
  Transaction tx = makeTransaction();
  EXPECT_EQ(tx.txid().toString(), tx.signingHash().toString());
}

TEST(Core_Transaction, RealSignatureValidates)
{
  // Generate a keypair, use it as sender.
  Crypto::KeyPair kp = Crypto::generateKeyPair();

  Transaction tx = makeTransaction();
  tx.from = kp.publicKey;

  // Sign the signing hash.
  Crypto::Hash sighash = tx.signingHash();
  tx.signature = Crypto::sign(sighash, kp.secretKey);

  // Verify.
  EXPECT_TRUE(Crypto::verify(sighash, kp.publicKey, tx.signature));
}

TEST(Core_Transaction, RealSignatureRejectsTamperedTx)
{
  Crypto::KeyPair kp = Crypto::generateKeyPair();

  Transaction tx = makeTransaction();
  tx.from = kp.publicKey;

  Crypto::Hash sighash = tx.signingHash();
  tx.signature = Crypto::sign(sighash, kp.secretKey);

  // Tamper with the amount after signing.
  tx.amount += 1;

  Crypto::Hash new_sighash = tx.signingHash();
  EXPECT_FALSE(Crypto::verify(new_sighash, kp.publicKey, tx.signature));
}

// TxTypes helpers

TEST(Core_TxTypes, UserSubmittedClassification)
{
  EXPECT_TRUE(isUserSubmitted(TxType::Transfer));
  EXPECT_TRUE(isUserSubmitted(TxType::CreateToken));
  EXPECT_TRUE(isUserSubmitted(TxType::Swap));
  EXPECT_FALSE(isUserSubmitted(TxType::BlockReward));
  EXPECT_FALSE(isUserSubmitted(TxType::OrderExpired));
  EXPECT_FALSE(isUserSubmitted(TxType::Slash));
  EXPECT_FALSE(isUserSubmitted(TxType::Invalid));
}

TEST(Core_TxTypes, SystemTxClassification)
{
  EXPECT_TRUE(isSystemTx(TxType::BlockReward));
  EXPECT_TRUE(isSystemTx(TxType::OrderExpired));
  EXPECT_TRUE(isSystemTx(TxType::Slash));
  EXPECT_FALSE(isSystemTx(TxType::Transfer));
  EXPECT_FALSE(isSystemTx(TxType::Invalid));
}

TEST(Core_TxTypes, NameLookup)
{
  EXPECT_EQ(txTypeName(TxType::Transfer), "transfer");
  EXPECT_EQ(txTypeName(TxType::Swap), "swap");
  EXPECT_EQ(txTypeName(TxType::CreateToken), "create-token");
  EXPECT_EQ(txTypeName(TxType::Invalid), "invalid");
}

// Copy semantics

TEST(Core_Transaction, CopyIsIndependent)
{
  Transaction original = makeTransaction();
  original.payload = {1, 2, 3};
  original.amount = 42;

  Transaction copy = original;

  copy.amount = 100;
  copy.payload.push_back(4);

  EXPECT_EQ(original.amount, 42u);
  EXPECT_EQ(original.payload.size(), 3u);
  EXPECT_EQ(copy.amount, 100u);
  EXPECT_EQ(copy.payload.size(), 4u);
}