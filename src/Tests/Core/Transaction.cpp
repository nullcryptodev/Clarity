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

TEST(Transaction, WellFormedBaseline)
{
  EXPECT_TRUE(makeTx().isWellFormed());
}

TEST(Transaction, RejectsWrongVersion)
{
  Transaction tx = makeTx();
  tx.version = 999;
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Transaction, RejectsZeroChainId)
{
  Transaction tx = makeTx();
  tx.chain_id = 0;
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Transaction, RejectsInvalidTxType)
{
  Transaction tx = makeTx();
  tx.tx_type = TxType::Invalid;
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Transaction, RejectsNullSender)
{
  Transaction tx = makeTx();
  tx.from = Crypto::Address{};
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Transaction, RejectsOversizePayload)
{
  Transaction tx = makeTx();
  tx.payload.assign(TX_MAX_PAYLOAD_SIZE + 1, 0xAA);
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Transaction, AcceptsMaxSizePayload)
{
  Transaction tx = makeTx();
  tx.payload.assign(TX_MAX_PAYLOAD_SIZE, 0xAA);
  EXPECT_TRUE(tx.isWellFormed());
}

TEST(Transaction, RejectsCompletelyEmpty)
{
  Transaction tx = makeTx();
  tx.amount = 0;
  tx.fee = 0;
  tx.payload.clear();
  EXPECT_FALSE(tx.isWellFormed());
}

TEST(Transaction, AcceptsZeroAmountWithFee)
{
  Transaction tx = makeTx();
  tx.amount = 0;
  tx.fee = 500;
  EXPECT_TRUE(tx.isWellFormed());
}

// Serialization round-trip

TEST(Transaction, SerializeRoundTrip)
{
  Transaction original = makeTx();
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

TEST(Transaction, SerializeEmptyPayloadRoundTrip)
{
  Transaction original = makeTx();
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

TEST(Transaction, SerializeDeterministic)
{
  Transaction tx = makeTx();
  tx.payload = {0xAA, 0xBB, 0xCC};

  auto a = tx.serialize();
  auto b = tx.serialize();
  EXPECT_EQ(a, b);
}

TEST(Transaction, DeserializeRejectsTruncated)
{
  Transaction tx = makeTx();
  auto bytes = tx.serialize();

  // Truncate at various points and confirm deserialization fails.
  for (size_t len : {size_t(5), size_t(20), size_t(100), bytes.size() - 1})
  {
    Transaction restored;
    EXPECT_FALSE(Transaction::deserialize(bytes.data(), len, restored))
        << "should fail at len=" << len;
  }
}

TEST(Transaction, SerializedSizeMatchesActual)
{
  Transaction tx = makeTx();
  tx.payload = {1, 2, 3, 4, 5};

  EXPECT_EQ(tx.serialize().size(), tx.serializedSize());
}

// Hash / signing

TEST(Transaction, SigningHashExcludesSignature)
{
  Transaction tx1 = makeTx();
  Transaction tx2 = makeTx();

  // Same everything except signature.
  tx1.signature = Crypto::Signature{};
  for (size_t i = 0; i < 64; ++i)
    tx2.signature.data[i] = 0xAA;

  EXPECT_EQ(tx1.signingHash().toString(), tx2.signingHash().toString());
}

TEST(Transaction, SigningHashCoversAllFields)
{
  Transaction tx1 = makeTx();
  Crypto::Hash h1 = tx1.signingHash();

  // Change one field.
  Transaction tx2 = tx1;
  tx2.amount += 1;

  EXPECT_NE(h1.toString(), tx2.signingHash().toString());
}

TEST(Transaction, SigningHashDeterministic)
{
  Transaction tx = makeTx();
  EXPECT_EQ(tx.signingHash().toString(), tx.signingHash().toString());
}

TEST(Transaction, TxidEqualsSigningHash)
{
  Transaction tx = makeTx();
  EXPECT_EQ(tx.txid().toString(), tx.signingHash().toString());
}

TEST(Transaction, RealSignatureValidates)
{
  // Generate a keypair, use it as sender.
  Crypto::KeyPair kp = Crypto::generateKeyPair();

  Transaction tx = makeTx();
  tx.from = kp.publicKey;

  // Sign the signing hash.
  Crypto::Hash sighash = tx.signingHash();
  tx.signature = Crypto::sign(sighash, kp.secretKey);

  // Verify.
  EXPECT_TRUE(Crypto::verify(sighash, kp.publicKey, tx.signature));
}

TEST(Transaction, RealSignatureRejectsTamperedTx)
{
  Crypto::KeyPair kp = Crypto::generateKeyPair();

  Transaction tx = makeTx();
  tx.from = kp.publicKey;

  Crypto::Hash sighash = tx.signingHash();
  tx.signature = Crypto::sign(sighash, kp.secretKey);

  // Tamper with the amount after signing.
  tx.amount += 1;

  Crypto::Hash new_sighash = tx.signingHash();
  EXPECT_FALSE(Crypto::verify(new_sighash, kp.publicKey, tx.signature));
}

// TxTypes helpers

TEST(TxTypes, UserSubmittedClassification)
{
  EXPECT_TRUE(isUserSubmitted(TxType::Transfer));
  EXPECT_TRUE(isUserSubmitted(TxType::CreateToken));
  EXPECT_TRUE(isUserSubmitted(TxType::Swap));
  EXPECT_FALSE(isUserSubmitted(TxType::BlockReward));
  EXPECT_FALSE(isUserSubmitted(TxType::OrderExpired));
  EXPECT_FALSE(isUserSubmitted(TxType::Slash));
  EXPECT_FALSE(isUserSubmitted(TxType::Invalid));
}

TEST(TxTypes, SystemTxClassification)
{
  EXPECT_TRUE(isSystemTx(TxType::BlockReward));
  EXPECT_TRUE(isSystemTx(TxType::OrderExpired));
  EXPECT_TRUE(isSystemTx(TxType::Slash));
  EXPECT_FALSE(isSystemTx(TxType::Transfer));
  EXPECT_FALSE(isSystemTx(TxType::Invalid));
}

TEST(TxTypes, NameLookup)
{
  EXPECT_EQ(txTypeName(TxType::Transfer), "transfer");
  EXPECT_EQ(txTypeName(TxType::Swap), "swap");
  EXPECT_EQ(txTypeName(TxType::CreateToken), "create-token");
  EXPECT_EQ(txTypeName(TxType::Invalid), "invalid");
}

// Copy semantics

TEST(Transaction, CopyIsIndependent)
{
  Transaction original = makeTx();
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