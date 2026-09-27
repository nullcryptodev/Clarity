// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Fixtures.h"
#include "Tests/Utils.h"

#include "Crypto/Ed25519.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/HdPath.h"
#include "Wallet/KeyStoreFormat.h"
#include "Wallet/LocalSigner.h"

using namespace Crypto;
using namespace Wallet;
using namespace Tests;

namespace fs = std::filesystem;

//  LocalSigner test suite.
//
//  All tests use a freshly-created keystore on a temp path. Most
//  tests use PBKDF2 for speed; one test exercises the Argon2 path.

namespace
{
  // A deterministic 32-byte hash for signing tests.
  Hash testHash(uint8_t seed = 0x42)
  {
    Hash h;
    for (size_t i = 0; i < 32; ++i)
      h.data[i] = uint8_t(seed + i);
    return h;
  }
} // namespace

//  Construction and readiness

TEST_F(Wallet_LocalSignerFixture, ConstructFromUnlockedKeystore)
{
  LocalSigner signer(ks());
  EXPECT_TRUE(signer.isReady());
}

TEST_F(Wallet_LocalSignerFixture, ConstructFromLockedKeystore)
{
  ks_->lock();
  LocalSigner signer(ks());
  EXPECT_FALSE(signer.isReady());
}

TEST_F(Wallet_LocalSignerFixture, NameIncludesKeystoreName)
{
  LocalSigner signer(ks());
  const std::string n = signer.name();
  EXPECT_NE(n.find("LocalSigner"), std::string::npos);
  EXPECT_NE(n.find(path_), std::string::npos);
}

//  Default registered keys
//
//  Construction registers the default account's receive and change
//  keys: (0, 0, 0) and (0, 1, 0).

TEST_F(Wallet_LocalSignerFixture, RegistersDefaultAccountKeys)
{
  LocalSigner signer(ks());
  auto keys = signer.publicKeys();
  EXPECT_EQ(keys.size(), 2u);
}

TEST_F(Wallet_LocalSignerFixture, DefaultKeysMatchDerivation)
{
  LocalSigner signer(ks());

  // Expected pubkeys.
  WalletStatus s1, s2;
  auto recv = ks_->derive(receivePath(0, 0), &s1);
  auto chg = ks_->derive(changePath(0, 0), &s2);
  ASSERT_TRUE(recv.has_value());
  ASSERT_TRUE(chg.has_value());

  auto keys = signer.publicKeys();
  auto has = [&](const PublicKey &pk)
  {
    for (const auto &k : keys)
      if (k == pk)
        return true;
    return false;
  };

  EXPECT_TRUE(has(recv->pubkey));
  EXPECT_TRUE(has(chg->pubkey));
}

//  registerPath

TEST_F(Wallet_LocalSignerFixture, RegisterPathReturnsPubkey)
{
  LocalSigner signer(ks());

  WalletStatus st;
  auto pk = signer.registerPath(clrtyPath(0, 0, 5), &st);
  ASSERT_TRUE(pk.has_value()) << walletErrorMessage(st.code);

  // Cross-check with direct derivation.
  WalletStatus st2;
  auto key = ks_->derive(clrtyPath(0, 0, 5), &st2);
  ASSERT_TRUE(key.has_value());
  EXPECT_EQ(*pk, key->pubkey);
}

TEST_F(Wallet_LocalSignerFixture, RegisterPathIsIdempotent)
{
  LocalSigner signer(ks());

  WalletStatus s1, s2;
  auto a = signer.registerPath(clrtyPath(0, 0, 5), &s1);
  auto b = signer.registerPath(clrtyPath(0, 0, 5), &s2);

  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(*a, *b);
  EXPECT_EQ(signer.publicKeys().size(), 3u); // default 2 + this one
}

TEST_F(Wallet_LocalSignerFixture, RegisterPathFailsWhenLocked)
{
  ks_->lock();
  LocalSigner signer(ks());

  WalletStatus st;
  auto pk = signer.registerPath(clrtyPath(0, 0, 5), &st);
  EXPECT_FALSE(pk.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreLocked);
}

//  registerAddressRange

TEST_F(Wallet_LocalSignerFixture, RegisterAddressRange)
{
  LocalSigner signer(ks());

  WalletStatus st;
  const size_t n = signer.registerAddressRange(0, 10, &st);
  EXPECT_EQ(n, 10u); // 10 successful registrations (one is a no-op)

  // 2 default keys (receive 0, change 0) + 9 new (receive 1..9).
  // receive 0 was already registered by the constructor, so the
  // range produces 9 new entries despite returning 10 successes.
  EXPECT_EQ(signer.publicKeys().size(), 11u);
}

TEST_F(Wallet_LocalSignerFixture, RegisterAddressRangeIsIdempotent)
{
  LocalSigner signer(ks());

  WalletStatus s1, s2;
  size_t n1 = signer.registerAddressRange(0, 10, &s1);
  size_t n2 = signer.registerAddressRange(0, 10, &s2);
  EXPECT_EQ(n1, 10u);
  EXPECT_EQ(n2, 10u);

  EXPECT_EQ(signer.publicKeys().size(), 11u);
}

TEST_F(Wallet_LocalSignerFixture, RegisterAddressRangeFailsWhenLocked)
{
  ks_->lock();
  LocalSigner signer(ks());

  WalletStatus st;
  const size_t n = signer.registerAddressRange(0, 10, &st);
  EXPECT_EQ(n, 0u);
}

TEST_F(Wallet_LocalSignerFixture, RegisterAddressRangeAccount1)
{
  LocalSigner signer(ks());

  WalletStatus st;
  const size_t n = signer.registerAddressRange(1, 5, &st);
  EXPECT_EQ(n, 5u);

  // Default 2 + 5 = 7.
  EXPECT_EQ(signer.publicKeys().size(), 7u);
}

//  sign — with registered key

TEST_F(Wallet_LocalSignerFixture, SignProducesVerifiableSignature)
{
  LocalSigner signer(ks());

  // Get the default receive pubkey.
  WalletStatus st;
  auto key = ks_->derive(receivePath(0, 0), &st);
  ASSERT_TRUE(key.has_value());

  const Hash h = testHash();

  WalletStatus s_st;
  auto sig = signer.sign(key->pubkey, h, &s_st);
  ASSERT_TRUE(sig.has_value()) << walletErrorMessage(s_st.code);

  EXPECT_TRUE(Crypto::verify(h, key->pubkey, *sig));
}

TEST_F(Wallet_LocalSignerFixture, SignIsDeterministic)
{
  LocalSigner signer(ks());

  WalletStatus st;
  auto key = ks_->derive(receivePath(0, 0), &st);
  ASSERT_TRUE(key.has_value());

  const Hash h = testHash();

  WalletStatus s1, s2;
  auto sig1 = signer.sign(key->pubkey, h, &s1);
  auto sig2 = signer.sign(key->pubkey, h, &s2);

  ASSERT_TRUE(sig1.has_value());
  ASSERT_TRUE(sig2.has_value());
  EXPECT_EQ(*sig1, *sig2);
}

TEST_F(Wallet_LocalSignerFixture, SignDifferentHashesProduceDifferentSignatures)
{
  LocalSigner signer(ks());

  WalletStatus st;
  auto key = ks_->derive(receivePath(0, 0), &st);
  ASSERT_TRUE(key.has_value());

  WalletStatus s1, s2;
  auto sig1 = signer.sign(key->pubkey, testHash(0x01), &s1);
  auto sig2 = signer.sign(key->pubkey, testHash(0x02), &s2);

  ASSERT_TRUE(sig1.has_value());
  ASSERT_TRUE(sig2.has_value());
  EXPECT_NE(*sig1, *sig2);
}

//  sign — unregistered key

TEST_F(Wallet_LocalSignerFixture, SignUnregisteredKeyFails)
{
  LocalSigner signer(ks());

  // Derive a key at (0, 0, 99) but don't register it.
  WalletStatus st;
  auto key = ks_->derive(clrtyPath(0, 0, 99), &st);
  ASSERT_TRUE(key.has_value());

  WalletStatus s_st;
  auto sig = signer.sign(key->pubkey, testHash(), &s_st);
  EXPECT_FALSE(sig.has_value());
  EXPECT_EQ(s_st.code, WalletError::KeyNotInStore);
}

TEST_F(Wallet_LocalSignerFixture, SignFailsWhenKeystoreLocked)
{
  LocalSigner signer(ks());

  WalletStatus st;
  auto key = ks_->derive(receivePath(0, 0), &st);
  ASSERT_TRUE(key.has_value());

  ks_->lock();

  WalletStatus s_st;
  auto sig = signer.sign(key->pubkey, testHash(), &s_st);
  EXPECT_FALSE(sig.has_value());
  EXPECT_EQ(s_st.code, WalletError::KeyStoreLocked);
}

//  signAtPath

TEST_F(Wallet_LocalSignerFixture, SignAtPathWorks)
{
  LocalSigner signer(ks());

  const HdPath path = clrtyPath(0, 0, 42);
  const Hash h = testHash(0x99);

  WalletStatus st;
  auto sig = signer.signAtPath(path, h, &st);
  ASSERT_TRUE(sig.has_value()) << walletErrorMessage(st.code);

  // Verify against the derived pubkey.
  WalletStatus d_st;
  auto key = ks_->derive(path, &d_st);
  ASSERT_TRUE(key.has_value());
  EXPECT_TRUE(Crypto::verify(h, key->pubkey, *sig));
}

TEST_F(Wallet_LocalSignerFixture, SignAtPathRegistersKey)
{
  LocalSigner signer(ks());

  const HdPath path = clrtyPath(0, 0, 42);
  ASSERT_EQ(signer.publicKeys().size(), 2u); // default only

  WalletStatus st;
  auto sig = signer.signAtPath(path, testHash(), &st);
  ASSERT_TRUE(sig.has_value());

  // After signing, the pubkey is now registered.
  EXPECT_EQ(signer.publicKeys().size(), 3u);

  // And a subsequent sign() with that pubkey works.
  WalletStatus d_st;
  auto key = ks_->derive(path, &d_st);
  ASSERT_TRUE(key.has_value());

  WalletStatus s2;
  auto sig2 = signer.sign(key->pubkey, testHash(), &s2);
  EXPECT_TRUE(sig2.has_value());
}

TEST_F(Wallet_LocalSignerFixture, SignAtPathFailsWhenLocked)
{
  LocalSigner signer(ks());
  ks_->lock();

  WalletStatus st;
  auto sig = signer.signAtPath(clrtyPath(0, 0, 42), testHash(), &st);
  EXPECT_FALSE(sig.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreLocked);
}

TEST_F(Wallet_LocalSignerFixture, SignAtPathConsistentWithSign)
{
  LocalSigner signer(ks());

  const HdPath path = clrtyPath(0, 0, 42);
  const Hash h = testHash();

  // Sign via signAtPath.
  WalletStatus s1;
  auto sig_path = signer.signAtPath(path, h, &s1);
  ASSERT_TRUE(sig_path.has_value());

  // Derive, register, sign via sign().
  WalletStatus d_st;
  auto key = ks_->derive(path, &d_st);
  ASSERT_TRUE(key.has_value());

  WalletStatus s2;
  auto sig_key = signer.sign(key->pubkey, h, &s2);
  ASSERT_TRUE(sig_key.has_value());

  EXPECT_EQ(*sig_path, *sig_key);
}

//  signBatch

TEST_F(Wallet_LocalSignerFixture, SignBatchAllSucceed)
{
  LocalSigner signer(ks());

  WalletStatus st;
  auto key = ks_->derive(receivePath(0, 0), &st);
  ASSERT_TRUE(key.has_value());

  std::vector<Hash> hashes = {
      testHash(0x01), testHash(0x02), testHash(0x03), testHash(0x04)};

  WalletStatus b_st;
  auto sigs = signer.signBatch(key->pubkey, hashes, &b_st);
  ASSERT_EQ(sigs.size(), hashes.size());

  for (size_t i = 0; i < hashes.size(); ++i)
  {
    ASSERT_TRUE(sigs[i].has_value()) << "hash " << i;
    EXPECT_TRUE(Crypto::verify(hashes[i], key->pubkey, *sigs[i]));
  }
}

TEST_F(Wallet_LocalSignerFixture, SignBatchEmptyInput)
{
  LocalSigner signer(ks());

  WalletStatus st;
  auto key = ks_->derive(receivePath(0, 0), &st);
  ASSERT_TRUE(key.has_value());

  WalletStatus b_st;
  auto sigs = signer.signBatch(key->pubkey, {}, &b_st);
  EXPECT_TRUE(sigs.empty());
}

TEST_F(Wallet_LocalSignerFixture, SignBatchStopsOnFailure)
{
  LocalSigner signer(ks());

  // Unregistered key: first sign fails immediately.
  WalletStatus st;
  auto key = ks_->derive(clrtyPath(0, 0, 99), &st);
  ASSERT_TRUE(key.has_value());

  std::vector<Hash> hashes = {testHash(0x01), testHash(0x02)};

  WalletStatus b_st;
  auto sigs = signer.signBatch(key->pubkey, hashes, &b_st);

  // First call fails, so the result is a single nullopt.
  ASSERT_EQ(sigs.size(), 1u);
  EXPECT_FALSE(sigs[0].has_value());
}

TEST_F(Wallet_LocalSignerFixture, SignBatchMatchesIndividual)
{
  LocalSigner signer(ks());

  WalletStatus st;
  auto key = ks_->derive(receivePath(0, 0), &st);
  ASSERT_TRUE(key.has_value());

  std::vector<Hash> hashes = {testHash(0x01), testHash(0x02), testHash(0x03)};

  WalletStatus b_st;
  auto batch = signer.signBatch(key->pubkey, hashes, &b_st);
  ASSERT_EQ(batch.size(), hashes.size());

  for (size_t i = 0; i < hashes.size(); ++i)
  {
    WalletStatus s_st;
    auto single = signer.sign(key->pubkey, hashes[i], &s_st);
    ASSERT_TRUE(single.has_value());
    ASSERT_TRUE(batch[i].has_value());
    EXPECT_EQ(*single, *batch[i]);
  }
}

//  Interoperability with the underlying key store

TEST_F(Wallet_LocalSignerFixture, KeyStoreAccessible)
{
  LocalSigner signer(ks());
  EXPECT_EQ(signer.keyStore().name(), ks_->name());
}

//  Ready state transitions

TEST_F(Wallet_LocalSignerFixture, ReadyAfterUnlock)
{
  ks_->lock();
  LocalSigner signer(ks());
  EXPECT_FALSE(signer.isReady());

  ASSERT_EQ(ks_->unlock(kPassword), WalletError::Ok);
  EXPECT_TRUE(signer.isReady());

  // And now we can register and sign.
  WalletStatus st;
  EXPECT_TRUE(signer.registerPath(clrtyPath(0, 0, 5), &st).has_value());
}

//  Multi-account

TEST_F(Wallet_LocalSignerFixture, MultipleAccountsSeparate)
{
  LocalSigner signer(ks());

  WalletStatus s1, s2;
  auto a = signer.registerPath(clrtyPath(0, 0, 0), &s1);
  auto b = signer.registerPath(clrtyPath(1, 0, 0), &s2);
  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());

  // Different accounts produce different keys.
  EXPECT_NE(*a, *b);

  // Both can be signed for.
  WalletStatus s3, s4;
  EXPECT_TRUE(signer.sign(*a, testHash(0x01), &s3).has_value());
  EXPECT_TRUE(signer.sign(*b, testHash(0x01), &s4).has_value());
}