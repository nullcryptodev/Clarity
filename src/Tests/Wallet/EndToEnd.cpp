// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Ed25519.h"
#include "Wallet/AddressCodec.h"
#include "Wallet/Bip39.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/HdPath.h"
#include "Wallet/KeyDerivation.h"
#include "Wallet/KeyStoreFormat.h"
#include "Wallet/LocalSigner.h"

using namespace Crypto;
using namespace Wallet;

namespace fs = std::filesystem;

//  End-to-end integration tests.
//
//  These tests exercise every module in the wallet stack together:
//
//    Bip39          mnemonic <-> entropy, seed derivation
//    Slip10         master node from seed, path derivation
//    KeyDerivation  SeedMaterial orchestration
//    EncryptedKeyStore  encryption, persistence, unlock
//    AddressCodec   bech32m address encoding
//    LocalSigner    signing with registered keys
//    Crypto::Ed25519  signature production and verification
//
//  If a test in this file passes, the wallet backend is functional.

namespace
{
  std::string tempPath()
  {
    static int counter = 0;
    return (fs::temp_directory_path() /
            ("clrty_e2e_" + std::to_string(::getpid()) + "_" +
             std::to_string(counter++) + ".json"))
        .string();
  }

  struct TempCleanup
  {
    std::string path;
    TempCleanup(std::string p) : path(std::move(p)) {}
    ~TempCleanup()
    {
      std::error_code ec;
      fs::remove(path, ec);
      fs::remove(path + ".tmp", ec);
    }
  };

  Hash testHash(uint8_t seed = 0x42)
  {
    Hash h;
    for (size_t i = 0; i < 32; ++i)
      h.data[i] = uint8_t(seed + i);
    return h;
  }

  std::string readFile(const std::string &path)
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
  }
} // namespace

//  Basic lifecycle

TEST(Wallet_EndToEnd, BasicWalletLifecycle)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  const std::string password = "hunter2";

  // ---- Step 1: Create ----

  std::string mnemonic;
  WalletStatus create_st;
  auto ks = EncryptedKeyStore::create(
      path, password, Network::Mainnet, 256, mnemonic,
      KDF_PBKDF2_HMAC_SHA512, &create_st);
  ASSERT_TRUE(ks.has_value())
      << "create failed: " << walletErrorMessage(create_st.code);

  ASSERT_EQ(validateMnemonic(mnemonic), WalletError::Ok);
  ASSERT_TRUE((*ks)->isUnlocked());

  const std::string address = (*ks)->address();
  ASSERT_FALSE(address.empty());
  EXPECT_EQ(address.substr(0, 6), "clrty1");
  EXPECT_TRUE(isPlausibleAddress(address));

  // ---- Step 2: Derive the default key ----

  WalletStatus d1;
  auto key1 = (*ks)->derive(clrtyPath(0, 0, 0), &d1);
  ASSERT_TRUE(key1.has_value()) << walletErrorMessage(d1.code);

  const auto decoded = decodeAddressAnyNetwork(address);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->address, key1->pubkey);
  EXPECT_EQ(decoded->network, Network::Mainnet);

  // ---- Step 3: Lock and forget the in-memory keystore ----

  (*ks)->lock();
  EXPECT_FALSE((*ks)->isUnlocked());
  ks.reset();

  // ---- Step 4: Reopen from disk ----

  WalletStatus open_st;
  auto reopened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(reopened.has_value())
      << "open failed: " << walletErrorMessage(open_st.code);
  EXPECT_FALSE((*reopened)->isUnlocked());

  // ---- Step 5: Unlock ----

  EXPECT_EQ((*reopened)->unlock(password), WalletError::Ok);
  ASSERT_TRUE((*reopened)->isUnlocked());

  // ---- Step 6: Derive the same key ----

  WalletStatus d2;
  auto key2 = (*reopened)->derive(clrtyPath(0, 0, 0), &d2);
  ASSERT_TRUE(key2.has_value());

  EXPECT_EQ(key1->pubkey, key2->pubkey);
  EXPECT_EQ(key1->secret, key2->secret);

  // ---- Step 7: Sign with the signer ----

  // LocalSigner takes a KeyStore&. `**reopened` dereferences the
  // optional then the unique_ptr, producing the reference.
  LocalSigner signer(**reopened);
  ASSERT_TRUE(signer.isReady());

  const Hash h = testHash();

  WalletStatus s_st;
  auto sig = signer.sign(key2->pubkey, h, &s_st);
  ASSERT_TRUE(sig.has_value()) << walletErrorMessage(s_st.code);

  // ---- Step 8: Verify ----

  EXPECT_TRUE(Crypto::verify(h, key2->pubkey, *sig));
}

//  Full wallet workflow

TEST(Wallet_EndToEnd, FullWalletWorkflow)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  const std::string password_v1 = "first-password";
  const std::string password_v2 = "second-password";

  // ---- Step 1: Create a fresh keystore ----

  std::string mnemonic;
  WalletStatus create_st;
  auto ks = EncryptedKeyStore::create(
      path, password_v1, Network::Mainnet, 256, mnemonic,
      KDF_PBKDF2_HMAC_SHA512, &create_st);
  ASSERT_TRUE(ks.has_value())
      << "create failed: " << walletErrorMessage(create_st.code);

  const std::string address_v1 = (*ks)->address();
  const auto fingerprint_v1 = (*ks)->fingerprint();
  const std::string id_v1 = (*ks)->id();

  // ---- Step 2: Save the mnemonic ----

  ASSERT_EQ(validateMnemonic(mnemonic), WalletError::Ok);

  // ---- Step 3: Derive a receive key and a change key ----

  WalletStatus d1, d2;
  auto recv_key = (*ks)->derive(receivePath(0, 0), &d1);
  auto chg_key = (*ks)->derive(changePath(0, 0), &d2);
  ASSERT_TRUE(recv_key.has_value()) << walletErrorMessage(d1.code);
  ASSERT_TRUE(chg_key.has_value()) << walletErrorMessage(d2.code);

  EXPECT_NE(recv_key->pubkey, chg_key->pubkey);

  // ---- Step 4: Address derivation matches the keystore's address ----

  const std::string derived_addr = encodeAddress(recv_key->pubkey, Network::Mainnet);
  EXPECT_EQ(derived_addr, address_v1);

  // ---- Step 5: Sign a mock transaction ----
  //
  // LocalSigner takes KeyStore&. `**ks` gives us the reference
  // without disturbing ownership of the unique_ptr inside the
  // optional. Do NOT move *ks into a shared_ptr — that would null
  // out the unique_ptr and break every subsequent (*ks)-> call.

  LocalSigner signer(**ks);

  WalletStatus reg_st;
  ASSERT_TRUE(signer.registerPath(receivePath(0, 0), &reg_st).has_value());

  const Hash tx_hash = testHash(0xAA);

  WalletStatus s1;
  auto sig_v1 = signer.sign(recv_key->pubkey, tx_hash, &s1);
  ASSERT_TRUE(sig_v1.has_value()) << walletErrorMessage(s1.code);
  EXPECT_TRUE(Crypto::verify(tx_hash, recv_key->pubkey, *sig_v1));

  // ---- Step 6: Change the password ----

  ASSERT_EQ((*ks)->changePassword(password_v2), WalletError::Ok);

  // ---- Step 7: Verify metadata is preserved ----

  EXPECT_EQ((*ks)->id(), id_v1);
  EXPECT_EQ((*ks)->address(), address_v1);
  EXPECT_EQ((*ks)->fingerprint(), fingerprint_v1);

  EXPECT_TRUE(Crypto::verify(tx_hash, recv_key->pubkey, *sig_v1));

  // ---- Step 8: Lock and reopen ----

  (*ks)->lock();
  EXPECT_FALSE((*ks)->isUnlocked());
  ks.reset();

  WalletStatus open_st;
  auto reopened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(reopened.has_value())
      << "open failed: " << walletErrorMessage(open_st.code);

  // ---- Step 9: Old password must fail, new one must work ----

  EXPECT_EQ((*reopened)->unlock(password_v1), WalletError::WrongPassword);
  EXPECT_FALSE((*reopened)->isUnlocked());

  EXPECT_EQ((*reopened)->unlock(password_v2), WalletError::Ok);
  ASSERT_TRUE((*reopened)->isUnlocked());

  // ---- Step 10: Derive the same key ----

  WalletStatus d3;
  auto recv_key_2 = (*reopened)->derive(receivePath(0, 0), &d3);
  ASSERT_TRUE(recv_key_2.has_value());
  EXPECT_EQ(recv_key->pubkey, recv_key_2->pubkey);
  EXPECT_EQ(recv_key->secret, recv_key_2->secret);

  // ---- Step 11: Verify the address is unchanged ----

  const std::string addr_v2 = (*reopened)->address();
  EXPECT_EQ(addr_v2, address_v1);

  // ---- Step 12: Verify the old signature is still valid ----

  EXPECT_TRUE(Crypto::verify(tx_hash, recv_key_2->pubkey, *sig_v1));
}

//  Mnemonic recovery

TEST(Wallet_EndToEnd, MnemonicRecovery)
{
  const std::string path_a = tempPath();
  const std::string path_b = tempPath();
  TempCleanup ca(path_a), cb(path_b);

  const std::string password = "irrelevant-for-this-test";

  std::string mnemonic;
  WalletStatus create_st;
  auto ks_a = EncryptedKeyStore::create(
      path_a, password, Network::Mainnet, 256, mnemonic,
      KDF_PBKDF2_HMAC_SHA512, &create_st);
  ASSERT_TRUE(ks_a.has_value());

  std::vector<PublicKey> keys_a;
  for (uint32_t i = 0; i < 5; ++i)
  {
    WalletStatus st;
    auto k = (*ks_a)->derive(receivePath(0, i), &st);
    ASSERT_TRUE(k.has_value());
    keys_a.push_back(k->pubkey);
  }

  WalletStatus mat_st;
  auto mat = SeedMaterial::fromMnemonic(mnemonic, "", &mat_st);
  ASSERT_TRUE(mat.has_value()) << walletErrorMessage(mat_st.code);

  for (uint32_t i = 0; i < 5; ++i)
  {
    WalletStatus st;
    auto k = mat->deriveKey(receivePath(0, i), &st);
    ASSERT_TRUE(k.has_value());
    EXPECT_EQ(k->pubkey, keys_a[i])
        << "restored key at index " << i << " differs from original";
  }

  WalletStatus st;
  auto k0 = mat->deriveKey(receivePath(0, 0), &st);
  ASSERT_TRUE(k0.has_value());

  const std::string recovered_addr =
      encodeAddress(k0->pubkey, Network::Mainnet);
  EXPECT_EQ(recovered_addr, (*ks_a)->address());
}

//  Multi-network

TEST(Wallet_EndToEnd, SameSeedDifferentNetworks)
{
  const std::string mnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about";

  WalletStatus mat_st;
  auto mat = SeedMaterial::fromMnemonic(mnemonic, "", &mat_st);
  ASSERT_TRUE(mat.has_value());

  WalletStatus d_st;
  auto key = mat->deriveKey(receivePath(0, 0), &d_st);
  ASSERT_TRUE(key.has_value());

  const std::string mainnet = encodeAddress(key->pubkey, Network::Mainnet);
  const std::string testnet = encodeAddress(key->pubkey, Network::Testnet);
  const std::string regtest = encodeAddress(key->pubkey, Network::Regtest);

  EXPECT_EQ(mainnet.substr(0, 6), "clrty1");
  EXPECT_EQ(testnet.substr(0, 7), "tclrty1");
  EXPECT_EQ(regtest.substr(0, 7), "rclrty1");

  auto d_mainnet = decodeAddressAnyNetwork(mainnet);
  auto d_testnet = decodeAddressAnyNetwork(testnet);
  auto d_regtest = decodeAddressAnyNetwork(regtest);

  ASSERT_TRUE(d_mainnet.has_value());
  ASSERT_TRUE(d_testnet.has_value());
  ASSERT_TRUE(d_regtest.has_value());

  EXPECT_EQ(d_mainnet->address, key->pubkey);
  EXPECT_EQ(d_testnet->address, key->pubkey);
  EXPECT_EQ(d_regtest->address, key->pubkey);
}

//  Password change preserves derivation

TEST(Wallet_EndToEnd, PasswordChangePreservesDerivation)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  std::string mnemonic;
  WalletStatus create_st;
  auto ks = EncryptedKeyStore::create(
      path, "password-a", Network::Mainnet, 256, mnemonic,
      KDF_PBKDF2_HMAC_SHA512, &create_st);
  ASSERT_TRUE(ks.has_value());

  std::vector<PublicKey> keys_before;
  for (uint32_t i = 0; i < 10; ++i)
  {
    WalletStatus st;
    auto k = (*ks)->derive(receivePath(0, i), &st);
    ASSERT_TRUE(k.has_value());
    keys_before.push_back(k->pubkey);
  }

  ASSERT_EQ((*ks)->changePassword("password-b"), WalletError::Ok);

  for (uint32_t i = 0; i < 10; ++i)
  {
    WalletStatus st;
    auto k = (*ks)->derive(receivePath(0, i), &st);
    ASSERT_TRUE(k.has_value());
    EXPECT_EQ(k->pubkey, keys_before[i]) << "index " << i;
  }
}

//  Signature survives session

TEST(Wallet_EndToEnd, SignatureSurvivesSession)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  const std::string password = "session-test";

  Hash h = testHash(0x55);
  std::vector<uint8_t> sig_bytes;
  std::vector<uint8_t> pk_bytes;

  {
    std::string mnemonic;
    WalletStatus st;
    auto ks = EncryptedKeyStore::create(
        path, password, Network::Mainnet, 256, mnemonic,
        KDF_PBKDF2_HMAC_SHA512, &st);
    ASSERT_TRUE(ks.has_value());

    WalletStatus d_st;
    auto key = (*ks)->derive(receivePath(0, 0), &d_st);
    ASSERT_TRUE(key.has_value());

    LocalSigner signer(**ks);

    WalletStatus s_st;
    auto sig = signer.sign(key->pubkey, h, &s_st);
    ASSERT_TRUE(sig.has_value());

    sig_bytes.assign(sig->data.begin(), sig->data.end());
    pk_bytes.assign(key->pubkey.data.begin(), key->pubkey.data.end());
  }

  {
    WalletStatus open_st;
    auto ks = EncryptedKeyStore::open(path, &open_st);
    ASSERT_TRUE(ks.has_value());
    ASSERT_EQ((*ks)->unlock(password), WalletError::Ok);

    PublicKey pk;
    std::copy(pk_bytes.begin(), pk_bytes.end(), pk.data.begin());

    Signature sig;
    std::copy(sig_bytes.begin(), sig_bytes.end(), sig.data.begin());

    EXPECT_TRUE(Crypto::verify(h, pk, sig));
  }
}

//  Tampered file rejected

TEST(Wallet_EndToEnd, TamperedFileRejectedAtUnlock)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  const std::string password = "password";
  std::string mnemonic;

  WalletStatus create_st;
  auto ks = EncryptedKeyStore::create(
      path, password, Network::Mainnet, 256, mnemonic,
      KDF_PBKDF2_HMAC_SHA512, &create_st);
  ASSERT_TRUE(ks.has_value());
  ks.reset();

  std::string json = readFile(path);
  auto parsed = Common::Json::parse(json);
  std::string ct = parsed["crypto"]["ciphertext"];
  ct[0] = (ct[0] == '0') ? '1' : '0';
  parsed["crypto"]["ciphertext"] = ct;

  {
    std::ofstream out(path);
    out << parsed.dump();
  }

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());
  EXPECT_EQ((*opened)->unlock(password), WalletError::WrongPassword);
}

//  Multi-keystore independence

TEST(Wallet_EndToEnd, MultipleKeystoresIndependent)
{
  const std::string pa = tempPath();
  const std::string pb = tempPath();
  TempCleanup ca(pa), cb(pb);

  std::string mnemonic_a, mnemonic_b;
  WalletStatus sa, sb;

  auto ksa = EncryptedKeyStore::create(
      pa, "password-a", Network::Mainnet, 256, mnemonic_a,
      KDF_PBKDF2_HMAC_SHA512, &sa);
  auto ksb = EncryptedKeyStore::create(
      pb, "password-b", Network::Testnet, 256, mnemonic_b,
      KDF_PBKDF2_HMAC_SHA512, &sb);

  ASSERT_TRUE(ksa.has_value());
  ASSERT_TRUE(ksb.has_value());

  EXPECT_NE(mnemonic_a, mnemonic_b);
  EXPECT_NE((*ksa)->address(), (*ksb)->address());
  EXPECT_NE((*ksa)->fingerprint(), (*ksb)->fingerprint());
  EXPECT_EQ((*ksa)->network(), Network::Mainnet);
  EXPECT_EQ((*ksb)->network(), Network::Testnet);

  WalletStatus d_st;
  auto key_a = (*ksa)->derive(receivePath(0, 0), &d_st);
  ASSERT_TRUE(key_a.has_value());

  auto key_b = (*ksb)->derive(receivePath(0, 0), &d_st);
  ASSERT_TRUE(key_b.has_value());

  EXPECT_NE(key_a->pubkey, key_b->pubkey);

  ASSERT_EQ((*ksa)->changePassword("password-a-v2"), WalletError::Ok);

  (*ksb)->lock();
  EXPECT_EQ((*ksb)->unlock("password-b"), WalletError::Ok);
}

//  Address book pattern

TEST(Wallet_EndToEnd, AddressBookPattern)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  std::string mnemonic;
  WalletStatus create_st;
  auto ks = EncryptedKeyStore::create(
      path, "password", Network::Mainnet, 256, mnemonic,
      KDF_PBKDF2_HMAC_SHA512, &create_st);
  ASSERT_TRUE(ks.has_value());

  LocalSigner signer(**ks);

  WalletStatus range_st;
  const size_t registered = signer.registerAddressRange(0, 100, &range_st);
  EXPECT_EQ(registered, 100u);

  const Hash h = testHash(0x11);
  for (uint32_t i = 0; i < 100; ++i)
  {
    WalletStatus d_st;
    auto key = (*ks)->derive(receivePath(0, i), &d_st);
    ASSERT_TRUE(key.has_value()) << "derive failed at index " << i;

    WalletStatus s_st;
    auto sig = signer.sign(key->pubkey, h, &s_st);
    ASSERT_TRUE(sig.has_value()) << "sign failed at index " << i;

    EXPECT_TRUE(Crypto::verify(h, key->pubkey, *sig)) << "index " << i;
  }
}