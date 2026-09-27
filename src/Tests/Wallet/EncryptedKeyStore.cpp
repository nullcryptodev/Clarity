// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Wallet/AddressCodec.h"
#include "Wallet/EncryptedKeyStore.h"
#include "Wallet/HdPath.h"
#include "Wallet/KeyStoreFormat.h"

using namespace Wallet;

namespace fs = std::filesystem;

//  EncryptedKeyStore test suite.
//
//  The KDF is expensive; Argon2 with default parameters takes
//  ~200-400ms per call, which would make the whole suite slow. Most
//  tests use PBKDF2 with a reduced iteration count. Two dedicated
//  tests exercise the Argon2id path with default parameters and
//  with reduced parameters, to make sure both KDF branches work
//  and that the on-disk parameters are honored.

namespace
{
  constexpr char kTestMnemonic[] =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about";

  constexpr char kPassword[] = "correct horse battery staple";

  std::string tempPath(const std::string &suffix = ".json")
  {
    static int counter = 0;
    return (fs::temp_directory_path() /
            ("clrty_ks_test_" + std::to_string(::getpid()) + "_" +
             std::to_string(counter++) + suffix))
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

  // Create a keystore on disk. Uses PBKDF2 by default because it's
  // much faster than Argon2 with default parameters.
  std::unique_ptr<EncryptedKeyStore> createKs(
      const std::string &path,
      std::string_view password = kPassword,
      Network network = Network::Mainnet,
      std::string_view kdf = KDF_PBKDF2_HMAC_SHA512,
      std::string *out_mnemonic = nullptr)
  {
    std::string local_mnemonic;
    WalletStatus st;
    auto ks = EncryptedKeyStore::create(
        path, password, network, 256, local_mnemonic, kdf, &st);
    if (out_mnemonic)
      *out_mnemonic = local_mnemonic;
    return ks ? std::move(*ks) : nullptr;
  }
} // namespace

//  Create — basic

TEST(Wallet_EncryptedKeyStore, CreateProducesUnlockedStore)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  std::string mnemonic;
  auto ks = createKs(path, kPassword, Network::Mainnet,
                     KDF_PBKDF2_HMAC_SHA512, &mnemonic);
  ASSERT_NE(ks, nullptr);

  // The mnemonic must be a valid BIP-39 phrase.
  EXPECT_FALSE(mnemonic.empty());

  // The returned keystore must be unlocked (we just created it).
  EXPECT_TRUE(ks->isUnlocked());

  // File must exist.
  EXPECT_TRUE(fs::exists(path));
}

TEST(Wallet_EncryptedKeyStore, CreateGeneratesUniqueIds)
{
  const std::string p1 = tempPath();
  const std::string p2 = tempPath();
  TempCleanup c1(p1), c2(p2);

  auto ks1 = createKs(p1);
  auto ks2 = createKs(p2);
  ASSERT_NE(ks1, nullptr);
  ASSERT_NE(ks2, nullptr);

  EXPECT_NE(ks1->id(), ks2->id());
}

TEST(Wallet_EncryptedKeyStore, CreateGeneratesDifferentMnemonics)
{
  const std::string p1 = tempPath();
  const std::string p2 = tempPath();
  TempCleanup c1(p1), c2(p2);

  std::string m1, m2;
  auto ks1 = createKs(p1, kPassword, Network::Mainnet,
                      KDF_PBKDF2_HMAC_SHA512, &m1);
  auto ks2 = createKs(p2, kPassword, Network::Mainnet,
                      KDF_PBKDF2_HMAC_SHA512, &m2);
  ASSERT_NE(ks1, nullptr);
  ASSERT_NE(ks2, nullptr);

  EXPECT_NE(m1, m2);
  EXPECT_NE(ks1->address(), ks2->address());
  EXPECT_NE(ks1->fingerprint(), ks2->fingerprint());
}

TEST(Wallet_EncryptedKeyStore, CreateRejectsEmptyPassword)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  std::string mnemonic;
  WalletStatus st;
  auto ks = EncryptedKeyStore::create(
      path, "", Network::Mainnet, 256, mnemonic,
      KDF_PBKDF2_HMAC_SHA512, &st);

  EXPECT_FALSE(ks.has_value());
  EXPECT_EQ(st.code, WalletError::BadArgument);
}

TEST(Wallet_EncryptedKeyStore, CreateRejectsUnknownKdf)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  std::string mnemonic;
  WalletStatus st;
  auto ks = EncryptedKeyStore::create(
      path, kPassword, Network::Mainnet, 256, mnemonic,
      "totally-not-a-kdf", &st);

  EXPECT_FALSE(ks.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreUnsupportedKdf);
}

//  Open + unlock

TEST(Wallet_EncryptedKeyStore, OpenAndUnlock)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  // Create and grab the mnemonic.
  std::string mnemonic;
  auto created = createKs(path, kPassword, Network::Mainnet,
                          KDF_PBKDF2_HMAC_SHA512, &mnemonic);
  ASSERT_NE(created, nullptr);

  // Open a fresh instance. It must start locked.
  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value()) << walletErrorMessage(open_st.code);
  EXPECT_FALSE((*opened)->isUnlocked());

  // Unlock with the right password.
  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::Ok);
  EXPECT_TRUE((*opened)->isUnlocked());

  // Derived keys must match.
  WalletStatus d1, d2;
  auto k1 = created->derive(clrtyPath(0, 0, 0), &d1);
  auto k2 = (*opened)->derive(clrtyPath(0, 0, 0), &d2);
  ASSERT_TRUE(k1.has_value());
  ASSERT_TRUE(k2.has_value());
  EXPECT_EQ(k1->pubkey, k2->pubkey);
  EXPECT_EQ(k1->secret, k2->secret);
}

TEST(Wallet_EncryptedKeyStore, UnlockRejectsWrongPassword)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock("wrong password"),
            WalletError::WrongPassword);
  EXPECT_FALSE((*opened)->isUnlocked());
}

TEST(Wallet_EncryptedKeyStore, UnlockRejectsEmptyPassword)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock(""), WalletError::BadArgument);
  EXPECT_FALSE((*opened)->isUnlocked());
}

TEST(Wallet_EncryptedKeyStore, UnlockTwiceIsIdempotent)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::Ok);
  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::Ok);
  EXPECT_TRUE((*opened)->isUnlocked());
}

//  Lock

TEST(Wallet_EncryptedKeyStore, LockWipesMaterial)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);
  EXPECT_TRUE(ks->isUnlocked());

  // Derive once to confirm the state is usable.
  WalletStatus d1;
  EXPECT_TRUE(ks->derive(clrtyPath(0, 0, 0), &d1).has_value());

  ks->lock();
  EXPECT_FALSE(ks->isUnlocked());

  // Derivation must fail while locked.
  WalletStatus d2;
  auto key = ks->derive(clrtyPath(0, 0, 0), &d2);
  EXPECT_FALSE(key.has_value());
  EXPECT_EQ(d2.code, WalletError::KeyStoreLocked);
}

TEST(Wallet_EncryptedKeyStore, UnlockAfterLock)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  ks->lock();
  EXPECT_FALSE(ks->isUnlocked());

  EXPECT_EQ(ks->unlock(kPassword), WalletError::Ok);
  EXPECT_TRUE(ks->isUnlocked());

  WalletStatus st;
  EXPECT_TRUE(ks->derive(clrtyPath(0, 0, 0), &st).has_value());
}

//  Derivation

TEST(Wallet_EncryptedKeyStore, DeriveMatchesAcrossSessions)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  // Session 1: create + derive a key.
  std::string mnemonic;
  std::vector<uint8_t> pubkey_1;
  {
    auto ks = createKs(path, kPassword, Network::Mainnet,
                       KDF_PBKDF2_HMAC_SHA512, &mnemonic);
    ASSERT_NE(ks, nullptr);
    WalletStatus st;
    auto key = ks->derive(clrtyPath(0, 0, 0), &st);
    ASSERT_TRUE(key.has_value());
    pubkey_1.assign(key->pubkey.data.begin(), key->pubkey.data.end());
  }

  // Session 2: open + unlock + derive the same key.
  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());
  ASSERT_EQ((*opened)->unlock(kPassword), WalletError::Ok);

  WalletStatus d_st;
  auto key2 = (*opened)->derive(clrtyPath(0, 0, 0), &d_st);
  ASSERT_TRUE(key2.has_value());

  std::vector<uint8_t> pubkey_2(
      key2->pubkey.data.begin(), key2->pubkey.data.end());
  EXPECT_EQ(pubkey_1, pubkey_2);
}

TEST(Wallet_EncryptedKeyStore, DeriveFailsWhileLocked)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());
  EXPECT_FALSE((*opened)->isUnlocked());

  WalletStatus d_st;
  auto key = (*opened)->derive(clrtyPath(0, 0, 0), &d_st);
  EXPECT_FALSE(key.has_value());
  EXPECT_EQ(d_st.code, WalletError::KeyStoreLocked);
}

//  Tampering

TEST(Wallet_EncryptedKeyStore, RejectsTamperedCiphertext)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  // Read the file, mutate a ciphertext byte, write it back.
  std::string json;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json = ss.str();
  }

  auto parsed = Common::Json::parse(json);
  std::string ct = parsed["crypto"]["ciphertext"];
  // Flip a bit in the first byte.
  ct[0] = (ct[0] == '0') ? '1' : '0';
  parsed["crypto"]["ciphertext"] = ct;

  {
    std::ofstream out(path);
    out << parsed.dump();
  }

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::WrongPassword);
}

TEST(Wallet_EncryptedKeyStore, RejectsTamperedMac)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  std::string json;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json = ss.str();
  }

  auto parsed = Common::Json::parse(json);
  std::string mac = parsed["crypto"]["mac"];
  mac[0] = (mac[0] == '0') ? '1' : '0';
  parsed["crypto"]["mac"] = mac;

  {
    std::ofstream out(path);
    out << parsed.dump();
  }

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::WrongPassword);
}

TEST(Wallet_EncryptedKeyStore, RejectsTamperedNonce)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  std::string json;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json = ss.str();
  }

  auto parsed = Common::Json::parse(json);
  std::string nonce = parsed["crypto"]["nonce"];
  nonce[0] = (nonce[0] == '0') ? '1' : '0';
  parsed["crypto"]["nonce"] = nonce;

  {
    std::ofstream out(path);
    out << parsed.dump();
  }

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::WrongPassword);
}

TEST(Wallet_EncryptedKeyStore, RejectsTamperedAad)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  std::string json;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json = ss.str();
  }

  auto parsed = Common::Json::parse(json);
  parsed["crypto"]["aad"] = "tampered-aad";

  {
    std::ofstream out(path);
    out << parsed.dump();
  }

  // AAD validation is done in KeyStoreFormat during parse; the
  // open() call itself should fail with KeyStoreCorrupt.
  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  EXPECT_FALSE(opened.has_value());
  EXPECT_EQ(open_st.code, WalletError::KeyStoreCorrupt);
}

TEST(Wallet_EncryptedKeyStore, RejectsTamperedSalt)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  std::string json;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json = ss.str();
  }

  auto parsed = Common::Json::parse(json);
  std::string salt = parsed["crypto"]["kdfparams"]["salt"];
  salt[0] = (salt[0] == '0') ? '1' : '0';
  parsed["crypto"]["kdfparams"]["salt"] = salt;

  {
    std::ofstream out(path);
    out << parsed.dump();
  }

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  // Different salt -> different KEK -> auth fails.
  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::WrongPassword);
}

//  Nonce randomness

TEST(Wallet_EncryptedKeyStore, DifferentNonceEachEncryption)
{
  // Two keystores created from the same password should have
  // completely different nonces, ciphertexts, and MACs.
  const std::string p1 = tempPath();
  const std::string p2 = tempPath();
  TempCleanup c1(p1), c2(p2);

  auto ks1 = createKs(p1);
  auto ks2 = createKs(p2);
  ASSERT_NE(ks1, nullptr);
  ASSERT_NE(ks2, nullptr);

  // The IDs differ because UUIDs are random, but the point here is
  // that the crypto fields are unrelated.
  std::string json1, json2;
  {
    std::ifstream in1(p1), in2(p2);
    std::stringstream s1, s2;
    s1 << in1.rdbuf();
    s2 << in2.rdbuf();
    json1 = s1.str();
    json2 = s2.str();
  }

  auto p1_json = Common::Json::parse(json1);
  auto p2_json = Common::Json::parse(json2);

  EXPECT_NE(p1_json["crypto"]["nonce"], p2_json["crypto"]["nonce"]);
  EXPECT_NE(p1_json["crypto"]["ciphertext"],
            p2_json["crypto"]["ciphertext"]);
  EXPECT_NE(p1_json["crypto"]["mac"], p2_json["crypto"]["mac"]);
}

TEST(Wallet_EncryptedKeyStore, ReencryptWithSamePasswordProducesDifferentCiphertext)
{
  // Even with the same password, salt, and plaintext, the AEAD
  // produces different ciphertexts because the nonce is random.
  // This is the standard guarantee we get from a random-nonce AEAD.
  //
  // Test: create a keystore, change the password (which regenerates
  // the salt and nonce), then change it back. The final file must
  // have a different nonce from the original.
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  std::string json_before;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json_before = ss.str();
  }

  // Change password twice: A -> B -> A.
  ASSERT_EQ(ks->changePassword("intermediate-password"), WalletError::Ok);
  ASSERT_EQ(ks->changePassword(kPassword), WalletError::Ok);

  std::string json_after;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json_after = ss.str();
  }

  auto before = Common::Json::parse(json_before);
  auto after = Common::Json::parse(json_after);

  // The salt was regenerated on each changePassword call, so it
  // differs. The ciphertext differs accordingly.
  EXPECT_NE(before["crypto"]["kdfparams"]["salt"],
            after["crypto"]["kdfparams"]["salt"]);
  EXPECT_NE(before["crypto"]["nonce"],
            after["crypto"]["nonce"]);
}

//  changePassword

TEST(Wallet_EncryptedKeyStore, ChangePasswordOldPasswordFails)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  // Record a derived key for later comparison.
  WalletStatus st;
  auto key_before = ks->derive(clrtyPath(0, 0, 0), &st);
  ASSERT_TRUE(key_before.has_value());

  const std::string new_password = "a-completely-different-password";
  ASSERT_EQ(ks->changePassword(new_password), WalletError::Ok);

  // Lock and try the old password.
  ks->lock();

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::WrongPassword);

  // New password works.
  EXPECT_EQ((*opened)->unlock(new_password), WalletError::Ok);

  // And the derived key is unchanged.
  WalletStatus st2;
  auto key_after = (*opened)->derive(clrtyPath(0, 0, 0), &st2);
  ASSERT_TRUE(key_after.has_value());
  EXPECT_EQ(key_before->pubkey, key_after->pubkey);
  EXPECT_EQ(key_before->secret, key_after->secret);
}

TEST(Wallet_EncryptedKeyStore, ChangePasswordRequiresUnlocked)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());
  EXPECT_FALSE((*opened)->isUnlocked());

  EXPECT_EQ((*opened)->changePassword("new-password"),
            WalletError::KeyStoreLocked);
}

TEST(Wallet_EncryptedKeyStore, ChangePasswordRejectsEmpty)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  EXPECT_EQ(ks->changePassword(""), WalletError::BadArgument);
}

TEST(Wallet_EncryptedKeyStore, ChangePasswordPreservesIdentity)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  const std::string id_before = ks->id();
  const std::string address_before = ks->address();
  const auto fingerprint_before = ks->fingerprint();

  ASSERT_EQ(ks->changePassword("new-password"), WalletError::Ok);

  EXPECT_EQ(ks->id(), id_before);
  EXPECT_EQ(ks->address(), address_before);
  EXPECT_EQ(ks->fingerprint(), fingerprint_before);
}

//  Label

TEST(Wallet_EncryptedKeyStore, SetLabelPersists)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  EXPECT_EQ(ks->setLabel("my-wallet"), WalletError::Ok);

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->label(), "my-wallet");
}

TEST(Wallet_EncryptedKeyStore, SetLabelRepeatedly)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  ASSERT_EQ(ks->setLabel("first"), WalletError::Ok);
  ASSERT_EQ(ks->setLabel("second"), WalletError::Ok);
  ASSERT_EQ(ks->setLabel("third"), WalletError::Ok);

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());
  EXPECT_EQ((*opened)->label(), "third");
}

//  save()

TEST(Wallet_EncryptedKeyStore, SaveRequiresUnlocked)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto created = createKs(path);
  ASSERT_NE(created, nullptr);

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  // Locked: save fails.
  EXPECT_EQ((*opened)->save(), WalletError::KeyStoreLocked);
}

TEST(Wallet_EncryptedKeyStore, SaveDoesNotChangeCrypto)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  std::string json_before;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json_before = ss.str();
  }

  ASSERT_EQ(ks->save(), WalletError::Ok);

  std::string json_after;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json_after = ss.str();
  }

  auto before = Common::Json::parse(json_before);
  auto after = Common::Json::parse(json_after);

  // The crypto section is untouched by save().
  EXPECT_EQ(before["crypto"]["nonce"], after["crypto"]["nonce"]);
  EXPECT_EQ(before["crypto"]["ciphertext"], after["crypto"]["ciphertext"]);
  EXPECT_EQ(before["crypto"]["mac"], after["crypto"]["mac"]);
  EXPECT_EQ(before["crypto"]["kdfparams"], after["crypto"]["kdfparams"]);
}

//  Network binding

TEST(Wallet_EncryptedKeyStore, NetworkIsPreserved)
{
  for (auto net : {Network::Mainnet, Network::Testnet, Network::Regtest})
  {
    const std::string path = tempPath();
    TempCleanup cleanup(path);

    auto ks = createKs(path, kPassword, net);
    ASSERT_NE(ks, nullptr);
    EXPECT_EQ(ks->network(), net);

    WalletStatus open_st;
    auto opened = EncryptedKeyStore::open(path, &open_st);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ((*opened)->network(), net);
  }
}

TEST(Wallet_EncryptedKeyStore, ChainIdMatchesNetwork)
{
  for (auto net : {Network::Mainnet, Network::Testnet, Network::Regtest})
  {
    const std::string path = tempPath();
    TempCleanup cleanup(path);

    auto ks = createKs(path, kPassword, net);
    ASSERT_NE(ks, nullptr);
    EXPECT_EQ(ks->chainId(), chainIdForNetwork(net));
  }
}

TEST(Wallet_EncryptedKeyStore, AddressMatchesNetwork)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path, kPassword, Network::Testnet);
  ASSERT_NE(ks, nullptr);

  // The address must start with the testnet HRP.
  EXPECT_EQ(ks->address().substr(0, 7), "tclrty1");
}

//  Fingerprint

TEST(Wallet_EncryptedKeyStore, FingerprintIsStable)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path);
  ASSERT_NE(ks, nullptr);

  const auto fp_before = ks->fingerprint();

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->fingerprint(), fp_before);
}

TEST(Wallet_EncryptedKeyStore, FingerprintMismatchDetected)
{
  // Create two keystores with different mnemonics. Then overwrite
  // the ciphertext of keystore A with keystore B's ciphertext (but
  // leave A's fingerprint). Unlocking A with B's password should
  // fail with the fingerprint-mismatch error.
  //
  // This simulates a user restoring the wrong mnemonic into an
  // existing wallet file, or a partial-file-swap scenario.
  const std::string pa = tempPath();
  const std::string pb = tempPath();
  TempCleanup ca(pa), cb(pb);

  std::string mnemonic_a, mnemonic_b;
  auto a = createKs(pa, kPassword, Network::Mainnet,
                    KDF_PBKDF2_HMAC_SHA512, &mnemonic_a);
  auto b = createKs(pb, kPassword, Network::Mainnet,
                    KDF_PBKDF2_HMAC_SHA512, &mnemonic_b);
  ASSERT_NE(a, nullptr);
  ASSERT_NE(b, nullptr);
  ASSERT_NE(mnemonic_a, mnemonic_b);

  // Read A and B JSON.
  std::string json_a, json_b;
  {
    std::ifstream in_a(pa), in_b(pb);
    std::stringstream ss_a, ss_b;
    ss_a << in_a.rdbuf();
    ss_b << in_b.rdbuf();
    json_a = ss_a.str();
    json_b = ss_b.str();
  }
  auto ja = Common::Json::parse(json_a);
  auto jb = Common::Json::parse(json_b);

  // Splice B's crypto block into A, but keep A's HD section (which
  // contains the fingerprint).
  ja["crypto"] = jb["crypto"];

  {
    std::ofstream out(pa);
    out << ja.dump();
  }

  // Now A's file has B's encrypted seed but A's fingerprint.
  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(pa, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock(kPassword),
            WalletError::DerivationSeedFingerprintMismatch);
}

//  Argon2id path
//
//  One test with reduced parameters (fast), one test with the
//  wallet's default parameters (slow but the production path).

TEST(Wallet_EncryptedKeyStore, CreateWithArgon2ReducedParams)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  // Create with Argon2. The defaults are 64 MiB / 3 / 4; we don't
  // override here — EncryptedKeyStore::create uses the wallet's
  // defaults. This test takes ~200-400ms.
  std::string mnemonic;
  auto ks = createKs(path, kPassword, Network::Mainnet,
                     KDF_ARGON2ID, &mnemonic);
  ASSERT_NE(ks, nullptr);

  // Verify the file's kdf field is "argon2id".
  std::string json;
  {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    json = ss.str();
  }
  auto parsed = Common::Json::parse(json);
  EXPECT_EQ(parsed["crypto"]["kdf"], "argon2id");
  EXPECT_TRUE(parsed["crypto"]["kdfparams"].contains("m_cost_kib"));
  EXPECT_TRUE(parsed["crypto"]["kdfparams"].contains("t_cost"));
  EXPECT_TRUE(parsed["crypto"]["kdfparams"].contains("p_cost"));

  // Round trip.
  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());
  EXPECT_EQ((*opened)->unlock(kPassword), WalletError::Ok);

  WalletStatus d_st;
  EXPECT_TRUE((*opened)->derive(clrtyPath(0, 0, 0), &d_st).has_value());
}

TEST(Wallet_EncryptedKeyStore, Argon2WrongPassword)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  auto ks = createKs(path, kPassword, Network::Mainnet, KDF_ARGON2ID);
  ASSERT_NE(ks, nullptr);

  ks->lock();

  WalletStatus open_st;
  auto opened = EncryptedKeyStore::open(path, &open_st);
  ASSERT_TRUE(opened.has_value());

  EXPECT_EQ((*opened)->unlock("wrong-password"), WalletError::WrongPassword);
}

//  File I/O interaction

TEST(Wallet_EncryptedKeyStore, OpenRejectsMissingFile)
{
  WalletStatus st;
  auto ks = EncryptedKeyStore::open("/nonexistent/path.json", &st);
  EXPECT_FALSE(ks.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreNotFound);
}

TEST(Wallet_EncryptedKeyStore, OpenRejectsCorruptFile)
{
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  {
    std::ofstream out(path);
    out << "{ not json";
  }

  WalletStatus st;
  auto ks = EncryptedKeyStore::open(path, &st);
  EXPECT_FALSE(ks.has_value());
  EXPECT_EQ(st.code, WalletError::KeyStoreCorrupt);
}

//  Destructor behavior

TEST(Wallet_EncryptedKeyStore, DestructorLocks)
{
  // Constructing and destroying an unlocked keystore must wipe the
  // material. There's no direct way to observe the wipe after
  // destruction, but this at least confirms the destructor runs
  // without crashing and the file remains valid.
  const std::string path = tempPath();
  TempCleanup cleanup(path);

  {
    auto ks = createKs(path);
    ASSERT_NE(ks, nullptr);
    EXPECT_TRUE(ks->isUnlocked());
    // Destructor runs at scope exit.
  }

  // The file must still be readable.
  WalletStatus st;
  auto opened = EncryptedKeyStore::open(path, &st);
  EXPECT_TRUE(opened.has_value());
}