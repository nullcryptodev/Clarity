// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Ed25519.h"
#include "Wallet/HdPath.h"
#include "Wallet/KeyDerivation.h"
#include "Wallet/Slip10.h"
#include "Wallet/WalletError.h"

using namespace Wallet;

//  KeyDerivation test suite.
//
//  Verifies that the mnemonic -> seed -> master -> child -> keypair
//  pipeline composes BIP-39 and SLIP-0010 correctly.
//
//  Individual primitives are tested in their own files:
//    - Tests/Wallet/Bip39.cpp        (mnemonic <-> seed, checksum)
//    - Tests/Wallet/Slip10.cpp       (derivation, chain codes)
//    - Tests/Crypto/Pbkdf2.cpp       (PBKDF2 primitive)
//
//  This file tests only the composition.

namespace
{
  // A canonical BIP-39 test mnemonic.
  constexpr char kTestMnemonic[] =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about";

  // 24-word variant.
  constexpr char kTestMnemonic24[] =
      "abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon abandon "
      "abandon abandon art";
} // namespace

//  fromMnemonic — success paths

TEST(Wallet_SeedMaterial, FromValidMnemonic)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value())
      << "error: " << walletErrorMessage(st.code)
      << " detail: " << st.detail;

  EXPECT_EQ(mat->seed().size(), 64u);
  EXPECT_FALSE(mat->master().secret.isNull());
  EXPECT_FALSE(mat->master().chain_code.isNull());
  EXPECT_EQ(mat->master().depth, 0u);
}

TEST(Wallet_SeedMaterial, FromValidMnemonic24Word)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic24, "", &st);
  ASSERT_TRUE(mat.has_value()) << walletErrorMessage(st.code);
  EXPECT_EQ(mat->seed().size(), 64u);
}

TEST(Wallet_SeedMaterial, SeedIsDeterministic)
{
  WalletStatus st1, st2;
  auto a = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st1);
  auto b = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st2);

  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());

  EXPECT_EQ(a->seed(), b->seed());
  EXPECT_EQ(a->master().secret, b->master().secret);
  EXPECT_EQ(a->master().chain_code, b->master().chain_code);
}

//  fromMnemonic — passphrase handling

TEST(Wallet_SeedMaterial, PassphraseChangesSeed)
{
  WalletStatus st1, st2;
  auto no_pass = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st1);
  auto with_pass = SeedMaterial::fromMnemonic(kTestMnemonic, "TREZOR", &st2);

  ASSERT_TRUE(no_pass.has_value());
  ASSERT_TRUE(with_pass.has_value());

  EXPECT_NE(no_pass->seed(), with_pass->seed());
  EXPECT_NE(no_pass->master().secret, with_pass->master().secret);
  EXPECT_NE(no_pass->fingerprint(), with_pass->fingerprint());
}

TEST(Wallet_SeedMaterial, SamePassphraseSameSeed)
{
  WalletStatus st1, st2;
  auto a = SeedMaterial::fromMnemonic(kTestMnemonic, "pass", &st1);
  auto b = SeedMaterial::fromMnemonic(kTestMnemonic, "pass", &st2);

  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());

  EXPECT_EQ(a->seed(), b->seed());
  EXPECT_EQ(a->fingerprint(), b->fingerprint());
}

//  fromMnemonic — validation propagation

TEST(Wallet_SeedMaterial, RejectsInvalidChecksum)
{
  // Correct: "abandon abandon ... about"
  // Wrong:   "abandon abandon ... abandon" (last word changed)
  constexpr char bad[] =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon";

  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(bad, "", &st);
  EXPECT_FALSE(mat.has_value());
  EXPECT_EQ(st.code, WalletError::InvalidChecksum);
}

TEST(Wallet_SeedMaterial, RejectsUnknownWord)
{
  constexpr char bad[] =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon notaword";

  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(bad, "", &st);
  EXPECT_FALSE(mat.has_value());
  EXPECT_EQ(st.code, WalletError::InvalidWord);
}

TEST(Wallet_SeedMaterial, RejectsWrongWordCount)
{
  constexpr char bad[] =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon about";

  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(bad, "", &st);
  EXPECT_FALSE(mat.has_value());
  EXPECT_EQ(st.code, WalletError::InvalidWordCount);
}

TEST(Wallet_SeedMaterial, RejectsEmptyMnemonic)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic("", "", &st);
  EXPECT_FALSE(mat.has_value());
  EXPECT_EQ(st.code, WalletError::InvalidMnemonic);
}

//  fromSeed

TEST(Wallet_SeedMaterial, FromSeedValid)
{
  std::vector<uint8_t> seed(64, 0x42);

  WalletStatus st;
  auto mat = SeedMaterial::fromSeed(seed, &st);
  ASSERT_TRUE(mat.has_value()) << walletErrorMessage(st.code);
  EXPECT_EQ(mat->seed(), seed);
}

TEST(Wallet_SeedMaterial, FromSeedMinimumLength)
{
  std::vector<uint8_t> seed(16, 0x01); // SLIP-0010 minimum
  WalletStatus st;
  auto mat = SeedMaterial::fromSeed(seed, &st);
  EXPECT_TRUE(mat.has_value());
}

TEST(Wallet_SeedMaterial, FromSeedMaximumLength)
{
  std::vector<uint8_t> seed(64, 0x01);
  WalletStatus st;
  auto mat = SeedMaterial::fromSeed(seed, &st);
  EXPECT_TRUE(mat.has_value());
}

TEST(Wallet_SeedMaterial, FromSeedRejectsEmpty)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromSeed({}, &st);
  EXPECT_FALSE(mat.has_value());
  EXPECT_EQ(st.code, WalletError::DerivationFailed);
}

TEST(Wallet_SeedMaterial, FromSeedRejectsTooShort)
{
  std::vector<uint8_t> seed(15, 0x01);
  WalletStatus st;
  auto mat = SeedMaterial::fromSeed(seed, &st);
  EXPECT_FALSE(mat.has_value());
  EXPECT_EQ(st.code, WalletError::DerivationFailed);
}

TEST(Wallet_SeedMaterial, FromSeedRejectsTooLong)
{
  std::vector<uint8_t> seed(65, 0x01);
  WalletStatus st;
  auto mat = SeedMaterial::fromSeed(seed, &st);
  EXPECT_FALSE(mat.has_value());
  EXPECT_EQ(st.code, WalletError::DerivationFailed);
}

TEST(Wallet_SeedMaterial, FromSeedDeterministic)
{
  std::vector<uint8_t> seed(64, 0x42);

  WalletStatus st1, st2;
  auto a = SeedMaterial::fromSeed(seed, &st1);
  auto b = SeedMaterial::fromSeed(seed, &st2);

  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());

  EXPECT_EQ(a->master().secret, b->master().secret);
  EXPECT_EQ(a->master().chain_code, b->master().chain_code);
  EXPECT_EQ(a->fingerprint(), b->fingerprint());
}

//  Fingerprint

TEST(Wallet_SeedFingerprint, NonZeroForRealMnemonic)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  // The fingerprint of a real seed should not be all zeros.
  const auto &fp = mat->fingerprint();
  const bool all_zero =
      fp.bytes[0] == 0 && fp.bytes[1] == 0 &&
      fp.bytes[2] == 0 && fp.bytes[3] == 0;
  EXPECT_FALSE(all_zero);
}

TEST(Wallet_SeedFingerprint, HexForm)
{
  SeedFingerprint fp;
  fp.bytes[0] = 0xDE;
  fp.bytes[1] = 0xAD;
  fp.bytes[2] = 0xBE;
  fp.bytes[3] = 0xEF;
  EXPECT_EQ(fp.toHex(), "deadbeef");
}

TEST(Wallet_SeedFingerprint, Equality)
{
  SeedFingerprint a;
  a.bytes[0] = 1;
  a.bytes[1] = 2;
  a.bytes[2] = 3;
  a.bytes[3] = 4;

  SeedFingerprint b = a;
  EXPECT_TRUE(a == b);
  EXPECT_FALSE(a != b);

  b.bytes[3] = 5;
  EXPECT_FALSE(a == b);
  EXPECT_TRUE(a != b);
}

TEST(Wallet_SeedFingerprint, MatchesStandaloneFunction)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  const auto fp_direct = fingerprintForMaster(mat->master());
  EXPECT_EQ(fp_direct, mat->fingerprint());
}

//  deriveKey

TEST(Wallet_SeedMaterial, DeriveKeyAtDefaultPath)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  const HdPath path = clrtyPath(0, 0, 0);

  WalletStatus st2;
  auto key = mat->deriveKey(path, &st2);
  ASSERT_TRUE(key.has_value()) << walletErrorMessage(st2.code);

  // Public key must match what we'd get from deriving the secret
  // through Ed25519 directly.
  const auto expected_pub = Crypto::derivePublicKey(key->secret);
  EXPECT_EQ(key->pubkey, expected_pub);

  // The path is preserved.
  EXPECT_EQ(key->path, path);
}

TEST(Wallet_SeedMaterial, DeriveClrtyKeyConvenienceMatchesDeriveKey)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  WalletStatus st2, st3;
  auto via_convenience = mat->deriveClrtyKey(0, 0, 0, &st2);
  auto via_derive = mat->deriveKey(clrtyPath(0, 0, 0), &st3);

  ASSERT_TRUE(via_convenience.has_value());
  ASSERT_TRUE(via_derive.has_value());

  EXPECT_EQ(via_convenience->pubkey, via_derive->pubkey);
  EXPECT_EQ(via_convenience->secret, via_derive->secret);
}

TEST(Wallet_SeedMaterial, DeriveKeyIsDeterministic)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  const HdPath path = clrtyPath(0, 0, 5);

  WalletStatus st2, st3;
  auto a = mat->deriveKey(path, &st2);
  auto b = mat->deriveKey(path, &st3);

  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(a->pubkey, b->pubkey);
  EXPECT_EQ(a->secret, b->secret);
}

TEST(Wallet_SeedMaterial, DifferentIndicesGiveDifferentKeys)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  std::vector<DerivedKey> keys;
  for (uint32_t i = 0; i < 5; ++i)
  {
    WalletStatus st2;
    auto k = mat->deriveKey(clrtyPath(0, 0, i), &st2);
    ASSERT_TRUE(k.has_value());
    keys.push_back(*k);
  }

  // Every pair of keys must be distinct.
  for (size_t i = 0; i < keys.size(); ++i)
  {
    for (size_t j = i + 1; j < keys.size(); ++j)
    {
      EXPECT_NE(keys[i].pubkey, keys[j].pubkey)
          << "collision at " << i << " and " << j;
      EXPECT_NE(keys[i].secret, keys[j].secret);
    }
  }
}

TEST(Wallet_SeedMaterial, DifferentAccountsDifferentKeys)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  WalletStatus s1, s2;
  auto a = mat->deriveClrtyKey(0, 0, 0, &s1);
  auto b = mat->deriveClrtyKey(1, 0, 0, &s2);

  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());
  EXPECT_NE(a->pubkey, b->pubkey);
}

TEST(Wallet_SeedMaterial, ReceiveAndChangeDiffer)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  WalletStatus s1, s2;
  auto recv = mat->deriveClrtyKey(0, 0, 0, &s1);
  auto chg = mat->deriveClrtyKey(0, 1, 0, &s2);

  ASSERT_TRUE(recv.has_value());
  ASSERT_TRUE(chg.has_value());
  EXPECT_NE(recv->pubkey, chg->pubkey);
}

//  deriveKey — failure modes

TEST(Wallet_SeedMaterial, DeriveKeyRejectsEmptyPath)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  HdPath empty; // length == 0
  WalletStatus st2;
  auto key = mat->deriveKey(empty, &st2);
  EXPECT_FALSE(key.has_value());
  EXPECT_EQ(st2.code, WalletError::InvalidPath);
}

TEST(Wallet_SeedMaterial, DeriveKeyRejectsNonHardenedComponent)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  // Build a path with a non-hardened component.
  HdPath bad;
  bad.push(44, true);
  bad.push(9000, true);
  bad.push(0, false); // non-hardened, SLIP-0010 requires hardened

  WalletStatus st2;
  auto key = mat->deriveKey(bad, &st2);
  EXPECT_FALSE(key.has_value());
  EXPECT_EQ(st2.code, WalletError::InvalidPath);
}

TEST(Wallet_SeedMaterial, DeriveKeyFailureLeavesMaterialIntact)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  // Snapshot the master before the failing derivation.
  const auto master_before = mat->master();

  // Failing derivation.
  HdPath bad;
  bad.push(0, false); // non-hardened
  WalletStatus st2;
  EXPECT_FALSE(mat->deriveKey(bad, &st2).has_value());

  // Master is unchanged.
  EXPECT_EQ(mat->master().secret, master_before.secret);
  EXPECT_EQ(mat->master().chain_code, master_before.chain_code);

  // A subsequent valid derivation must still work.
  WalletStatus st3;
  auto ok = mat->deriveKey(clrtyPath(0, 0, 0), &st3);
  EXPECT_TRUE(ok.has_value());
}

//  Move semantics

TEST(Wallet_SeedMaterial, MoveConstruction)
{
  WalletStatus st;
  auto a = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(a.has_value());

  const auto seed_copy = a->seed();
  const auto master_copy = a->master();

  SeedMaterial b = std::move(*a);

  EXPECT_EQ(b.seed(), seed_copy);
  EXPECT_EQ(b.master().secret, master_copy.secret);
  EXPECT_EQ(b.master().chain_code, master_copy.chain_code);

  // The moved-from object's secret material must be wiped.
  EXPECT_TRUE(a->master().secret.isNull())
      << "moved-from master secret should be wiped";
  EXPECT_TRUE(a->master().chain_code.isNull())
      << "moved-from master chain code should be wiped";
}

TEST(Wallet_SeedMaterial, MoveAssignmentWorks)
{
  WalletStatus st1, st2;
  auto a = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st1);
  ASSERT_TRUE(a.has_value());

  const auto seed_a = a->seed();
  const auto master_a = a->master();

  // Construct a second SeedMaterial from a different seed.
  std::vector<uint8_t> other(64, 0xAA);
  auto b = SeedMaterial::fromSeed(other, &st2);
  ASSERT_TRUE(b.has_value());

  // Move-assign a into b. b's old seed must be wiped and replaced.
  *b = std::move(*a);

  EXPECT_EQ(b->seed(), seed_a);
  EXPECT_EQ(b->master().secret, master_a.secret);
  EXPECT_EQ(b->master().chain_code, master_a.chain_code);

  // Source wiped.
  EXPECT_TRUE(a->master().secret.isNull());
}

//  Cross-check with Slip10 directly
//
//  SeedMaterial's master node must match what slip10Master produces
//  from the same seed.

TEST(Wallet_SeedMaterial, MasterMatchesSlip10Directly)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  WalletStatus st2;
  auto master_direct = slip10Master(mat->seed(), &st2);
  ASSERT_TRUE(master_direct.has_value());

  EXPECT_EQ(mat->master().secret, master_direct->secret);
  EXPECT_EQ(mat->master().chain_code, master_direct->chain_code);
}

//  Cross-check with Bip39 directly
//
//  SeedMaterial's seed must match what BIP-39's mnemonicToSeed
//  produces.

TEST(Wallet_SeedMaterial, SeedMatchesBip39Directly)
{
  WalletStatus st;
  auto mat = SeedMaterial::fromMnemonic(kTestMnemonic, "", &st);
  ASSERT_TRUE(mat.has_value());

  uint8_t seed_direct[64];
  mnemonicToSeed(kTestMnemonic, "", seed_direct);

  EXPECT_EQ(std::memcmp(mat->seed().data(), seed_direct, 64), 0);
}

//  pubkeyHash160

TEST(Wallet_KeyDerivation, PubkeyHash160IsDeterministic)
{
  const auto pk = Crypto::derivePublicKey(
      Crypto::SecretKey{}); // derives pubkey of all-zero secret

  const auto h1 = pubkeyHash160(pk);
  const auto h2 = pubkeyHash160(pk);
  EXPECT_EQ(h1, h2);
}

TEST(Wallet_KeyDerivation, PubkeyHash160DiffersForDifferentKeys)
{
  Crypto::SecretKey sk_a;
  Crypto::SecretKey sk_b;
  sk_a.data[0] = 1;
  sk_b.data[0] = 2;

  const auto pk_a = Crypto::derivePublicKey(sk_a);
  const auto pk_b = Crypto::derivePublicKey(sk_b);

  EXPECT_NE(pubkeyHash160(pk_a), pubkeyHash160(pk_b));
}