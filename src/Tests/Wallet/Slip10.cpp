// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Wallet/HdPath.h"
#include "Wallet/Slip10.h"
#include "Wallet/WalletError.h"

using namespace Wallet;

//  SLIP-0010 test vectors for Ed25519.
//
//  Source: https://github.com/satoshilabs/slips/blob/master/slip-0010.md
//
//  Two test vector sets for Ed25519:
//    Test vector 1: 16-byte seed "000102030405060708090a0b0c0d0e0f"
//    Test vector 2: 64-byte seed (long, quoted below)
//
//  Each vector gives, for a derivation path:
//    - chain code (32 bytes, hex)
//    - private key (32 bytes, hex)  <- this is "IL" from the spec
//    - public key  (33 bytes, hex)  <- first byte is a 0x00 prefix
//
//  The 0x00 prefix on the public key is an artifact of how SLIP-0010
//  serializes Ed25519 public keys. The actual 32-byte key is the last
//  32 bytes. Our tests strip the prefix.
//
//  IMPORTANT: verify every hex string below against the spec before
//  relying on these tests. Transcription errors in 64-char hex values
//  are extremely easy to make, and a wrong vector will silently pass
//  if the implementation is also wrong in the same way (unlikely) or
//  fail confusingly if only the vector is wrong (common).

namespace
{
  std::vector<uint8_t> fromHexBytes(std::string_view s)
  {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    auto nib = [](char c) -> int
    {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return -1;
    };
    for (size_t i = 0; i + 1 < s.size(); i += 2)
      out.push_back(uint8_t((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
  }

  std::string bytesToHex(const uint8_t *p, size_t n)
  {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i)
    {
      out.push_back(hex[p[i] >> 4]);
      out.push_back(hex[p[i] & 0x0F]);
    }
    return out;
  }

  // Strip an optional leading "00" from the SLIP-0010 public-key hex
  // form. The spec quotes public keys as 66 hex chars (33 bytes) with
  // a leading 00 byte; the actual Ed25519 public key is 32 bytes.
  std::string stripPubkeyPrefix(std::string_view s)
  {
    if (s.size() == 66 && s[0] == '0' && s[1] == '0')
      return std::string(s.substr(2));
    return std::string(s);
  }

  // Derive a full path and return the leaf node. Asserts on failure.
  Slip10Node deriveOrDie(const Slip10Node &master, const char *path_str)
  {
    WalletStatus st;
    auto path = parseHdPath(path_str, &st);
    EXPECT_TRUE(path.has_value()) << "parse failed for " << path_str
                                  << ": " << walletErrorMessage(st.code);
    if (!path.has_value())
      return {};

    WalletStatus st2;
    auto node = slip10DerivePath(master, *path, &st2);
    EXPECT_TRUE(node.has_value()) << "derive failed for " << path_str
                                  << ": " << walletErrorMessage(st2.code);
    if (!node.has_value())
      return {};
    return *node;
  }

  // Assert that a node matches the expected chain code, private key,
  // and public key.
  void expectNodeMatches(const Slip10Node &node,
                         const char *expected_chain_code_hex,
                         const char *expected_private_hex,
                         const char *expected_public_hex)
  {
    EXPECT_EQ(bytesToHex(node.chain_code.data.data(), 32),
              std::string(expected_chain_code_hex))
        << "chain code mismatch";
    EXPECT_EQ(bytesToHex(node.secret.data.data(), 32),
              std::string(expected_private_hex))
        << "private key mismatch";

    const auto pub = slip10PublicKey(node);
    EXPECT_EQ(bytesToHex(pub.data.data(), 32),
              stripPubkeyPrefix(expected_public_hex))
        << "public key mismatch";
  }
} // namespace

//  Test vector 1 for ed25519
//
//  Seed (16 bytes):
//    000102030405060708090a0b0c0d0e0f

TEST(Wallet_Slip10, Tv1Master)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value()) << walletErrorMessage(st.code);

  expectNodeMatches(*master,
                    "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
                    "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                    "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed");
}

TEST(Wallet_Slip10, Tv1Path0)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto node = deriveOrDie(*master, "m/0'");
  expectNodeMatches(node,
                    "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69",
                    "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                    "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c");
}

TEST(Wallet_Slip10, Tv1Path0H1H)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto node = deriveOrDie(*master, "m/0'/1'");
  expectNodeMatches(node,
                    "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14",
                    "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                    "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187");
}

TEST(Wallet_Slip10, Tv1Path0H1H2H)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto node = deriveOrDie(*master, "m/0'/1'/2'");
  expectNodeMatches(node,
                    "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c",
                    "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                    "00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1");
}

TEST(Wallet_Slip10, Tv1Path0H1H2H2H)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto node = deriveOrDie(*master, "m/0'/1'/2'/2'");
  expectNodeMatches(node,
                    "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc",
                    "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                    "008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c");
}

TEST(Wallet_Slip10, Tv1Path0H1H2H2H1000000000H)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto node = deriveOrDie(*master, "m/0'/1'/2'/2'/1000000000'");
  expectNodeMatches(node,
                    "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230",
                    "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                    "003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a");
}

//  Test vector 2 for ed25519
//
//  Seed (64 bytes):
//    fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2
//    9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542

namespace
{
  std::vector<uint8_t> tv2Seed()
  {
    return fromHexBytes(
        "fffcf9f6f3f0edeae7e4e1dedbd8d5d2"
        "cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"
        "9f9c999693908d8a8784817e7b787572"
        "6f6c696663605d5a5754514e4b484542");
  }
} // namespace

TEST(Wallet_Slip10, Tv2Master)
{
  const auto seed = tv2Seed();
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value()) << walletErrorMessage(st.code);

  expectNodeMatches(*master,
                    "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b",
                    "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
                    "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a");
}

TEST(Wallet_Slip10, Tv2Path0H)
{
  const auto seed = tv2Seed();
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto node = deriveOrDie(*master, "m/0'");
  expectNodeMatches(node,
                    "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d",
                    "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                    "0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037");
}

TEST(Wallet_Slip10, Tv2Path0H2147483647H)
{
  const auto seed = tv2Seed();
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  // 2147483647 = 2^31 - 1, the maximum non-hardened index.
  // The path uses 2147483647' so raw() = 0xFFFFFFFF.
  const auto node = deriveOrDie(*master, "m/0'/2147483647'");
  expectNodeMatches(node,
                    "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f",
                    "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                    "005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d");
}

TEST(Wallet_Slip10, Tv2Path0H2147483647H1H)
{
  const auto seed = tv2Seed();
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto node = deriveOrDie(*master, "m/0'/2147483647'/1'");
  expectNodeMatches(node,
                    "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90",
                    "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                    "002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45");
}

TEST(Wallet_Slip10, Tv2Path0H2147483647H1H2147483646H)
{
  const auto seed = tv2Seed();
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto node = deriveOrDie(*master, "m/0'/2147483647'/1'/2147483646'");
  expectNodeMatches(node,
                    "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a",
                    "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                    "00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b");
}

//  Master node parameter validation

TEST(Wallet_Slip10, MasterRejectsEmptySeed)
{
  WalletStatus st;
  auto m = slip10Master(nullptr, 0, &st);
  EXPECT_FALSE(m.has_value());
  EXPECT_EQ(st.code, WalletError::DerivationFailed);
}

TEST(Wallet_Slip10, MasterRejectsShortSeed)
{
  // SLIP-0010 requires seed length in [16, 64].
  const std::vector<uint8_t> seed(15, 0x00);
  WalletStatus st;
  auto m = slip10Master(seed, &st);
  EXPECT_FALSE(m.has_value());
  EXPECT_EQ(st.code, WalletError::DerivationFailed);
}

TEST(Wallet_Slip10, MasterRejectsLongSeed)
{
  const std::vector<uint8_t> seed(65, 0x00);
  WalletStatus st;
  auto m = slip10Master(seed, &st);
  EXPECT_FALSE(m.has_value());
  EXPECT_EQ(st.code, WalletError::DerivationFailed);
}

TEST(Wallet_Slip10, MasterAcceptsMinSeed)
{
  const std::vector<uint8_t> seed(16, 0x00);
  WalletStatus st;
  auto m = slip10Master(seed, &st);
  EXPECT_TRUE(m.has_value());
  EXPECT_EQ(m->depth, 0u);
  EXPECT_EQ(m->child_number, 0u);
}

TEST(Wallet_Slip10, MasterAcceptsMaxSeed)
{
  const std::vector<uint8_t> seed(64, 0x00);
  WalletStatus st;
  auto m = slip10Master(seed, &st);
  EXPECT_TRUE(m.has_value());
}

//  Child derivation — hardened only

TEST(Wallet_Slip10, RejectsNonHardenedChild)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  PathElement e;
  e.index = 0;
  e.hardened = false;

  WalletStatus st2;
  auto child = slip10DeriveChild(*master, e, &st2);
  EXPECT_FALSE(child.has_value());
  EXPECT_EQ(st2.code, WalletError::InvalidPath);
}

TEST(Wallet_Slip10, ChildDepthIncrements)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  PathElement e;
  e.index = 0;
  e.hardened = true;

  auto child = slip10DeriveChild(*master, e, &st);
  ASSERT_TRUE(child.has_value());
  EXPECT_EQ(child->depth, 1u);
  EXPECT_EQ(child->child_number, 0x80000000u); // hardened index 0
}

TEST(Wallet_Slip10, ChildChildNumber)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  PathElement e;
  e.index = 44;
  e.hardened = true;

  auto child = slip10DeriveChild(*master, e, &st);
  ASSERT_TRUE(child.has_value());
  EXPECT_EQ(child->child_number, 44u | 0x80000000u);
}

TEST(Wallet_Slip10, DerivePathFromMasterPreservesMaster)
{
  // Deriving a path must NOT mutate the master node.
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto master_copy = *master;

  WalletStatus st2;
  auto path = parseHdPath("m/0'/1'", &st2);
  ASSERT_TRUE(path.has_value());

  auto node = slip10DerivePath(*master, *path, &st2);
  ASSERT_TRUE(node.has_value());

  // Master must be unchanged.
  EXPECT_EQ(master->secret, master_copy.secret);
  EXPECT_EQ(master->chain_code, master_copy.chain_code);
  EXPECT_EQ(master->depth, master_copy.depth);
  EXPECT_EQ(master->child_number, master_copy.child_number);
}

TEST(Wallet_Slip10, DerivePathOnFailureLeavesMasterIntact)
{
  // A failing derivation must not corrupt the master.
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto master_copy = *master;

  // A path with a non-hardened component will fail at the first
  // non-hardened step. Let's build one manually.
  HdPath bad;
  bad.push(0, true);  // fine
  bad.push(0, false); // non-hardened, will fail
  bad.push(0, true);  // never reached

  WalletStatus st2;
  auto node = slip10DerivePath(*master, bad, &st2);
  EXPECT_FALSE(node.has_value());

  // Master must be unchanged.
  EXPECT_EQ(master->secret, master_copy.secret);
  EXPECT_EQ(master->chain_code, master_copy.chain_code);
}

//  Derived node mutations don't affect subsequent derivations

TEST(Wallet_Slip10, SiblingDerivationsAreIndependent)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  PathElement e0;
  e0.index = 0;
  e0.hardened = true;
  PathElement e1;
  e1.index = 1;
  e1.hardened = true;

  auto child0 = slip10DeriveChild(*master, e0, &st);
  auto child1 = slip10DeriveChild(*master, e1, &st);

  ASSERT_TRUE(child0.has_value());
  ASSERT_TRUE(child1.has_value());

  EXPECT_NE(child0->secret, child1->secret);
  EXPECT_NE(child0->chain_code, child1->chain_code);
}

//  wipeNode

TEST(Wallet_Slip10, WipeNodeClearsSecrets)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  EXPECT_FALSE(master->secret.isNull());
  EXPECT_FALSE(master->chain_code.isNull());

  wipeNode(*master);

  EXPECT_TRUE(master->secret.isNull());
  EXPECT_TRUE(master->chain_code.isNull());
  EXPECT_EQ(master->depth, 0u);
  EXPECT_EQ(master->child_number, 0u);
}

//  slip10PublicKey matches Crypto::derivePublicKey

TEST(Wallet_Slip10, PublicKeyMatchesCrypto)
{
  const auto seed = fromHexBytes("000102030405060708090a0b0c0d0e0f");
  WalletStatus st;
  auto master = slip10Master(seed, &st);
  ASSERT_TRUE(master.has_value());

  const auto pk = slip10PublicKey(*master);
  const auto pk_direct = Crypto::derivePublicKey(master->secret);

  EXPECT_EQ(pk, pk_direct);
}