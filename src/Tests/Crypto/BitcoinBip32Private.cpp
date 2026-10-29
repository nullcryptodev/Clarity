// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Crypto/BitcoinBip32Private.h"

#include <string>
#include <vector>

using namespace Crypto;

namespace
{
  std::vector<uint8_t> hexToBytes(const std::string &hex)
  {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
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
    for (size_t i = 0; i + 1 < hex.size(); i += 2)
    {
      int hi = nib(hex[i]);
      int lo = nib(hex[i + 1]);
      if (hi < 0 || lo < 0)
        return {};
      out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
  }

  std::string bytesToHex(const std::array<uint8_t, 33> &a)
  {
    static const char H[] = "0123456789abcdef";
    std::string s;
    s.reserve(a.size() * 2);
    for (uint8_t b : a)
    {
      s.push_back(H[b >> 4]);
      s.push_back(H[b & 0xF]);
    }
    return s;
  }
} // namespace

//  ---------------------------------------------------------------------
//  BIP32 test vector 1
//
//  Seed: 000102030405060708090a0b0c0d0e0f
//  Chain:
//    m
//    m/0'
//    m/0'/1
//    m/0'/1/2'
//    m/0'/1/2'/2
//    m/0'/1/2'/2/1000000000
//
//  The BIP publishes the xprv and xpub at every node; we check a
//  representative subset (the account and the two hardened-to-public
//  boundaries) rather than every single step, which keeps the test
//  readable while still catching any off-by-one in the chain.
//  ---------------------------------------------------------------------

TEST(Crypto_BitcoinBip32Private, Vector1_XprvAtMPath)
{
  const auto seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
  ASSERT_EQ(seed.size(), 16u);

  std::string err;
  auto master = masterFromSeed(seed, &err);
  ASSERT_TRUE(master.has_value()) << err;

  const std::string xprv = encodeExtendedPrivKey(*master,
                                                 BitcoinNetwork::Mainnet);
  EXPECT_EQ(xprv,
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");

  auto xpub = toXpub(*master, &err);
  ASSERT_TRUE(xpub.has_value()) << err;
  EXPECT_EQ(encodeExtendedPubKey(*xpub, BitcoinNetwork::Mainnet),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8");
}

TEST(Crypto_BitcoinBip32Private, Vector1_ChainToM0h1)
{
  const auto seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
  auto master = masterFromSeed(seed);
  ASSERT_TRUE(master.has_value());

  std::string err;
  //  m/0'
  auto m0h = derivePathPriv(*master, {0x80000000u}, &err);
  ASSERT_TRUE(m0h.has_value()) << err;

  //  m/0'/1
  auto m0h1 = derivePathPriv(*m0h, {1u}, &err);
  ASSERT_TRUE(m0h1.has_value()) << err;

  auto xpub = toXpub(*m0h1, &err);
  ASSERT_TRUE(xpub.has_value()) << err;
  EXPECT_EQ(encodeExtendedPubKey(*xpub, BitcoinNetwork::Mainnet),
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ");
}

//  ---------------------------------------------------------------------
//  Cross-consistency: private and public non-hardened derivation must
//  agree on the child pubkey.
//
//  For a handful of non-hardened indices, derive the child xprv via
//  deriveChildPriv(parent, i) and the child xpub via
//  deriveChild(toXpub(parent), i). toXpub(derived xprv) must equal
//  that xpub, byte for byte (including the chain code — same
//  arithmetic, same HMAC input).
//  ---------------------------------------------------------------------

TEST(Crypto_BitcoinBip32Private, NonHardenedAgreesWithPublicDerivation)
{
  const auto seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
  auto master = masterFromSeed(seed);
  ASSERT_TRUE(master.has_value());

  std::string err;
  auto account = derivePathPriv(*master, {0x80000000u}, &err);
  ASSERT_TRUE(account.has_value()) << err;

  auto account_pub = toXpub(*account, &err);
  ASSERT_TRUE(account_pub.has_value()) << err;

  for (uint32_t i : {0u, 1u, 7u, 42u, 999u})
  {
    auto priv_child = deriveChildPriv(*account, i, &err);
    ASSERT_TRUE(priv_child.has_value()) << err;

    auto priv_child_pub = toXpub(*priv_child, &err);
    ASSERT_TRUE(priv_child_pub.has_value()) << err;

    auto pub_child = deriveChild(*account_pub, i, &err);
    ASSERT_TRUE(pub_child.has_value()) << err;

    EXPECT_EQ(priv_child_pub->pubkey, pub_child->pubkey)
        << "mismatch at index " << i;
    EXPECT_EQ(priv_child_pub->chaincode, pub_child->chaincode)
        << "chaincode mismatch at index " << i;
    EXPECT_EQ(priv_child_pub->child_number, pub_child->child_number);
  }
}

//  ---------------------------------------------------------------------
//  BIP84 account xpub for test vector 1 mnemonic.
//
//  "abandon abandon abandon abandon abandon abandon abandon abandon
//   abandon abandon abandon about"
//
//  BIP39 seed (passphrase "") =
//    5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
//
//  BIP84 account path m/84'/0'/0', published account xpub =
//    xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V
//
//  This is the exact xpub that BitcoinBip32.cpp's
//  DerivesBip84FirstAddress test uses. Getting the same string here
//  closes the loop: bip84AccountXpub(seed) == the account xpub the
//  bridge will use to derive user deposit addresses.
//  ---------------------------------------------------------------------

TEST(Crypto_BitcoinBip32Private, Bip84AccountXpubMatchesPublishedVector)
{
  const auto seed = hexToBytes(
      "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
      "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
  ASSERT_EQ(seed.size(), 64u);

  std::string err;
  auto account_xpub = bip84AccountXpub(seed, BitcoinNetwork::Mainnet, &err);
  ASSERT_TRUE(account_xpub.has_value()) << err;

  EXPECT_EQ(encodeExtendedPubKey(*account_xpub, BitcoinNetwork::Mainnet),
            "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V");

  //  And that xpub must produce the BIP84 first receiving address
  //  when fed through the public derivation path. This is the same
  //  assertion BitcoinBip32.cpp makes, but sourced from the seed —
  //  proving the end-to-end chain (seed -> account xpub -> address)
  //  agrees with itself.
  auto receiving = derivePath(*account_xpub, {0u, 0u}, &err);
  ASSERT_TRUE(receiving.has_value()) << err;
  EXPECT_EQ(p2wpkhAddressFromPubkey(receiving->pubkey,
                                    BitcoinNetwork::Mainnet),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
}

//  ---------------------------------------------------------------------
//  Parse-roundtrip and error cases
//  ---------------------------------------------------------------------

TEST(Crypto_BitcoinBip32Private, XprvRoundTrip)
{
  const auto seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
  auto master = masterFromSeed(seed);
  ASSERT_TRUE(master.has_value());

  const std::string encoded =
      encodeExtendedPrivKey(*master, BitcoinNetwork::Mainnet);
  auto parsed = parseExtendedPrivKey(encoded, BitcoinNetwork::Mainnet);
  ASSERT_TRUE(parsed.has_value());

  EXPECT_EQ(parsed->key, master->key);
  EXPECT_EQ(parsed->chaincode, master->chaincode);
  EXPECT_EQ(parsed->depth, master->depth);
}

TEST(Crypto_BitcoinBip32Private, RejectsWrongNetworkVersion)
{
  const auto seed = hexToBytes("000102030405060708090a0b0c0d0e0f");
  auto master = masterFromSeed(seed);
  ASSERT_TRUE(master.has_value());

  const std::string encoded =
      encodeExtendedPrivKey(*master, BitcoinNetwork::Mainnet);

  std::string err;
  EXPECT_FALSE(parseExtendedPrivKey(encoded, BitcoinNetwork::Testnet, &err)
                   .has_value());
  EXPECT_NE(err.find("network"), std::string::npos) << err;
}

TEST(Crypto_BitcoinBip32Private, ParseFullPathAcceptsHardened)
{
  std::string err;
  auto path = parseFullPath("m/84'/0'/0'", &err);
  ASSERT_TRUE(path.has_value()) << err;
  ASSERT_EQ(path->size(), 3u);
  EXPECT_EQ((*path)[0], 0x80000054u);
  EXPECT_EQ((*path)[1], 0x80000000u);
  EXPECT_EQ((*path)[2], 0x80000000u);
}

TEST(Crypto_BitcoinBip32Private, ParseFullPathAcceptsMixed)
{
  std::string err;
  auto path = parseFullPath("m/84'/0'/0'/0/5", &err);
  ASSERT_TRUE(path.has_value()) << err;
  ASSERT_EQ(path->size(), 5u);
  EXPECT_EQ((*path)[0], 0x80000054u);
  EXPECT_EQ((*path)[1], 0x80000000u);
  EXPECT_EQ((*path)[2], 0x80000000u);
  EXPECT_EQ((*path)[3], 0x00000000u);
  EXPECT_EQ((*path)[4], 0x00000005u);
}