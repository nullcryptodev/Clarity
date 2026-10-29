// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Crypto/BitcoinBip32.h"

using namespace Crypto;

namespace
{
  //  BIP84 test vector 1 (the canonical "abandon ... about" mnemonic).
  //  Account xpub at m/84'/0'/0', published in BIP84 itself.
  constexpr const char *kBip84AccountXpub =
      "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";

  //  First receiving address, m/84'/0'/0'/0/0.
  constexpr const char *kBip84FirstAddress =
      "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
} // namespace

TEST(Crypto_BitcoinBip32, ParsesBip84AccountXpub)
{
  std::string err;
  auto key = parseExtendedPubKey(kBip84AccountXpub,
                                 BitcoinNetwork::Mainnet, &err);
  ASSERT_TRUE(key.has_value()) << err;
  EXPECT_EQ(key->depth, 3u);
  EXPECT_EQ(key->child_number, 0x80000000u); // account is hardened

  // Round-trip through the encoder must reproduce the input exactly.
  EXPECT_EQ(encodeExtendedPubKey(*key, BitcoinNetwork::Mainnet),
            kBip84AccountXpub);
}

TEST(Crypto_BitcoinBip32, DerivesBip84FirstAddress)
{
  std::string err;
  auto account = parseExtendedPubKey(kBip84AccountXpub,
                                     BitcoinNetwork::Mainnet, &err);
  ASSERT_TRUE(account.has_value()) << err;

  auto receiving = derivePath(*account, {0, 0}, &err);
  ASSERT_TRUE(receiving.has_value()) << err;

  EXPECT_EQ(p2wpkhAddressFromPubkey(receiving->pubkey,
                                    BitcoinNetwork::Mainnet),
            kBip84FirstAddress);
}

TEST(Crypto_BitcoinBip32, RejectsHardenedPath)
{
  auto account = parseExtendedPubKey(kBip84AccountXpub,
                                     BitcoinNetwork::Mainnet);
  ASSERT_TRUE(account.has_value());

  std::string err;
  EXPECT_FALSE(derivePath(*account, {0x80000000u}, &err).has_value());
  EXPECT_FALSE(err.empty());
}

TEST(Crypto_BitcoinBip32, RejectsWrongNetworkVersion)
{
  std::string err;
  EXPECT_FALSE(parseExtendedPubKey(kBip84AccountXpub,
                                   BitcoinNetwork::Testnet, &err)
                   .has_value());
  EXPECT_NE(err.find("network"), std::string::npos) << err;
}

TEST(Crypto_BitcoinBip32, RejectsTamperedChecksum)
{
  std::string bad = kBip84AccountXpub;
  bad.back() = (bad.back() == '1') ? '2' : '1';
  EXPECT_FALSE(parseExtendedPubKey(bad, BitcoinNetwork::Mainnet)
                   .has_value());
}

TEST(Crypto_BitcoinBip32, DerivationIsDeterministic)
{
  auto account = parseExtendedPubKey(kBip84AccountXpub,
                                     BitcoinNetwork::Mainnet);
  ASSERT_TRUE(account.has_value());

  const std::string first =
      p2wpkhAddressFromPubkey(derivePath(*account, {0, 0})->pubkey,
                              BitcoinNetwork::Mainnet);
  for (int i = 0; i < 100; ++i)
  {
    EXPECT_EQ(p2wpkhAddressFromPubkey(derivePath(*account, {0, 0})->pubkey,
                                      BitcoinNetwork::Mainnet),
              first);
  }
}

TEST(Crypto_BitcoinBip32, DistinctIndicesGiveDistinctAddresses)
{
  auto account = parseExtendedPubKey(kBip84AccountXpub,
                                     BitcoinNetwork::Mainnet);
  ASSERT_TRUE(account.has_value());

  const std::string a0 =
      p2wpkhAddressFromPubkey(derivePath(*account, {0, 0})->pubkey,
                              BitcoinNetwork::Mainnet);
  const std::string a1 =
      p2wpkhAddressFromPubkey(derivePath(*account, {0, 1})->pubkey,
                              BitcoinNetwork::Mainnet);
  EXPECT_NE(a0, a1);
}

TEST(Crypto_BitcoinBip32, ParseDerivationTailAcceptsNonHardened)
{
  std::string err;
  auto tail = parseDerivationTail("m/0/7", &err);
  ASSERT_TRUE(tail.has_value()) << err;
  ASSERT_EQ(tail->size(), 2u);
  EXPECT_EQ((*tail)[0], 0u);
  EXPECT_EQ((*tail)[1], 7u);
}

TEST(Crypto_BitcoinBip32, ParseDerivationTailRejectsHardened)
{
  std::string err;
  EXPECT_FALSE(parseDerivationTail("m/0'/7", &err).has_value());
  EXPECT_FALSE(err.empty());
}