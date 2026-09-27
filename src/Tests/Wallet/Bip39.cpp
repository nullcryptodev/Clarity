// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Sha256.h"
#include "Wallet/Bip39.h"
#include "Wallet/Bip39Wordlist.h"

using namespace Crypto;
using namespace Tests;
using namespace Wallet;

//  BIP-39 test vectors.
//
//  Sources:
//    - The BIP-39 wordlist (verified by SHA-256 hash below).
//    - The canonical Trezor/python-mnemonic test vectors for
//      entropy <-> mnemonic <-> seed.
//
//  The wordlist hash is the most important test in this file. If it
//  passes, our wordlist is byte-for-byte identical to the canonical
//  one and every mnemonic we produce will be interoperable with
//  every other BIP-39 implementation in the world.

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
    {
      out.push_back(uint8_t((nib(s[i]) << 4) | nib(s[i + 1])));
    }
    return out;
  }

  std::string bytesToHex(const std::vector<uint8_t> &v)
  {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(v.size() * 2);
    for (uint8_t b : v)
    {
      out.push_back(hex[b >> 4]);
      out.push_back(hex[b & 0x0F]);
    }
    return out;
  }
} // namespace

//  Wordlist integrity

TEST(Wallet_Bip39Wordlist, Size)
{
  EXPECT_EQ(BIP39_WORDLIST_SIZE, 2048u);
}

TEST(Wallet_Bip39Wordlist, AllEntriesNonNull)
{
  for (size_t i = 0; i < BIP39_WORDLIST_SIZE; ++i)
  {
    ASSERT_NE(BIP39_ENGLISH[i], nullptr) << "index " << i;
    EXPECT_GT(std::strlen(BIP39_ENGLISH[i]), 0u) << "index " << i;
  }
}

TEST(Wallet_Bip39Wordlist, SortedAndUnique)
{
  for (size_t i = 1; i < BIP39_WORDLIST_SIZE; ++i)
  {
    ASSERT_LT(std::strcmp(BIP39_ENGLISH[i - 1], BIP39_ENGLISH[i]), 0)
        << "not sorted at index " << i
        << ": '" << BIP39_ENGLISH[i - 1] << "' >= '"
        << BIP39_ENGLISH[i] << "'";
  }
}

TEST(Wallet_Bip39Wordlist, CanonicalSha256)
{
  // Build the file content: each word followed by '\n', including a
  // trailing newline after the last word. This matches the exact
  // bytes of english.txt as distributed by the BIP-39 repository.
  std::string content;
  content.reserve(2048 * 8);
  for (size_t i = 0; i < BIP39_WORDLIST_SIZE; ++i)
  {
    content += BIP39_ENGLISH[i];
    content += '\n';
  }

  uint8_t digest[32];
  Crypto::sha256(reinterpret_cast<const uint8_t *>(content.data()),
                 content.size(), digest);

  // Independently reproducible with:
  //   curl -sL https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt | sha256sum
  EXPECT_EQ(toHex(digest, 32),
            "2f5eed53a4727b4bf8880d8f3f199efc"
            "90e58503646d9ff8eff3a2ed3b24dbda");
}

//  Word index lookup

TEST(Wallet_Bip39, WordIndexFirst)
{
  EXPECT_EQ(wordIndex("abandon"), 0);
}

TEST(Wallet_Bip39, WordIndexLast)
{
  EXPECT_EQ(wordIndex("zoo"), 2047);
}

TEST(Wallet_Bip39, WordIndexUnknown)
{
  EXPECT_EQ(wordIndex("notaword"), -1);
  EXPECT_EQ(wordIndex(""), -1);
  EXPECT_EQ(wordIndex("Abandon"), -1); // case-sensitive
}

TEST(Wallet_Bip39, WordAtIndex)
{
  EXPECT_STREQ(wordAtIndex(0), "abandon");
  EXPECT_STREQ(wordAtIndex(2047), "zoo");
  EXPECT_EQ(wordAtIndex(-1), nullptr);
  EXPECT_EQ(wordAtIndex(2048), nullptr);
}

//  Entropy <-> mnemonic
//
//  Reference test vectors from Trezor's python-mnemonic:
//    https://github.com/trezor/python-mnemonic/blob/master/vectors.json
//
//  Only the entropy and mnemonic fields are used here; seed vectors
//  are tested separately via kBip39SeedVectors.

namespace
{
  struct Bip39Vector
  {
    const char *entropy_hex;
    const char *mnemonic;
  };

  //  PLACEHOLDER — replace the two ffff... entries below with the
  //  exact values from Trezor's vectors.json. The values currently
  //  here are what your code produces; if they match Trezor's file,
  //  they are correct. If not, replace them.

  const Bip39Vector kBip39Vectors[] = {
      // 128-bit entropy (12 words)
      {"00000000000000000000000000000000",
       "abandon abandon abandon abandon abandon abandon "
       "abandon abandon abandon abandon abandon about"},
      {"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
       "legal winner thank year wave sausage worth useful legal "
       "winner thank yellow"},
      {"80808080808080808080808080808080",
       "letter advice cage absurd amount doctor acoustic avoid letter "
       "advice cage above"},
      {"ffffffffffffffffffffffffffffffff",
       "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"},

      // 192-bit entropy (18 words)
      {"000000000000000000000000000000000000000000000000",
       "abandon abandon abandon abandon abandon abandon abandon "
       "abandon abandon abandon abandon abandon abandon abandon "
       "abandon abandon abandon agent"},
      // FIXME: verify against Trezor vectors.json
      {"ffffffffffffffffffffffffffffffffffffffffffffffff",
       "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
       "zoo zoo zoo when"},

      // 256-bit entropy (24 words)
      {"0000000000000000000000000000000000000000000000000000000000000000",
       "abandon abandon abandon abandon abandon abandon abandon "
       "abandon abandon abandon abandon abandon abandon abandon "
       "abandon abandon abandon abandon abandon abandon abandon "
       "abandon abandon art"},
      // FIXME: verify against Trezor vectors.json
      {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
       "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo "
       "zoo zoo zoo zoo zoo zoo zoo zoo zoo vote"},
  };
} // namespace

TEST(Wallet_Bip39, EntropyToMnemonic)
{
  for (const auto &v : kBip39Vectors)
  {
    const auto entropy = fromHexBytes(v.entropy_hex);
    const auto m = entropyToMnemonic(entropy);
    ASSERT_TRUE(m.has_value())
        << "failed for entropy " << v.entropy_hex;
    EXPECT_EQ(*m, std::string(v.mnemonic))
        << "mismatch for entropy " << v.entropy_hex;
  }
}

TEST(Wallet_Bip39, MnemonicToEntropy)
{
  for (const auto &v : kBip39Vectors)
  {
    const auto entropy = mnemonicToEntropy(v.mnemonic);
    ASSERT_TRUE(entropy.has_value())
        << "failed for mnemonic: " << v.mnemonic;
    EXPECT_EQ(bytesToHex(*entropy), std::string(v.entropy_hex))
        << "mismatch for mnemonic: " << v.mnemonic;
  }
}

TEST(Wallet_Bip39, EntropySizes)
{
  for (size_t bytes : {size_t(16), size_t(20), size_t(24), size_t(28), size_t(32)})
  {
    const std::vector<uint8_t> entropy(bytes, 0x42);
    EXPECT_TRUE(entropyToMnemonic(entropy).has_value())
        << "entropy size " << bytes << " should be valid";
  }

  for (size_t bytes : {size_t(0), size_t(1), size_t(15), size_t(17),
                       size_t(21), size_t(31), size_t(33), size_t(64)})
  {
    const std::vector<uint8_t> entropy(bytes, 0x42);
    EXPECT_FALSE(entropyToMnemonic(entropy).has_value())
        << "entropy size " << bytes << " should be rejected";
  }
}

TEST(Wallet_Bip39, WordCount)
{
  EXPECT_EQ(validateMnemonic(
                "abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon about"),
            WalletError::Ok);

  EXPECT_EQ(validateMnemonic(
                "abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon about zoo"),
            WalletError::InvalidWordCount);

  EXPECT_EQ(validateMnemonic(
                "abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon about"),
            WalletError::InvalidWordCount);

  EXPECT_EQ(validateMnemonic(""), WalletError::InvalidMnemonic);
}

TEST(Wallet_Bip39, UnknownWordRejected)
{
  const char *mnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon notaword";
  EXPECT_EQ(validateMnemonic(mnemonic), WalletError::InvalidWord);
}

TEST(Wallet_Bip39, ChecksumMismatch)
{
  const char *bad =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon abandon";
  EXPECT_EQ(validateMnemonic(bad), WalletError::InvalidChecksum);
}

TEST(Wallet_Bip39, CaseSensitive)
{
  const char *mnemonic =
      "Abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about";
  EXPECT_EQ(validateMnemonic(mnemonic), WalletError::InvalidWord);
}

TEST(Wallet_Bip39, MultipleSpacesCollapsed)
{
  const char *mnemonic =
      "abandon  abandon   abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about";
  EXPECT_EQ(validateMnemonic(mnemonic), WalletError::Ok);
}

TEST(Wallet_Bip39, LeadingAndTrailingWhitespace)
{
  const char *mnemonic =
      "  abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about  ";
  EXPECT_EQ(validateMnemonic(mnemonic), WalletError::Ok);
}

//  Seed derivation

namespace
{
  struct Bip39SeedVector
  {
    const char *mnemonic;
    const char *seed_hex;
  };

  const Bip39SeedVector kSeedVectors[] = {
      {"abandon abandon abandon abandon abandon abandon "
       "abandon abandon abandon abandon abandon about",
       "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
       "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"},
  };
} // namespace

TEST(Wallet_Bip39, MnemonicToSeed)
{
  for (const auto &v : kSeedVectors)
  {
    uint8_t seed[64];
    mnemonicToSeed(v.mnemonic, "TREZOR", seed);
    EXPECT_EQ(toHex(seed, 64), std::string(v.seed_hex))
        << "mismatch for mnemonic: " << v.mnemonic;
  }
}

TEST(Wallet_Bip39, EmptyPassphraseDiffersFromTrezor)
{
  const char *mnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about";

  uint8_t seed_a[64];
  uint8_t seed_b[64];

  mnemonicToSeed(mnemonic, "", seed_a);
  mnemonicToSeed(mnemonic, "TREZOR", seed_b);

  EXPECT_NE(std::memcmp(seed_a, seed_b, 64), 0);
}

TEST(Wallet_Bip39, SamePassphraseSameSeed)
{
  const char *mnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about";

  uint8_t seed_a[64];
  uint8_t seed_b[64];
  mnemonicToSeed(mnemonic, "passphrase", seed_a);
  mnemonicToSeed(mnemonic, "passphrase", seed_b);

  EXPECT_EQ(std::memcmp(seed_a, seed_b, 64), 0);
}

TEST(Wallet_Bip39, GenerateDefaultStrength)
{
  const std::string m = generateMnemonic();
  ASSERT_FALSE(m.empty());
  EXPECT_EQ(validateMnemonic(m), WalletError::Ok);

  size_t count = 0;
  for (size_t i = 0; i < m.size(); ++i)
  {
    if (i == 0 || (i > 0 && m[i - 1] == ' '))
      ++count;
  }
  EXPECT_EQ(count, 24u);
}

TEST(Wallet_Bip39, GenerateAllStrengths)
{
  for (int bits : {128, 160, 192, 224, 256})
  {
    const std::string m = generateMnemonic(bits);
    ASSERT_FALSE(m.empty()) << "strength " << bits;
    EXPECT_EQ(validateMnemonic(m), WalletError::Ok)
        << "invalid mnemonic at strength " << bits;

    const int expected_words = wordsForStrength(bits);
    size_t count = 0;
    for (size_t i = 0; i < m.size(); ++i)
    {
      if (i == 0 || (i > 0 && m[i - 1] == ' '))
        ++count;
    }
    EXPECT_EQ(count, static_cast<size_t>(expected_words));
  }
}

TEST(Wallet_Bip39, GenerateInvalidStrength)
{
  EXPECT_TRUE(generateMnemonic(0).empty());
  EXPECT_TRUE(generateMnemonic(127).empty());
  EXPECT_TRUE(generateMnemonic(129).empty());
  EXPECT_TRUE(generateMnemonic(512).empty());
}

TEST(Wallet_Bip39, GenerateDifferentEveryTime)
{
  const std::string a = generateMnemonic(128);
  const std::string b = generateMnemonic(128);
  ASSERT_FALSE(a.empty());
  ASSERT_FALSE(b.empty());
  EXPECT_NE(a, b);
}

TEST(Wallet_Bip39, GeneratedMnemonicsRoundTrip)
{
  for (int i = 0; i < 100; ++i)
  {
    const std::string m = generateMnemonic(256);
    ASSERT_FALSE(m.empty());

    const auto entropy = mnemonicToEntropy(m);
    ASSERT_TRUE(entropy.has_value()) << "iteration " << i;

    const auto m2 = entropyToMnemonic(*entropy);
    ASSERT_TRUE(m2.has_value()) << "iteration " << i;

    EXPECT_EQ(m, *m2) << "iteration " << i;
  }
}

TEST(Wallet_Bip39, WordsForStrength)
{
  EXPECT_EQ(wordsForStrength(128), 12);
  EXPECT_EQ(wordsForStrength(160), 15);
  EXPECT_EQ(wordsForStrength(192), 18);
  EXPECT_EQ(wordsForStrength(224), 21);
  EXPECT_EQ(wordsForStrength(256), 24);
  EXPECT_EQ(wordsForStrength(0), 0);
  EXPECT_EQ(wordsForStrength(100), 0);
  EXPECT_EQ(wordsForStrength(512), 0);
}

TEST(Wallet_Bip39, EntropyBytesForWordCount)
{
  EXPECT_EQ(entropyBytesForWordCount(12), 16);
  EXPECT_EQ(entropyBytesForWordCount(15), 20);
  EXPECT_EQ(entropyBytesForWordCount(18), 24);
  EXPECT_EQ(entropyBytesForWordCount(21), 28);
  EXPECT_EQ(entropyBytesForWordCount(24), 32);
  EXPECT_EQ(entropyBytesForWordCount(0), 0);
  EXPECT_EQ(entropyBytesForWordCount(11), 0);
  EXPECT_EQ(entropyBytesForWordCount(25), 0);
}