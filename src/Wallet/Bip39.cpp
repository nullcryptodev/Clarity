// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Bip39.h"
#include "Bip39Wordlist.h"

#include "Crypto/Pbkdf2.h"
#include "Crypto/Random.h"
#include "Crypto/SecureZero.h"
#include "Crypto/Sha256.h" // BIP-39 checksum uses SHA-256, not SHA-512
#include "Crypto/Sha512.h"

#include <cstring>
#include <sstream>

namespace Wallet
{
  namespace
  {
    // BIP-39 checksum uses the first (entropy_bits / 32) bits of the
    // SHA-256 hash of the entropy.
    //
    // Example: 128 bits of entropy -> 4 checksum bits.
    //          256 bits of entropy -> 8 checksum bits.
    //
    // Total bits = entropy_bits + checksum_bits. Every 11 bits maps to
    // one word.

    // Split a string on ASCII whitespace, collapsing runs. Returns
    // the tokens in order. Empty input returns an empty vector.
    std::vector<std::string> splitWords(std::string_view s)
    {
      std::vector<std::string> out;
      size_t i = 0;
      while (i < s.size())
      {
        while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
          ++i;
        if (i >= s.size())
          break;
        size_t start = i;
        while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i])))
          ++i;
        out.emplace_back(s.substr(start, i - start));
      }
      return out;
    }
  } // namespace

  //  Introspection

  int wordIndex(std::string_view word) noexcept
  {
    // Linear scan. 2048 entries. Only ever called during mnemonic
    // validation and generation, both of which are user-interactive
    // speed. A hash map would be faster but adds static-init cost for
    // no benefit at this scale.
    for (size_t i = 0; i < BIP39_WORDLIST_SIZE; ++i)
    {
      if (word == BIP39_ENGLISH[i])
        return static_cast<int>(i);
    }
    return -1;
  }

  const char *wordAtIndex(int index) noexcept
  {
    if (index < 0 || static_cast<size_t>(index) >= BIP39_WORDLIST_SIZE)
      return nullptr;
    return BIP39_ENGLISH[static_cast<size_t>(index)];
  }

  //  Entropy -> Mnemonic

  std::optional<std::string> entropyToMnemonic(const std::vector<uint8_t> &entropy)
  {
    // Entropy must be one of {16, 20, 24, 28, 32} bytes.
    const int word_count = entropyBytesForWordCount(0); // placeholder
    (void)word_count;

    const size_t entropy_len = entropy.size();
    const int entropy_bits = static_cast<int>(entropy_len * 8);
    const int words = wordsForStrength(entropy_bits);
    if (words == 0)
      return std::nullopt;

    // Compute checksum: first (entropy_bits / 32) bits of SHA-256.
    uint8_t hash[32];
    Crypto::sha256(entropy.data(), entropy.size(), hash);

    const int checksum_bits = entropy_bits / 32;
    const int total_bits = entropy_bits + checksum_bits;

    // The bit stream is: entropy || checksum_bits.
    // Every 11 bits is one word index.

    std::string out;
    out.reserve(static_cast<size_t>(words) * 12); // rough

    auto getBit = [&](int bit_pos) -> int
    {
      // bit 0 is the MSB of the first entropy byte.
      if (bit_pos < entropy_bits)
      {
        const int byte_idx = bit_pos / 8;
        const int bit_in_byte = 7 - (bit_pos % 8);
        return (entropy[byte_idx] >> bit_in_byte) & 1;
      }
      const int hash_bit = bit_pos - entropy_bits;
      const int byte_idx = hash_bit / 8;
      const int bit_in_byte = 7 - (hash_bit % 8);
      return (hash[byte_idx] >> bit_in_byte) & 1;
    };

    for (int w = 0; w < words; ++w)
    {
      int idx = 0;
      for (int b = 0; b < 11; ++b)
      {
        idx = (idx << 1) | getBit(w * 11 + b);
      }
      if (w > 0)
        out.push_back(' ');
      out += BIP39_ENGLISH[static_cast<size_t>(idx)];
    }

    Crypto::secureZero(hash, sizeof(hash));
    return out;
  }

  //  Mnemonic -> Entropy

  std::optional<std::vector<uint8_t>> mnemonicToEntropy(std::string_view mnemonic)
  {
    const auto words = splitWords(mnemonic);
    const int word_count = static_cast<int>(words.size());
    const int entropy_len = entropyBytesForWordCount(word_count);
    if (entropy_len == 0)
      return std::nullopt;

    const int entropy_bits = entropy_len * 8;
    const int checksum_bits = entropy_bits / 32;
    const int total_bits = entropy_bits + checksum_bits;

    // Convert words to 11-bit indices.
    std::vector<uint8_t> entropy(static_cast<size_t>(entropy_len), 0);
    uint8_t hash[32];
    // We'll compute the hash after filling entropy.

    // Bit stream assembly.
    auto setBit = [&](int bit_pos, int bit)
    {
      if (bit_pos >= entropy_bits)
        return; // checksum bits are verified separately
      const int byte_idx = bit_pos / 8;
      const int bit_in_byte = 7 - (bit_pos % 8);
      if (bit)
        entropy[byte_idx] |= (1 << bit_in_byte);
    };

    // Collect all bits from the words, plus remember the checksum bits.
    std::vector<uint8_t> checksum_bits_in(static_cast<size_t>(checksum_bits));

    for (int w = 0; w < word_count; ++w)
    {
      const int idx = wordIndex(words[static_cast<size_t>(w)]);
      if (idx < 0)
        return std::nullopt;

      for (int b = 0; b < 11; ++b)
      {
        const int bit = (idx >> (10 - b)) & 1;
        const int pos = w * 11 + b;
        if (pos < entropy_bits)
          setBit(pos, bit);
        else
          checksum_bits_in[static_cast<size_t>(pos - entropy_bits)] = static_cast<uint8_t>(bit);
      }
    }

    // Verify checksum.
    Crypto::sha256(entropy.data(), entropy.size(), hash);
    for (int b = 0; b < checksum_bits; ++b)
    {
      const int byte_idx = b / 8;
      const int bit_in_byte = 7 - (b % 8);
      const int expected = (hash[byte_idx] >> bit_in_byte) & 1;
      if (expected != checksum_bits_in[static_cast<size_t>(b)])
      {
        Crypto::secureZero(hash, sizeof(hash));
        return std::nullopt;
      }
    }

    Crypto::secureZero(hash, sizeof(hash));
    return entropy;
  }

  //  Validation

  WalletError validateMnemonic(std::string_view mnemonic)
  {
    const auto words = splitWords(mnemonic);
    if (words.empty())
      return WalletError::InvalidMnemonic;

    const int word_count = static_cast<int>(words.size());
    if (entropyBytesForWordCount(word_count) == 0)
      return WalletError::InvalidWordCount;

    // Word membership check.
    for (const auto &w : words)
    {
      if (wordIndex(w) < 0)
        return WalletError::InvalidWord;
    }

    // Checksum check.
    const auto entropy = mnemonicToEntropy(mnemonic);
    if (!entropy)
      return WalletError::InvalidChecksum;

    return WalletError::Ok;
  }

  //  Generation

  std::string generateMnemonic(int strength_bits)
  {
    const int words = wordsForStrength(strength_bits);
    if (words == 0)
      return {};

    const int entropy_bytes = entropyBytesForWordCount(words);
    if (entropy_bytes == 0)
      return {};

    std::vector<uint8_t> entropy(static_cast<size_t>(entropy_bytes));
    Crypto::randomBytes(entropy.data(), entropy.size());

    auto m = entropyToMnemonic(entropy);
    Crypto::secureZero(entropy.data(), entropy.size());

    if (!m)
      return {};
    return *m;
  }

  //  Seed derivation

  void mnemonicToSeed(std::string_view mnemonic,
                      std::string_view passphrase,
                      uint8_t out_seed[64]) noexcept
  {
    // BIP-39 uses PBKDF2-HMAC-SHA512, 2048 iterations, salt =
    // "mnemonic" || passphrase. The Crypto::pbkdf2Bip39 helper does
    // exactly this and is already validated against BIP-39 test
    // vectors in Tests/Wallet/Pbkdf2.cpp.
    Crypto::pbkdf2Bip39(mnemonic, passphrase, out_seed);
  }

} // namespace Wallet