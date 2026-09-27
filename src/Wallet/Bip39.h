// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "WalletError.h"

namespace Wallet
{
  //  BIP-39: Mnemonic code for generating deterministic keys
  //
  //  A mnemonic is a sequence of words that encodes entropy plus a
  //  checksum. The entropy is what actually seeds the HD wallet; the
  //  words are a human-transcribable encoding of that entropy.
  //
  //  Supported entropy sizes:
  //    128 bits -> 12 words
  //    160 bits -> 15 words
  //    192 bits -> 18 words
  //    224 bits -> 21 words
  //    256 bits -> 24 words
  //
  //  We default to 256-bit (24 words). It's what modern wallets use.
  //
  //  This module does NOT derive keys. It only produces and consumes
  //  mnemonics. The mnemonic -> seed step is BIP-39's PBKDF2 with
  //  HMAC-SHA512, exposed as `mnemonicToSeed` below. Seeding the HD
  //  tree from that seed is SLIP-0010's job; see Slip10.h.

  //  Generation
  //
  //  Produce a fresh mnemonic using the platform CSPRNG. `strength_bits`
  //  must be one of {128, 160, 192, 224, 256}. Returns an empty string
  //  on failure (RNG failure, invalid strength).
  //
  //  Entropy source: Crypto::Random, which is the same Monocypher-backed
  //  RNG used elsewhere in the codebase.
  std::string generateMnemonic(int strength_bits = 256);

  //  Validation
  //
  //  Check whether a mnemonic is well-formed: correct word count,
  //  every word in the wordlist, checksum matches. Case-sensitive;
  //  mnemonics are lowercase by convention. Multiple consecutive
  //  spaces are collapsed before checking.
  //
  //  Returns WalletError::Ok on success. On failure, the returned
  //  error code tells you which check failed (InvalidWordCount,
  //  InvalidWord, or InvalidChecksum).
  WalletError validateMnemonic(std::string_view mnemonic);

  //  Entropy <-> mnemonic
  //
  //  Convert between raw entropy bytes and the mnemonic encoding.
  //  Entropy length must be one of {16, 20, 24, 28, 32} bytes.
  //
  //  For `entropyToMnemonic`, entropy must not be all zeros (it would
  //  encode to "abandon abandon ... about" — valid by checksum but
  //  suspiciously predictable). We don't reject it, but callers who
  //  care should check.
  std::optional<std::string> entropyToMnemonic(const std::vector<uint8_t> &entropy);
  std::optional<std::vector<uint8_t>> mnemonicToEntropy(std::string_view mnemonic);

  //  Seed derivation
  //
  //  BIP-39's mnemonic -> 64-byte seed step. PBKDF2-HMAC-SHA512 with
  //  2048 iterations, salt = "mnemonic" || passphrase.
  //
  //  The passphrase may be empty (the common case). It provides
  //  deniability: a wrong passphrase produces a completely different
  //  but still valid seed, so there's no way to prove a mnemonic
  //  encodes a particular wallet without knowing the passphrase.
  //
  //  Writes 64 bytes to `out_seed`. The seed is raw key material; the
  //  caller is responsible for wiping it after use (see
  //  Crypto::secureZero).
  //
  //  Note: the mnemonic must already be validated. This function does
  //  not re-validate; if given a malformed mnemonic it will still
  //  produce a deterministic seed, but the result will be garbage.
  void mnemonicToSeed(std::string_view mnemonic,
                      std::string_view passphrase,
                      uint8_t out_seed[64]) noexcept;

  //  Introspection
  //
  //  Index of a word in the wordlist, or -1 if not present.
  int wordIndex(std::string_view word) noexcept;

  //  Word at a given index, or nullptr if out of range.
  const char *wordAtIndex(int index) noexcept;

  //  Number of words for a given entropy strength. Returns 0 for
  //  unsupported strengths.
  constexpr int wordsForStrength(int strength_bits) noexcept
  {
    switch (strength_bits)
    {
    case 128:
      return 12;
    case 160:
      return 15;
    case 192:
      return 18;
    case 224:
      return 21;
    case 256:
      return 24;
    }
    return 0;
  }

  //  Number of entropy bytes for a given word count. Returns 0 for
  //  unsupported counts.
  constexpr int entropyBytesForWordCount(int word_count) noexcept
  {
    switch (word_count)
    {
    case 12:
      return 16;
    case 15:
      return 20;
    case 18:
      return 24;
    case 21:
      return 28;
    case 24:
      return 32;
    }
    return 0;
  }

} // namespace Wallet