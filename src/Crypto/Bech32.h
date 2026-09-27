// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Crypto
{
  //  Bech32 / Bech32m (BIP-173, BIP-350)
  //
  //  Human-readable, checksummed encoding for binary payloads. We use it
  //  for CLRTY addresses: the human-readable part (HRP) is the network
  //  prefix, and the data part is the witness version byte followed by
  //  the 32-byte account public key.
  //
  //  This module is deliberately payload-agnostic: it knows nothing
  //  about addresses, networks, or witness versions. Callers compose
  //  those concerns. Wallet::AddressCodec does the address-specific
  //  wrapping; see the Wallet module.
  //
  //  Both encode and decode are strict:
  //    - Lowercase only on encode. Decode accepts lowercase or uppercase
  //      but not mixed.
  //    - Maximum total length 90 characters (BIP-173 limit).
  //    - HRP must be 1-83 characters, ASCII 33-126.
  //    - Data part must be at least 6 characters (checksum).
  //    - Rejects any character outside the Bech32 charset.
  //
  //  We default to Bech32m (BIP-350). The Bech32 variant is supported
  //  for decoding only, so legacy addresses can be read if they ever
  //  appear. New encodings should always use Bech32m.

  inline constexpr size_t BECH32_CHECKSUM_LENGTH = 6;
  inline constexpr size_t BECH32_MAX_LENGTH = 90;
  inline constexpr size_t BECH32_MAX_HRP_LENGTH = 83;

  enum class Bech32Encoding
  {
    Bech32,  // BIP-173, constant 1. Legacy. Decode only.
    Bech32m, // BIP-350, constant 0x2bc830a3. Default.
  };

  enum class Bech32Error
  {
    Ok = 0,
    Empty,
    TooLong,
    InvalidHrpLength,
    InvalidHrpCharacter,
    MixedCase,
    NoSeparator,
    InvalidDataCharacter,
    ChecksumMismatch,
    InvalidPadding,
  };

  const char *bech32ErrorName(Bech32Error e) noexcept;

  // Encode `data` (raw bytes) with the given HRP and checksum variant.
  // Returns an empty string on failure. `data` must not be empty.
  //
  // The internal 8-to-5 bit conversion is applied with padding, matching
  // how BIP-173's reference implementation and every wallet in the
  // ecosystem encode address payloads.
  std::string bech32Encode(std::string_view hrp,
                           const std::vector<uint8_t> &data,
                           Bech32Encoding encoding = Bech32Encoding::Bech32m);

  // Decode a Bech32m (or Bech32) string.
  //
  // On success, writes the raw payload bytes (post-5-bit-unpacking) to
  // `out_data`, the HRP to `out_hrp`, and the matched variant to
  // `out_encoding`. Returns Bech32Error::Ok.
  //
  // To require a specific variant, callers should check `out_encoding`
  // after a successful call. The two checksum constants are distinct,
  // so a string encoded as one never verifies as the other.
  Bech32Error bech32Decode(std::string_view input,
                           std::vector<uint8_t> &out_data,
                           std::string &out_hrp,
                           Bech32Encoding &out_encoding);

  //  Low-level helpers
  //
  //  Exposed for tests and for callers that need to work with 5-bit
  //  groups directly (e.g. segwit address encoding in a future
  //  light-client protocol).
  //
  //  `pad == true` pads with zero bits to the next boundary.
  //  `pad == false` requires the input to be exactly representable
  //  (no non-zero padding, no more than 4 leftover bits).

  bool convertBitsTo5(const uint8_t *in, size_t in_len,
                      std::vector<uint8_t> &out,
                      bool pad) noexcept;

  bool convertBitsFrom5(const uint8_t *in, size_t in_len,
                        std::vector<uint8_t> &out,
                        bool pad) noexcept;

} // namespace Crypto