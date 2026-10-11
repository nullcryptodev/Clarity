// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <vector>

#include "Crypto/Types.h"

namespace Core
{
  //  One entry in a validator's consensus-key history. The interval
  //  is half-open: [valid_from_height, valid_until_height). A
  //  valid_until_height of zero means "current" — the entry covers
  //  every height from valid_from_height onward.
  //
  //  A vote or equivocation proof at height H verifies against the
  //  key whose range contains H. Ranges are gapless and
  //  non-overlapping by construction: a rotation sets the previous
  //  last entry's valid_until_height to the rotation height and the
  //  new entry's valid_from_height to the same value. If the ranges
  //  ever overlapped, a vote could verify under two different keys,
  //  which would make an equivocation proof ambiguous.
  //
  //  This is a companion to ValidatorInfo, not part of its wire
  //  format. See State::Keys::validatorKeyHistory.
  struct KeyRotation
  {
    Crypto::PublicKey key{};
    uint64_t valid_from_height{0};
    uint64_t valid_until_height{0}; // 0 = current
  };

  //  Fixed wire size of one entry: 32-byte key + 8-byte from
  //  + 8-byte until = 48 bytes. The history list is a 4-byte LE
  //  count followed by N entries, no per-entry framing.
  inline constexpr size_t KEY_ROTATION_WIRE_SIZE = 32 + 8 + 8;

  std::vector<uint8_t> encodeKeyHistory(
      const std::vector<KeyRotation> &history);

  bool decodeKeyHistory(const uint8_t *data, size_t len,
                        std::vector<KeyRotation> &out);

} // namespace Core