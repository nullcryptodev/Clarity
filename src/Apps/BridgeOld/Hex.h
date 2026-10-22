// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "Common/Json.h"

namespace Bridge::BridgeHex
{
  //  0x-prefixed (or bare) lower- or upper-case hex, decoded into
  //  bytes. Returns nullopt on any malformed input.
  std::optional<std::vector<uint8_t>> Decode(const std::string &s);

  //  Encode bytes as 0x-prefixed hex.
  std::string Encode(const uint8_t *data, size_t len);
  std::string Encode(const std::vector<uint8_t> &bytes);

  //  Encode a uint64 / uint32 as the canonical "0x…" hex string
  //  used by the RPC params (no leading zeros).
  std::string EncodeU64Hex(uint64_t v);
  std::string EncodeU32Hex(uint32_t v);

  //  Decode a "0x…" string back to uint64. Returns nullopt on
  //  malformed input.
  std::optional<uint64_t> DecodeU64Hex(const std::string &s);
} // namespace Bridge::BridgeHex