#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <optional>
#include <vector>

namespace Common
{
  // Base58 - uses cryptonotes special base58.
  // We should add the proper base58 too or replace this
  std::string encodeBase58(std::string_view data);
  bool decodeBase58(std::string_view enc, std::string &data);

  //  Base58Check, as used by Bitcoin for xpub/xprv, WIF, P2PKH,
  //  P2SH, and BIP38.
  //
  //  The existing Common::encodeBase58 / decodeBase58 are
  //  plain base58 (CryptoNote-style), which is what CCX addresses
  //  use. This module adds the checksum layer that Bitcoin
  //  serialization requires, without touching the plain variant
  //  (which has on-chain-committed callers).
  //
  //  encodeBase58Check(payload) =
  //      base58( payload || SHA256(SHA256(payload))[0..4] )
  //
  //  decodeBase58Check(s) verifies the trailing 4-byte
  //  double-SHA256 checksum and returns the payload without it.
  //  A checksum mismatch, an invalid base58 character, or a
  //  payload shorter than 4 bytes all return std::nullopt.
  //
  //  There is deliberately no "skip checksum" variant: the whole
  //  point of this format is the checksum, and every caller here
  //  must reject corruption.

  std::string encodeBase58Check(const std::vector<uint8_t> &payload);

  std::optional<std::vector<uint8_t>>
  decodeBase58Check(const std::string &encoded);

  // Base64
  std::string encodeBase64(std::string_view data);
  std::string decodeBase64(std::string_view data);
}