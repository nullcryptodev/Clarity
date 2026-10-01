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

#include "Common/Json.h"
#include "Crypto/Types.h"

namespace Node
{
  class Node;
}

namespace Rpc
{
  //  Encoding conventions
  //  --------------------
  //
  //  Numeric quantities (balances, fees, nonces, heights, token IDs,
  //  supplies, reserve amounts, etc.):
  //
  //      On the wire:  JSON string, "0x" prefix, lowercase hex,
  //                    no leading zeros. Zero is "0x0".
  //
  //      As params:    Accepts "0x"-prefixed hex, decimal string, or
  //                    JSON number. A bare "26" means decimal 26;
  //                    "0x26" means 38. The prefix disambiguates.
  //
  //      Reason: JS clients lose precision above 2^53. Amounts and
  //      reserves routinely exceed that. Hex strings avoid the cliff.
  //
  //  Hashes (block hash, tx hash, state root, tx root, receipts root,
  //  validator-set root):
  //
  //      On the wire:  JSON string, "0x" prefix, 64 lowercase hex.
  //      As params:    "0x"-prefixed or bare 64-char hex.
  //
  //      Reason: hashes are opaque lookup keys. Clients format them
  //      uniformly with the 0x prefix.
  //
  //  Addresses (Crypto::Address = 32-byte Ed25519 pubkey):
  //
  //      On the wire:  Bech32m string ("clrty1...", "tclrty1...",
  //                    "rclrty1..."). Matches Wallet::AddressCodec,
  //                    which is what every other user-facing surface
  //                    of the codebase emits.
  //
  //      As params:    Bech32m or 64-char hex (with or without 0x).
  //                    The HRP must match the node's network.
  //
  //      Reason: the codebase already has a presentation-layer
  //      encoding for addresses and RPC should produce the same form
  //      so a client can compare strings from RPC, CLI, and config
  //      files without normalizing. Raw hex is accepted on input as
  //      a convenience for tools that hold the raw bytes.
  //
  //  Signatures:       "0x" prefix + 128 lowercase hex.
  //
  //  Byte blobs (tx payloads, arbitrary data):
  //      "0x" prefix + lowercase hex.
  //
  //  Small integers (version, decimals, tx counts, bps, uptime score):
  //      JSON number. These fit in 2^53 by a wide margin.
  //
  //  Booleans:         JSON boolean.
  //  Strings:          JSON string.

  // ---- Hex encoding ----

  // "0x" + lowercase hex. Zero is "0x0". No leading zeros.
  std::string encodeU64Hex(uint64_t v);
  std::string encodeU32Hex(uint32_t v);

  // "0x" + lowercase hex, two hex chars per byte.
  std::string encodeBytesHex(const std::vector<uint8_t> &bytes);
  std::string encodeBytesHex(const uint8_t *data, size_t len);

  // "0x" + 64 lowercase hex.
  std::string encodeHash(const Crypto::Hash &h);

  // "0x" + 128 lowercase hex.
  std::string encodeSignature(const Crypto::Signature &s);

  // Bech32m. `hrp` must be one of the network HRPs from GlobalConfig.
  // Returns an empty string if the address is null or the hrp is
  // unknown. Reuses Wallet::AddressCodec so the two encoders cannot
  // drift.
  std::string encodeAddress(const Crypto::Address &a, const std::string &hrp);

  // ---- Parsing ----

  // parseHexU64 accepts "0x1234" or "0X1234". It rejects strings
  // without a prefix — use requireU64 for the param-parsing entry
  // point that also accepts decimal.
  bool parseHexU64(const std::string &s, uint64_t &out);
  bool parseHexU32(const std::string &s, uint32_t &out);

  // parseHash accepts 64-char hex with or without the 0x prefix.
  bool parseHash(const std::string &s, Crypto::Hash &out);

  // parseSignature accepts 128-char hex with or without the 0x prefix.
  bool parseSignature(const std::string &s, Crypto::Signature &out);

  // parseBytesHex accepts "0x"-prefixed or bare even-length hex.
  bool parseBytesHex(const std::string &s, std::vector<uint8_t> &out);

  // parseAddress accepts Bech32m (validated against expected_hrp) or
  // 64-char hex (with or without 0x). Returns false on network
  // mismatch, malformed Bech32m, wrong payload length, or wrong
  // witness version.
  bool parseAddress(const std::string &s,
                    const std::string &expected_hrp,
                    Crypto::Address &out);

  // ---- JSON helpers for writing fields ----

  void putU64(Common::Json &obj, const char *key, uint64_t v);
  void putU32(Common::Json &obj, const char *key, uint32_t v);
  void putHash(Common::Json &obj, const char *key, const Crypto::Hash &h);
  void putSignature(Common::Json &obj, const char *key, const Crypto::Signature &s);

  // Same wire form as a hash (0x + 64 lowercase hex), but named
  // distinctly because a public key is not a hash. The two are both
  // 32-byte blobs on the wire; the distinction is semantic.
  void putPublicKey(Common::Json &obj, const char *key, const Crypto::PublicKey &pk);

  void putAddress(Common::Json &obj, const char *key,
                  const Crypto::Address &a, const std::string &hrp);
  void putBytes(Common::Json &obj, const char *key, const std::vector<uint8_t> &b);

  // ---- JSON helpers for reading params ----

  // requireX: throw RpcMethodError(InvalidParams) if the field is
  // missing or unparseable. These are the normal entry points for
  // handlers.
  uint64_t requireU64(const Common::Json &obj, const char *key);
  uint32_t requireU32(const Common::Json &obj, const char *key);
  Crypto::Hash requireHash(const Common::Json &obj, const char *key);
  Crypto::Address requireAddress(const Common::Json &obj, const char *key,
                                 const std::string &expected_hrp);
  std::string requireString(const Common::Json &obj, const char *key);

  // optionalX: return std::nullopt if the field is absent or null.
  // Throw InvalidParams if present-but-unparseable. Use for params
  // that have defaults.
  std::optional<uint64_t> optionalU64(const Common::Json &obj, const char *key);
  std::optional<bool> optionalBool(const Common::Json &obj, const char *key);
  std::optional<std::string> optionalString(const Common::Json &obj, const char *key);

  // ---- Network helpers ----

  // Return the HRP for the node's configured network. `clrty`,
  // `tclrty`, or `rclrty`.
  std::string hrpForNode(const Node::Node &node);

} // namespace Rpc