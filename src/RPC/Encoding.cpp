// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Encoding.h"

#include "RPC/JsonRpcDispatcher.h"

#include "GlobalConfig.h"
#include "JsonRpcError.h"
#include "Node/Node.h"
#include "Node/NodeConfig.h"
#include "Wallet/AddressCodec.h"
#include "Wallet/WalletTypes.h"

#include <cstring>

namespace Rpc
{

  //  Local helpers

  namespace
  {
    constexpr char HEX_LOWER[] = "0123456789abcdef";

    void appendHex(std::string &out, uint8_t b)
    {
      out.push_back(HEX_LOWER[b >> 4]);
      out.push_back(HEX_LOWER[b & 0x0F]);
    }

    int hexNibble(char c)
    {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      return -1;
    }

    std::string_view stripHexPrefix(std::string_view s)
    {
      if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return s.substr(2);
      return s;
    }

    bool hasHexPrefix(const std::string &s) noexcept
    {
      return s.size() >= 2 && s[0] == '0' &&
             (s[1] == 'x' || s[1] == 'X');
    }

    bool tryParseDecimalU64(const std::string &s, uint64_t &out)
    {
      if (s.empty())
        return false;
      // Reject anything that looks hex-prefixed; that's the other path.
      if (hasHexPrefix(s))
        return false;

      uint64_t v = 0;
      for (char c : s)
      {
        if (c < '0' || c > '9')
          return false;
        uint64_t nv = v * 10 + uint64_t(c - '0');
        if (nv < v)
          return false; // overflow
        v = nv;
      }
      out = v;
      return true;
    }

    // Map HRP string to the Wallet::Network enum. Returns false if the
    // HRP is not one of the three known networks.
    bool networkForHrp(const std::string &hrp, Wallet::Network &out) noexcept
    {
      if (hrp == GlobalConfig::MAINNET_HRP)
      {
        out = Wallet::Network::Mainnet;
        return true;
      }
      if (hrp == GlobalConfig::TESTNET_HRP)
      {
        out = Wallet::Network::Testnet;
        return true;
      }
      if (hrp == GlobalConfig::REGTEST_HRP)
      {
        out = Wallet::Network::Regtest;
        return true;
      }
      return false;
    }

    [[noreturn]] void missingOrBad(const char *key, const char *expected)
    {
      throw RpcMethodError(
          ErrorCode::InvalidParams,
          std::string("field '") + key + "' must be " + expected,
          makeErrorData(ErrorCode::InvalidParams,
                        {{"field", key}, {"expected", expected}}));
    }
  } // anonymous namespace

  //  Hex encoding

  std::string encodeU64Hex(uint64_t v)
  {
    if (v == 0)
      return "0x0";

    std::string out = "0x";
    bool started = false;
    for (int i = 15; i >= 0; --i)
    {
      uint8_t nib = uint8_t((v >> (i * 4)) & 0xF);
      if (!started)
      {
        if (nib == 0)
          continue;
        started = true;
      }
      out.push_back(HEX_LOWER[nib]);
    }
    return out;
  }

  std::string encodeU32Hex(uint32_t v)
  {
    return encodeU64Hex(static_cast<uint64_t>(v));
  }

  std::string encodeBytesHex(const std::vector<uint8_t> &bytes)
  {
    return encodeBytesHex(bytes.data(), bytes.size());
  }

  std::string encodeBytesHex(const uint8_t *data, size_t len)
  {
    std::string out = "0x";
    out.reserve(2 + len * 2);
    for (size_t i = 0; i < len; ++i)
      appendHex(out, data[i]);
    return out;
  }

  std::string encodeHash(const Crypto::Hash &h)
  {
    std::string out = "0x";
    out.reserve(66);
    for (uint8_t b : h.data)
      appendHex(out, b);
    return out;
  }

  std::string encodeSignature(const Crypto::Signature &s)
  {
    std::string out = "0x";
    out.reserve(130);
    for (uint8_t b : s.data)
      appendHex(out, b);
    return out;
  }

  std::string encodeAddress(const Crypto::Address &a, const std::string &hrp)
  {
    if (a.isNull())
      return {};

    Wallet::Network network;
    if (!networkForHrp(hrp, network))
      return {};

    return Wallet::encodeAddress(a, network);
  }

  //  Parsing

  bool parseHexU64(const std::string &s, uint64_t &out)
  {
    // Require the 0x prefix. This is the param-parsing contract; bare
    // "26" is decimal, not hex.
    if (!hasHexPrefix(s))
      return false;

    std::string_view body = stripHexPrefix(s);
    if (body.empty() || body.size() > 16)
      return false;

    uint64_t v = 0;
    for (char c : body)
    {
      int nib = hexNibble(c);
      if (nib < 0)
        return false;
      v = (v << 4) | uint64_t(nib);
    }
    out = v;
    return true;
  }

  bool parseHexU32(const std::string &s, uint32_t &out)
  {
    uint64_t v64 = 0;
    if (!parseHexU64(s, v64))
      return false;
    if (v64 > UINT32_MAX)
      return false;
    out = static_cast<uint32_t>(v64);
    return true;
  }

  bool parseHash(const std::string &s, Crypto::Hash &out)
  {
    std::string_view body = stripHexPrefix(s);
    if (body.size() != 64)
      return false;
    for (size_t i = 0; i < 32; ++i)
    {
      int hi = hexNibble(body[i * 2]);
      int lo = hexNibble(body[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        return false;
      out.data[i] = uint8_t((hi << 4) | lo);
    }
    return true;
  }

  bool parseSignature(const std::string &s, Crypto::Signature &out)
  {
    std::string_view body = stripHexPrefix(s);
    if (body.size() != 128)
      return false;
    for (size_t i = 0; i < 64; ++i)
    {
      int hi = hexNibble(body[i * 2]);
      int lo = hexNibble(body[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        return false;
      out.data[i] = uint8_t((hi << 4) | lo);
    }
    return true;
  }

  bool parseBytesHex(const std::string &s, std::vector<uint8_t> &out)
  {
    if (!hasHexPrefix(s))
      return false;

    std::string_view body = stripHexPrefix(s);
    if (body.size() % 2 != 0)
      return false;

    out.clear();
    out.reserve(body.size() / 2);
    for (size_t i = 0; i < body.size(); i += 2)
    {
      int hi = hexNibble(body[i]);
      int lo = hexNibble(body[i + 1]);
      if (hi < 0 || lo < 0)
        return false;
      out.push_back(uint8_t((hi << 4) | lo));
    }
    return true;
  }

  bool parseAddress(const std::string &s,
                    const std::string &expected_hrp,
                    Crypto::Address &out)
  {
    // ---- Bech32m path ----
    //
    // Detect by HRP prefix rather than trying decode always, so a
    // 64-char hex string doesn't get run through the Bech32 machinery
    // pointlessly.
    if (!s.empty() &&
        (s.compare(0, 5, "clrty") == 0 ||
         s.compare(0, 6, "tclrty") == 0 ||
         s.compare(0, 6, "rclrty") == 0))
    {
      auto decoded = Wallet::decodeAddressAnyNetwork(s);
      if (!decoded)
        return false;

      // Network must match.
      Wallet::Network expected_net;
      if (!networkForHrp(expected_hrp, expected_net))
        return false;
      if (decoded->network != expected_net)
        return false;

      out = decoded->address;
      return true;
    }

    // ---- Hex path ----
    std::string_view body = stripHexPrefix(s);
    if (body.size() != 64)
      return false;

    for (size_t i = 0; i < 32; ++i)
    {
      int hi = hexNibble(body[i * 2]);
      int lo = hexNibble(body[i * 2 + 1]);
      if (hi < 0 || lo < 0)
        return false;
      out.data[i] = uint8_t((hi << 4) | lo);
    }
    return true;
  }

  //  JSON writing helpers

  void putU64(Common::Json &obj, const char *key, uint64_t v)
  {
    obj[key] = encodeU64Hex(v);
  }

  void putU32(Common::Json &obj, const char *key, uint32_t v)
  {
    obj[key] = encodeU32Hex(v);
  }

  void putHash(Common::Json &obj, const char *key, const Crypto::Hash &h)
  {
    obj[key] = encodeHash(h);
  }

  void putSignature(Common::Json &obj, const char *key, const Crypto::Signature &s)
  {
    obj[key] = encodeSignature(s);
  }

  void putPublicKey(Common::Json &obj, const char *key, const Crypto::PublicKey &pk)
  {
    obj[key] = encodeBytesHex(pk.data.data(), pk.data.size());
  }

  void putAddress(Common::Json &obj, const char *key,
                  const Crypto::Address &a, const std::string &hrp)
  {
    obj[key] = encodeAddress(a, hrp);
  }

  void putBytes(Common::Json &obj, const char *key, const std::vector<uint8_t> &b)
  {
    obj[key] = encodeBytesHex(b);
  }

  //  JSON reading helpers

  uint64_t requireU64(const Common::Json &obj, const char *key)
  {
    if (!obj.contains(key))
      missingOrBad(key, "a hex (0x-prefixed) or decimal number");

    const auto &v = obj.at(key);

    if (v.is_string())
    {
      const std::string &s = v.get<std::string>();
      uint64_t out = 0;
      if (hasHexPrefix(s))
      {
        if (parseHexU64(s, out))
          return out;
      }
      else if (tryParseDecimalU64(s, out))
      {
        return out;
      }
      missingOrBad(key, "a hex (0x-prefixed) or decimal number");
    }

    if (v.is_number_unsigned())
      return v.get<uint64_t>();

    if (v.is_number_integer())
    {
      int64_t i = v.get<int64_t>();
      if (i < 0)
        missingOrBad(key, "a non-negative number");
      return static_cast<uint64_t>(i);
    }

    missingOrBad(key, "a hex (0x-prefixed) or decimal number");
  }

  uint32_t requireU32(const Common::Json &obj, const char *key)
  {
    uint64_t v = requireU64(obj, key);
    if (v > UINT32_MAX)
      missingOrBad(key, "a 32-bit value");
    return static_cast<uint32_t>(v);
  }

  Crypto::Hash requireHash(const Common::Json &obj, const char *key)
  {
    if (!obj.contains(key) || !obj.at(key).is_string())
      missingOrBad(key, "a 32-byte hex string");

    Crypto::Hash out;
    if (!parseHash(obj.at(key).get<std::string>(), out))
      missingOrBad(key, "a 32-byte hex string");
    return out;
  }

  // ===========================================================================
  //  requireAddress
  // ===========================================================================
  //
  //  Resolve a "address" parameter to a Crypto::Address. Accepts two
  //  forms:
  //
  //    1. bech32m — decoded with the network matching `hrp`. A mismatch
  //       between the address's HRP and `hrp` is rejected with a
  //       message that names both, so the user knows they sent a
  //       mainnet address to a regtest node (or vice versa).
  //
  //    2. raw hex — a 64-character hex string is decoded as a bare
  //       32-byte Ed25519 public key. This is the format that appears
  //       in ValidatorInfo::consensus_key, in some RPC responses, and
  //       in genesis configs. Accepting it here means a client that
  //       has a raw key from one query can use it directly in another
  //       without round-tripping through bech32m.
  //
  //  Throws RpcMethodError with ErrorCode::InvalidParams on any
  //  failure. The error data carries both the field name and the
  //  rejected value so the client can diagnose.
  //
  //  The order of attempts matters. bech32m is tried first because it
  //  is what every user-facing address is, and what the RPC emits in
  //  its own responses. Hex is the fallback for tooling.
  //
  //  A note on the HRP-detection in the error path: bech32m addresses
  //  have an HRP separated from the rest of the string by the
  //  character '1'. Splitting on the first '1' gives us the HRP that
  //  the address claims to have. If it differs from `hrp`, that's the
  //  most useful thing we can tell the user.
  //
  //  The '1' separator is unique to bech32m; a raw hex string
  //  contains only [0-9a-fA-F], none of which is '1'... actually '1'
  //  IS a valid hex character. So we have to be careful: the HRP
  //  detection should only run when the input is clearly not hex.
  //  See the guard below.

  Crypto::Address requireAddress(const Common::Json &params,
                                 const char *name,
                                 const std::string &hrp)
  {
    //  Fetch the parameter as a string. requireString throws
    //  RpcMethodError(InvalidParams) if the field is missing or not a
    //  string.
    const std::string value = requireString(params, name);

    //  Empty input is never valid.
    if (value.empty())
    {
      throw RpcMethodError(
          ErrorCode::InvalidParams,
          ("field '" + std::string(name) + "' is empty").c_str(),
          makeErrorData(ErrorCode::InvalidParams,
                        {{"field", name}, {"value", value}}));
    }

    //  ---- Attempt 1: bech32m ----
    //
    //  Look up the network for the expected HRP. If the HRP is
    //  unknown (a config error on the server side, not a client
    //  error), fall through to the hex attempt rather than throwing
    //  — the raw-hex path doesn't need to know about networks.
    {
      auto network_opt = Wallet::networkForHrp(hrp);
      if (network_opt.has_value())
      {
        auto decoded = Wallet::decodeAddress(value, *network_opt);
        if (decoded.has_value())
          return *decoded;
      }
    }

    //  ---- Attempt 2: raw hex ----
    //
    //  A 64-character hex string. Decode byte by byte. Rejects
    //  anything that isn't exactly 32 bytes or contains a non-hex
    //  character.
    if (value.size() == 64)
    {
      auto hexNibble = [](char c) -> int
      {
        if (c >= '0' && c <= '9')
          return c - '0';
        if (c >= 'a' && c <= 'f')
          return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
          return c - 'A' + 10;
        return -1;
      };

      Crypto::Address addr;
      bool all_hex = true;

      for (size_t i = 0; i < 32; ++i)
      {
        const int hi = hexNibble(value[i * 2]);
        const int lo = hexNibble(value[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
          all_hex = false;
          break;
        }
        addr.data[i] = static_cast<uint8_t>((hi << 4) | lo);
      }

      if (all_hex)
        return addr;
    }

    //  ---- Neither form worked. Build a helpful error. ----

    std::string message = "field '" + std::string(name) +
                          "' is not a valid address";

    //  If the input looks like a bech32m address with the wrong HRP,
    //  say so explicitly. This is the single most common cause of
    //  this error in practice: a user pastes a mainnet address into
    //  a regtest session (or vice versa).
    //
    //  Detection: the input contains a '1' that isn't part of a
    //  hex-only string. A 64-char input containing any non-hex
    //  character is not a raw key, so it might be a bech32m address
    //  with the wrong HRP.
    {
      const size_t sep = value.find('1');
      if (sep != std::string::npos && sep > 0 && sep < value.size() - 1)
      {
        const std::string value_hrp = value.substr(0, sep);

        //  Only report an HRP mismatch if the prefix actually looks
        //  like an HRP (all lowercase letters). This avoids a false
        //  positive on something like "0x1234...1abc..." where the
        //  '1' is a hex digit.
        bool hrp_looks_valid = !value_hrp.empty();
        for (char c : value_hrp)
        {
          if (c < 'a' || c > 'z')
          {
            hrp_looks_valid = false;
            break;
          }
        }

        if (hrp_looks_valid && value_hrp != hrp)
        {
          message += ": address is for '";
          message += value_hrp;
          message += "' but this node is '";
          message += hrp;
          message += "'";
        }
      }
    }

    throw RpcMethodError(
        ErrorCode::InvalidParams,
        message.c_str(),
        makeErrorData(ErrorCode::InvalidParams,
                      {{"field", name},
                       {"value", value},
                       {"expected_hrp", hrp}}));
  }

  std::string requireString(const Common::Json &obj, const char *key)
  {
    if (!obj.contains(key) || !obj.at(key).is_string())
      missingOrBad(key, "a string");
    return obj.at(key).get<std::string>();
  }

  std::optional<uint64_t> optionalU64(const Common::Json &obj, const char *key)
  {
    if (!obj.contains(key) || obj.at(key).is_null())
      return std::nullopt;

    const auto &v = obj.at(key);

    if (v.is_string())
    {
      const std::string &s = v.get<std::string>();
      uint64_t out = 0;
      if (hasHexPrefix(s))
      {
        if (parseHexU64(s, out))
          return out;
      }
      else if (tryParseDecimalU64(s, out))
      {
        return out;
      }
      missingOrBad(key, "a hex (0x-prefixed) or decimal number");
    }

    if (v.is_number_unsigned())
      return v.get<uint64_t>();

    if (v.is_number_integer())
    {
      int64_t i = v.get<int64_t>();
      if (i < 0)
        missingOrBad(key, "a non-negative number");
      return static_cast<uint64_t>(i);
    }

    missingOrBad(key, "a hex (0x-prefixed) or decimal number");
  }

  std::optional<bool> optionalBool(const Common::Json &obj, const char *key)
  {
    if (!obj.contains(key) || obj.at(key).is_null())
      return std::nullopt;
    if (!obj.at(key).is_boolean())
      missingOrBad(key, "a boolean");
    return obj.at(key).get<bool>();
  }

  std::optional<std::string> optionalString(const Common::Json &obj, const char *key)
  {
    if (!obj.contains(key) || obj.at(key).is_null())
      return std::nullopt;
    if (!obj.at(key).is_string())
      missingOrBad(key, "a string");
    return obj.at(key).get<std::string>();
  }

  //  Network helpers

  std::string hrpForNode(const Node::Node &node)
  {
    switch (node.status().network)
    {
    case Node::Network::Mainnet:
      return GlobalConfig::MAINNET_HRP;
    case Node::Network::Testnet:
      return GlobalConfig::TESTNET_HRP;
    case Node::Network::Regtest:
      return GlobalConfig::REGTEST_HRP;
    }
    return GlobalConfig::REGTEST_HRP;
  }

} // namespace Rpc