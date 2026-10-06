// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "RpcClient.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include <chrono>
#include <exception>
#include <sstream>
#include <string>

namespace Wallet
{
  namespace beast = boost::beast;
  namespace http = beast::http;
  namespace net = boost::asio;
  using tcp = net::ip::tcp;

  //  ---- JSON-RPC method names ----
  //
  //  The dispatcher registers methods under bare names (no `clrty_`
  //  prefix). These constants keep the strings in one place.

  namespace RpcMethods
  {
    constexpr const char *GetBalance = "getBalance";
    constexpr const char *GetNonce = "getNonce";
    constexpr const char *SendRawTransaction = "sendRawTransaction";
    constexpr const char *GetTransactionReceipt = "getTransactionReceipt";
    constexpr const char *GetProof = "getProof";
    constexpr const char *GetBlockHeaderByNumber = "getBlockHeaderByNumber";
    constexpr const char *BlockNumber = "blockNumber";
  } // namespace RpcMethods

  //  ---- Hex helpers ----

  namespace
  {

    constexpr char HEX_LOWER[] = "0123456789abcdef";

    //  The ReceiptNotFound error code. This duplicates the value in
    //  Rpc/JsonRpcError.h so the wallet client doesn't need to link
    //  against the RPC server headers. If the code changes on the
    //  server side, the client will retry on the wrong error code and
    //  the failure will be visible as a hung waitForReceipt. Watch
    //  for that if you ever renumber the ErrorCode enum.
    constexpr int RECEIPT_NOT_FOUND_CODE = 1055; // should match ErrorCode::ReceiptNotFound

    //  Parse a "0x..." hex string into a uint64_t. Returns nullopt on
    //  malformed input or if the value doesn't fit. Empty after the
    //  prefix is treated as "0".
    std::optional<uint64_t> parseHexU64(const std::string &s)
    {
      if (s.size() < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
        return std::nullopt;

      if (s.size() == 2)
        return uint64_t(0);

      uint64_t value = 0;
      for (size_t i = 2; i < s.size(); ++i)
      {
        const char c = s[i];
        int nib;
        if (c >= '0' && c <= '9')
          nib = c - '0';
        else if (c >= 'a' && c <= 'f')
          nib = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
          nib = c - 'A' + 10;
        else
          return std::nullopt;

        //  Guard against overflow on a 64-bit accumulator.
        if (value > (UINT64_MAX >> 4))
          return std::nullopt;
        value = (value << 4) | static_cast<uint64_t>(nib);
      }
      return value;
    }

    //  Parse a 0x-prefixed hex string into a 32-byte hash. Returns
    //  false if the string isn't exactly 66 characters (0x + 64 hex).
    bool parseHashHex(const std::string &s, Crypto::Hash &out)
    {
      if (s.size() != 66 || s[0] != '0' ||
          (s[1] != 'x' && s[1] != 'X'))
        return false;

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

      for (size_t i = 0; i < 32; ++i)
      {
        const int hi = nib(s[2 + i * 2]);
        const int lo = nib(s[2 + i * 2 + 1]);
        if (hi < 0 || lo < 0)
          return false;
        out.data[i] = static_cast<uint8_t>((hi << 4) | lo);
      }
      return true;
    }

    //  Parse a 0x-prefixed hex string into a byte vector. Returns
    //  false on malformed input.
    bool parseBytesHex(const std::string &s, std::vector<uint8_t> &out)
    {
      if (s.size() < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
        return false;
      if (((s.size() - 2) & 1) != 0)
        return false;

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

      out.clear();
      out.reserve((s.size() - 2) / 2);
      for (size_t i = 2; i < s.size(); i += 2)
      {
        const int hi = nib(s[i]);
        const int lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0)
          return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
      }
      return true;
    }

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
  } // anonymous namespace

  //  ---- RpcClient ----

  RpcClient::RpcClient(RpcEndpoint endpoint)
      : endpoint_(std::move(endpoint))
  {
  }

  RpcClient::~RpcClient() = default;

  RpcResult RpcClient::call(const std::string &method,
                            const Common::Json &params)
  {
    RpcResult out;

    try
    {
      net::io_context ioc;
      tcp::resolver resolver(ioc);
      beast::tcp_stream stream(ioc);

      const auto timeout = std::chrono::seconds(timeout_seconds_);

      //  Resolve.
      const auto results = resolver.resolve(endpoint_.host,
                                            std::to_string(endpoint_.port));

      //  Connect with timeout.
      stream.expires_after(timeout);
      stream.connect(results);

      //  Build the JSON-RPC request body.
      Common::Json req = Common::Json::object();
      req["jsonrpc"] = "2.0";
      req["id"] = 1;
      req["method"] = method;
      req["params"] = params;

      http::request<http::string_body> http_req{http::verb::post, "/", 11};
      http_req.set(http::field::host, endpoint_.host);
      http_req.set(http::field::user_agent, "clrty-wallet/0.1");
      http_req.set(http::field::content_type, "application/json");
      http_req.body() = req.dump();
      http_req.prepare_payload();

      //  Send with timeout.
      stream.expires_after(timeout);
      http::write(stream, http_req);

      //  Read the response with a larger timeout. A slow method (e.g.
      //  a full block query with transactions) may take longer than
      //  a simple state query.
      beast::flat_buffer buffer;
      http::response<http::string_body> http_resp;
      stream.expires_after(std::chrono::seconds(timeout_seconds_ * 2));
      http::read(stream, buffer, http_resp);

      //  Graceful close. Ignore errors — the data is already in hand.
      beast::error_code ec;
      stream.socket().shutdown(tcp::socket::shutdown_both, ec);

      //  Any non-200 is a transport-level failure, even if the body
      //  looks like a JSON-RPC error. The JSON-RPC spec says servers
      //  should return 200 for JSON-RPC errors, reserving non-200 for
      //  transport problems.
      if (http_resp.result() != http::status::ok)
      {
        out.error = RpcError{
            /*code=*/0,
            /*message=*/"HTTP " + std::to_string(http_resp.result_int()),
            /*is_transport_error=*/true};
        return out;
      }

      //  Parse the response body.
      Common::Json resp;
      try
      {
        resp = Common::Json::parse(http_resp.body());
      }
      catch (const std::exception &e)
      {
        out.error = RpcError{
            /*code=*/0,
            /*message=*/std::string("malformed JSON response: ") + e.what(),
            /*is_transport_error=*/true};
        return out;
      }

      //  A JSON-RPC error object from the server. Extract code and
      //  message from the standard structure.
      if (resp.contains("error") && !resp["error"].is_null())
      {
        const auto &err = resp["error"];
        RpcError rpc_err;
        rpc_err.is_transport_error = false;

        if (err.is_object())
        {
          if (err.contains("code") && err["code"].is_number_integer())
            rpc_err.code = err["code"].get<int>();
          if (err.contains("message") && err["message"].is_string())
            rpc_err.message = err["message"].get<std::string>();
          if (err.contains("data") && !err["data"].is_null())
            rpc_err.data = err["data"];
        }
        else
        {
          rpc_err.message = err.dump();
        }

        out.error = std::move(rpc_err);
        return out;
      }

      //  Standard success path.
      if (!resp.contains("result"))
      {
        out.error = RpcError{
            /*code=*/0,
            /*message=*/"JSON-RPC response has no 'result' field",
            /*is_transport_error=*/true};
        return out;
      }

      out.result = resp["result"];
      return out;
    }
    catch (const std::exception &e)
    {
      //  Transport-layer exception (asio, beast, std::string, ...).
      out.error = RpcError{
          /*code=*/0,
          /*message=*/std::string("transport error: ") + e.what(),
          /*is_transport_error=*/true};
      return out;
    }
  }

  //  ---- Typed helpers ----

  std::optional<uint64_t> getBalance(RpcClient &rpc,
                                     const std::string &address_bech32m,
                                     std::string *error_out)
  {
    Common::Json params = Common::Json::object();
    params["address"] = address_bech32m;
    params["token_id"] = "0x0";

    auto result = rpc.call(RpcMethods::GetBalance, params);
    if (!result.ok())
    {
      if (error_out)
        *error_out = result.error->message;
      return std::nullopt;
    }

    if (!result.result.is_object() || !result.result.contains("balance"))
    {
      if (error_out)
        *error_out = "getBalance: response missing 'balance' field";
      return std::nullopt;
    }

    const auto &bal = result.result["balance"];
    if (!bal.is_string())
    {
      if (error_out)
        *error_out = "getBalance: 'balance' is not a string";
      return std::nullopt;
    }

    auto parsed = parseHexU64(bal.get<std::string>());
    if (!parsed.has_value())
    {
      if (error_out)
        *error_out = "getBalance: 'balance' is not valid hex";
      return std::nullopt;
    }

    return *parsed;
  }

  std::optional<uint64_t> getNonce(RpcClient &rpc,
                                   const std::string &address_bech32m,
                                   std::string *error_out)
  {
    Common::Json params = Common::Json::object();
    params["address"] = address_bech32m;

    auto result = rpc.call(RpcMethods::GetNonce, params);
    if (!result.ok())
    {
      if (error_out)
        *error_out = result.error->message;
      return std::nullopt;
    }

    if (!result.result.is_object() || !result.result.contains("nonce"))
    {
      if (error_out)
        *error_out = "getNonce: response missing 'nonce' field";
      return std::nullopt;
    }

    const auto &nonce = result.result["nonce"];
    if (!nonce.is_string())
    {
      if (error_out)
        *error_out = "getNonce: 'nonce' is not a string";
      return std::nullopt;
    }

    auto parsed = parseHexU64(nonce.get<std::string>());
    if (!parsed.has_value())
    {
      if (error_out)
        *error_out = "getNonce: 'nonce' is not valid hex";
      return std::nullopt;
    }

    return *parsed;
  }

  std::optional<std::string> sendRawTransaction(
      RpcClient &rpc,
      const std::string &signed_hex,
      std::string *error_out)
  {
    Common::Json params = Common::Json::object();
    params["tx"] = signed_hex;

    auto result = rpc.call(RpcMethods::SendRawTransaction, params);
    if (!result.ok())
    {
      if (error_out)
        *error_out = result.error->message;
      return std::nullopt;
    }

    if (!result.result.is_object() || !result.result.contains("tx_hash"))
    {
      if (error_out)
        *error_out = "sendRawTransaction: response missing 'tx_hash' field";
      return std::nullopt;
    }

    const auto &hash = result.result["tx_hash"];
    if (!hash.is_string())
    {
      if (error_out)
        *error_out = "sendRawTransaction: 'tx_hash' is not a string";
      return std::nullopt;
    }

    return hash.get<std::string>();
  }

  std::optional<Common::Json> getTransactionReceipt(
      RpcClient &rpc,
      const std::string &txid_hex,
      bool *is_receipt_not_found,
      std::string *error_out)
  {
    if (is_receipt_not_found)
      *is_receipt_not_found = false;

    Common::Json params = Common::Json::object();
    params["hash"] = txid_hex;

    auto result = rpc.call(RpcMethods::GetTransactionReceipt, params);

    if (!result.ok())
    {
      //  Distinguish "not yet confirmed" from real errors. The
      //  server returns ReceiptNotFound as a normal JSON-RPC error;
      //  the caller uses this signal to decide whether to retry.
      if (!result.error->is_transport_error &&
          result.error->code == RECEIPT_NOT_FOUND_CODE)
      {
        if (is_receipt_not_found)
          *is_receipt_not_found = true;
        return std::nullopt;
      }

      if (error_out)
        *error_out = result.error->message;
      return std::nullopt;
    }

    return result.result;
  }

  std::optional<Common::Json> getValidatorByAddress(
      RpcClient &rpc,
      const std::string &address_bech32m,
      bool *is_not_found,
      std::string *error_out)
  {
    if (is_not_found)
      *is_not_found = false;

    Common::Json params = Common::Json::object();
    params["address"] = address_bech32m;

    auto result = rpc.call("getValidatorByAddress", params);

    if (!result.ok())
    {
      //  ValidatorNotFound = 1052 (see Rpc/JsonRpcError.h).
      if (!result.error->is_transport_error && result.error->code == 1052)
      {
        if (is_not_found)
          *is_not_found = true;
        return std::nullopt;
      }

      if (error_out)
        *error_out = result.error->message;
      return std::nullopt;
    }

    return result.result;
  }

  std::optional<HeaderInfo> getCurrentHeader(
      RpcClient &rpc,
      std::string *error_out)
  {
    //  Step 1: current height.
    auto height_result = rpc.call(RpcMethods::BlockNumber,
                                  Common::Json::object());
    if (!height_result.ok())
    {
      if (error_out)
        *error_out = height_result.error->message;
      return std::nullopt;
    }
    if (!height_result.result.is_object() ||
        !height_result.result.contains("height"))
    {
      if (error_out)
        *error_out = "blockNumber: response missing 'height' field";
      return std::nullopt;
    }

    const auto &h = height_result.result["height"];
    if (!h.is_string())
    {
      if (error_out)
        *error_out = "blockNumber: 'height' is not a string";
      return std::nullopt;
    }
    auto parsed_height = parseHexU64(h.get<std::string>());
    if (!parsed_height.has_value())
    {
      if (error_out)
        *error_out = "blockNumber: 'height' is not valid hex";
      return std::nullopt;
    }

    //  Step 2: header at that height.
    Common::Json params = Common::Json::object();
    params["height"] = "0x" + [&]
    {
      static const char hex[] = "0123456789abcdef";
      std::string s;
      uint64_t v = *parsed_height;
      if (v == 0)
      {
        s = "0";
        return s;
      }
      while (v)
      {
        s.push_back(hex[v & 0xF]);
        v >>= 4;
      }
      std::reverse(s.begin(), s.end());
      return s;
    }();

    auto header_result = rpc.call(RpcMethods::GetBlockHeaderByNumber, params);
    if (!header_result.ok())
    {
      if (error_out)
        *error_out = header_result.error->message;
      return std::nullopt;
    }
    if (!header_result.result.is_object() ||
        !header_result.result.contains("state_root"))
    {
      if (error_out)
        *error_out = "getBlockHeaderByNumber: response missing 'state_root'";
      return std::nullopt;
    }

    const auto &sr = header_result.result["state_root"];
    if (!sr.is_string())
    {
      if (error_out)
        *error_out = "getBlockHeaderByNumber: 'state_root' is not a string";
      return std::nullopt;
    }

    HeaderInfo info;
    info.height = *parsed_height;
    if (!parseHashHex(sr.get<std::string>(), info.state_root))
    {
      if (error_out)
        *error_out = "getBlockHeaderByNumber: 'state_root' is not a valid hash";
      return std::nullopt;
    }

    return info;
  }

  std::optional<ProofResult> getProof(
      RpcClient &rpc,
      State::ProofKeyType key_type,
      const std::vector<uint8_t> &key_bytes,
      uint64_t version,
      std::string *error_out)
  {
    Common::Json params = Common::Json::object();
    params["key_type"] = static_cast<uint64_t>(key_type);
    params["key_bytes"] = "0x" + [&]
    {
      static const char hex[] = "0123456789abcdef";
      std::string s;
      s.reserve(key_bytes.size() * 2);
      for (uint8_t b : key_bytes)
      {
        s.push_back(hex[b >> 4]);
        s.push_back(hex[b & 0x0F]);
      }
      return s;
    }();

    if (version == State::PROOF_VERSION_CURRENT)
    {
      params["version"] = "current";
    }
    else
    {
      params["version"] = encodeU64Hex(version);
    }

    auto result = rpc.call(RpcMethods::GetProof, params);
    if (!result.ok())
    {
      if (error_out)
        *error_out = result.error->message;
      return std::nullopt;
    }

    if (!result.result.is_object())
    {
      if (error_out)
        *error_out = "getProof: response is not an object";
      return std::nullopt;
    }

    const auto &obj = result.result;
    if (!obj.contains("state_root") || !obj["state_root"].is_string())
    {
      if (error_out)
        *error_out = "getProof: missing or malformed 'state_root'";
      return std::nullopt;
    }
    if (!obj.contains("version") || !obj["version"].is_string())
    {
      if (error_out)
        *error_out = "getProof: missing or malformed 'version'";
      return std::nullopt;
    }
    if (!obj.contains("proof") || !obj["proof"].is_string())
    {
      if (error_out)
        *error_out = "getProof: missing or malformed 'proof'";
      return std::nullopt;
    }

    ProofResult pr;
    if (!parseHashHex(obj["state_root"].get<std::string>(), pr.state_root))
    {
      if (error_out)
        *error_out = "getProof: 'state_root' is not a valid hash";
      return std::nullopt;
    }
    auto parsed_version = parseHexU64(obj["version"].get<std::string>());
    if (!parsed_version.has_value())
    {
      if (error_out)
        *error_out = "getProof: 'version' is not valid hex";
      return std::nullopt;
    }
    pr.version = *parsed_version;

    std::vector<uint8_t> proof_bytes;
    if (!parseBytesHex(obj["proof"].get<std::string>(), proof_bytes))
    {
      if (error_out)
        *error_out = "getProof: 'proof' is not valid hex";
      return std::nullopt;
    }

    if (!State::SmtProof::deserialize(proof_bytes.data(),
                                      proof_bytes.size(),
                                      pr.proof))
    {
      if (error_out)
        *error_out = "getProof: proof failed to deserialize";
      return std::nullopt;
    }

    return pr;
  }
} // namespace Wallet