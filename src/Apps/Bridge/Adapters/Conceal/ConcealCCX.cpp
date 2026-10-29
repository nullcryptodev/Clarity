// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ConcealCCX.h"

#include "Core/Bridge/ConcealCCX.h"

#include "Common/Base.h"
#include "Common/Json.h"
#include "Common/StringTools.h"
#include "Common/Varint.h"

#include "Crypto/Helpers.h"
#include "Crypto/Ed25519.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace Bridge
{

  namespace beast = boost::beast;
  namespace http = beast::http;
  namespace net = boost::asio;
  using tcp = net::ip::tcp;

  namespace
  {
    constexpr uint8_t TX_EXTRA_TAG_PAYMENT_ID = 0x00;
    constexpr uint8_t TX_EXTRA_TAG_PUBKEY = 0x01;
    constexpr uint8_t TX_EXTRA_TAG_NONCE = 0x02;
    constexpr uint8_t TX_EXTRA_TAG_MERGE_MINING = 0x03;
    constexpr uint8_t TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04;

    constexpr uint32_t CCX_BLOCK_CHUNK_SIZE = 1000;
    constexpr int CCX_HTTP_TIMEOUT_SECONDS = 30;

    //  The wallet RPC's sendTransaction and getTransaction are both
    //  fast index lookups; a 30-minute timeout is not needed for
    //  walletd (unlike conceal-wallet-rpc, where `transfer` blocks
    //  until confirmation). walletd returns as soon as the tx is
    //  relayed to the daemon, so a short timeout is correct.
    //
    //  We still use the longer timeout for the daemon's
    //  /gettransactions path since a slow daemon under load can
    //  take a while, and we don't want to spuriously fail a
    //  confirmed tx just because a node was briefly slow.
    constexpr int CCX_WALLET_HTTP_TIMEOUT_SECONDS = 60;

    //  Diagnostic helper for hex previews in log lines. Not gated
    //  by a verbosity flag — used only where a caller already
    //  decided the case is worth logging.
    std::string hexPreview(const std::vector<uint8_t> &bytes,
                           size_t max_bytes = 32)
    {
      static const char HEX[] = "0123456789abcdef";
      std::string out;
      out.reserve(std::min(bytes.size(), max_bytes) * 2 + 3);
      const size_t n = std::min(bytes.size(), max_bytes);
      for (size_t i = 0; i < n; ++i)
      {
        out.push_back(HEX[bytes[i] >> 4]);
        out.push_back(HEX[bytes[i] & 0xF]);
      }
      if (bytes.size() > max_bytes)
        out += "...";
      return out;
    }

    bool parseHexBytes(const std::string &s, uint8_t *out, size_t out_len)
    {
      size_t i = 0;
      if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        i = 2;
      if (s.size() - i != out_len * 2)
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
      for (size_t j = 0; j < out_len; ++j)
      {
        const int hi = nib(s[i + j * 2]);
        const int lo = nib(s[i + j * 2 + 1]);
        if (hi < 0 || lo < 0)
          return false;
        out[j] = static_cast<uint8_t>((hi << 4) | lo);
      }
      return true;
    }

    std::string bytesToHex(const uint8_t *data, size_t len)
    {
      static const char HEX[] = "0123456789abcdef";
      std::string s;
      s.reserve(len * 2);
      for (size_t i = 0; i < len; ++i)
      {
        s.push_back(HEX[data[i] >> 4]);
        s.push_back(HEX[data[i] & 0xF]);
      }
      return s;
    }

    bool jsonToBytes(const Common::Json &j, std::vector<uint8_t> &out)
    {
      out.clear();
      if (j.is_array())
      {
        out.reserve(j.size());
        for (const auto &b : j)
        {
          if (b.is_number_unsigned())
            out.push_back(static_cast<uint8_t>(b.get<uint32_t>()));
          else if (b.is_number_integer())
            out.push_back(static_cast<uint8_t>(b.get<int>()));
          else
            return false;
        }
        return true;
      }
      if (j.is_string())
      {
        const std::string s = j.get<std::string>();
        std::string cleaned = s;
        if (cleaned.size() >= 2 && cleaned[0] == '0' &&
            (cleaned[1] == 'x' || cleaned[1] == 'X'))
          cleaned = cleaned.substr(2);
        if ((cleaned.size() & 1) != 0)
          return false;
        out.reserve(cleaned.size() / 2);
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
        for (size_t i = 0; i < cleaned.size(); i += 2)
        {
          const int hi = nib(cleaned[i]);
          const int lo = nib(cleaned[i + 1]);
          if (hi < 0 || lo < 0)
            return false;
          out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        }
        return true;
      }
      return false;
    }

    Common::Json doHttpPost(const Wallet::RpcEndpoint &ep,
                            const std::string &path,
                            const std::string &body,
                            int timeout_seconds,
                            std::string *error_out)
    {
      try
      {
        net::io_context ioc;
        tcp::resolver resolver(ioc);
        beast::tcp_stream stream(ioc);

        const auto timeout =
            std::chrono::seconds(timeout_seconds);

        const auto results = resolver.resolve(
            ep.host, std::to_string(ep.port));

        stream.expires_after(timeout);
        stream.connect(results);

        http::request<http::string_body> http_req{
            http::verb::post, path, 11};
        http_req.set(http::field::host, ep.host);
        http_req.set(http::field::user_agent, "clarity-bridge/0.1");
        http_req.set(http::field::content_type, "application/json");
        http_req.body() = body;
        http_req.prepare_payload();

        stream.expires_after(timeout);
        http::write(stream, http_req);

        beast::flat_buffer buffer;
        http::response<http::string_body> http_resp;
        stream.expires_after(timeout);
        http::read(stream, buffer, http_resp);

        beast::error_code ec;
        stream.socket().shutdown(tcp::socket::shutdown_both, ec);

        if (http_resp.result() != http::status::ok)
        {
          if (error_out)
            *error_out = "HTTP " +
                         std::to_string(http_resp.result_int());
          return Common::Json{};
        }

        try
        {
          return Common::Json::parse(http_resp.body());
        }
        catch (const std::exception &e)
        {
          if (error_out)
            *error_out = std::string("malformed JSON: ") + e.what();
          return Common::Json{};
        }
      }
      catch (const std::exception &e)
      {
        if (error_out)
          *error_out = std::string("transport: ") + e.what();
        return Common::Json{};
      }
    }

    std::optional<Common::Json> rawCall(
        const Wallet::RpcEndpoint &ep,
        const std::string &path,
        const Common::Json &params,
        std::string *error_out)
    {
      std::string transport_error;
      Common::Json resp =
          doHttpPost(ep, path, params.dump(),
                     CCX_HTTP_TIMEOUT_SECONDS, &transport_error);

      if (!transport_error.empty())
      {
        if (error_out)
          *error_out = transport_error;
        return std::nullopt;
      }

      if (!resp.is_object())
      {
        if (error_out)
          *error_out = "response is not an object";
        return std::nullopt;
      }

      return resp;
    }

    //  Call the Conceal PaymentService (walletd) JSON-RPC endpoint.
    //
    //  The walletd protocol is:
    //
    //    POST /json_rpc
    //    {
    //      "jsonrpc": "2.0",
    //      "id": <any>,
    //      "method": "<name>",
    //      "params": { ... }
    //    }
    //
    //  Unlike the daemon's JSON-RPC 2.0 endpoint, walletd
    //  *requires* the params to be nested under a "params" key.
    //  Unlike `transfer` on conceal-wallet-rpc, walletd's
    //  `sendTransaction` returns as soon as the tx is relayed to the
    //  daemon — it does not block until confirmation.
    //
    //  The timeout is short because nothing walletd does blocks for
    //  long: `sendTransaction` relays immediately, and the
    //  `getTransaction`/`getStatus` calls it also serves are index
    //  lookups.
    std::optional<Common::Json> call_wallet_rpc(
        const Wallet::RpcEndpoint &ep,
        const std::string &method,
        const Common::Json &params,
        std::string *error_out)
    {
      Common::Json envelope = Common::Json::object();
      envelope["jsonrpc"] = "2.0";
      envelope["id"] = 1;
      envelope["method"] = method;
      envelope["params"] = params;

      std::string transport_error;
      Common::Json resp =
          doHttpPost(ep, "/json_rpc", envelope.dump(),
                     CCX_WALLET_HTTP_TIMEOUT_SECONDS, &transport_error);

      if (!transport_error.empty())
      {
        if (error_out)
          *error_out = transport_error;
        return std::nullopt;
      }

      if (!resp.is_object())
      {
        if (error_out)
          *error_out = "wallet response is not an object";
        return std::nullopt;
      }

      if (resp.contains("error") && !resp["error"].is_null())
      {
        const auto &err = resp["error"];
        if (err.is_object() && err.contains("message") &&
            err["message"].is_string())
        {
          if (error_out)
            *error_out = err["message"].get<std::string>();
        }
        else
        {
          if (error_out)
            *error_out = err.dump();
        }
        return std::nullopt;
      }

      if (!resp.contains("result"))
      {
        if (error_out)
          *error_out = "wallet response has no 'result' field";
        return std::nullopt;
      }

      return resp["result"];
    }

    //  Extract a tx pubkey from the tx's extra field. The tx pubkey
    //  is the only thing the deposit scanner needs from extra; the
    //  payment ID (which is also sometimes in extra, at the top
    //  level or nested inside a nonce tag) is not consulted here.
    bool extractTxPubkey(const std::vector<uint8_t> &extra,
                         Crypto::PublicKey &out)
    {
      size_t i = 0;
      while (i < extra.size())
      {
        const uint8_t tag = extra[i++];

        if (tag == TX_EXTRA_TAG_PUBKEY)
        {
          if (i + 32 > extra.size())
            return false;
          std::memcpy(out.data.data(), &extra[i], 32);
          return true;
        }

        if (tag == TX_EXTRA_TAG_PAYMENT_ID)
        {
          if (i + 8 > extra.size())
            return false;
          i += 8;
          continue;
        }

        if (tag == TX_EXTRA_TAG_NONCE ||
            tag == TX_EXTRA_TAG_MERGE_MINING ||
            tag == TX_EXTRA_TAG_ADDITIONAL_PUBKEYS)
        {
          if (i >= extra.size())
            return false;
          const uint8_t len = extra[i++];
          if (i + len > extra.size())
            return false;
          i += len;
          continue;
        }

        return false;
      }

      return false;
    }
  } // anonymous namespace

  std::string CcxAdapter::name() const
  {
    return "Conceal CCX";
  }

  std::string CcxAdapter::short_name() const
  {
    return "ccx";
  }

  uint64_t CcxAdapter::source_chain_id() const
  {
    return Core::CcxBridge::CCX_CHAIN_ID;
  }

  std::string CcxAdapter::default_rpc_endpoint() const
  {
    return "127.0.0.1:16000";
  }

  uint16_t CcxAdapter::default_confirmation_depth() const
  {
    return Core::CcxBridge::CCX_CONFIRMATION_DEPTH;
  }

  uint8_t CcxAdapter::source_decimals() const
  {
    return Core::CcxBridge::CCX_SOURCE_DECIMALS;
  }

  bool CcxAdapter::probe_rpc(Wallet::RpcClient &rpc,
                             std::string *error_out) const
  {
    const auto ep = rpc.endpoint();
    Common::Json params = Common::Json::object();
    auto resp = rawCall(ep, "/getinfo", params, error_out);
    if (!resp.has_value() || !resp->is_object())
    {
      if (error_out && error_out->empty())
        *error_out = "getinfo response is not an object";
      return false;
    }

    const Common::Json &j = *resp;
    if (!j.contains("status") || !j["status"].is_string())
    {
      if (error_out)
        *error_out = "getinfo response missing 'status'";
      return false;
    }

    const std::string status = j["status"].get<std::string>();
    if (status != "OK")
    {
      if (error_out)
        *error_out = "getinfo status=" + status;
      return false;
    }
    return true;
  }

  ChainStatus CcxAdapter::fetch_status(Wallet::RpcClient &rpc) const
  {
    ChainStatus out;
    out.reachable = false;

    const auto ep = rpc.endpoint();
    Common::Json params = Common::Json::object();
    std::string err;
    auto resp = rawCall(ep, "/getinfo", params, &err);

    if (!resp.has_value() || !resp->is_object())
    {
      out.daemon_version =
          err.empty() ? std::string("(malformed response)") : err;
      return out;
    }

    const Common::Json &j = *resp;

    if (j.contains("status") && j["status"].is_string() &&
        j["status"].get<std::string>() == "OK")
    {
      out.reachable = true;
    }

    if (j.contains("height") && j["height"].is_number_unsigned())
      out.current_height = j["height"].get<uint64_t>();
    else if (j.contains("height") && j["height"].is_number_integer())
      out.current_height = static_cast<uint64_t>(
          j["height"].get<int64_t>());

    if (j.contains("last_known_block_index") &&
        j["last_known_block_index"].is_number_unsigned())
      out.best_peer_height =
          j["last_known_block_index"].get<uint64_t>();

    if (j.contains("version") && j["version"].is_string())
      out.daemon_version = j["version"].get<std::string>();

    return out;
  }

  void CcxAdapter::scan_deposits(
      Wallet::RpcClient &rpc,
      uint64_t from_height,
      uint64_t to_height,
      const std::function<bool(const ObservedDeposit &)> &on_deposit) const
  {
    highest_fully_resolved_height_.reset();

    if (bridge_deposit_address_.size() != 64)
      throw BridgeError(
          "scan_deposits: bridge deposit address not set; call "
          "set_deposit_address first");

    if (!custody_view_key_.has_value())
    {
      std::cerr << "[ccx] scan_deposits: no custody view key configured. "
                   "Cannot derive subaddresses; no deposits will be "
                   "detected. Set --view-key-file (the reduced scalar, "
                   "not the seed).\n";
      return;
    }

    if (bridge_deposits_by_spend_ == nullptr)
    {
      std::cerr << "[ccx] scan_deposits: no deposit-destination cache "
                   "installed. No deposits will be detected until "
                   "refreshBridgeDeposits populates the cache and "
                   "set_bridge_deposits_cache installs it.\n";
      return;
    }

    if (to_height < from_height)
      return;

    const auto ep = rpc.endpoint();

    //  The last height at which every vout was fully resolved.
    //  nullopt means "the first chunk stalled" — the scan loop
    //  should leave its cursor where it is and retry after the
    //  next cache refresh.
    std::optional<uint64_t> last_clean;

    uint64_t cursor = from_height;
    while (cursor <= to_height)
    {
      const uint64_t chunk_end =
          std::min<uint64_t>(cursor + CCX_BLOCK_CHUNK_SIZE - 1,
                             to_height);

      Common::Json params = Common::Json::object();
      params["range"] = true;
      Common::Json heights = Common::Json::array();
      heights.push_back(cursor);
      heights.push_back(chunk_end + 1);
      params["heights"] = heights;
      params["include_miner_txs"] = false;

      std::string err;
      auto resp = rawCall(
          ep, "/get_raw_transactions_by_heights", params, &err);

      if (!resp.has_value() || !resp->is_object())
      {
        throw BridgeError(
            std::string("get_raw_transactions_by_heights failed on [") +
            std::to_string(cursor) + ", " +
            std::to_string(chunk_end) + "]: " +
            (err.empty() ? std::string("(malformed response)") : err));
      }

      const Common::Json &j = *resp;

      if (!j.contains("status") || !j["status"].is_string() ||
          j["status"].get<std::string>() != "OK")
      {
        throw BridgeError(
            "get_raw_transactions_by_heights returned non-OK status");
      }

      if (!j.contains("transactions") || !j["transactions"].is_array())
        throw BridgeError(
            "get_raw_transactions_by_heights returned no transactions");

      bool chunk_clean = true;

      for (const auto &tx : j["transactions"])
      {
        std::vector<ObservedDeposit> deposits;
        bool had_unresolved = false;

        if (!populateDepositsFromJson(tx,
                                      bridge_deposits_by_spend_,
                                      bridge_deposit_address_,
                                      custody_view_key_,
                                      deposits,
                                      had_unresolved))
        {
          //  Structurally malformed tx. Skip it — we can't fix it
          //  by rescanning, so it doesn't hold the cursor.
          continue;
        }

        if (had_unresolved)
        {
          //  A vout in this tx couldn't be matched to a cached
          //  subaddress. The next scan poll after
          //  refreshBridgeDeposits will re-derive and match. Hold
          //  the cursor at the last fully clean chunk.
          chunk_clean = false;
          break;
        }

        for (auto &d : deposits)
        {
          if (!on_deposit(d))
          {
            //  Caller wants to stop. Preserve whatever clean
            //  progress we have.
            if (last_clean.has_value())
              highest_fully_resolved_height_ = *last_clean;
            return;
          }
        }
      }

      if (chunk_clean)
      {
        last_clean = chunk_end;
      }
      else
      {
        //  Unclean chunk: don't advance past it.
        break;
      }

      if (chunk_end == to_height)
        break;
      cursor = chunk_end + 1;
    }

    if (last_clean.has_value())
      highest_fully_resolved_height_ = *last_clean;
  }

  //  =========================================================================
  //  submit_release
  //
  //  Asks walletd to build, sign, and relay a release transaction from
  //  the custody address to the withdrawal's destination.
  //
  //  The walletd protocol:
  //
  //    sendTransaction:
  //      params: {
  //        "transfers": [
  //          { "address": "<base58>", "amount": <atomic> }
  //        ],
  //        "paymentId": "<32-byte hex, no 0x>",
  //        "changeAddress": "<base58>"   // where change goes
  //      }
  //      result: {
  //        "transactionHash": "<hex>",
  //        "transactionSecretKey": "<hex>"
  //      }
  //
  //  Notes:
  //
  //    - sendTransaction returns as soon as the daemon accepts the
  //      tx into the mempool. It does NOT block until confirmation.
  //
  //    - "changeAddress" is the address the walletd puts any change
  //      on. For our release, we want change back to the custody
  //      address (so subsequent releases can draw on it).
  //
  //    - We use walletd's dedicated paymentId field for the
  //      32-byte Blake2b("back" || LE64(withdrawal_id)) value.
  //
  //  The signature_block parameter is ignored: it's the quorum-of-acks
  //  audit record that lands on Clarity in the subsequent
  //  BridgeAckWithdrawal. walletd's authority is the custody spend
  //  key it holds.
  //  =========================================================================
  ReleaseSubmission CcxAdapter::submit_release(
      Wallet::RpcClient & /*rpc*/,
      const ReleaseRequest &request,
      uint64_t amount_source_atomic,
      const std::vector<uint8_t> & /*signature_block*/) const
  {
    ReleaseSubmission out;
    out.ok = false;

    if (wallet_rpc_endpoint_.host.empty() || wallet_rpc_endpoint_.port == 0)
    {
      out.reason =
          "no CCX wallet RPC configured; cannot release. "
          "Set wallet_rpc_host / wallet_rpc_port in the bridge "
          "config (or --ccx-wallet-rpc).";
      return out;
    }

    if (!validate_destination(request.destination_blob))
    {
      out.reason = "destination_blob is not a valid 64-byte "
                   "(spend ‖ view) pubkey pair";
      return out;
    }

    if (amount_source_atomic == 0)
    {
      out.reason = "amount_source_atomic is zero; refusing to release";
      return out;
    }

    const std::string destination_addr = request.destination_address;
    const std::string change_addr = custody_address_string_;

    if (destination_addr.empty())
    {
      out.reason = "withdrawal has no destination_address; cannot "
                   "build a transfer";
      return out;
    }

    if (change_addr.empty())
    {
      out.reason = "no custody address string configured on the "
                   "adapter; cannot build a transfer. Call "
                   "set_custody_address_string at startup.";
      return out;
    }

    Crypto::Hash payment_id;
    {
      uint8_t preimage[8];
      for (int i = 0; i < 8; ++i)
        preimage[i] = uint8_t(request.withdrawal_id >> (i * 8));

      payment_id = Crypto::hashDomain("back", preimage, sizeof(preimage));
    }

    const std::string payment_id_hex =
        bytesToHex(payment_id.data.data(), payment_id.data.size());

    Common::Json params = Common::Json::object();

    Common::Json source_addrs = Common::Json::array();
    source_addrs.push_back(change_addr);
    params["sourceAddresses"] = std::move(source_addrs);

    Common::Json transfers = Common::Json::array();
    Common::Json t = Common::Json::object();
    t["address"] = destination_addr;
    t["amount"] = amount_source_atomic;
    t["message"] = "";
    transfers.push_back(std::move(t));
    params["transfers"] = std::move(transfers);

    params["changeAddress"] = change_addr;
    params["paymentId"] = payment_id_hex;
    params["fee"] = static_cast<uint64_t>(1000);
    params["anonymity"] = static_cast<uint64_t>(0);
    params["unlockTime"] = static_cast<uint64_t>(0);

    std::string wallet_err;
    auto result = call_wallet_rpc(
        wallet_rpc_endpoint_, "sendTransaction", params, &wallet_err);

    if (!result.has_value())
    {
      out.reason = "wallet transfer failed: " +
                   (wallet_err.empty() ? std::string("(unknown error)")
                                       : wallet_err);
      return out;
    }

    if (!result->is_object() ||
        !result->contains("transactionHash") ||
        !(*result)["transactionHash"].is_string())
    {
      out.reason = "wallet transfer returned no transactionHash";
      return out;
    }

    const std::string tx_hash_hex =
        (*result)["transactionHash"].get<std::string>();

    if (!parseHexBytes(tx_hash_hex,
                       out.source_tx_hash.data.data(),
                       out.source_tx_hash.data.size()))
    {
      out.reason = "wallet transfer returned a malformed transactionHash \"" +
                   tx_hash_hex + "\"";
      return out;
    }

    out.ok = true;
    return out;
  }

  void CcxAdapter::set_wallet_rpc_endpoint(const std::string &host,
                                           uint16_t port,
                                           const std::string &user,
                                           const std::string &password)
  {
    wallet_rpc_endpoint_.host = host;
    wallet_rpc_endpoint_.port = port;
    wallet_rpc_endpoint_.user = user;
    wallet_rpc_endpoint_.password = password;
  }

  void CcxAdapter::set_network_prefix(uint64_t prefix)
  {
    ccx_network_prefix_ = prefix;
  }

  std::optional<Crypto::Hash> CcxAdapter::find_existing_release(
      const Crypto::Hash &payment_id) const
  {
    if (wallet_rpc_endpoint_.host.empty() || wallet_rpc_endpoint_.port == 0)
      return std::nullopt;

    const std::string pid_hex =
        bytesToHex(payment_id.data.data(), payment_id.data.size());

    Common::Json params = Common::Json::object();
    params["addresses"] = Common::Json::array();
    params["addresses"].push_back(custody_address_string_);
    params["blockCount"] = static_cast<uint64_t>(200);
    params["paymentId"] = pid_hex;

    std::string err;
    auto result = call_wallet_rpc(
        wallet_rpc_endpoint_, "getTransactionHashes", params, &err);

    if (!result.has_value() || !result->is_object())
      return std::nullopt;

    if (!result->contains("items") || !(*result)["items"].is_array())
      return std::nullopt;

    for (const auto &item : (*result)["items"])
    {
      if (!item.is_object())
        continue;
      if (!item.contains("transactionHashes") ||
          !item["transactionHashes"].is_array())
        continue;
      for (const auto &hash_val : item["transactionHashes"])
      {
        if (!hash_val.is_string())
          continue;
        Crypto::Hash out;
        if (parseHexBytes(hash_val.get<std::string>(),
                          out.data.data(), out.data.size()))
        {
          return out;
        }
      }
    }

    return std::nullopt;
  }

  std::optional<uint64_t> CcxAdapter::fetch_release_height(
      Wallet::RpcClient & /*rpc*/,
      const Crypto::Hash &tx_hash) const
  {
    if (wallet_rpc_endpoint_.host.empty() || wallet_rpc_endpoint_.port == 0)
      return std::nullopt;

    const std::string hash_hex =
        bytesToHex(tx_hash.data.data(), tx_hash.data.size());

    Common::Json params = Common::Json::object();
    params["transactionHash"] = hash_hex;

    std::string err;
    auto resp = call_wallet_rpc(
        wallet_rpc_endpoint_, "getTransaction", params, &err);

    if (!resp.has_value() || !resp->is_object())
      return std::nullopt;

    const Common::Json &j = *resp;

    if (!j.contains("transaction") || !j["transaction"].is_object())
      return std::nullopt;

    const Common::Json &tx = j["transaction"];

    if (!tx.contains("blockIndex") || !tx["blockIndex"].is_number_unsigned())
      return std::nullopt;

    const uint64_t height = tx["blockIndex"].get<uint64_t>();
    if (height == 0 || height == 0xFFFFFFFFull)
      return std::nullopt;

    return height;
  }

  bool CcxAdapter::validate_destination(
      const std::vector<uint8_t> &destination_blob) const
  {
    Crypto::PublicKey spend, view;
    return Core::CcxBridge::decodeDestination(destination_blob,
                                              spend, view);
  }

  void CcxAdapter::set_deposit_address(
      const std::vector<uint8_t> &blob)
  {
    if (blob.size() != Core::CcxBridge::CCX_DESTINATION_BYTES)
    {
      bridge_deposit_address_.clear();
      custody_spend_pub_.reset();
      return;
    }

    bridge_deposit_address_ = blob;

    if (custody_view_key_.has_value())
    {
      Crypto::PublicKey sp;
      std::memcpy(sp.data.data(), blob.data(), 32);
      custody_spend_pub_ = sp;
    }
  }

  void CcxAdapter::set_deposit_ident_secret(
      const Crypto::SecretKey &secret)
  {
    custody_view_key_ = secret;

    if (bridge_deposit_address_.size() >= 32)
    {
      Crypto::PublicKey sp;
      std::memcpy(sp.data.data(), bridge_deposit_address_.data(), 32);
      custody_spend_pub_ = sp;
    }
    else
    {
      custody_spend_pub_.reset();
    }
  }

  std::optional<std::vector<uint8_t>>
  CcxAdapter::parse_deposit_address(const std::string &base58_address,
                                    std::string *error_out) const
  {
    if (base58_address.empty())
    {
      if (error_out)
        *error_out = "empty bridge address";
      return std::nullopt;
    }

    std::string decoded_str;
    if (!Common::decodeBase58(std::string_view(base58_address),
                              decoded_str))
    {
      if (error_out)
        *error_out = "address is not valid base58";
      return std::nullopt;
    }

    if (decoded_str.size() < 1 + 64 + 4)
    {
      if (error_out)
        *error_out = "address is too short (" +
                     std::to_string(decoded_str.size()) + " bytes)";
      return std::nullopt;
    }

    const auto varint = Common::read_varint_from_string<uint64_t>(
        std::string_view(decoded_str));
    if (!varint.success())
    {
      if (error_out)
        *error_out = "address has a malformed varint prefix: " +
                     Common::VarintReadResult<uint64_t>::errorToString(
                         varint.error);
      return std::nullopt;
    }

    const size_t varint_len = varint.bytesRead;

    if (decoded_str.size() != varint_len + 68)
    {
      if (error_out)
        *error_out = "address has unexpected length (" +
                     std::to_string(decoded_str.size()) + " bytes; expected " +
                     std::to_string(varint_len + 68) + ")";
      return std::nullopt;
    }

    const auto *decoded =
        reinterpret_cast<const uint8_t *>(decoded_str.data());

    std::vector<uint8_t> out(
        decoded + varint_len,
        decoded + varint_len + 64);

    bool all_zero = true;
    for (uint8_t b : out)
    {
      if (b != 0)
      {
        all_zero = false;
        break;
      }
    }
    if (all_zero)
    {
      if (error_out)
        *error_out = "bridge address decodes to all-zero pubkeys";
      return std::nullopt;
    }

    return out;
  }

  bool CcxAdapter::validate_deposit_address(
      const std::vector<uint8_t> &blob) const
  {
    if (blob.size() != Core::CcxBridge::CCX_DESTINATION_BYTES)
      return false;

    Crypto::PublicKey spend, view;
    std::memcpy(spend.data.data(), blob.data(), 32);
    std::memcpy(view.data.data(), blob.data() + 32, 32);
    return !spend.isNull() && !view.isNull();
  }

  //  Walk one transaction and emit one ObservedDeposit per vout
  //  that pays to a cached subaddress.
  //
  //  `cache` may be null (no cache installed). In that case no
  //  deposit is emitted and *had_unresolved_vout is set to true —
  //  the scan loop holds its cursor so a later refresh + rescan
  //  can retry.
  //
  //  `bridge_deposit_address` is the custody address's 64-byte
  //  (spend ‖ view) blob. It's used to detect "user sent to the
  //  custody address directly, not to a subaddress" — such a vout
  //  is not a bridge deposit, is skipped, and does NOT count as
  //  unresolved (it will never become a deposit).
  //
  //  Returns true iff the tx was structurally understood (even if
  //  it contained unresolved vouts); the caller decides whether
  //  to hold the cursor based on *had_unresolved_vout.
  bool CcxAdapter::populateDepositsFromJson(
      const Common::Json &tx,
      const BridgeDepositCache *cache,
      const std::vector<uint8_t> &bridge_deposit_address,
      const std::optional<Crypto::SecretKey> &custody_view_key,
      std::vector<ObservedDeposit> &out,
      bool &had_unresolved_vout)
  {
    out.clear();
    had_unresolved_vout = false;

    if (bridge_deposit_address.size() != 64)
      return false;

    if (!custody_view_key.has_value())
    {
      //  No view key means no derivation is possible. Every vout
      //  is unresolvable. scan_deposits bails early in this case
      //  anyway, so this is defence-in-depth.
      had_unresolved_vout = true;
      return true;
    }

    if (!tx.is_object() ||
        !tx.contains("transaction") ||
        !tx["transaction"].is_object())
      return false;

    const auto &txobj = tx["transaction"];

    //  ---- tx hash ----

    Crypto::Hash source_tx_hash;
    if (!tx.contains("hash"))
      return false;
    if (tx["hash"].is_string())
    {
      if (!parseHexBytes(tx["hash"].get<std::string>(),
                         source_tx_hash.data.data(),
                         source_tx_hash.data.size()))
        return false;
    }
    else if (tx["hash"].is_array())
    {
      const auto &arr = tx["hash"];
      if (arr.size() != 32)
        return false;
      for (size_t i = 0; i < 32; ++i)
      {
        if (arr[i].is_number_unsigned())
          source_tx_hash.data[i] =
              static_cast<uint8_t>(arr[i].get<uint32_t>());
        else if (arr[i].is_number_integer())
          source_tx_hash.data[i] =
              static_cast<uint8_t>(arr[i].get<int>());
        else
          return false;
      }
    }
    else
    {
      return false;
    }

    //  ---- block height ----

    uint64_t block_height = 0;
    if (tx.contains("height") && tx["height"].is_number_unsigned())
      block_height = tx["height"].get<uint64_t>();
    else if (tx.contains("height") && tx["height"].is_number_integer())
      block_height = static_cast<uint64_t>(
          tx["height"].get<int64_t>());
    else
      return false;

    //  ---- extra → tx pubkey ----

    if (!txobj.contains("extra"))
      return false;
    std::vector<uint8_t> extra;
    if (!jsonToBytes(txobj["extra"], extra))
      return false;

    Crypto::PublicKey tx_pub;
    if (!extractTxPubkey(extra, tx_pub))
      return false;

    //  ---- derivation ----

    Crypto::KeyDerivation derivation;
    if (!Crypto::generateKeyDerivation(
            tx_pub, *custody_view_key, derivation))
    {
      //  A structurally present tx with a malformed tx pubkey or
      //  invalid view key. Not a deposit; not unresolved either
      //  (retrying won't help — the inputs are wrong).
      return true;
    }

    //  ---- vout walk ----

    if (!txobj.contains("vout") || !txobj["vout"].is_array())
      return false;

    const auto &outputs = txobj["vout"];

    Crypto::PublicKey custody_spend_pub;
    std::memcpy(custody_spend_pub.data.data(),
                bridge_deposit_address.data(), 32);

    for (size_t i = 0; i < outputs.size(); ++i)
    {
      const auto &o = outputs[i];
      if (!o.is_object() || !o.contains("amount"))
        continue;

      if (!o.contains("target") || !o["target"].is_object() ||
          !o["target"].contains("data") ||
          !o["target"]["data"].is_object() ||
          !o["target"]["data"].contains("key"))
        continue;

      std::vector<uint8_t> onchain_key;
      if (!jsonToBytes(o["target"]["data"]["key"], onchain_key))
        continue;
      if (onchain_key.size() != 32)
        continue;

      Crypto::PublicKey P;
      std::memcpy(P.data.data(), onchain_key.data(), 32);

      //  Reverse-derive: what spend pubkey would have produced
      //  this output pubkey under (derivation, i)?
      Crypto::PublicKey candidate;
      if (!Crypto::reverseDeriveCandidate(
              P, derivation, i, candidate))
      {
        //  Malformed on-chain pubkey; not a deposit.
        continue;
      }

      //  Was this vout paid to the custody address directly?
      //  That's not a bridge deposit. Resolved as "not a deposit";
      //  doesn't hold the cursor.
      if (candidate == custody_spend_pub)
        continue;

      //  Is the candidate spend pubkey a registered subaddress?
      if (cache == nullptr)
      {
        had_unresolved_vout = true;
        continue;
      }

      auto it = cache->find(candidate);
      if (it == cache->end())
      {
        //  Candidate is not a known subaddress. This vout
        //  doesn't pay anything we recognize today. It might
        //  become a deposit later (the user registered after
        //  our last cache refresh), so hold the cursor.
        had_unresolved_vout = true;
        continue;
      }

      //  Cache hit. Emit the deposit.
      uint64_t amount = 0;
      if (o["amount"].is_number_unsigned())
        amount = o["amount"].get<uint64_t>();
      else if (o["amount"].is_number_integer())
        amount = static_cast<uint64_t>(o["amount"].get<int64_t>());
      else
        continue;

      if (amount == 0)
        continue;

      ObservedDeposit d;
      d.source_chain_id = Core::CcxBridge::CCX_CHAIN_ID;
      d.source_tx_hash = source_tx_hash;
      d.source_output_index = static_cast<uint32_t>(i);
      d.amount_source_atomic = amount;
      d.block_height = block_height;
      d.deposit_blob.assign(candidate.data.begin(),
                            candidate.data.end());
      d.destination = it->second.destination;

      out.push_back(std::move(d));
    }

    return true;
  }

  namespace
  {
    struct CcxAdapterRegistrar
    {
      CcxAdapterRegistrar()
      {
        ChainAdapterRegistry::registerAdapter(
            std::make_shared<CcxAdapter>());
      }
    };

    [[maybe_unused]] static CcxAdapterRegistrar g_ccx_registrar;
  } // anonymous namespace
} // namespace Bridge