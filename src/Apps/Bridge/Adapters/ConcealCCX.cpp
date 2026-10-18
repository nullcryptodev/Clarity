// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ConcealCCX.h"

#include "Core/Bridge/ConcealCCX.h"

#include "Common/Json.h"
#include "Common/StringTools.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace Bridge
{

  namespace beast = boost::beast;
  namespace http = beast::http;
  namespace net = boost::asio;
  using tcp = net::ip::tcp;

  // ===========================================================================
  // Constants
  //
  // The payment ID that identifies deposits to the bridge.
  //
  // A CCX payment ID is a caller-chosen 8-byte value attached to a
  // transaction's extra field. Deposits to the bridge address are
  // filtered on it; every deposit the bridge will mint has this
  // exact payment ID. The value is ASCII "clrty-br":
  //
  // c l r t y - b r
  // 63 6c 72 74 79 2d 62 72
  //
  // Chosen so it's obvious in a block explorer ("this is a Clarity
  // bridge deposit") and doesn't collide with payment-ID namespaces
  // used by exchanges or other services. Changing it would
  // invalidate every previously-identified deposit; it's fixed for
  // the lifetime of this deployment.
  // ===========================================================================

  namespace
  {
    constexpr uint8_t CCX_BRIDGE_PAYMENT_ID[8] = {
        0x63, 0x6c, 0x72, 0x74, 0x79, 0x2d, 0x62, 0x72};

    // Transaction extra tag for a payment ID (CryptoNote
    // TX_EXTRA_TAG_PAYMENT_ID = 0x00).
    constexpr uint8_t TX_EXTRA_TAG_PAYMENT_ID = 0x00;

    // Chunk size for the scan's batched block queries. conceald
    // caps /get_raw_transactions_by_heights at BLOCK_LIST_MAX_COUNT
    // (1000 in RpcServer.cpp); we use the same value so a scan
    // never has to be rejected for being too large.
    constexpr uint32_t CCX_BLOCK_CHUNK_SIZE = 1000;

    // Timeout for the two HTTP helpers below. Longer than
    // RpcClient's default (5s) because a raw-transactions query
    // over 1000 blocks can genuinely take a while on a busy node.
    constexpr int CCX_HTTP_TIMEOUT_SECONDS = 30;

    // =======================================================================
    // HTTP helpers — two shapes
    //
    // conceald exposes two HTTP surfaces that this adapter uses:
    //
    // JSON-RPC: POST to /, body:
    // {"jsonrpc":"2.0","id":1,"method":"f_block_json","params":{...}}
    //
    // Raw: POST to /getinfo (etc.), body: {...params...}
    //
    // Wallet::RpcClient only speaks the first shape (its call
    // hardcodes path="/" and wraps in the JSON-RPC envelope). The
    // raw shape needs a different path per method, so it doesn't fit
    // RpcClient's interface at all. Rather than growing RpcClient
    // with a second mode — it's a wallet concern, not a bridge
    // concern — the two helpers below duplicate ~80 lines of the
    // transport setup. The alternative (a shared HTTP client library
    // used by both) is more code than the duplication, so the
    // duplication is the deliberate choice.
    //
    // Both helpers return std::nullopt on any failure; the caller
    // is responsible for surfacing a specific error message (they
    // have different error text for "reachable but returns garbage"
    // vs "not reachable").
    // =======================================================================

    Common::Json doHttpPost(const Wallet::RpcEndpoint &ep,
                            const std::string &path,
                            const std::string &body,
                            std::string *error_out)
    {
      try
      {
        net::io_context ioc;
        tcp::resolver resolver(ioc);
        beast::tcp_stream stream(ioc);

        const auto timeout =
            std::chrono::seconds(CCX_HTTP_TIMEOUT_SECONDS);

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

    // JSON-RPC 2.0 POST to /. Envelopes the body and unwraps the
    // result field on success; on a JSON-RPC error object,
    // populates error_out with the error's message and returns
    // nullopt.
    std::optional<Common::Json> jsonRpcCall(
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
          doHttpPost(ep, "/", envelope.dump(), &transport_error);

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

      // JSON-RPC error object.
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
          *error_out = "response has no 'result' field";
        return std::nullopt;
      }

      return resp["result"];
    }

    // Raw POST to a specific path. Caller is responsible for
    // checking status on the response; the raw handlers
    // communicate success in the body, not via HTTP codes.
    std::optional<Common::Json> rawCall(
        const Wallet::RpcEndpoint &ep,
        const std::string &path,
        const Common::Json &params,
        std::string *error_out)
    {
      std::string transport_error;
      Common::Json resp =
          doHttpPost(ep, path, params.dump(), &transport_error);

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

    // =======================================================================
    // Payment-ID extraction
    //
    // A CCX transaction's extra field is a byte array of
    // tag-length-value records. The payment-ID record is:
    //
    // [0x00] tag
    // [0x00..0x08] (8 bytes, BE) payment ID
    //
    // Walk the extra bytes, find the tag, read the following 8
    // bytes. If no record with tag 0x00 is present, the transaction
    // has no payment ID and is not a bridge deposit.
    //
    // This is the standard CryptoNote layout; it hasn't changed in
    // Conceal's fork. If a future hardfork changed the tag or the
    // length, this function is the only place that would need
    // updating.
    // =======================================================================

    bool extractPaymentId(const std::vector<uint8_t> &extra,
                          std::vector<uint8_t> &out)
    {
      out.clear();

      size_t i = 0;
      while (i < extra.size())
      {
        const uint8_t tag = extra[i++];

        if (tag == TX_EXTRA_TAG_PAYMENT_ID)
        {
          if (i + 8 > extra.size())
            return false;
          out.assign(extra.begin() + i, extra.begin() + i + 8);
          return true;
        }

        if (tag == 0x01)
        {
          //  Tag 0x01 (tx public key) is followed by 32 raw bytes,
          //  no length prefix.
          i += 32;
        }
        else if (tag == 0x02 || tag == 0x04)
        {
          if (i >= extra.size())
            return false;
          const uint8_t len = extra[i++];
          if (i + len > extra.size())
            return false;
          i += len;
        }
        else
        {
          return false;
        }
      }
      return false;
    }

    // Compare two 8-byte arrays for equality. Used for the payment
    // ID match. Exposed because it's clearer than std::equal with
    // raw pointers.
    bool paymentIdEquals(const uint8_t a[8], const uint8_t b[8])
    {
      return std::memcmp(a, b, 8) == 0;
    }

    // =======================================================================
    // Deposit reference → ObservedDeposit
    //
    // The scan yields ObservedDeposit records. This helper fills
    // one from the JSON that conceald returns.
    // =======================================================================

    bool populateDepositFromJson(
        const Common::Json &tx,
        const std::vector<uint8_t> &payment_id,
        ObservedDeposit &out)
    {
      if (payment_id.size() != 8)
        return false;
      if (!paymentIdEquals(payment_id.data(), CCX_BRIDGE_PAYMENT_ID))
        return false;

      // source_tx_hash.
      if (!tx.contains("hash") || !tx["hash"].is_string())
        return false;
      const std::string hash_hex = tx["hash"].get<std::string>();
      if (hash_hex.size() != 64)
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
        const int hi = nib(hash_hex[i * 2]);
        const int lo = nib(hash_hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
          return false;
        out.source_tx_hash.data[i] =
            static_cast<uint8_t>((hi << 4) | lo);
      }

      // source_output_index. conceald's raw-transactions response
      // provides output_indexes (a parallel array to the
      // transaction's outputs) — for the bridge there's exactly
      // one relevant output index, but conceald represents this
      // as a vector. We use the first index; the bridge address
      // has one spendable output per deposit by construction.
      //
      // If output_indexes is missing or empty, we fall back to
      // 0, which is the safe default (the executor's replay
      // guard keys on (source_chain_id, tx_hash, index), and
      // index 0 is what the bridge's own output-0 convention
      // uses).
      out.source_output_index = 0;
      if (tx.contains("output_indexes") &&
          tx["output_indexes"].is_array() &&
          !tx["output_indexes"].empty())
      {
        const auto &idxs = tx["output_indexes"];
        if (idxs[0].is_number_unsigned())
          out.source_output_index = idxs[0].get<uint32_t>();
        else if (idxs[0].is_number_integer())
          out.source_output_index =
              static_cast<uint32_t>(idxs[0].get<int64_t>());
        else if (idxs[0].is_string())
        {
          // conceald emits numbers, but a string is possible if
          // the RPC layer serializes 64-bit values as hex. Parse
          // either form.
          const std::string s = idxs[0].get<std::string>();
          errno = 0;
          char *end = nullptr;
          const unsigned long v = std::strtoul(s.c_str(), &end, 0);
          if (errno == 0 && end != s.c_str() && *end == '\0')
            out.source_output_index = static_cast<uint32_t>(v);
        }
      }

      // block_height.
      if (tx.contains("height") && tx["height"].is_number_unsigned())
        out.block_height = tx["height"].get<uint64_t>();
      else if (tx.contains("height") && tx["height"].is_number_integer())
        out.block_height = static_cast<uint64_t>(
            tx["height"].get<int64_t>());
      else
        return false;

      // amount. The raw-transactions response exposes the
      // per-output amount in the transaction sub-object
      // (tx.transaction.outputs[i].amount), or in the flat
      // amount_out field on some conceald builds. Try both.
      // For the bridge, output 0 is the deposit output.
      bool have_amount = false;
      if (tx.contains("amount_out") &&
          tx["amount_out"].is_number_unsigned())
      {
        out.amount_source_atomic = tx["amount_out"].get<uint64_t>();
        have_amount = true;
      }
      else if (tx.contains("transaction") &&
               tx["transaction"].is_object() &&
               tx["transaction"].contains("outputs") &&
               tx["transaction"]["outputs"].is_array() &&
               !tx["transaction"]["outputs"].empty())
      {
        const auto &first_out = tx["transaction"]["outputs"][0];
        if (first_out.is_object() && first_out.contains("amount") &&
            first_out["amount"].is_number_unsigned())
        {
          out.amount_source_atomic =
              first_out["amount"].get<uint64_t>();
          have_amount = true;
        }
      }

      if (!have_amount)
        return false;

      // deposit_blob: the CCX-side reference. Not consumed by the
      // current bridge (the mint identifies the deposit by
      // (tx_hash, output_index)), but the field is part of the
      // interface and future-proofs the deposit record against a
      // second adapter that needs extra context.
      out.deposit_blob.clear();

      out.source_chain_id = Core::CcxBridge::CCX_CHAIN_ID;
      return true;
    }

  } // anonymous namespace

  // ===========================================================================
  // Identity
  // ===========================================================================

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

  // ===========================================================================
  // Defaults
  // ===========================================================================

  std::string CcxAdapter::default_rpc_endpoint() const
  {
    // conceald's default RPC endpoint. The same default the
    // wallet's startup wizard uses for the Clarity node (but a
    // different port: 16000 is conceald's default RPC port;
    // 9633 is the Clarity node's).
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

  // ===========================================================================
  // RPC
  // ===========================================================================

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

    // Bind a const ref once. Inside this block every field read
    // is against j, which is the actual nlohmann::json, not the
    // optional. That's the cleanest way to avoid the deref-per-line
    // pattern.
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

  // ===========================================================================
  // Deposit scan
  //
  // Uses /get_raw_transactions_by_heights in chunks of
  // CCX_BLOCK_CHUNK_SIZE blocks. The response contains, per
  // transaction, the raw TransactionPrefix JSON (with extra as
  // a byte array) which is where we find the payment ID.
  //
  // Alternative considered: f_block_json per block + a
  // f_transaction_json per transaction. Rejected: it's O(txs)
  // round trips instead of O(1), and a scan from genesis would
  // be prohibitively slow. The batch call exists in conceald
  // precisely for this use case.
  // ===========================================================================

  void CcxAdapter::scan_deposits(
      Wallet::RpcClient &rpc,
      const Crypto::PublicKey & /*bridge_view_pubkey*/,
      uint64_t from_height,
      uint64_t to_height,
      const std::function<bool(const ObservedDeposit &)> &on_deposit) const
  {
    if (to_height < from_height)
      return;

    const auto ep = rpc.endpoint();

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
      heights.push_back(chunk_end + 1); // exclusive end (conceald's convention)
      params["heights"] = heights;
      params["include_miner_txs"] = false;

      std::string err;
      auto resp = rawCall(
          ep, "/get_raw_transactions_by_heights", params, &err);

      if (!resp.has_value())
      {
        throw BridgeError(
            std::string("get_raw_transactions_by_heights failed on [") +
            std::to_string(cursor) + ", " + std::to_string(chunk_end) + "]: " + err);
      }

      if (!resp->is_object())
        throw BridgeError(
            "get_raw_transactions_by_heights returned non-object");

      const Common::Json &j = *resp;

      if (!j.contains("status") ||
          !j["status"].is_string() ||
          j["status"].get<std::string>() != "OK")
      {
        const std::string status =
            j.contains("status") && j["status"].is_string()
                ? j["status"].get<std::string>()
                : std::string("(missing)");
        throw BridgeError(
            "get_raw_transactions_by_heights status=" + status);
      }

      if (!j.contains("transactions") ||
          !j["transactions"].is_array())
      {
        throw BridgeError(
            "get_raw_transactions_by_heights response missing "
            "'transactions'");
      }

      for (const auto &tx : j["transactions"])
      {
        if (!tx.is_object())
          continue;

        // Extract payment ID from the transaction's extra.
        // tx.transaction.extra is an array of byte values
        // (0..255) in conceald's JSON encoder.
        if (!tx.contains("transaction") ||
            !tx["transaction"].is_object() ||
            !tx["transaction"].contains("extra") ||
            !tx["transaction"]["extra"].is_array())
          continue;

        std::vector<uint8_t> extra;
        const auto &extra_arr = tx["transaction"]["extra"];
        extra.reserve(extra_arr.size());
        for (const auto &b : extra_arr)
        {
          if (b.is_number_unsigned())
            extra.push_back(static_cast<uint8_t>(b.get<uint32_t>()));
          else if (b.is_number_integer())
            extra.push_back(static_cast<uint8_t>(b.get<int>()));
        }

        std::vector<uint8_t> payment_id;
        if (!extractPaymentId(extra, payment_id))
          continue;

        ObservedDeposit deposit;
        if (!populateDepositFromJson(tx, payment_id, deposit))
          continue;

        if (!on_deposit(deposit))
          return; // caller asked us to stop
      }

      if (chunk_end == to_height)
        break;
      cursor = chunk_end + 1;
    }
  }

  // ===========================================================================
  // Release submission
  // ===========================================================================

  ReleaseSubmission CcxAdapter::submit_release(
      Wallet::RpcClient &rpc,
      const ReleaseRequest & /*request*/,
      uint64_t /*amount_source_atomic*/,
      const std::vector<uint8_t> & /*signature_block*/) const
  {
    // Release submission is not implemented in v1 because the
    // signing service that would produce signature_block is a
    // separate process, out of scope for this batch. When it
    // lands, this becomes:
    //
    // 1. Fetch the CCX-side inputs to spend (from the release
    // custody address — outputs previously deposited by
    // earlier releases).
    // 2. Build a CCX transaction spending one or more of those
    // inputs to request.destination_blob's address, with
    // the fee and signature block that the signing service
    // produced.
    // 3. Serialize the transaction to hex.
    // 4. POST {"tx_as_hex": "<hex>"} to /sendrawtransaction.
    // 5. Return the response's tx hash and depth.
    //
    // The current stub returns ok=false with a clear reason.
    // Callers (currently the scan loop's withdrawal-drain TODO)
    // will surface the reason.
    ReleaseSubmission out;
    out.ok = false;
    out.reason =
        "submit_release not implemented in v1 — signing service "
        "integration is out of scope";
    (void)rpc;
    return out;
  }

  // ===========================================================================
  // Conversion
  //
  // Source → clarity: floor(source / 10^(source_decimals - clarity_decimals)).
  // With CCX's 6 and Clarity's 5, that's source / 10.
  //
  // Clarity → source: multiply by the same divisor. Exact — no
  // rounding, because we're going from fewer decimals to more.
  // ===========================================================================

  uint64_t CcxAdapter::to_clarity_atomic(uint64_t amount_source_atomic,
                                         uint8_t clarity_decimals) const
  {
    if (clarity_decimals >= Core::CcxBridge::CCX_SOURCE_DECIMALS)
    {
      // Unusual configuration: clarity has at least as many
      // decimals as CCX. The conversion is exact (multiply).
      const uint8_t diff =
          clarity_decimals - Core::CcxBridge::CCX_SOURCE_DECIMALS;
      uint64_t mul = 1;
      for (uint8_t i = 0; i < diff; ++i)
        mul *= 10;
      return amount_source_atomic * mul;
    }

    const uint8_t diff =
        Core::CcxBridge::CCX_SOURCE_DECIMALS - clarity_decimals;
    uint64_t div = 1;
    for (uint8_t i = 0; i < diff; ++i)
      div *= 10;
    return amount_source_atomic / div;
  }

  uint64_t CcxAdapter::to_source_atomic(
      uint64_t amount_clarity_atomic,
      uint8_t clarity_decimals) const
  {
    if (clarity_decimals >= Core::CcxBridge::CCX_SOURCE_DECIMALS)
    {
      const uint8_t diff =
          clarity_decimals - Core::CcxBridge::CCX_SOURCE_DECIMALS;
      uint64_t div = 1;
      for (uint8_t i = 0; i < diff; ++i)
        div *= 10;
      return amount_clarity_atomic / div;
    }

    const uint8_t diff =
        Core::CcxBridge::CCX_SOURCE_DECIMALS - clarity_decimals;
    uint64_t mul = 1;
    for (uint8_t i = 0; i < diff; ++i)
      mul *= 10;
    return amount_clarity_atomic * mul;
  }

  // ===========================================================================
  // Destination validation
  // ===========================================================================

  bool CcxAdapter::validate_destination(
      const std::vector<uint8_t> &destination_blob) const
  {
    // Delegate to the CCX bridge's own codec. A valid destination
    // is exactly 64 bytes (spend pubkey || view pubkey), and
    // neither key is null. See Core/Bridge/ConcealCCX.h.
    Crypto::PublicKey spend, view;
    return Core::CcxBridge::decodeDestination(destination_blob,
                                              spend, view);
  }

  // ===========================================================================
  //  Static registration
  //
  //  Populates ChainAdapterRegistry with a single CcxAdapter
  //  instance. Runs once at program startup (before main()),
  //  via the static object's constructor.
  // ===========================================================================

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

    //  The static object whose constructor does the registration.
    //  The `[[maybe_unused]]` is for compilers.
    [[maybe_unused]] static CcxAdapterRegistrar g_ccx_registrar;
  } // anonymous namespace
} // namespace Bridge