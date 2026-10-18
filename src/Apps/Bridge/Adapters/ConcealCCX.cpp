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
    constexpr uint8_t CCX_BRIDGE_PAYMENT_ID[8] = {
        0x63, 0x6c, 0x72, 0x74, 0x79, 0x2d, 0x62, 0x72};

    constexpr uint8_t TX_EXTRA_TAG_PAYMENT_ID = 0x00;
    constexpr uint8_t TX_EXTRA_TAG_PUBKEY = 0x01;
    constexpr uint8_t TX_EXTRA_TAG_NONCE = 0x02;
    constexpr uint8_t TX_EXTRA_TAG_MERGE_MINING = 0x03;
    constexpr uint8_t TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04;

    constexpr uint32_t CCX_BLOCK_CHUNK_SIZE = 1000;
    constexpr int CCX_HTTP_TIMEOUT_SECONDS = 30;

    void dbg(const std::string &msg)
    {
      std::cerr << "[ccx] " << msg << "\n";
    }

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

    bool extractPaymentId(const std::vector<uint8_t> &extra,
                          std::vector<uint8_t> &out)
    {
      out.clear();

      dbg("extractPaymentId: extra.size()=" + std::to_string(extra.size()) +
          " preview=" + hexPreview(extra, 80));

      size_t i = 0;
      while (i < extra.size())
      {
        const uint8_t tag = extra[i];
        dbg("extractPaymentId: tag=0x" + std::to_string(tag) +
            " at offset " + std::to_string(i));
        ++i;

        if (tag == TX_EXTRA_TAG_PAYMENT_ID)
        {
          if (i + 8 > extra.size())
          {
            dbg("extractPaymentId: tag 0x00 but fewer than 8 bytes remain");
            return false;
          }
          out.assign(extra.begin() + i, extra.begin() + i + 8);
          dbg("extractPaymentId: found top-level payment ID " +
              hexPreview(out));
          return true;
        }

        if (tag == TX_EXTRA_TAG_PUBKEY)
        {
          if (i + 32 > extra.size())
          {
            dbg("extractPaymentId: tag 0x01 but fewer than 32 bytes remain");
            return false;
          }
          dbg("extractPaymentId: skipping 32-byte tx pubkey");
          i += 32;
          continue;
        }

        if (tag == TX_EXTRA_TAG_NONCE)
        {
          if (i >= extra.size())
          {
            dbg("extractPaymentId: tag 0x02 but no length byte");
            return false;
          }

          const uint8_t len = extra[i++];
          dbg("extractPaymentId: nonce length=" + std::to_string(len));

          if (i + len > extra.size())
          {
            dbg("extractPaymentId: nonce length exceeds remaining bytes");
            return false;
          }

          const size_t nonce_start = i;
          const size_t nonce_end = i + len;

          size_t j = nonce_start;
          while (j < nonce_end)
          {
            const uint8_t sub_tag = extra[j];
            dbg("extractPaymentId: nonce sub_tag=0x" +
                std::to_string(sub_tag) + " at offset " + std::to_string(j));
            ++j;

            if (sub_tag == TX_EXTRA_TAG_PAYMENT_ID)
            {
              if (j + 8 > nonce_end)
              {
                dbg("extractPaymentId: nonce payment ID shorter than 8 bytes");
                return false;
              }
              out.assign(extra.begin() + j, extra.begin() + j + 8);
              dbg("extractPaymentId: found nonce payment ID " +
                  hexPreview(out));
              return true;
            }

            if (j >= nonce_end)
            {
              dbg("extractPaymentId: sub_tag 0x" +
                  std::to_string(sub_tag) + " with no length");
              return false;
            }
            const uint8_t sub_len = extra[j++];
            dbg("extractPaymentId: sub_tag 0x" +
                std::to_string(sub_tag) + " length=" +
                std::to_string(sub_len));
            if (j + sub_len > nonce_end)
            {
              dbg("extractPaymentId: sub_tag length exceeds nonce data");
              return false;
            }
            j += sub_len;
          }

          i = nonce_end;
          continue;
        }

        if (tag == TX_EXTRA_TAG_MERGE_MINING ||
            tag == TX_EXTRA_TAG_ADDITIONAL_PUBKEYS)
        {
          if (i >= extra.size())
          {
            dbg("extractPaymentId: tag 0x" + std::to_string(tag) +
                " but no length byte");
            return false;
          }
          const uint8_t len = extra[i++];
          dbg("extractPaymentId: tag 0x" + std::to_string(tag) +
              " length=" + std::to_string(len));
          if (i + len > extra.size())
          {
            dbg("extractPaymentId: tag length exceeds remaining bytes");
            return false;
          }
          i += len;
          continue;
        }

        dbg("extractPaymentId: unknown tag 0x" + std::to_string(tag) +
            " — abandoning parse");
        return false;
      }

      dbg("extractPaymentId: exhausted extra without finding a payment ID");
      return false;
    }

    bool paymentIdEquals(const uint8_t a[8], const uint8_t b[8])
    {
      return std::memcmp(a, b, 8) == 0;
    }

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
          {
            dbg("extractTxPubkey: tag 0x01 but fewer than 32 bytes remain");
            return false;
          }
          std::memcpy(out.data.data(), &extra[i], 32);
          dbg("extractTxPubkey: found tx pubkey " +
              hexPreview(std::vector<uint8_t>(
                  out.data.begin(), out.data.end())));
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

        dbg("extractTxPubkey: unknown tag 0x" + std::to_string(tag) +
            " — abandoning parse");
        return false;
      }

      dbg("extractTxPubkey: exhausted extra without finding a tx pubkey");
      return false;
    }

    size_t writeVarint(uint8_t *out, size_t value)
    {
      size_t n = 0;
      do
      {
        uint8_t b = static_cast<uint8_t>(value & 0x7F);
        value >>= 7;
        if (value != 0)
          b |= 0x80;
        out[n++] = b;
      } while (value != 0);
      return n;
    }

    bool populateDepositFromJson(
        const Common::Json &tx,
        const std::vector<uint8_t> &payment_id,
        const std::vector<uint8_t> &bridge_deposit_address,
        const std::optional<Crypto::SecretKey> &custody_view_key,
        const std::optional<Crypto::PublicKey> &custody_spend_pub,
        ObservedDeposit &out)
    {
      dbg("populate: --- entering populateDepositFromJson ---");

      if (payment_id.size() != 8)
      {
        dbg("populate: payment_id.size()=" +
            std::to_string(payment_id.size()) + " (expected 8)");
        return false;
      }

      if (!paymentIdEquals(payment_id.data(), CCX_BRIDGE_PAYMENT_ID))
      {
        dbg("populate: payment ID mismatch (got " +
            hexPreview(payment_id) + ", expected 636c7274792d6272)");
        return false;
      }
      dbg("populate: payment ID matches CCX_BRIDGE_PAYMENT_ID");

      if (bridge_deposit_address.size() != 64)
      {
        dbg("populate: bridge_deposit_address.size()=" +
            std::to_string(bridge_deposit_address.size()) +
            " (expected 64)");
        return false;
      }

      dbg("populate: hash field check — contains=" +
          std::string(tx.contains("hash") ? "yes" : "no") +
          " is_string=" +
          std::string(tx.contains("hash") && tx["hash"].is_string() ? "yes" : "no") +
          " is_array=" +
          std::string(tx.contains("hash") && tx["hash"].is_array() ? "yes" : "no"));

      if (!tx.contains("hash"))
      {
        dbg("populate: no hash field");
        return false;
      }

      if (tx["hash"].is_string())
      {
        const std::string hash_hex = tx["hash"].get<std::string>();
        dbg("populate: hash string \"" + hash_hex + "\" (len " +
            std::to_string(hash_hex.size()) + ")");
        if (!parseHexBytes(hash_hex, out.source_tx_hash.data.data(),
                           out.source_tx_hash.data.size()))
        {
          dbg("populate: hash hex parse failed");
          return false;
        }
      }
      else if (tx["hash"].is_array())
      {
        const auto &arr = tx["hash"];
        dbg("populate: hash is array, size=" + std::to_string(arr.size()));
        if (arr.size() != 32)
        {
          dbg("populate: hash array size != 32");
          return false;
        }
        for (size_t i = 0; i < 32; ++i)
        {
          if (arr[i].is_number_unsigned())
            out.source_tx_hash.data[i] =
                static_cast<uint8_t>(arr[i].get<uint32_t>());
          else if (arr[i].is_number_integer())
            out.source_tx_hash.data[i] =
                static_cast<uint8_t>(arr[i].get<int>());
          else
          {
            dbg("populate: hash array element not numeric");
            return false;
          }
        }
      }
      else
      {
        dbg("populate: hash field is neither string nor array");
        return false;
      }
      dbg("populate: source_tx_hash parsed ok");

      dbg("populate: transaction field check — contains=" +
          std::string(tx.contains("transaction") ? "yes" : "no") +
          " is_object=" +
          std::string(tx.contains("transaction") && tx["transaction"].is_object() ? "yes" : "no"));

      if (!tx.contains("transaction") || !tx["transaction"].is_object())
      {
        dbg("populate: no transaction object");
        return false;
      }

      dbg("populate: transaction.vout field check — contains=" +
          std::string(tx["transaction"].contains("vout") ? "yes" : "no") +
          " is_array=" +
          std::string(tx["transaction"].contains("vout") && tx["transaction"]["vout"].is_array() ? "yes" : "no"));

      if (!tx["transaction"].contains("vout") ||
          !tx["transaction"]["vout"].is_array())
      {
        dbg("populate: vout is not an array");
        return false;
      }

      const auto &outputs = tx["transaction"]["vout"];
      dbg("populate: vout array size=" +
          std::to_string(outputs.size()));

      if (outputs.empty())
      {
        dbg("populate: vout array is empty");
        return false;
      }

      const bool have_keys =
          custody_view_key.has_value() && custody_spend_pub.has_value();

      if (have_keys)
      {
        dbg("populate: using per-output derivation (view+spend configured)");

        if (!tx["transaction"].contains("extra"))
        {
          dbg("populate: no transaction.extra — cannot derive");
          return false;
        }

        std::vector<uint8_t> extra;
        if (!jsonToBytes(tx["transaction"]["extra"], extra))
        {
          dbg("populate: extra could not be parsed as bytes");
          return false;
        }

        Crypto::PublicKey tx_pub;
        if (!extractTxPubkey(extra, tx_pub))
        {
          dbg("populate: no tx pubkey in extra — cannot derive");
          return false;
        }

        Crypto::KeyDerivation derivation;
        if (!Crypto::generateKeyDerivation(tx_pub, *custody_view_key,
                                           derivation))
        {
          dbg("populate: generateKeyDerivation failed "
              "(invalid tx pubkey or view key)");
          return false;
        }

        bool found = false;
        for (size_t i = 0; i < outputs.size(); ++i)
        {
          Crypto::PublicKey expected;
          if (!Crypto::derivePublicKey(derivation, i,
                                       *custody_spend_pub, expected))
          {
            dbg("populate: derivePublicKey failed at index " +
                std::to_string(i));
            continue;
          }

          const auto &o = outputs[i];
          if (!o.is_object() ||
              !o.contains("target") ||
              !o["target"].is_object() ||
              !o["target"].contains("data") ||
              !o["target"]["data"].is_object() ||
              !o["target"]["data"].contains("key"))
          {
            continue;
          }

          std::vector<uint8_t> onchain_key;
          if (!jsonToBytes(o["target"]["data"]["key"], onchain_key))
            continue;
          if (onchain_key.size() != 32)
            continue;

          if (std::memcmp(onchain_key.data(),
                          expected.data.data(), 32) != 0)
            continue;

          out.source_output_index = static_cast<uint32_t>(i);
          if (o["amount"].is_number_unsigned())
            out.amount_source_atomic = o["amount"].get<uint64_t>();
          else if (o["amount"].is_number_integer())
            out.amount_source_atomic = static_cast<uint64_t>(
                o["amount"].get<int64_t>());
          else
          {
            dbg("populate: matched vout[" + std::to_string(i) +
                "] but amount is not numeric");
            return false;
          }

          dbg("populate: matched vout[" + std::to_string(i) +
              "] amount=" + std::to_string(out.amount_source_atomic));
          found = true;
          break;
        }

        if (!found)
        {
          dbg("populate: payment ID matched but no output pays to "
              "the custody address — refusing to mint. Check that "
              "the configured deposit address and view key match.");
          return false;
        }
      }
      else
      {
        static std::atomic<bool> warned{false};
        if (!warned.exchange(true))
        {
          std::cerr
              << "[ccx] WARNING: custody view/spend keys not configured; "
                 "using sum-of-outputs fallback. Minted amounts will be "
                 "WRONG (sum of all vouts, not the deposit output). "
                 "Configure --view-key-file and --bridge-address to fix.\n";
        }

        out.source_output_index = 0;
        out.amount_source_atomic = 0;

        for (size_t i = 0; i < outputs.size(); ++i)
        {
          const auto &o = outputs[i];
          if (!o.is_object())
            continue;
          if (!o.contains("amount"))
            continue;
          if (o["amount"].is_number_unsigned())
          {
            out.amount_source_atomic += o["amount"].get<uint64_t>();
          }
          else if (o["amount"].is_number_integer())
          {
            out.amount_source_atomic += static_cast<uint64_t>(
                o["amount"].get<int64_t>());
          }
        }

        dbg("populate: sum-of-outputs total=" +
            std::to_string(out.amount_source_atomic));
      }

      if (out.amount_source_atomic == 0)
      {
        dbg("populate: amount_source_atomic is 0");
        return false;
      }

      dbg("populate: height field check — contains=" +
          std::string(tx.contains("height") ? "yes" : "no") +
          " is_number_unsigned=" +
          std::string(tx.contains("height") && tx["height"].is_number_unsigned() ? "yes" : "no") +
          " is_number_integer=" +
          std::string(tx.contains("height") && tx["height"].is_number_integer() ? "yes" : "no"));

      if (tx.contains("height") && tx["height"].is_number_unsigned())
      {
        out.block_height = tx["height"].get<uint64_t>();
      }
      else if (tx.contains("height") && tx["height"].is_number_integer())
      {
        out.block_height = static_cast<uint64_t>(
            tx["height"].get<int64_t>());
      }
      else
      {
        dbg("populate: height field missing or wrong type");
        return false;
      }

      dbg("populate: block_height=" + std::to_string(out.block_height));

      out.deposit_blob.clear();
      out.source_chain_id = Core::CcxBridge::CCX_CHAIN_ID;

      dbg("populate: SUCCESS — deposit populated");
      return true;
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
      const Crypto::PublicKey & /*bridge_view_pubkey*/,
      uint64_t from_height,
      uint64_t to_height,
      const std::function<bool(const ObservedDeposit &)> &on_deposit) const
  {
    dbg("scan_deposits: from=" + std::to_string(from_height) +
        " to=" + std::to_string(to_height) +
        " bridge_addr_size=" + std::to_string(bridge_deposit_address_.size()) +
        " have_custody_keys=" +
        std::string(custody_view_key_.has_value() &&
                            custody_spend_pub_.has_value()
                        ? "yes"
                        : "no"));

    if (bridge_deposit_address_.size() != 64)
      throw BridgeError(
          "scan_deposits: bridge deposit address not set; call "
          "set_deposit_address first");

    if (to_height < from_height)
    {
      dbg("scan_deposits: to < from, returning");
      return;
    }

    const auto ep = rpc.endpoint();

    uint64_t cursor = from_height;
    while (cursor <= to_height)
    {
      const uint64_t chunk_end =
          std::min<uint64_t>(cursor + CCX_BLOCK_CHUNK_SIZE - 1,
                             to_height);
      dbg("scan_deposits: chunk [" + std::to_string(cursor) + ", " +
          std::to_string(chunk_end) + "]");

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

      if (!resp.has_value())
      {
        dbg("scan_deposits: rawCall failed: " + err);
        throw BridgeError(
            std::string("get_raw_transactions_by_heights failed on [") +
            std::to_string(cursor) + ", " + std::to_string(chunk_end) + "]: " + err);
      }

      if (!resp->is_object())
      {
        dbg("scan_deposits: response is not object");
        throw BridgeError(
            "get_raw_transactions_by_heights returned non-object");
      }

      const Common::Json &j = *resp;

      if (!j.contains("status") ||
          !j["status"].is_string() ||
          j["status"].get<std::string>() != "OK")
      {
        const std::string status =
            j.contains("status") && j["status"].is_string()
                ? j["status"].get<std::string>()
                : std::string("(missing)");
        dbg("scan_deposits: status not OK: " + status);
        throw BridgeError(
            "get_raw_transactions_by_heights status=" + status);
      }

      if (!j.contains("transactions") ||
          !j["transactions"].is_array())
      {
        dbg("scan_deposits: response missing 'transactions' array");
        throw BridgeError(
            "get_raw_transactions_by_heights response missing "
            "'transactions'");
      }

      dbg("scan_deposits: response has " +
          std::to_string(j["transactions"].size()) + " transactions");

      for (const auto &tx : j["transactions"])
      {
        dbg("scan_deposits: --- transaction ---");
        dbg("scan_deposits: tx keys=" +
            std::string(tx.is_object() ? "object" : "not-object"));

        if (tx.is_object())
        {
          std::string keys;
          for (auto it = tx.begin(); it != tx.end(); ++it)
          {
            if (!keys.empty())
              keys += ", ";
            keys += it.key();
          }
          dbg("scan_deposits: tx top-level keys: " + keys);

          if (tx.contains("hash"))
          {
            const auto &h = tx["hash"];
            if (h.is_string())
              dbg("scan_deposits: tx.hash (string) = " +
                  h.get<std::string>());
            else if (h.is_array())
            {
              std::string hex;
              static const char HEX[] = "0123456789abcdef";
              for (const auto &b : h)
              {
                uint8_t v = 0;
                if (b.is_number_unsigned())
                  v = static_cast<uint8_t>(b.get<uint32_t>());
                else if (b.is_number_integer())
                  v = static_cast<uint8_t>(b.get<int>());
                hex.push_back(HEX[v >> 4]);
                hex.push_back(HEX[v & 0xF]);
              }
              dbg("scan_deposits: tx.hash (array) = " + hex);
            }
            else
              dbg("scan_deposits: tx.hash (unknown type)");
          }
        }

        if (!tx.contains("transaction") ||
            !tx["transaction"].is_object() ||
            !tx["transaction"].contains("extra"))
        {
          dbg("scan_deposits: no transaction.extra — skipping");
          continue;
        }

        std::vector<uint8_t> extra;
        if (!jsonToBytes(tx["transaction"]["extra"], extra))
        {
          dbg("scan_deposits: extra could not be parsed as bytes");
          continue;
        }
        dbg("scan_deposits: extra size=" +
            std::to_string(extra.size()));

        std::vector<uint8_t> payment_id;
        if (!extractPaymentId(extra, payment_id))
        {
          dbg("scan_deposits: extractPaymentId returned false");
          continue;
        }
        dbg("scan_deposits: payment ID = " + hexPreview(payment_id));

        ObservedDeposit deposit;
        if (!populateDepositFromJson(tx, payment_id,
                                     bridge_deposit_address_,
                                     custody_view_key_,
                                     custody_spend_pub_,
                                     deposit))
        {
          dbg("scan_deposits: populateDepositFromJson returned false");
          continue;
        }

        dbg("scan_deposits: deposit populated: "
            "hash=" +
            deposit.source_tx_hash.toString().substr(0, 16) +
            "... index=" + std::to_string(deposit.source_output_index) +
            " amount=" + std::to_string(deposit.amount_source_atomic) +
            " height=" + std::to_string(deposit.block_height));

        if (!on_deposit(deposit))
        {
          dbg("scan_deposits: on_deposit returned false — stopping");
          return;
        }
      }

      if (chunk_end == to_height)
        break;
      cursor = chunk_end + 1;
    }
  }

  ReleaseSubmission CcxAdapter::submit_release(
      Wallet::RpcClient &rpc,
      const ReleaseRequest & /*request*/,
      uint64_t /*amount_source_atomic*/,
      const std::vector<uint8_t> & /*signature_block*/) const
  {
    ReleaseSubmission out;
    out.ok = false;
    out.reason =
        "submit_release not implemented in v1 — signing service "
        "integration is out of scope";
    (void)rpc;
    return out;
  }

  uint64_t CcxAdapter::to_clarity_atomic(uint64_t amount_source_atomic,
                                         uint8_t clarity_decimals) const
  {
    if (clarity_decimals >= Core::CcxBridge::CCX_SOURCE_DECIMALS)
    {
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
      dbg("set_deposit_address: spend_pub re-derived from address");
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
      dbg("set_deposit_ident_secret: view key set; spend_pub derived "
          "from address: " +
          sp.toString().substr(0, 16) + "...");
    }
    else
    {
      custody_spend_pub_.reset();
      dbg("set_deposit_ident_secret: WARNING — no bridge address set, "
          "derivation path inactive until set_deposit_address is called");
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