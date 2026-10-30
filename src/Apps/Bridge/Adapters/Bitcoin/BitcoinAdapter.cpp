// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BitcoinAdapter.h"

#include "Common/Json.h"
#include "Common/StringTools.h"

#include "Core/Bridge/Bitcoin.h"

#include "Crypto/Types.h"
#include "Crypto/BitcoinEcdsa.h"
#include "Crypto/BitcoinTransaction.h"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <iostream>

#include <sys/socket.h>
#include <sys/time.h>

namespace Bridge
{
  namespace net = boost::asio;
  using tcp = net::ip::tcp;

  namespace
  {
    constexpr uint64_t BTC_CHAIN_ID = 0x42544331ULL;
    constexpr uint8_t BTC_SOURCE_DECIMALS = 8;
    constexpr uint16_t BTC_CONFIRMATION_DEPTH = 6;
    constexpr int BTC_HTTP_TIMEOUT_SECONDS = 30;
    constexpr size_t BTC_MAX_SCRIPT_BYTES = 10'000;

    //  ---- URL parsing ----

    struct ParsedUrl
    {
      std::string scheme;
      std::string host;
      std::string port;
      std::string path;
    };

    std::optional<ParsedUrl> parseUrl(const std::string &url,
                                      std::string *error_out)
    {
      ParsedUrl out;

      const size_t scheme_end = url.find("://");
      if (scheme_end == std::string::npos)
      {
        if (error_out)
          *error_out = "URL has no scheme: " + url;
        return std::nullopt;
      }
      out.scheme = url.substr(0, scheme_end);
      if (out.scheme != "http" && out.scheme != "https")
      {
        if (error_out)
          *error_out = "URL scheme not http/https: " + out.scheme;
        return std::nullopt;
      }

      const std::string rest = url.substr(scheme_end + 3);
      const size_t slash = rest.find('/');
      const std::string host_port = (slash == std::string::npos)
                                        ? rest
                                        : rest.substr(0, slash);
      out.path = (slash == std::string::npos) ? "/" : rest.substr(slash);

      const size_t colon = host_port.find(':');
      if (colon == std::string::npos)
      {
        out.host = host_port;
        out.port = (out.scheme == "https") ? "443" : "80";
      }
      else
      {
        out.host = host_port.substr(0, colon);
        out.port = host_port.substr(colon + 1);
      }

      if (out.host.empty())
      {
        if (error_out)
          *error_out = "URL has no host: " + url;
        return std::nullopt;
      }

      return out;
    }

    //  ---- Synchronous HTTPS/HTTP client ----

    struct HttpResult
    {
      bool ok{false};
      bool timed_out{false};
      unsigned status_code{0};
      std::string body;
      std::string error;
    };

    void setSocketTimeout(tcp::socket &sock, int seconds)
    {
      const int fd = sock.native_handle();
      struct timeval tv;
      tv.tv_sec = seconds;
      tv.tv_usec = 0;
      ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }

    HttpResult doHttpRequest(
        const std::string &method,
        const std::string &url,
        const std::string &body,
        int timeout_seconds)
    {
      HttpResult result;

      auto parsed = parseUrl(url, &result.error);
      if (!parsed.has_value())
        return result;

      const auto &p = *parsed;
      const bool is_https = (p.scheme == "https");

      try
      {
        net::io_context ioc;
        tcp::resolver resolver(ioc);
        auto endpoints = resolver.resolve(p.host, p.port);
        if (endpoints.empty())
        {
          result.error = "DNS resolve returned no endpoints";
          return result;
        }

        if (is_https)
        {
          net::ssl::context ctx(net::ssl::context::tls_client);
          ctx.set_default_verify_paths();

          net::ssl::stream<tcp::socket> stream(ioc, ctx);
          if (!SSL_set_tlsext_host_name(
                  stream.native_handle(), p.host.c_str()))
          {
            result.error = "TLS SNI setup failed";
            return result;
          }

          net::connect(stream.next_layer(), endpoints);
          setSocketTimeout(stream.next_layer(), timeout_seconds);

          boost::system::error_code ec;
          stream.handshake(net::ssl::stream_base::client, ec);
          if (ec)
          {
            if (ec.value() ==
                    static_cast<int>(boost::asio::error::would_block) ||
                ec.value() ==
                    static_cast<int>(boost::asio::error::try_again))
            {
              result.error = "timeout";
              result.timed_out = true;
              return result;
            }
            result.error = "TLS handshake: " + ec.message();
            return result;
          }

          std::ostringstream req;
          req << method << " " << p.path << " HTTP/1.1\r\n";
          req << "Host: " << p.host << "\r\n";
          req << "User-Agent: clarity-bridge/0.1\r\n";
          req << "Connection: close\r\n";
          if (!body.empty())
          {
            req << "Content-Type: application/json\r\n";
            req << "Content-Length: " << body.size() << "\r\n";
          }
          req << "\r\n";
          req << body;

          boost::system::error_code wec;
          net::write(stream, net::buffer(req.str()), wec);
          if (wec)
          {
            if (wec.value() ==
                    static_cast<int>(boost::asio::error::would_block) ||
                wec.value() ==
                    static_cast<int>(boost::asio::error::try_again))
            {
              result.error = "timeout";
              result.timed_out = true;
              return result;
            }
            result.error = "HTTP write: " + wec.message();
            return result;
          }

          std::string response_str;
          for (;;)
          {
            char buf[8192];
            boost::system::error_code rec;
            const size_t n = stream.read_some(net::buffer(buf), rec);
            if (n > 0)
              response_str.append(buf, n);
            if (rec == net::error::eof)
              break;
            if (rec)
            {
              if (rec.value() ==
                      static_cast<int>(boost::asio::error::would_block) ||
                  rec.value() ==
                      static_cast<int>(boost::asio::error::try_again))
              {
                result.error = "timeout";
                result.timed_out = true;
                return result;
              }
              result.error = "HTTP read: " + rec.message();
              return result;
            }
            if (n == 0)
              break;
          }

          const size_t header_end = response_str.find("\r\n\r\n");
          if (header_end == std::string::npos)
          {
            result.error = "malformed HTTP response (no CRLFCRLF)";
            return result;
          }
          const std::string header_block =
              response_str.substr(0, header_end);
          std::string body_bytes =
              response_str.substr(header_end + 4);

          std::istringstream hs(header_block);
          std::string status_line;
          std::getline(hs, status_line);
          if (!status_line.empty() && status_line.back() == '\r')
            status_line.pop_back();
          if (status_line.size() >= 12)
          {
            result.status_code = static_cast<unsigned>(
                std::stoul(status_line.substr(9, 3)));
          }

          bool chunked = false;
          std::string header_line;
          while (std::getline(hs, header_line))
          {
            if (!header_line.empty() && header_line.back() == '\r')
              header_line.pop_back();
            std::string lower = header_line;
            for (auto &c : lower)
              c = std::tolower(c);
            if (lower.rfind("transfer-encoding:", 0) == 0 &&
                lower.find("chunked") != std::string::npos)
              chunked = true;
          }

          if (chunked)
          {
            std::string decoded;
            size_t pos = 0;
            while (pos < body_bytes.size())
            {
              const size_t line_end = body_bytes.find("\r\n", pos);
              if (line_end == std::string::npos)
                break;
              size_t chunk_size = 0;
              try
              {
                chunk_size = std::stoul(
                    body_bytes.substr(pos, line_end - pos), nullptr, 16);
              }
              catch (...)
              {
                break;
              }
              pos = line_end + 2;
              if (chunk_size == 0)
                break;
              if (pos + chunk_size > body_bytes.size())
                break;
              decoded.append(body_bytes, pos, chunk_size);
              pos += chunk_size + 2;
            }
            body_bytes = std::move(decoded);
          }

          result.ok = true;
          result.body = std::move(body_bytes);
          return result;
        }
        else
        {
          tcp::socket sock(ioc);
          net::connect(sock, endpoints);
          setSocketTimeout(sock, timeout_seconds);

          std::ostringstream req;
          req << method << " " << p.path << " HTTP/1.1\r\n";
          req << "Host: " << p.host << "\r\n";
          req << "User-Agent: clarity-bridge/0.1\r\n";
          req << "Connection: close\r\n";
          if (!body.empty())
          {
            req << "Content-Type: application/json\r\n";
            req << "Content-Length: " << body.size() << "\r\n";
          }
          req << "\r\n";
          req << body;

          boost::system::error_code wec;
          net::write(sock, net::buffer(req.str()), wec);
          if (wec)
          {
            if (wec.value() ==
                    static_cast<int>(boost::asio::error::would_block) ||
                wec.value() ==
                    static_cast<int>(boost::asio::error::try_again))
            {
              result.error = "timeout";
              result.timed_out = true;
              return result;
            }
            result.error = "HTTP write: " + wec.message();
            return result;
          }

          std::string response_str;
          for (;;)
          {
            char buf[8192];
            boost::system::error_code rec;
            const size_t n = net::read(sock, net::buffer(buf), rec);
            if (rec == net::error::eof)
              break;
            if (rec)
            {
              if (rec.value() ==
                      static_cast<int>(boost::asio::error::would_block) ||
                  rec.value() ==
                      static_cast<int>(boost::asio::error::try_again))
              {
                result.error = "timeout";
                result.timed_out = true;
                return result;
              }
              result.error = "HTTP read: " + rec.message();
              return result;
            }
            if (n == 0)
              break;
            response_str.append(buf, n);
          }

          const size_t header_end = response_str.find("\r\n\r\n");
          if (header_end == std::string::npos)
          {
            result.error = "malformed HTTP response (no CRLFCRLF)";
            return result;
          }
          const std::string header_block =
              response_str.substr(0, header_end);
          std::string body_bytes =
              response_str.substr(header_end + 4);

          std::istringstream hs(header_block);
          std::string status_line;
          std::getline(hs, status_line);
          if (!status_line.empty() && status_line.back() == '\r')
            status_line.pop_back();
          if (status_line.size() >= 12)
          {
            result.status_code = static_cast<unsigned>(
                std::stoul(status_line.substr(9, 3)));
          }

          bool chunked = false;
          std::string header_line;
          while (std::getline(hs, header_line))
          {
            if (!header_line.empty() && header_line.back() == '\r')
              header_line.pop_back();
            std::string lower = header_line;
            for (auto &c : lower)
              c = std::tolower(c);
            if (lower.rfind("transfer-encoding:", 0) == 0 &&
                lower.find("chunked") != std::string::npos)
              chunked = true;
          }

          if (chunked)
          {
            std::string decoded;
            size_t pos = 0;
            while (pos < body_bytes.size())
            {
              const size_t line_end = body_bytes.find("\r\n", pos);
              if (line_end == std::string::npos)
                break;
              size_t chunk_size = 0;
              try
              {
                chunk_size = std::stoul(
                    body_bytes.substr(pos, line_end - pos), nullptr, 16);
              }
              catch (...)
              {
                break;
              }
              pos = line_end + 2;
              if (chunk_size == 0)
                break;
              if (pos + chunk_size > body_bytes.size())
                break;
              decoded.append(body_bytes, pos, chunk_size);
              pos += chunk_size + 2;
            }
            body_bytes = std::move(decoded);
          }

          result.ok = true;
          result.body = std::move(body_bytes);
          return result;
        }
      }
      catch (const std::exception &e)
      {
        result.error = std::string("transport: ") + e.what();
        return result;
      }
    }

    //  ---- JSON wrappers ----

    std::optional<Common::Json> jsonGet(
        const std::string &url,
        int timeout_seconds,
        std::string *error_out)
    {
      auto result = doHttpRequest("GET", url, "", timeout_seconds);
      if (!result.ok)
      {
        if (error_out)
          *error_out = result.error;
        return std::nullopt;
      }

      try
      {
        return Common::Json::parse(result.body);
      }
      catch (const std::exception &e)
      {
        if (error_out)
          *error_out = std::string("malformed JSON: ") + e.what();
        return std::nullopt;
      }
    }

    std::optional<Common::Json> jsonPost(
        const std::string &url,
        const std::string &body,
        int timeout_seconds,
        std::string *error_out)
    {
      auto result = doHttpRequest("POST", url, body, timeout_seconds);
      if (!result.ok)
      {
        if (error_out)
          *error_out = result.error;
        return std::nullopt;
      }

      try
      {
        return Common::Json::parse(result.body);
      }
      catch (const std::exception &e)
      {
        if (error_out)
          *error_out = std::string("malformed JSON: ") + e.what();
        return std::nullopt;
      }
    }

    //  ---- bitcoind JSON-RPC call ----

    std::optional<Common::Json> callBitcoinRpc(
        const Wallet::RpcEndpoint &ep,
        const std::string &method,
        const Common::Json &params,
        std::string *error_out)
    {
      Common::Json envelope = Common::Json::object();
      envelope["jsonrpc"] = "1.0";
      envelope["id"] = 1;
      envelope["method"] = method;
      envelope["params"] = params;

      const std::string url =
          "http://" + ep.host + ":" + std::to_string(ep.port) + "/";

      auto resp = jsonPost(url, envelope.dump(),
                           BTC_HTTP_TIMEOUT_SECONDS, error_out);
      if (!resp.has_value())
        return std::nullopt;

      if (!resp->is_object())
      {
        if (error_out)
          *error_out = "response is not an object";
        return std::nullopt;
      }

      if (resp->contains("error") && !(*resp)["error"].is_null())
      {
        const auto &err = (*resp)["error"];
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

      if (!resp->contains("result"))
      {
        if (error_out)
          *error_out = "response has no 'result' field";
        return std::nullopt;
      }

      return (*resp)["result"];
    }

    //  ---- mempool.space calls ----

    std::optional<Common::Json> callMempoolGet(
        const BitcoinConfig &config,
        const std::string &path,
        std::string *error_out)
    {
      std::string base = config.mempool_url;
      if (base.empty())
      {
        if (error_out)
          *error_out = "mempool_url is empty";
        return std::nullopt;
      }
      if (base.find("://") == std::string::npos)
        base = "https://" + base;

      std::string url = base + path;
      if (!config.mempool_api_key.empty())
      {
        url += (url.find('?') == std::string::npos ? '?' : '&');
        url += "key=";
        url += config.mempool_api_key;
      }

      return jsonGet(url, BTC_HTTP_TIMEOUT_SECONDS, error_out);
    }

    std::optional<std::string> callMempoolGetText(
        const BitcoinConfig &config,
        const std::string &path,
        std::string *error_out)
    {
      std::string base = config.mempool_url;
      if (base.empty())
      {
        if (error_out)
          *error_out = "mempool_url is empty";
        return std::nullopt;
      }
      if (base.find("://") == std::string::npos)
        base = "https://" + base;

      std::string url = base + path;
      if (!config.mempool_api_key.empty())
      {
        url += (url.find('?') == std::string::npos ? '?' : '&');
        url += "key=";
        url += config.mempool_api_key;
      }

      auto result = doHttpRequest("GET", url, "", BTC_HTTP_TIMEOUT_SECONDS);
      if (!result.ok)
      {
        if (error_out)
          *error_out = result.error;
        return std::nullopt;
      }
      return result.body;
    }

    //  ---- Hex helpers ----

    std::string hexOf(const std::vector<uint8_t> &bytes)
    {
      static const char HEX[] = "0123456789abcdef";
      std::string out;
      out.reserve(bytes.size() * 2);
      for (uint8_t b : bytes)
      {
        out.push_back(HEX[b >> 4]);
        out.push_back(HEX[b & 0xF]);
      }
      return out;
    }

    bool bytesFromHex(const std::string &s, std::vector<uint8_t> &out)
    {
      out.clear();
      size_t i = 0;
      if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        i = 2;
      if ((s.size() - i) % 2 != 0)
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
      out.reserve((s.size() - i) / 2);
      for (; i < s.size(); i += 2)
      {
        const int hi = nib(s[i]);
        const int lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0)
          return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
      }
      return true;
    }

    bool parseTxidFromHex(const std::string &hex_txid, Crypto::Hash &out)
    {
      std::vector<uint8_t> bytes;
      if (!bytesFromHex(hex_txid, bytes) || bytes.size() != 32)
        return false;
      std::reverse(bytes.begin(), bytes.end());
      std::memcpy(out.data.data(), bytes.data(), 32);
      return true;
    }

    bool scriptFromHex(const std::string &hex_script,
                       std::vector<uint8_t> &out)
    {
      return bytesFromHex(hex_script, out) && !out.empty() &&
             out.size() <= BTC_MAX_SCRIPT_BYTES;
    }

    bool looksLikeScriptHex(const std::string &s)
    {
      size_t i = 0;
      if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        i = 2;
      if (i >= s.size() || (s.size() - i) % 2 != 0)
        return false;
      const size_t bytes = (s.size() - i) / 2;
      if (bytes == 0 || bytes > BTC_MAX_SCRIPT_BYTES)
        return false;
      for (; i < s.size(); ++i)
      {
        const char c = s[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
          return false;
      }
      return true;
    }

    //  Turn a 22-byte P2WPKH scriptPubKey into the lookup key used
    //  by BitcoinCustody::scriptsInWindow(). We copy into a fixed
    //  array (not a vector) because that's what the custody map's
    //  key type is.
    bool scriptToCustodyKey(const std::vector<uint8_t> &script,
                            std::array<uint8_t, 22> &out)
    {
      if (script.size() != 22)
        return false;
      if (script[0] != 0x00 || script[1] != 0x14)
        return false;
      std::memcpy(out.data(), script.data(), 22);
      return true;
    }

    //  Fetch all UTXOs across the custody window. Returns the
    //  union, unsorted. Fails if any address's UTXO fetch fails —
    //  partial success here would be worse than failure, because
    //  "I checked and there's no UTXO big enough" is a much
    //  stronger claim than "I checked the first three addresses
    //  and the fourth errored out". The caller decides whether
    //  a failure is retriable.
    //
    //  Per-address query shape (mempool.space Esplora):
    //    GET /address/<addr>/utxo
    //  returns a JSON array of {txid, vout, value, status:{...}}.
    //  `status.confirmed` is true for buried outputs. We accept
    //  both confirmed and unconfirmed — an unconfirmed UTXO is
    //  spendable if we can outbid its ancestor, and mempool.space
    //  broadcast will surface an RBF-or-cpfp failure if not.
    std::optional<std::vector<BitcoinAdapter::UtxoCandidate>>
    fetchCustodyUtxosImpl(
        const BitcoinConfig &config,
        const BitcoinCustody &custody,
        std::string *error_out)
    {
      std::vector<BitcoinAdapter::UtxoCandidate> out;

      if (!custody.canSpend())
      {
        if (error_out)
          *error_out = "custody is watch-only (FromXpub); cannot "
                       "enumerate spendable UTXOs";
        return std::nullopt;
      }

      for (const auto &[script_key, ds] : custody.scriptsInWindow())
      {
        (void)script_key;
        std::string err;
        auto resp = callMempoolGet(
            config, "/address/" + ds.address + "/utxo", &err);
        if (!resp.has_value() || !resp->is_array())
        {
          if (error_out)
            *error_out = "GET /address/" + ds.address +
                         "/utxo failed: " +
                         (err.empty() ? std::string("(malformed)") : err);
          return std::nullopt;
        }

        for (const auto &u : *resp)
        {
          if (!u.is_object())
            continue;
          if (!u.contains("txid") || !u["txid"].is_string())
            continue;
          if (!u.contains("vout") || !u["vout"].is_number_unsigned())
            continue;
          if (!u.contains("value") || !u["value"].is_number_unsigned())
            continue;

          BitcoinAdapter::UtxoCandidate c;
          c.address = ds.address;
          c.script = std::vector<uint8_t>(ds.script.begin(), ds.script.end());
          c.index = ds.index;
          Crypto::Hash txid_hash;
          if (!parseTxidFromHex(u["txid"].get<std::string>(), txid_hash))
            continue;
          std::memcpy(c.txid_wire.data(), txid_hash.data.data(), 32);
          c.vout = static_cast<uint32_t>(u["vout"].get<uint64_t>());
          c.value_sat = u["value"].get<uint64_t>();
          if (c.value_sat == 0)
            continue;
          out.push_back(std::move(c));
        }
      }

      return out;
    }

    //  Fetch the half-hour fee rate (sat/vB) from mempool.space.
    //  Returns nullopt on failure; the caller falls back to 1
    //  sat/vB. The response shape is:
    //    {"fastestFee":N,"halfHourFee":N,"hourFee":N,
    //     "economyFee":N,"minimumFee":N}
    std::optional<uint64_t>
    fetchHalfHourFeeRateImpl(const BitcoinConfig &config,
                             std::string *error_out)
    {
      std::string err;
      auto resp = callMempoolGet(config, "/v1/fees/recommended", &err);
      if (!resp.has_value() || !resp->is_object())
      {
        if (error_out)
          *error_out = err.empty() ? "fee rate: malformed response"
                                   : err;
        return std::nullopt;
      }
      if (!resp->contains("halfHourFee") ||
          !(*resp)["halfHourFee"].is_number_unsigned())
      {
        if (error_out)
          *error_out = "fee rate: no halfHourFee field";
        return std::nullopt;
      }
      return (*resp)["halfHourFee"].get<uint64_t>();
    }
  } // anonymous namespace

  //  ==========================================================================
  //  Identity and defaults
  //  ==========================================================================

  std::string BitcoinAdapter::name() const
  {
    return "Bitcoin";
  }

  std::string BitcoinAdapter::short_name() const
  {
    return "btc";
  }

  uint64_t BitcoinAdapter::source_chain_id() const
  {
    return BTC_CHAIN_ID;
  }

  std::string BitcoinAdapter::default_rpc_endpoint() const
  {
    return "127.0.0.1:8332";
  }

  uint16_t BitcoinAdapter::default_confirmation_depth() const
  {
    return BTC_CONFIRMATION_DEPTH;
  }

  uint8_t BitcoinAdapter::source_decimals() const
  {
    return BTC_SOURCE_DECIMALS;
  }

  //  ==========================================================================
  //  Probe and status
  //  ==========================================================================

  bool BitcoinAdapter::probe_rpc(Wallet::RpcClient &rpc,
                                 std::string *error_out) const
  {
    if (config_.transport == BitcoinTransport::MempoolSpace)
    {
      std::string err;
      auto resp = callMempoolGet(config_, "/blocks/tip/height", &err);
      if (!resp.has_value() || !resp->is_number_unsigned())
      {
        if (error_out)
          *error_out = err.empty()
                           ? "mempool tip height not a number"
                           : err;
        return false;
      }
      return true;
    }

    const auto ep = rpc.endpoint();
    Common::Json params = Common::Json::array();
    auto resp = callBitcoinRpc(ep, "getblockchaininfo", params, error_out);
    if (!resp.has_value() || !resp->is_object())
    {
      if (error_out && error_out->empty())
        *error_out = "getblockchaininfo response is not an object";
      return false;
    }
    return true;
  }

  ChainStatus BitcoinAdapter::fetch_status(Wallet::RpcClient &rpc) const
  {
    ChainStatus out;
    out.reachable = false;

    if (config_.transport == BitcoinTransport::MempoolSpace)
    {
      std::string err;
      auto resp = callMempoolGet(config_, "/blocks/tip/height", &err);
      if (!resp.has_value() || !resp->is_number_unsigned())
      {
        out.daemon_version =
            err.empty() ? "(malformed response)" : err;
        return out;
      }
      out.reachable = true;
      out.current_height = resp->get<uint64_t>();
      out.best_peer_height = 0;
      out.daemon_version = "mempool.space";
      return out;
    }

    const auto ep = rpc.endpoint();
    Common::Json params = Common::Json::array();
    std::string err;
    auto resp = callBitcoinRpc(ep, "getblockchaininfo", params, &err);

    if (!resp.has_value() || !resp->is_object())
    {
      out.daemon_version =
          err.empty() ? std::string("(malformed response)") : err;
      return out;
    }

    const Common::Json &j = *resp;
    out.reachable = true;

    if (j.contains("blocks") && j["blocks"].is_number_unsigned())
      out.current_height = j["blocks"].get<uint64_t>();

    out.best_peer_height = 0;

    if (j.contains("chain") && j["chain"].is_string())
      out.daemon_version = j["chain"].get<std::string>();

    return out;
  }

  //  ==========================================================================
  //  Deposit scanning
  //  ==========================================================================

  void BitcoinAdapter::scan_deposits(
      Wallet::RpcClient &rpc,
      uint64_t from_height,
      uint64_t to_height,
      const std::function<bool(const ObservedDeposit &)> &on_deposit) const
  {
    highest_fully_resolved_height_.reset();
    cache_miss_detected_ = false;

    if (custody_ == nullptr)
      throw BridgeError(
          "scan_deposits: Bitcoin custody not configured; call "
          "set_custody first");

    if (deposit_cache_ == nullptr)
      throw BridgeError(
          "scan_deposits: Bitcoin deposit cache not installed; call "
          "set_deposit_cache first");

    if (to_height < from_height)
      return;

    if (config_.transport == BitcoinTransport::MempoolSpace)
      scan_deposits_mempool(from_height, to_height, on_deposit);
    else
      scan_deposits_bitcoind(rpc, from_height, to_height, on_deposit);
  }

  namespace
  {
    //  Shared per-vout logic. Given a scriptPubKey (in a std::vector
    //  from the JSON parser) and the tx's {txid, block_height,
    //  output_index, amount}, decide whether to emit a deposit.
    //
    //    - If the script is not in the custody window -> not ours.
    //    - If the script is in the window but the index is not in
    //      the deposit cache -> no on-chain registration exists for
    //      this index. The executor assigns indices monotonically
    //      and never reuses them, so this will never become a
    //      registration; it is a payment to a custody address that
    //      nobody registered as a deposit destination (a mistake,
    //      or a griefing attempt). SKIP it. Holding the cursor here
    //      would let one satoshi sent to any future custody address
    //      freeze the scanner forever — that is a denial-of-service
    //      vector, not a safety guarantee.
    //    - If the script is in the window and the index is in the
    //      cache -> emit the deposit with the cache's destination.
    //
    //  There is no "unresolved" state. A deposit to a registered
    //  index is always resolvable: the cache is refreshed at the
    //  top of every scan poll (from ScanRegistry::startScan ->
    //  refreshBridgeDeposits), so a registration that confirmed
    //  before this scan started is in the cache. A registration
    //  that confirms *during* a scan will be picked up on the next
    //  poll; the deposit is still in a block we've already
    //  processed, so the only cost is that the mint happens one
    //  poll later, not never.
    struct VoutLookup
    {
      bool matched{false};
      std::optional<ObservedDeposit> deposit;
    };

    VoutLookup classifyVout(
        const std::vector<uint8_t> &script,
        const Crypto::Hash &txid,
        uint64_t block_height,
        uint32_t output_index,
        uint64_t amount_sat,
        const BitcoinCustody &custody,
        const std::map<uint64_t, Crypto::Address> &cache)
    {
      VoutLookup r;

      std::array<uint8_t, 22> key{};
      if (!scriptToCustodyKey(script, key))
        return r; // not P2WPKH-shaped; not ours

      const auto &window = custody.scriptsInWindow();
      auto it = window.find(key);
      if (it == window.end())
        return r; // not in our window; not ours

      r.matched = true;

      const DerivedScript &ds = it->second;
      auto cit = cache.find(ds.index);
      if (cit == cache.end())
      {
        //  In-window script with no on-chain registration for its
        //  index. Not a bridge deposit. Skip. See the block
        //  comment above for why this is not "unresolved."
        return r;
      }

      ObservedDeposit d;
      d.source_chain_id = BTC_CHAIN_ID;
      d.source_tx_hash = txid;
      d.source_output_index = output_index;
      d.amount_source_atomic = amount_sat;
      d.block_height = block_height;
      d.destination = cit->second;

      d.deposit_blob.assign(script.begin(), script.end());

      r.deposit = std::move(d);
      return r;
    }
  } // anonymous namespace

  void BitcoinAdapter::scan_deposits_bitcoind(
      Wallet::RpcClient &rpc,
      uint64_t from_height,
      uint64_t to_height,
      const std::function<bool(const ObservedDeposit &)> &on_deposit) const
  {
    const auto ep = rpc.endpoint();

    for (uint64_t height = from_height; height <= to_height; ++height)
    {
      Common::Json hash_params = Common::Json::array();
      hash_params.push_back(height);
      std::string err;
      auto hash_resp = callBitcoinRpc(ep, "getblockhash", hash_params, &err);
      if (!hash_resp.has_value() || !hash_resp->is_string())
      {
        throw BridgeError(
            std::string("getblockhash failed at height ") +
            std::to_string(height) + ": " +
            (err.empty() ? std::string("(malformed response)") : err));
      }
      const std::string block_hash = hash_resp->get<std::string>();

      Common::Json block_params = Common::Json::array();
      block_params.push_back(block_hash);
      block_params.push_back(2);
      auto block_resp = callBitcoinRpc(ep, "getblock", block_params, &err);
      if (!block_resp.has_value() || !block_resp->is_object())
      {
        throw BridgeError(
            std::string("getblock failed at height ") +
            std::to_string(height) + " (" + block_hash + "): " +
            (err.empty() ? std::string("(malformed response)") : err));
      }

      const Common::Json &block = *block_resp;
      if (!block.contains("tx") || !block["tx"].is_array())
        continue;

      for (const auto &tx : block["tx"])
      {
        if (!tx.is_object())
          continue;

        if (!tx.contains("txid") || !tx["txid"].is_string())
          continue;

        Crypto::Hash txid;
        if (!parseTxidFromHex(tx["txid"].get<std::string>(), txid))
          continue;

        if (!tx.contains("vout") || !tx["vout"].is_array())
          continue;

        for (size_t vout_index = 0; vout_index < tx["vout"].size();
             ++vout_index)
        {
          const auto &vout = tx["vout"][vout_index];
          if (!vout.is_object())
            continue;

          if (!vout.contains("scriptPubKey") ||
              !vout["scriptPubKey"].is_object())
            continue;
          const auto &spk = vout["scriptPubKey"];

          if (!spk.contains("hex") || !spk["hex"].is_string())
            continue;

          std::vector<uint8_t> script_bytes;
          if (!scriptFromHex(spk["hex"].get<std::string>(), script_bytes))
            continue;

          if (!vout.contains("value") || !vout["value"].is_number())
            continue;

          const double btc_value = vout["value"].get<double>();
          const uint64_t sat_value = static_cast<uint64_t>(
              std::llround(btc_value * 100'000'000.0));

          if (sat_value == 0)
            continue;

          const VoutLookup look = classifyVout(
              script_bytes, txid, height,
              static_cast<uint32_t>(vout_index),
              sat_value, *custody_, *deposit_cache_);

          if (!look.deposit.has_value())
            continue;

          if (!on_deposit(*look.deposit))
            return;
        }
      }
    }
  }

  void BitcoinAdapter::scan_deposits_mempool(
      uint64_t from_height,
      uint64_t to_height,
      const std::function<bool(const ObservedDeposit &)> &on_deposit) const
  {
    for (uint64_t height = from_height; height <= to_height; ++height)
    {
      std::string err;

      auto hash_resp = callMempoolGetText(
          config_, "/block-height/" + std::to_string(height), &err);
      if (!hash_resp.has_value() || hash_resp->empty())
      {
        throw BridgeError(
            std::string("mempool block-height failed at ") +
            std::to_string(height) + ": " +
            (err.empty() ? std::string("(empty response)") : err));
      }
      std::string block_hash = *hash_resp;
      while (!block_hash.empty() &&
             (block_hash.back() == '\n' ||
              block_hash.back() == '\r' ||
              block_hash.back() == ' ' ||
              block_hash.back() == '\t'))
        block_hash.pop_back();
      if (block_hash.size() != 64)
      {
        throw BridgeError(
            std::string("mempool block-height returned a non-hash "
                        "body at ") +
            std::to_string(height) +
            ": \"" + block_hash + "\"");
      }

      auto txids_resp = callMempoolGet(
          config_, "/block/" + block_hash + "/txids", &err);
      if (!txids_resp.has_value() || !txids_resp->is_array())
      {
        throw BridgeError(
            std::string("mempool block txids failed for ") + block_hash +
            ": " + (err.empty() ? std::string("(malformed)") : err));
      }

      for (const auto &txid_val : *txids_resp)
      {
        if (!txid_val.is_string())
          continue;
        const std::string txid_hex = txid_val.get<std::string>();

        auto tx_resp = callMempoolGet(config_, "/tx/" + txid_hex, &err);
        if (!tx_resp.has_value() || !tx_resp->is_object())
          continue;

        const Common::Json &tx = *tx_resp;

        Crypto::Hash txid;
        if (!parseTxidFromHex(txid_hex, txid))
          continue;

        if (!tx.contains("vout") || !tx["vout"].is_array())
          continue;

        for (size_t vout_index = 0; vout_index < tx["vout"].size();
             ++vout_index)
        {
          const auto &vout = tx["vout"][vout_index];
          if (!vout.is_object())
            continue;

          if (!vout.contains("scriptpubkey") ||
              !vout["scriptpubkey"].is_string())
            continue;

          std::vector<uint8_t> script_bytes;
          if (!scriptFromHex(
                  vout["scriptpubkey"].get<std::string>(),
                  script_bytes))
            continue;

          if (!vout.contains("value") || !vout["value"].is_number())
            continue;

          const double sat_value_d = vout["value"].get<double>();
          const uint64_t sat_value =
              static_cast<uint64_t>(std::llround(sat_value_d));

          if (sat_value == 0)
            continue;

          const VoutLookup look = classifyVout(
              script_bytes, txid, height,
              static_cast<uint32_t>(vout_index),
              sat_value, *custody_, *deposit_cache_);

          if (!look.deposit.has_value())
            continue;

          if (!on_deposit(*look.deposit))
            return;
        }
      }
    }
  }

  //  ==========================================================================
  //  Release submission (stubbed)
  //  ==========================================================================

  ReleaseSubmission BitcoinAdapter::submit_release(
      Wallet::RpcClient &rpc,
      const ReleaseRequest &request,
      uint64_t amount_source_atomic,
      const std::vector<uint8_t> &signature_block) const
  {
    //  The Wallet::RpcClient argument is unused for Bitcoin:
    //  the adapter talks to its source chain through config_
    //  (mempool.space or bitcoind), not through a Wallet RPC.
    //  The ReleaseTracker worker passes a dummy. Matches the
    //  pattern of scan_deposits_mempool and fetch_release_height.
    (void)rpc;
    (void)signature_block; // audit artifact only; Bitcoin has
                           // no on-chain ack verification

    ReleaseSubmission out;
    out.ok = false;

    //  ---- Preconditions ----

    if (custody_ == nullptr)
    {
      out.reason = "custody not installed";
      return out;
    }
    if (!custody_->canSpend())
    {
      out.reason = "custody is watch-only (FromXpub); cannot sign "
                   "a Bitcoin release";
      return out;
    }
    if (config_.transport != BitcoinTransport::MempoolSpace)
    {
      out.reason = "Bitcoin release currently supports mempool.space "
                   "transport only; bitcoind transport is not yet "
                   "implemented for the release path";
      return out;
    }
    if (!validate_destination(request.destination_blob))
    {
      out.reason = "destination_blob is not a supported Bitcoin "
                   "output script (expected P2WPKH, P2SH, P2PKH, "
                   "or P2TR)";
      return out;
    }
    if (amount_source_atomic == 0)
    {
      out.reason = "release amount is zero";
      return out;
    }

    //  ---- Step 1: enumerate candidate UTXOs ----

    std::string utxo_err;
    auto utxos = fetchCustodyUtxos(&utxo_err);
    if (!utxos.has_value())
    {
      out.reason = "UTXO enumeration failed: " + utxo_err;
      return out;
    }

    //  Largest-first. Single-UTXO policy for v1: no
    //  consolidation, no fan-in. If the largest UTXO doesn't
    //  cover amount + fee, the release waits for a larger one
    //  (or the operator consolidates manually). This is simple
    //  and predictable; fan-in can come later if needed.
    std::sort(utxos->begin(), utxos->end(),
              [](const UtxoCandidate &a, const UtxoCandidate &b)
              {
                return a.value_sat > b.value_sat;
              });

    //  ---- Step 2: fee rate ----

    uint64_t fee_rate = 1;
    {
      std::string fee_err;
      auto r = fetchHalfHourFeeRate(&fee_err);
      if (r.has_value() && *r >= 1)
        fee_rate = *r;
      //  On failure: fall back to 1 sat/vB. The broadcast may
      //  fail if the mempool is congested, but that's a
      //  diagnosable error surfaced below, not a reason to
      //  refuse before trying.
    }

    //  Estimated vsize for a 1-in-2-out P2WPKH spend. The
    //  theoretical minimum is ~110 vB; using the standard figure
    //  absorbs DER-signature-length variance (71 or 72 bytes).
    constexpr uint64_t kEstimatedVsize = 110;
    uint64_t fee = fee_rate * kEstimatedVsize;
    if (fee < kEstimatedVsize)
      fee = kEstimatedVsize; // floor at 1 sat/vB

    //  Sanity cap: if the fee exceeds 5% of the amount, the fee
    //  rate is anomalous (or the amount is tiny). Refuse rather
    //  than burn the user's value on fees.
    if (amount_source_atomic > 0 &&
        fee > amount_source_atomic / 20)
    {
      out.reason = "computed fee (" + std::to_string(fee) +
                   " sat) exceeds 5% of the release amount (" +
                   std::to_string(amount_source_atomic) +
                   " sat) at fee rate " + std::to_string(fee_rate) +
                   " sat/vB";
      return out;
    }

    //  ---- Step 3: pick the UTXO ----

    const UtxoCandidate *selected = nullptr;
    for (const auto &u : *utxos)
    {
      if (u.value_sat >= amount_source_atomic + fee)
      {
        selected = &u;
        break;
      }
    }
    if (selected == nullptr)
    {
      out.reason = "no custody UTXO covers amount + fee (" +
                   std::to_string(amount_source_atomic) + " + " +
                   std::to_string(fee) + " = " +
                   std::to_string(amount_source_atomic + fee) +
                   " sat); largest available: " +
                   (utxos->empty() ? std::string("none")
                                   : std::to_string((*utxos)[0].value_sat) +
                                         " sat");
      return out;
    }

    //  ---- Step 4: derive the spending key ----

    std::string key_err;
    auto privkey = custody_->derivePrivateKeyAt(selected->index, &key_err);
    if (!privkey.has_value())
    {
      out.reason = "could not derive private key for custody index " +
                   std::to_string(selected->index) + ": " + key_err;
      return out;
    }

    //  ---- Step 5: build the transaction ----

    Crypto::BitcoinTransaction tx;
    tx.version = 2;
    tx.locktime = 0; // no timelock; the release is unconditional

    //  Input: the selected UTXO.
    Crypto::BitcoinTxIn in;
    in.prev_txid = selected->txid_wire;
    in.prev_vout = selected->vout;
    in.sequence = 0xFFFFFFFD; // opt into nLockTime (BIP125-style),
                              // though we set locktime=0. The
                              // semantics don't differ at locktime
                              // 0; using FFFFFFFD rather than
                              // FFFFFFFF is the modern default and
                              // keeps the tx RBF-eligible if we
                              // ever add it.
    //  script_sig empty (P2WPKH), witness populated after signing.
    tx.inputs.push_back(in);

    //  Output 0: the destination, verbatim.
    Crypto::BitcoinTxOut dest_out;
    dest_out.value_sat = amount_source_atomic;
    dest_out.script_pubkey = request.destination_blob;
    tx.outputs.push_back(dest_out);

    //  Output 1: change back to the source custody address.
    const uint64_t change_sat =
        selected->value_sat - amount_source_atomic - fee;
    if (change_sat > 0)
    {
      //  Dust threshold for P2WPKH change is 294 sat
      //  (Bitcoin Core's GetDustThreshold for a P2WPKH output,
      //  as of this writing). Below that, drop the change into
      //  the fee rather than create an unspendable output.
      constexpr uint64_t kP2wpkhDust = 294;
      if (change_sat >= kP2wpkhDust)
      {
        Crypto::BitcoinTxOut change_out;
        change_out.value_sat = change_sat;
        change_out.script_pubkey = selected->script;
        tx.outputs.push_back(change_out);
      }
      else
      {
        //  Change too small: the fee absorbs it. The reason
        //  string for this is informational only; the release
        //  still succeeds with the effective fee.
        fee += change_sat;
        //  Note: fee is now the effective fee, not the
        //  estimate. The output value is unchanged (we still
        //  send amount_source_atomic to the destination), so
        //  the extra value comes out of the change allocation
        //  and is absorbed.
      }
    }

    //  ---- Step 6: sign ----

    //  BIP143 sighash for input 0. script_code is the spent
    //  P2WPKH script, prev_output_value is the UTXO value.
    const Crypto::Hash sighash = Crypto::sighashBip143(
        tx,
        /*input_index=*/0,
        selected->script,
        selected->value_sat,
        /*hash_type=*/0x01);

    if (sighash.isNull())
    {
      out.reason = "sighashBip143 returned a null hash";
      return out;
    }

    std::string sign_err;
    auto sig_with_type = Crypto::signDerWithHashType(
        *privkey, sighash, 0x01, &sign_err);
    if (!sig_with_type.has_value())
    {
      out.reason = "signing failed: " + sign_err;
      return out;
    }

    //  Compressed pubkey for the second witness item.
    std::string pub_err;
    auto pub = Crypto::toXpub(*privkey, &pub_err);
    if (!pub.has_value())
    {
      out.reason = "could not derive public key for witness: " + pub_err;
      return out;
    }

    //  ---- Step 7: assemble the witness ----

    //  P2WPKH witness stack, exactly two items:
    //    [ DER signature || SIGHASH_ALL ]  [ 33-byte compressed pubkey ]
    std::vector<uint8_t> pubkey_vec(pub->pubkey.begin(), pub->pubkey.end());
    tx.inputs[0].witness.push_back(*sig_with_type);
    tx.inputs[0].witness.push_back(std::move(pubkey_vec));

    //  ---- Step 8: serialize and broadcast ----

    const auto raw_tx = tx.serialize();
    const std::string raw_hex = hexOf(raw_tx);

    //  POST /api/tx with the raw hex as the body. mempool.space
    //  returns the txid as plain text on success, and a JSON
    //  error body on rejection. We can't use jsonPost here
    //  because the success body isn't JSON.
    std::string base = config_.mempool_url;
    if (base.empty())
    {
      out.reason = "mempool_url is empty";
      return out;
    }
    if (base.find("://") == std::string::npos)
      base = "https://" + base;

    std::string url = base + "/tx";
    if (!config_.mempool_api_key.empty())
    {
      url += (url.find('?') == std::string::npos ? '?' : '&');
      url += "key=";
      url += config_.mempool_api_key;
    }

    auto result = doHttpRequest("POST", url, raw_hex,
                                BTC_HTTP_TIMEOUT_SECONDS);
    if (!result.ok)
    {
      out.reason = "broadcast POST failed: " +
                   (result.error.empty() ? "(no detail)" : result.error);
      return out;
    }
    if (result.status_code < 200 || result.status_code >= 300)
    {
      out.reason = "broadcast rejected (HTTP " +
                   std::to_string(result.status_code) + "): " +
                   result.body;
      return out;
    }

    //  Success: mempool.space returns the txid (64 hex chars) as
    //  the body. Trim trailing whitespace and validate.
    std::string txid_hex = result.body;
    while (!txid_hex.empty() &&
           (txid_hex.back() == '\n' || txid_hex.back() == '\r' ||
            txid_hex.back() == ' ' || txid_hex.back() == '\t'))
      txid_hex.pop_back();
    if (txid_hex.size() != 64)
    {
      out.reason = "broadcast response body is not a 64-char txid: \"" +
                   txid_hex + "\"";
      return out;
    }

    //  Convert display txid to Crypto::Hash's wire order.
    Crypto::Hash txid_hash;
    if (!parseTxidFromHex(txid_hex, txid_hash))
    {
      out.reason = "broadcast returned an unparseable txid: " + txid_hex;
      return out;
    }

    out.ok = true;
    out.source_tx_hash = txid_hash;
    //  block_height is zero on broadcast; fetch_release_height
    //  will populate it on a later poll once the tx confirms.
    return out;
  }

  //  ==========================================================================
  //  Release height lookup
  //  ==========================================================================

  std::optional<uint64_t> BitcoinAdapter::fetch_release_height(
      Wallet::RpcClient &rpc,
      const Crypto::Hash &tx_hash) const
  {
    if (config_.transport == BitcoinTransport::MempoolSpace)
      return fetch_release_height_mempool(tx_hash);
    return fetch_release_height_bitcoind(rpc, tx_hash);
  }

  std::optional<uint64_t> BitcoinAdapter::fetch_release_height_bitcoind(
      Wallet::RpcClient &rpc,
      const Crypto::Hash &tx_hash) const
  {
    std::vector<uint8_t> bytes(
        tx_hash.data.begin(), tx_hash.data.end());
    std::reverse(bytes.begin(), bytes.end());
    const std::string display_hex = hexOf(bytes);

    Common::Json params = Common::Json::array();
    params.push_back(display_hex);
    params.push_back(true);

    const auto ep = rpc.endpoint();
    std::string err;
    auto resp = callBitcoinRpc(ep, "getrawtransaction", params, &err);
    if (!resp.has_value() || !resp->is_object())
      return std::nullopt;

    const Common::Json &tx = *resp;

    if (!tx.contains("blockhash") || !tx["blockhash"].is_string())
      return std::nullopt;

    const std::string block_hash = tx["blockhash"].get<std::string>();

    Common::Json header_params = Common::Json::array();
    header_params.push_back(block_hash);
    header_params.push_back(true);

    auto hdr = callBitcoinRpc(ep, "getblockheader", header_params, &err);
    if (!hdr.has_value() || !hdr->is_object())
      return std::nullopt;

    if (!hdr->contains("height") || !(*hdr)["height"].is_number_unsigned())
      return std::nullopt;

    return (*hdr)["height"].get<uint64_t>();
  }

  std::optional<uint64_t> BitcoinAdapter::fetch_release_height_mempool(
      const Crypto::Hash &tx_hash) const
  {
    std::vector<uint8_t> bytes(tx_hash.data.begin(), tx_hash.data.end());
    std::reverse(bytes.begin(), bytes.end());
    const std::string display_hex = hexOf(bytes);

    std::string err;
    auto resp = callMempoolGet(
        config_, "/tx/" + display_hex + "/status", &err);
    if (!resp.has_value() || !resp->is_object())
      return std::nullopt;

    const Common::Json &status = *resp;
    if (!status.contains("confirmed") || !status["confirmed"].is_boolean() ||
        !status["confirmed"].get<bool>())
      return std::nullopt;

    if (!status.contains("block_height") ||
        !status["block_height"].is_number_unsigned())
      return std::nullopt;

    return status["block_height"].get<uint64_t>();
  }

  //  ==========================================================================
  //  Destination and deposit-address codec
  //  ==========================================================================

  bool BitcoinAdapter::validate_destination(
      const std::vector<uint8_t> &destination_blob) const
  {
    //  Accept the four standard output-script shapes a Bitcoin
    //  wallet will produce for a user-supplied address:
    //
    //    P2WPKH  22 bytes: 0x00 0x14 || 20-byte-hash
    //    P2SH    23 bytes: 0xa9 0x14 || 20-byte-hash || 0x87
    //    P2PKH   25 bytes: 0x76 0xa9 0x14 || 20-byte-hash || 0x88 0xac
    //    P2TR    34 bytes: 0x51 0x20 || 32-byte-x-only-key
    //
    //  Anything else is rejected. This is the burn-side gate:
    //  an invalid destination is an unreleasable burn, which is
    //  a loss of funds. Being strict here is the difference
    //  between "the front end rejects an unparseable address" and
    //  "the user burns wBTC and the bridge can't pay it out".
    //
    //  P2WSH (34 bytes, 0x00 0x20) is deliberately NOT accepted.
    //  A P2WSH destination is a multisig or script-hash address;
    //  releasing to one is almost certainly a user error or a
    //  front end that didn't validate. If we ever support it, the
    //  right change is to accept it here AND to test end to end,
    //  not to loosen the check speculatively.
    const auto &b = destination_blob;
    const size_t n = b.size();

    if (n == 22 && b[0] == 0x00 && b[1] == 0x14)
      return true; // P2WPKH

    if (n == 23 && b[0] == 0xa9 && b[1] == 0x14 && b[22] == 0x87)
      return true; // P2SH

    if (n == 25 && b[0] == 0x76 && b[1] == 0xa9 && b[2] == 0x14 &&
        b[23] == 0x88 && b[24] == 0xac)
      return true; // P2PKH

    if (n == 34 && b[0] == 0x51 && b[1] == 0x20)
      return true; // P2TR

    return false;
  }

  bool BitcoinAdapter::validate_deposit_address(
      const std::vector<uint8_t> &blob) const
  {
    return !blob.empty() && blob.size() <= BTC_MAX_SCRIPT_BYTES;
  }

  std::string BitcoinAdapter::deposit_address_display() const
  {
    //  No static deposit address any more. If we ever want a
    //  human-readable summary here, it would be "first N custody
    //  addresses"; for now, empty is honest.
    return {};
  }

  void BitcoinAdapter::set_deposit_address(
      const std::vector<uint8_t> &blob)
  {
    //  Legacy. The static-script model is gone; this is kept as a
    //  no-op so the ChainAdapter interface stays uniform, and so a
    //  stale config that calls set_deposit_address doesn't silently
    //  poison the scanner. If a future deployment needs a static
    //  address (it shouldn't), this is where it would go, guarded
    //  by a check that custody_ is null.
    if (!blob.empty())
    {
      std::cerr << "[btc] ignoring set_deposit_address("
                << blob.size() << " bytes): deposit addresses are "
                                  "derived per registration index from the custody "
                                  "seed; the static-address model is no longer used\n";
    }
  }

  std::optional<std::vector<uint8_t>>
  BitcoinAdapter::decodeAddressViaMempool(const std::string &address,
                                          std::string *error_out) const
  {
    std::string err;
    auto resp = callMempoolGet(
        config_, "/v1/validate-address/" + address, &err);
    if (!resp.has_value() || !resp->is_object())
    {
      if (error_out)
        *error_out = err.empty() ? "validate-address failed" : err;
      return std::nullopt;
    }

    const Common::Json &j = *resp;

    if (!j.contains("isvalid") || !j["isvalid"].is_boolean() ||
        !j["isvalid"].get<bool>())
    {
      if (error_out)
        *error_out = "address is not a valid Bitcoin address: " + address;
      return std::nullopt;
    }

    if (!j.contains("scriptPubKey") || !j["scriptPubKey"].is_string())
    {
      if (error_out)
        *error_out = "validate-address response has no scriptPubKey";
      return std::nullopt;
    }

    std::vector<uint8_t> script;
    if (!scriptFromHex(j["scriptPubKey"].get<std::string>(), script))
    {
      if (error_out)
        *error_out = "scriptPubKey from validate-address is not valid hex";
      return std::nullopt;
    }

    return script;
  }

  std::optional<std::vector<uint8_t>>
  BitcoinAdapter::parse_deposit_address(const std::string &address_str,
                                        std::string *error_out) const
  {
    //  Legacy. Kept for interface uniformity; deposits no longer
    //  go to a static address. Returning nullopt with a message
    //  that names the current model is more honest than pretending
    //  we can parse one.
    (void)address_str;
    if (error_out)
      *error_out = "Bitcoin deposits go to per-registration derived "
                   "addresses (ask the bridge for one via address "
                   "<index> / getBridgeDepositAddress). There is no "
                   "static Bitcoin deposit address to parse.";
    return std::nullopt;
  }

  std::optional<std::string>
  BitcoinAdapter::deriveDepositAddress(uint64_t index,
                                       std::string *error_out) const
  {
    if (custody_ == nullptr)
    {
      if (error_out)
        *error_out = "Bitcoin custody is not configured. Start the "
                     "chain before requesting deposit addresses.";
      return std::nullopt;
    }
    return custody_->deriveAddress(index, error_out);
  }

  //  ==========================================================================
  //  Transport configuration
  //  ==========================================================================

  void BitcoinAdapter::set_wallet_rpc_endpoint(
      const std::string &host,
      uint16_t port,
      const std::string &user,
      const std::string &password)
  {
    config_.transport = BitcoinTransport::BitcoindRpc;
    config_.rpc_host = host;
    config_.rpc_port = port;
    config_.rpc_user = user;
    config_.rpc_password = password;
  }

  void BitcoinAdapter::set_transport_config(const Common::Json &config)
  {
    if (!config.is_object())
      return;

    std::cerr << "[btc] set_transport_config: "
              << (config.is_object() ? config.dump() : "(not object)")
              << "\n";

    if (config.contains("transport") && config["transport"].is_string())
    {
      const std::string t = config["transport"].get<std::string>();
      if (t == "mempool" || t == "esplora")
        config_.transport = BitcoinTransport::MempoolSpace;
      else if (t == "bitcoind-rpc" || t == "rpc" || t == "bitcoind")
        config_.transport = BitcoinTransport::BitcoindRpc;
    }

    if (config.contains("mempool_url") && config["mempool_url"].is_string())
      config_.mempool_url = config["mempool_url"].get<std::string>();
    else if (config.contains("esplora_url") &&
             config["esplora_url"].is_string())
      config_.mempool_url = config["esplora_url"].get<std::string>();

    if (config.contains("mempool_api_key") &&
        config["mempool_api_key"].is_string())
      config_.mempool_api_key = config["mempool_api_key"].get<std::string>();
    else if (config.contains("esplora_api_key") &&
             config["esplora_api_key"].is_string())
      config_.mempool_api_key = config["esplora_api_key"].get<std::string>();
  }

  //  ---- Registration support ----

  Crypto::Hash BitcoinAdapter::wrapped_token_fingerprint() const
  {
    return Core::BitcoinBridge::wrappedTokenFingerprint();
  }

  std::pair<uint8_t, uint8_t>
  BitcoinAdapter::registration_blob_bounds() const
  {
    return {Core::BitcoinBridge::BTC_DESTINATION_MIN_BYTES,
            Core::BitcoinBridge::BTC_DESTINATION_MAX_BYTES};
  }

  uint32_t BitcoinAdapter::registration_active_validator_min() const
  {
    return GlobalConfig::ACTIVE_SET_MIN;
  }

  std::optional<std::vector<BitcoinAdapter::UtxoCandidate>>
  BitcoinAdapter::fetchCustodyUtxos(std::string *error_out) const
  {
    if (custody_ == nullptr)
    {
      if (error_out)
        *error_out = "Bitcoin custody is not installed";
      return std::nullopt;
    }
    return fetchCustodyUtxosImpl(config_, *custody_, error_out);
  }

  std::optional<uint64_t>
  BitcoinAdapter::fetchHalfHourFeeRate(std::string *error_out) const
  {
    return fetchHalfHourFeeRateImpl(config_, error_out);
  }

  //  ==========================================================================
  //  Registration
  //  ==========================================================================

  namespace
  {
    struct BitcoinAdapterRegistrar
    {
      BitcoinAdapterRegistrar()
      {
        ChainAdapterRegistry::registerAdapter(
            std::make_shared<BitcoinAdapter>());
      }
    };

    [[maybe_unused]] static BitcoinAdapterRegistrar g_btc_registrar;
  } // anonymous namespace
} // namespace Bridge