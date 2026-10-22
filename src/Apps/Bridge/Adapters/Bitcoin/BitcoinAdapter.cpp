// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "BitcoinAdapter.h"

#include "Common/Json.h"
#include "Common/StringTools.h"

#include "Core/Bridge/Bitcoin.h"

#include "Crypto/Types.h"

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

    //  ---- URL parsing -------------------------------------------------------

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

    //  ---- Synchronous HTTPS/HTTP client -------------------------------------
    //
    //  Raw asio::ssl::stream (or tcp::socket for http) with an
    //  OS-level SO_RCVTIMEO/SO_SNDTIMEO timeout. Synchronous — no
    //  handlers, no lifetimes. The OS enforces the timeout at the
    //  socket level, so a stuck handshake or a stuck read fails
    //  with an error instead of hanging.
    //
    //  HTTP/1.1 request, read-until for the headers, then a
    //  Content-Length-bounded body read. Handles Content-Length
    //  and Connection: close (the latter by reading until EOF).

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
      //  SO_RCVTIMEO / SO_SNDTIMEO via native handle. asio doesn't
      //  expose these portably, but on POSIX they're the OS
      //  enforcement of a synchronous read/write timeout, which is
      //  exactly what we want here.
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

          //  Read the entire response to EOF. The request sent
          //  Connection: close, so the server will close after the
          //  body. read_some returns as soon as there's some data,
          //  and reports eof with n == 0 on close. Net::read (the
          //  "fill the buffer" version) returns eof with n > 0 on
          //  the last chunk, which would silently discard it.
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

          //  Split headers and body.
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

          //  Parse the status line.
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

          //  Decode chunked bodies if the server used them.
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
          //  Plain HTTP: same read-to-EOF and split.
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

    //  ---- JSON wrappers -----------------------------------------------------

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

    //  ---- bitcoind JSON-RPC call --------------------------------------------

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

    //  ---- mempool.space calls ----------------------------------------------

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

    //  ---- Hex helpers -------------------------------------------------------

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
    if (deposit_script_.empty())
      throw BridgeError(
          "scan_deposits: deposit script not set; call "
          "set_deposit_address first");

    if (to_height < from_height)
      return;

    if (config_.transport == BitcoinTransport::MempoolSpace)
      scan_deposits_mempool(from_height, to_height, on_deposit);
    else
      scan_deposits_bitcoind(rpc, from_height, to_height, on_deposit);
  }

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

          if (script_bytes != deposit_script_)
            continue;

          if (!vout.contains("value") || !vout["value"].is_number())
            continue;

          const double btc_value = vout["value"].get<double>();
          const uint64_t sat_value = static_cast<uint64_t>(
              std::llround(btc_value * 100'000'000.0));

          ObservedDeposit deposit;
          deposit.source_chain_id = BTC_CHAIN_ID;
          deposit.source_tx_hash = txid;
          deposit.source_output_index = static_cast<uint32_t>(vout_index);
          deposit.amount_source_atomic = sat_value;
          deposit.block_height = height;
          deposit.deposit_blob = script_bytes;

          if (!on_deposit(deposit))
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

        auto tx_resp = callMempoolGet(
            config_, "/tx/" + txid_hex, &err);
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

          if (script_bytes != deposit_script_)
            continue;

          if (!vout.contains("value") || !vout["value"].is_number())
            continue;

          const double sat_value_d = vout["value"].get<double>();
          const uint64_t sat_value = static_cast<uint64_t>(std::llround(sat_value_d));

          ObservedDeposit deposit;
          deposit.source_chain_id = BTC_CHAIN_ID;
          deposit.source_tx_hash = txid;
          deposit.source_output_index = static_cast<uint32_t>(vout_index);
          deposit.amount_source_atomic = sat_value;
          deposit.block_height = height;
          deposit.deposit_blob = script_bytes;

          if (!on_deposit(deposit))
            return;
        }
      }
    }
  }

  //  ==========================================================================
  //  Release submission (stubbed)
  //  ==========================================================================

  ReleaseSubmission BitcoinAdapter::submit_release(
      Wallet::RpcClient & /*rpc*/,
      const ReleaseRequest & /*request*/,
      uint64_t /*amount_source_atomic*/,
      const std::vector<uint8_t> & /*signature_block*/) const
  {
    ReleaseSubmission out;
    out.ok = false;
    out.reason = "Bitcoin release not yet implemented; "
                 "deposits work, withdrawals stay in Releasable";
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
    return !destination_blob.empty() &&
           destination_blob.size() <= BTC_MAX_SCRIPT_BYTES;
  }

  bool BitcoinAdapter::validate_deposit_address(
      const std::vector<uint8_t> &blob) const
  {
    return !blob.empty() && blob.size() <= BTC_MAX_SCRIPT_BYTES;
  }

  std::string BitcoinAdapter::deposit_address_display() const
  {
    if (deposit_script_.empty())
      return {};
    return hexOf(deposit_script_);
  }

  void BitcoinAdapter::set_deposit_address(
      const std::vector<uint8_t> &blob)
  {
    if (blob.empty() || blob.size() > BTC_MAX_SCRIPT_BYTES)
    {
      deposit_script_.clear();
      return;
    }
    deposit_script_ = blob;
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
    if (address_str.empty())
    {
      if (error_out)
        *error_out = "empty deposit address";
      return std::nullopt;
    }

    if (looksLikeScriptHex(address_str))
    {
      std::vector<uint8_t> script;
      if (!scriptFromHex(address_str, script))
      {
        if (error_out)
          *error_out = "deposit address is hex but does not parse as a "
                       "scriptPubKey";
        return std::nullopt;
      }
      return script;
    }

    if (config_.transport == BitcoinTransport::MempoolSpace)
    {
      auto script = decodeAddressViaMempool(address_str, error_out);
      if (script.has_value())
        return script;
      return std::nullopt;
    }

    if (error_out)
      *error_out = "deposit address is not scriptPubKey hex; a "
                   "BitcoindRpc deployment must pass the scriptPubKey "
                   "hex form (getaddressinfo's scriptPubKey field)";
    return std::nullopt;
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