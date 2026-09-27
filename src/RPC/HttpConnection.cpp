// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "HttpConnection.h"

#include "JsonRpcDispatcher.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <string_view>

#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace Rpc
{

  namespace
  {
    std::string toLower(std::string_view s)
    {
      std::string out;
      out.reserve(s.size());
      for (char c : s)
        out.push_back(char(std::tolower(static_cast<unsigned char>(c))));
      return out;
    }

    std::string trim(std::string_view s)
    {
      size_t start = 0;
      while (start < s.size() && (s[start] == ' ' || s[start] == '\t'))
        ++start;
      size_t end = s.size();
      while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        --end;
      return std::string(s.substr(start, end - start));
    }

    bool contentTypeIsJson(const std::string &ct)
    {
      std::string lower = toLower(ct);
      auto semi = lower.find(';');
      std::string base = semi == std::string::npos ? lower : lower.substr(0, semi);
      base = trim(base);
      return base == "application/json" ||
             base == "application/json-rpc" ||
             base == "application/jsonrequest" ||
             base == "text/plain";
    }

    // Parse a decimal content-length. Returns false on invalid.
    bool parseContentLength(const std::string &s, size_t &out)
    {
      if (s.empty())
        return false;
      size_t v = 0;
      for (char c : s)
      {
        if (c < '0' || c > '9')
          return false;
        size_t nv = v * 10 + size_t(c - '0');
        if (nv < v)
          return false;
        v = nv;
      }
      out = v;
      return true;
    }
  } // anonymous namespace

  //  Construction

  HttpConnection::HttpConnection(int client_fd,
                                 const RpcConfig &config,
                                 JsonRpcDispatcher &dispatcher,
                                 std::string remote_ip)
      : fd_(client_fd),
        config_(config),
        dispatcher_(dispatcher),
        remote_ip_(std::move(remote_ip))
  {
    // Socket-level timeout on recv and send. A stalled client
    // releases its worker when this expires.
    struct timeval tv;
    tv.tv_sec = config_.socket_timeout_seconds;
    tv.tv_usec = 0;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }

  HttpConnection::~HttpConnection()
  {
    if (fd_ >= 0)
    {
      ::close(fd_);
      fd_ = -1;
    }
  }

  //  I/O primitives

  ssize_t HttpConnection::readSome(void *buf, size_t len)
  {
    for (;;)
    {
      ssize_t n = ::recv(fd_, buf, len, 0);
      if (n >= 0)
        return n;
      if (errno == EINTR)
        continue;
      return -1;
    }
  }

  bool HttpConnection::writeAll(const void *buf, size_t len)
  {
    const uint8_t *p = static_cast<const uint8_t *>(buf);
    size_t remaining = len;
    while (remaining > 0)
    {
      ssize_t n = ::send(fd_, p, remaining, MSG_NOSIGNAL);
      if (n > 0)
      {
        p += n;
        remaining -= size_t(n);
        continue;
      }
      if (n < 0 && errno == EINTR)
        continue;
      return false;
    }
    return true;
  }

  //  Request reading

  bool HttpConnection::readRequest(Request &out,
                                   int &error_status,
                                   std::string &error_message)
  {
    std::string raw;
    raw.reserve(2048);

    const size_t max_head =
        std::min<size_t>(config_.max_request_bytes, 64 * 1024);

    size_t header_end = std::string::npos;

    // ---- Read until we have a full header block ----
    while (raw.size() < max_head)
    {
      char buf[4096];
      ssize_t n = readSome(buf, sizeof(buf));

      if (n == 0)
      {
        error_status = 400;
        error_message = "connection closed before request was sent";
        return false;
      }
      if (n < 0)
      {
        // Timeout or socket error. Signal "no response" via status 0.
        error_status = 0;
        return false;
      }

      raw.append(buf, size_t(n));

      auto pos = raw.find("\r\n\r\n");
      if (pos != std::string::npos)
      {
        header_end = pos + 4;
        break;
      }
    }

    if (header_end == std::string::npos)
    {
      error_status = 413;
      error_message = "request headers too large";
      return false;
    }

    // ---- Parse head ----
    if (!parseHead(raw, out, header_end, error_status, error_message))
      return false;

    // ---- Read body ----
    if (out.has_content_length)
    {
      if (out.content_length > config_.max_request_bytes)
      {
        error_status = 413;
        error_message = "request body too large";
        return false;
      }

      // Body may already be partially in `raw` (bytes past header_end).
      if (header_end < raw.size())
      {
        out.body = raw.substr(header_end);
      }

      while (out.body.size() < out.content_length)
      {
        char buf[4096];
        ssize_t n = readSome(buf, sizeof(buf));
        if (n <= 0)
        {
          error_status = 400;
          error_message = "connection closed mid-body";
          return false;
        }
        out.body.append(buf, size_t(n));
      }

      // If we read more than Content-Length, that's a protocol
      // violation. Truncate and ignore the rest.
      if (out.body.size() > out.content_length)
      {
        out.body.resize(out.content_length);
      }
    }

    return true;
  }

  bool HttpConnection::parseHead(const std::string &raw,
                                 Request &out,
                                 size_t &header_end,
                                 int &error_status,
                                 std::string &error_message)
  {
    // ---- Request line ----
    auto line_end = raw.find("\r\n");
    if (line_end == std::string::npos)
    {
      error_status = 400;
      error_message = "malformed request line";
      return false;
    }

    std::string line = raw.substr(0, line_end);

    // METHOD SP PATH SP VERSION
    auto sp1 = line.find(' ');
    if (sp1 == std::string::npos)
    {
      error_status = 400;
      error_message = "malformed request line";
      return false;
    }
    auto sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos)
    {
      error_status = 400;
      error_message = "malformed request line";
      return false;
    }

    out.method = line.substr(0, sp1);
    out.path = line.substr(sp1 + 1, sp2 - sp1 - 1);
    out.version = line.substr(sp2 + 1);

    if (out.version != "HTTP/1.1" && out.version != "HTTP/1.0")
    {
      error_status = 400;
      error_message = "unsupported HTTP version";
      return false;
    }

    // ---- Headers ----
    size_t pos = line_end + 2;
    while (pos < header_end)
    {
      auto next = raw.find("\r\n", pos);
      if (next == std::string::npos || next >= header_end)
        break;

      std::string hline = raw.substr(pos, next - pos);
      pos = next + 2;

      if (hline.empty())
        continue;

      auto colon = hline.find(':');
      if (colon == std::string::npos)
        continue;

      std::string name = toLower(trim(hline.substr(0, colon)));
      std::string value = trim(hline.substr(colon + 1));

      if (name == "content-type")
        out.content_type = value;
      else if (name == "authorization")
        out.authorization = value;
      else if (name == "connection")
        out.connection = value;
      else if (name == "content-length")
      {
        size_t n = 0;
        if (!parseContentLength(value, n))
        {
          error_status = 400;
          error_message = "invalid Content-Length";
          return false;
        }
        out.content_length = n;
        out.has_content_length = true;
      }
      // Unknown headers are ignored.
    }

    header_end = pos;
    return true;
  }

  //  Request handling

  void HttpConnection::run()
  {
    Request req;
    int status = 0;
    std::string message;

    if (!readRequest(req, status, message))
    {
      if (status == 0)
        return; // no response possible
      writeTextError(status, "Bad Request", message);
      return;
    }

    handleRequest(req);
  }

  void HttpConnection::handleRequest(const Request &req)
  {
    // ---- Route ----
    //
    // GET  /       -> tiny info page (helps debugging)
    // POST /rpc    -> the RPC endpoint
    // POST /       -> same as /rpc
    // OPTIONS *    -> 204 with CORS headers
    // anything else -> 404 or 405

    if (req.method == "OPTIONS")
    {
      // CORS preflight. We don't actually enforce origin, but
      // responding to preflight lets browser-based clients proceed.
      // A production deployment should add explicit CORS config;
      // for v1 loopback-only, this is enough.
      std::string body;
      std::string headers =
          "HTTP/1.1 204 No Content\r\n"
          "Access-Control-Allow-Origin: *\r\n"
          "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
          "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
          "Content-Length: 0\r\n"
          "Connection: close\r\n\r\n";
      writeAll(headers.data(), headers.size());
      (void)body;
      return;
    }

    if (req.method == "GET" && (req.path == "/" || req.path == "/rpc"))
    {
      // Friendly banner so `curl localhost:9633` isn't silence.
      std::string body =
          "Clarity RPC. Send POST /rpc with a JSON-RPC 2.0 request.\n";
      writeResponse(200, "OK", body, "text/plain");
      return;
    }

    if (req.path != "/rpc" && req.path != "/")
    {
      writeTextError(404, "Not Found", "path must be / or /rpc");
      return;
    }

    if (req.method != "POST")
    {
      writeTextError(405, "Method Not Allowed", "use POST for RPC");
      return;
    }

    if (!req.content_type.empty() && !contentTypeIsJson(req.content_type))
    {
      writeTextError(415, "Unsupported Media Type",
                     "Content-Type must be application/json");
      return;
    }

    if (!req.has_content_length)
    {
      writeTextError(400, "Bad Request",
                     "Content-Length is required");
      return;
    }

    // ---- Parse JSON ----
    //
    // On parse failure, emit a JSON-RPC ParseError response. The
    // HTTP status is 200 — the JSON-RPC layer owns the error.
    Common::Json input;
    try
    {
      input = Common::Json::parse(req.body);
    }
    catch (const std::exception &)
    {
      Common::Json err = Common::Json::object();
      err["jsonrpc"] = "2.0";
      err["error"] = makeError(ErrorCode::ParseError);
      err["id"] = nullptr;

      writeResponse(200, "OK", err.dump());
      return;
    }

    // ---- Dispatch ----
    //
    // The dispatcher handles single requests, batches, and shape
    // errors. It never throws.

    // Set the auth context so admin methods can read the header.
    Rpc::setCurrentAuthorization(req.authorization);
    auto result = dispatcher_.dispatchJson(input);
    Rpc::setCurrentAuthorization({});

    if (result.is_empty)
    {
      // All notifications. Per JSON-RPC 2.0, no response is sent.
      // We still close the connection cleanly. A 204 is the most
      // honest HTTP-level representation of "nothing to say".
      std::string headers =
          "HTTP/1.1 204 No Content\r\n"
          "Content-Length: 0\r\n"
          "Connection: close\r\n\r\n";
      writeAll(headers.data(), headers.size());
      return;
    }

    writeResponse(200, "OK", result.response.dump());
  }

  //  Response writing

  void HttpConnection::writeResponse(int status,
                                     const std::string &reason,
                                     const std::string &body,
                                     const std::string &content_type)
  {
    std::string head;
    head.reserve(256 + body.size());

    head += "HTTP/1.1 ";
    head += std::to_string(status);
    head += " ";
    head += reason;
    head += "\r\n";
    head += "Content-Type: ";
    head += content_type;
    head += "\r\n";
    head += "Content-Length: ";
    head += std::to_string(body.size());
    head += "\r\n";
    head += "Connection: close\r\n";
    head += "\r\n";

    if (!writeAll(head.data(), head.size()))
      return;
    if (!body.empty())
      writeAll(body.data(), body.size());
  }

  void HttpConnection::writeTextError(int status,
                                      const std::string &reason,
                                      const std::string &message)
  {
    std::string body = message;
    body += "\n";
    writeResponse(status, reason, body, "text/plain");
  }

} // namespace Rpc