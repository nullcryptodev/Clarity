// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "HttpConnection.h"

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

    // Canonical reason phrase for a status code. Handlers that
    // want a different phrase override it via
    // HttpResponse::reason_override. The map covers the codes we
    // produce ourselves plus a few standard ones a handler might
    // return.
    const char *reasonFor(int status)
    {
      switch (status)
      {
      case 200:
        return "OK";
      case 204:
        return "No Content";
      case 400:
        return "Bad Request";
      case 404:
        return "Not Found";
      case 405:
        return "Method Not Allowed";
      case 413:
        return "Payload Too Large";
      case 415:
        return "Unsupported Media Type";
      case 429:
        return "Too Many Requests";
      case 500:
        return "Internal Server Error";
      case 503:
        return "Service Unavailable";
      default:
        return "Unknown";
      }
    }
  } // anonymous namespace

  //  Construction

  HttpConnection::HttpConnection(int client_fd,
                                 const HttpServerConfig &config,
                                 IHttpHandler &handler,
                                 std::string remote_ip)
      : fd_(client_fd),
        config_(config),
        handler_(handler),
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

  bool HttpConnection::readRequest(HttpRequest &out,
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
                                 HttpRequest &out,
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
      else if (name == "origin")
        out.origin = value;
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

  bool HttpConnection::appendCorsHeaders(std::string &out,
                                         const std::string &origin) const
  {
    if (config_.cors_origins.empty())
      return false;

    const bool allow_any =
        std::find(config_.cors_origins.begin(),
                  config_.cors_origins.end(), "*") !=
        config_.cors_origins.end();

    std::string allowed;
    if (allow_any)
    {
      // Echo the request's Origin if present, otherwise "*". This
      // matters if credentials are ever enabled — a wildcard is
      // illegal with credentials, but echoing is fine.
      allowed = origin.empty() ? "*" : origin;
    }
    else
    {
      if (origin.empty())
        return false; // no Origin, not a CORS request
      if (std::find(config_.cors_origins.begin(),
                    config_.cors_origins.end(), origin) ==
          config_.cors_origins.end())
      {
        return false; // not allowed
      }
      allowed = origin;
    }

    out += "Access-Control-Allow-Origin: ";
    out += allowed;
    out += "\r\n";
    out += "Access-Control-Allow-Methods: POST, OPTIONS\r\n";
    out += "Access-Control-Allow-Headers: Content-Type, Authorization\r\n";
    out += "Access-Control-Max-Age: 86400\r\n";

    return true;
  }

  void HttpConnection::run()
  {
    HttpRequest req;
    int status = 0;
    std::string message;

    if (!readRequest(req, status, message))
    {
      if (status == 0)
        return; // no response possible
      writeTextError(status, reasonFor(status), message);
      return;
    }

    handleRequest(req);
  }

  void HttpConnection::handleRequest(const HttpRequest &req)
  {
    current_origin_ = req.origin;

    // ---- OPTIONS: CORS preflight, answered by the transport layer ----
    //
    // A browser's preflight for a cross-origin request never reaches
    // a handler: the browser is asking "will you accept this?" and
    // the answer depends only on the server's CORS config, not on
    // which handler is behind the port. Answering here avoids a
    // wasted round trip through the handler.

    if (req.method == "OPTIONS")
    {
      std::string headers;
      headers.reserve(256);
      headers += "HTTP/1.1 204 No Content\r\n";
      appendCorsHeaders(headers, req.origin);
      headers += "Content-Length: 0\r\n";
      headers += "Connection: close\r\n";
      headers += "\r\n";
      writeAll(headers.data(), headers.size());
      return;
    }

    // ---- Method validation: transport-level ----
    //
    // The server speaks GET and POST. A request with any other
    // method is not something any current handler can act on, so
    // the transport refuses it before dispatch. A future handler
    // that wants to serve DELETE or PUT will need to move this
    // check into the handler — the same pattern this commit is
    // applying to the POST framing checks below.

    if (req.method != "POST" && req.method != "GET")
    {
      writeTextError(405, "Method Not Allowed",
                     "use POST for application requests, GET for the banner");
      return;
    }

    // ---- Handler dispatch ----
    //
    // The method-specific framing checks (POST requires a
    // Content-Length and an acceptable Content-Type) have moved
    // into the handler. That's the correct place for them because
    // which framing is required depends on which handler is
    // running. Concretely: POST /metrics should return 405 "use
    // GET for metrics" from the metrics handler, not 400 "Content-
    // Length is required" from the transport, because the request
    // is doing two things wrong at once and the more specific
    // error is the more useful one.

    HttpResponse resp;
    try
    {
      resp = handler_.handle(req);
    }
    catch (const std::exception &e)
    {
      // A handler that throws is a bug. Log the message and
      // return a generic 500 — never leak internal exception
      // text to the client.
      (void)e;
      writeTextError(500, "Internal Server Error", "internal error");
      return;
    }
    catch (...)
    {
      writeTextError(500, "Internal Server Error", "internal error");
      return;
    }

    writeResponse(resp);
  }

  //  Response writing

  void HttpConnection::writeResponse(const HttpResponse &resp)
  {
    const std::string reason = resp.reason_override.empty()
                                   ? reasonFor(resp.status)
                                   : resp.reason_override;

    std::string head;
    head.reserve(256);

    head += "HTTP/1.1 ";
    head += std::to_string(resp.status);
    head += " ";
    head += reason;
    head += "\r\n";
    head += "Content-Type: ";
    head += resp.content_type;
    head += "\r\n";
    head += "Content-Length: ";
    head += std::to_string(resp.body.size());
    head += "\r\n";
    head += "Connection: close\r\n";

    appendCorsHeaders(head, current_origin_);

    head += "\r\n";

    if (!writeAll(head.data(), head.size()))
      return;
    if (!resp.body.empty())
      writeAll(resp.body.data(), resp.body.size());
  }

  void HttpConnection::writeTextError(int status,
                                      const std::string &reason,
                                      const std::string &message)
  {
    HttpResponse resp;
    resp.status = status;
    resp.content_type = "text/plain";
    resp.body = message;
    resp.body += "\n";
    resp.reason_override = reason;
    writeResponse(resp);
  }

} // namespace Rpc