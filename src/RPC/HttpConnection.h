// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>

#include "Config.h"
#include "IHttpHandler.h"
#include "HttpServerConfig.h"

namespace Rpc
{
  //  HttpConnection
  //
  //  Handles one HTTP request on one socket. Constructed by
  //  HttpServer's worker thread; run() executes entirely on that
  //  thread; destructor closes the socket. No internal state is
  //  shared with any other object.
  //
  //  One request per connection. The `Connection: keep-alive` header
  //  is honored in the sense that we don't reject it, but we always
  //  close after one response. Clients that want persistent
  //  connections should reconnect. This is documented, deliberate,
  //  and easy to change later if the wallet ends up making enough
  //  requests to care.
  //
  //  HttpConnection does not know what a "JSON-RPC request" or a
  //  "metrics request" is. It parses HTTP, applies the transport-
  //  level checks that apply to every handler (Content-Length
  //  present, Content-Type allowed), builds an HttpRequest, and
  //  hands it to the IHttpHandler. Every routing decision below
  //  that point is the handler's.
  //
  //  Status codes owned by this layer:
  //    400  — malformed HTTP, or request body framing errors
  //    404  — reserved (handlers currently don't route by path, but
  //           the connection still refuses non-"/" and non-"/rpc"
  //           paths so a future handler can't accidentally accept
  //           them; see handleRequest for the exact check)
  //    405  — method is not POST or GET
  //    413  — body larger than max_request_bytes
  //    415  — Content-Type is not JSON
  //    500  — internal error (handler threw)
  //    503  — server shutting down or overloaded
  //
  //  Status codes owned by handlers:
  //    200  — normal response
  //    204  — no content
  //    and anything else a specific handler chooses to return.

  class HttpConnection
  {
  public:
    HttpConnection(int client_fd,
                   const HttpServerConfig &config,
                   IHttpHandler &handler,
                   std::string remote_ip);

    ~HttpConnection();

    HttpConnection(const HttpConnection &) = delete;
    HttpConnection &operator=(const HttpConnection &) = delete;

    // Handle the connection and return when it's done. Never throws.
    void run();

  private:
    // Read and parse the request head + body. Returns true on success.
    // On failure, fills error_status and error_message.
    bool readRequest(HttpRequest &out, int &error_status, std::string &error_message);

    // Parse the request line + headers. `raw` must contain at least
    // one full header block (terminated by CRLF CRLF). On success,
    // `header_end` is the offset just past the terminator, and `out`
    // is populated with whatever headers we recognize. `raw`'s tail
    // (from `header_end` on) is the beginning of the body.
    bool parseHead(const std::string &raw,
                   HttpRequest &out,
                   size_t &header_end,
                   int &error_status,
                   std::string &error_message);

    // Validate the parsed request and hand it to the handler. The
    // handler returns an HttpResponse; this method writes it.
    void handleRequest(const HttpRequest &req);

    // Write a response using the connection's HTTP framing. Used by
    // both the success path (handler-returned response) and the
    // error path (transport-level rejection).
    void writeResponse(const HttpResponse &resp);

    // Convenience for transport-level errors: a plain-text body,
    // the given status, and no CORS on the failure path (a browser
    // that gets a 400 on a preflight doesn't need CORS headers,
    // because the browser will block the request regardless).
    void writeTextError(int status,
                        const std::string &reason,
                        const std::string &message);

    bool writeAll(const void *buf, size_t len);
    ssize_t readSome(void *buf, size_t len);

    // Append CORS headers to `out` if the request's Origin is allowed
    // by config_.cors_origins. Returns true if any header was added.
    bool appendCorsHeaders(std::string &out, const std::string &origin) const;

    int fd_;
    const HttpServerConfig &config_;
    IHttpHandler &handler_;
    std::string remote_ip_;
    std::string current_origin_;
  };

} // namespace Rpc