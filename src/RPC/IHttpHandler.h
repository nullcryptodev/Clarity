// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <string>

namespace Rpc
{
  //  HttpResponse
  //
  //  A fully-formed response the connection will write to the socket.
  //  The status line reason phrase is derived from `status` by the
  //  connection, so a handler doesn't have to know the phrase for
  //  each code it might return. (A handler that wants a specific
  //  reason phrase can still provide it via `reason_override`.)
  //
  //  `body` may be empty for status codes that carry no payload
  //  (204, 304, or a 4xx that just wants to signal failure). The
  //  connection still writes a Content-Length: 0 header.
  struct HttpResponse
  {
    int status{200};
    std::string content_type{"text/plain"};
    std::string body;

    // Optional. When non-empty, used verbatim as the reason phrase
    // after the status code. When empty, the connection uses a
    // canonical phrase for `status`.
    std::string reason_override;
  };

  //  HttpRequest
  //
  //  The parsed HTTP request, as delivered to a handler. Mirrors the
  //  private HttpConnection::Request, but lives at namespace scope
  //  because it crosses the handler interface.
  //
  //  The `body` field is only populated when `has_content_length`
  //  is true. A GET request, for example, typically has neither
  //  header nor body.
  struct HttpRequest
  {
    std::string method;
    std::string path;
    std::string version;
    std::string content_type;
    std::string authorization;
    std::string connection;
    std::string origin;
    size_t content_length{0};
    bool has_content_length{false};
    std::string body;
  };

  //  IHttpHandler
  //
  //  The seam between HttpConnection (which does HTTP parsing,
  //  socket I/O, and CORS) and whatever logic actually serves a
  //  request (the JSON-RPC dispatcher, the metrics exporter, a
  //  future healthz handler, etc.).
  //
  //  Contract:
  //
  //   * `handle` runs on a worker thread, never on the P2P event
  //     loop. It must not block on any subsystem that is only
  //     touched by the event loop. If it needs data from such a
  //     subsystem, it must read a lock-free snapshot.
  //
  //   * `handle` must not throw. Any exception that escapes will be
  //     caught by the connection, logged, and turned into a 500. A
  //     handler that wants to signal a specific failure should
  //     return an HttpResponse with the appropriate status code.
  //
  //   * `handle` must not perform its own socket I/O. It returns
  //     an HttpResponse; the connection writes it.
  //
  //   * `handle` must be thread-safe: two connections can be
  //     handled concurrently by different workers, and both will
  //     call `handle` on the same handler instance.
  class IHttpHandler
  {
  public:
    virtual ~IHttpHandler() = default;

    IHttpHandler(const IHttpHandler &) = delete;
    IHttpHandler &operator=(const IHttpHandler &) = delete;

    virtual HttpResponse handle(const HttpRequest &request) = 0;

  protected:
    IHttpHandler() = default;
  };

} // namespace Rpc