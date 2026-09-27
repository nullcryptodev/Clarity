// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>

#include "Config.h"

namespace Rpc
{
  class JsonRpcDispatcher;

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
  //  Status codes:
  //    200  — every JSON-RPC response (success or error) rides on 200
  //    400  — malformed HTTP, or a JSON body that isn't a valid request
  //    404  — path is not / or /rpc
  //    405  — method is not POST (and path is /rpc)
  //    413  — body larger than max_request_bytes
  //    415  — Content-Type is not JSON
  //    500  — internal error
  //    503  — server shutting down or overloaded

  class HttpConnection
  {
  public:
    HttpConnection(int client_fd,
                   const RpcConfig &config,
                   JsonRpcDispatcher &dispatcher,
                   std::string remote_ip);

    ~HttpConnection();

    HttpConnection(const HttpConnection &) = delete;
    HttpConnection &operator=(const HttpConnection &) = delete;

    // Handle the connection and return when it's done. Never throws.
    void run();

  private:
    struct Request
    {
      std::string method;
      std::string path;
      std::string version;
      std::string content_type;
      std::string authorization;
      std::string connection;
      size_t content_length{0};
      bool has_content_length{false};
      std::string body;
    };

    // Read and parse the request head + body. Returns true on success.
    // On failure, fills error_status and error_message.
    bool readRequest(Request &out, int &error_status, std::string &error_message);

    // Parse the request line + headers. `raw` must contain at least
    // one full header block (terminated by CRLF CRLF). On success,
    // `header_end` is the offset just past the terminator, and `out`
    // is populated with whatever headers we recognize. `raw`'s tail
    // (from `header_end` on) is the beginning of the body.
    bool parseHead(const std::string &raw,
                   Request &out,
                   size_t &header_end,
                   int &error_status,
                   std::string &error_message);

    void handleRequest(const Request &req);

    void writeResponse(int status,
                       const std::string &reason,
                       const std::string &body,
                       const std::string &content_type = "application/json");

    void writeTextError(int status,
                        const std::string &reason,
                        const std::string &message);

    bool writeAll(const void *buf, size_t len);
    ssize_t readSome(void *buf, size_t len);

    int fd_;
    const RpcConfig &config_;
    JsonRpcDispatcher &dispatcher_;
    std::string remote_ip_;
  };

} // namespace Rpc