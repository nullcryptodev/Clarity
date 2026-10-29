// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

#include "Session/Session.h"

namespace Bridge
{
  //  Minimal HTTP server for the bridge's deposit-address API.
  //
  //  One thread, one route: POST /bridge/deposit-address. See
  //  DepositRequest.h for the request/response contract.
  //
  //  The server is deliberately small: it accepts a request,
  //  hands the body to the deposit-request handler, writes the
  //  response, closes. No keep-alive, no chunked encoding on the
  //  request side, no compression. That is enough for a
  //  payment-processor front end making a handful of requests
  //  per minute, and it means the whole thing is ~150 lines of
  //  boost::beast that we can read end-to-end.
  //
  //  If the port is already in use, start() returns false and
  //  logs the bind error. The caller (main.cpp) should treat a
  //  failed bind as non-fatal: the bridge's scan worker can
  //  still run; only the front-end API is unavailable.
  class HttpServer
  {
  public:
    HttpServer(WatcherSession &session,
               std::string bind_address,
               uint16_t port);
    ~HttpServer();

    HttpServer(const HttpServer &) = delete;
    HttpServer &operator=(const HttpServer &) = delete;

    //  Bind and start the accept loop on a background thread.
    //  Returns false on bind failure (port in use, invalid
    //  address). Idempotent: a second call while running is a
    //  no-op that returns true.
    bool start();

    //  Signal stop and join. Idempotent.
    void stop();

    //  The port the server actually bound to (useful when the
    //  caller passed port 0 for "pick a free port" — mostly a
    //  test convenience). 0 until start() succeeds.
    uint16_t boundPort() const noexcept { return bound_port_; }

  private:
    void run();

    WatcherSession &session_;
    std::string bind_address_;
    uint16_t requested_port_;
    uint16_t bound_port_{0};

    std::thread thread_;
    std::atomic<bool> stop_{false};
    std::atomic<bool> started_{false};

    struct Impl;
    std::unique_ptr<Impl> impl_;
  };
} // namespace Bridge