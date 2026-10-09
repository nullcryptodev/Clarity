// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "Config.h"
#include "MetricsConfig.h"

namespace Rpc
{
  //  HttpServerConfig
  //
  //  The subset of transport-level configuration HttpServer and
  //  HttpConnection need. Neither class knows about JSON-RPC, admin
  //  tokens, or the many other things RpcConfig carries — they know
  //  about sockets, timeouts, and rate limits.
  //
  //  Both RpcConfig and MetricsConfig are converted into this struct
  //  at construction time. This is deliberately not a config struct
  //  an operator sets directly; it's the projection of the caller's
  //  config that the server understands.
  struct HttpServerConfig
  {
    uint32_t worker_threads{1};
    uint32_t max_queued_connections{16};
    uint32_t max_request_bytes{1024 * 1024};
    uint32_t socket_timeout_seconds{15};
    uint32_t rate_limit_burst{0};
    uint32_t rate_limit_per_second{0};
    std::string bind_address{"127.0.0.1"};
    uint16_t port{0};
    std::vector<std::string> cors_origins{};
  };

  inline HttpServerConfig httpServerConfigFrom(const RpcConfig &rc)
  {
    HttpServerConfig c;
    c.worker_threads = rc.worker_threads;
    c.max_queued_connections = rc.max_queued_connections;
    c.max_request_bytes = rc.max_request_bytes;
    c.socket_timeout_seconds = rc.socket_timeout_seconds;
    c.rate_limit_burst = rc.rate_limit_burst;
    c.rate_limit_per_second = rc.rate_limit_per_second;
    c.bind_address = rc.bind_address;
    c.port = rc.port;
    c.cors_origins = rc.cors_origins;
    return c;
  }

  inline HttpServerConfig httpServerConfigFrom(const MetricsConfig &mc)
  {
    HttpServerConfig c;
    c.worker_threads = mc.worker_threads;
    c.max_queued_connections = mc.max_queued_connections;
    c.max_request_bytes = mc.max_request_bytes;
    c.socket_timeout_seconds = mc.socket_timeout_seconds;
    c.rate_limit_burst = mc.rate_limit_burst;
    c.rate_limit_per_second = mc.rate_limit_per_second;
    c.bind_address = mc.bind_address;
    c.port = mc.port;
    // No CORS on metrics — a Prometheus scraper is not a browser.
    return c;
  }

} // namespace Rpc