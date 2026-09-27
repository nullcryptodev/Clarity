// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>

namespace Rpc
{
  inline constexpr uint16_t DEFAULT_RPC_PORT = 9633;
  inline constexpr const char *DEFAULT_RPC_BIND = "127.0.0.1";

  struct RpcConfig
  {
    // ---- Master switch ----

    bool enabled{true};

    // ---- Binding ----

    std::string bind_address{DEFAULT_RPC_BIND};
    uint16_t port{DEFAULT_RPC_PORT};

    // ---- Concurrency ----

    // Worker threads that serve HTTP connections. The accept loop runs
    // on its own dedicated thread and is not counted here.
    //
    // 0 means "auto": max(1, min(hardware_concurrency() - 1, 8)).
    //
    // RPC is I/O-bound on loopback and further serialized by StateDB's
    // internal mutex, so more than a handful of workers rarely helps.
    // 4 is a reasonable default for a laptop or small server.
    uint32_t worker_threads{4};

    // Maximum queued connections waiting for a worker. When full, new
    // connections are accepted, sent a 503, and closed. This is the
    // pool's bounded queue size, not a cap on total connections — an
    // active worker doesn't count against the queue.
    uint32_t max_queued_connections{64};

    // ---- Request limits ----

    // Maximum HTTP request size, headers included. Requests larger
    // than this are closed with a 413.
    uint32_t max_request_bytes{1024 * 1024}; // 1 MiB

    // Per-connection socket timeout. Applies to both recv and send.
    // A worker that can't read a full request within this window
    // releases and the connection is closed. Keep this short under a
    // pool — a stalled connection holds a worker, which is a real
    // resource.
    uint32_t socket_timeout_seconds{15};

    // ---- Rate limiting ----

    // Token bucket per source IP. Both zero = disabled.
    uint32_t rate_limit_burst{200};
    uint32_t rate_limit_per_second{50};

    // ---- Admin ----

    // Bearer token required for admin methods. Empty means admin
    // methods are not registered and requests for them return
    // MethodNotFound.
    std::string admin_token;

    // ---- Introspection ----

    bool verbose_errors{false};
  };

  void validateConfig(const RpcConfig &config);

} // namespace Rpc