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

#include "Config.h"
#include "WorkerPool.h"

#include "Common/RateLimiter.h"

namespace Logging
{
  class ILogger;
  class LoggerRef;
}

namespace Rpc
{
  class JsonRpcDispatcher;

  //  HttpServer
  //
  //  Owns the listening socket and the worker pool. One dedicated
  //  accept thread; N worker threads from WorkerPool. On shutdown,
  //  closes the listening socket, stops accepting, drains the pool
  //  with a bounded timeout, and joins.
  //
  //  Threading:
  //    - start() may be called from any thread.
  //    - stop() is safe from any thread and is idempotent.
  //    - The accept thread and workers are internal.

  class HttpServer
  {
  public:
    HttpServer(const RpcConfig &config,
               JsonRpcDispatcher &dispatcher,
               Logging::ILogger &logger);

    ~HttpServer();

    HttpServer(const HttpServer &) = delete;
    HttpServer &operator=(const HttpServer &) = delete;

    // Bind, listen, and start accepting. Throws on bind failure.
    // Returns after the listener is up but before any client is
    // accepted — this is deliberate so the caller knows the server
    // is ready.
    void start();

    // Stop accepting, drain, join. Bounded by
    // socket_timeout_seconds + a small grace period. Safe to call
    // multiple times.
    void stop();

    // For introspection / tests.
    uint16_t listeningPort() const noexcept { return listening_port_; }
    size_t activeConnections() const noexcept { return active_.load(); }
    size_t pendingConnections() const noexcept { return pool_.pendingJobs(); }

  private:
    void acceptLoop();
    void handleConnection(int client_fd, std::string remote_ip);

    // Returns true if the request from `ip` is allowed. Consumes a
    // token if so. Thread-safe.
    bool allowRequest(const std::string &ip);

    const RpcConfig &config_;
    JsonRpcDispatcher &dispatcher_;
    Logging::ILogger &logger_;
    std::unique_ptr<Logging::LoggerRef> log_;

    int listen_fd_{-1};
    uint16_t listening_port_{0};
    std::atomic<bool> stopping_{false};

    std::thread accept_thread_;
    WorkerPool pool_;

    std::atomic<size_t> active_{0};

    // Per-source-IP rate limiters. Guarded by rate_limit_mutex_.
    //
    // The map is capped at MAX_RATE_LIMIT_ENTRIES. When the cap is
    // hit, the whole map is cleared rather than evicting the oldest
    // entry — a cheap v1 defense against an attacker with a large
    // set of spoofed source IPs filling the map. Real LRU eviction
    // is a later change.
    //
    // Disabled (no lookups, no insertions) when config_.rate_limit_burst
    // and config_.rate_limit_per_second are both zero.
    static constexpr size_t MAX_RATE_LIMIT_ENTRIES = 10'000;
    std::mutex rate_limit_mutex_;
    std::unordered_map<std::string, Common::RateLimiter> rate_limiters_;

    // ---- CORS ----

    // Allowed origins for cross-origin requests. Empty means CORS is
    // disabled (browser clients will be blocked by the same-origin
    // policy). "*" allows any origin — appropriate for local dev and
    // public read-only RPC endpoints. An explicit list is appropriate
    // when the endpoint is also a control plane.
    //
    // A browser sends a preflight OPTIONS request for any non-simple
    // request (POST with content-type: application/json qualifies),
    // so the server must answer OPTIONS with the CORS headers and no
    // body. See HttpConnection.
    std::vector<std::string> cors_origins{};
  };

} // namespace Rpc