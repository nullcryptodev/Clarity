// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "HttpServerConfig.h"
#include "IHttpHandler.h"
#include "WorkerPool.h"

#include "Common/RateLimiter.h"

namespace Logging
{
  class ILogger;
  class LoggerRef;
}

namespace Rpc
{
  //  HttpServer
  //
  //  Owns the listening socket and the worker pool. One dedicated
  //  accept thread; N worker threads from WorkerPool. On shutdown,
  //  closes the listening socket, stops accepting, drains the pool
  //  with a bounded timeout, and joins.
  //
  //  The handler is supplied at construction time and is not owned.
  //  It must outlive the server. Concurrent calls to `handle` from
  //  different worker threads are the handler's responsibility; see
  //  IHttpHandler.
  //
  //  Threading:
  //    - start() may be called from any thread.
  //    - stop() is safe from any thread and is idempotent.
  //    - The accept thread and workers are internal.

  class HttpServer
  {
  public:
    HttpServer(const HttpServerConfig &config,
               IHttpHandler &handler,
               Logging::ILogger &logger);

    ~HttpServer();

    HttpServer(const HttpServer &) = delete;
    HttpServer &operator=(const HttpServer &) = delete;

    void start();
    void stop();

    uint16_t listeningPort() const noexcept { return listening_port_; }
    size_t activeConnections() const noexcept { return active_.load(); }
    size_t pendingConnections() const noexcept { return pool_.pendingJobs(); }

  private:
    void acceptLoop();
    void handleConnection(int client_fd, std::string remote_ip);
    bool allowRequest(const std::string &ip);

    HttpServerConfig config_;
    IHttpHandler &handler_;
    Logging::ILogger &logger_;
    std::unique_ptr<Logging::LoggerRef> log_;

    int listen_fd_{-1};
    uint16_t listening_port_{0};
    std::atomic<bool> stopping_{false};

    std::thread accept_thread_;
    WorkerPool pool_;

    std::atomic<size_t> active_{0};

    static constexpr size_t MAX_RATE_LIMIT_ENTRIES = 10'000;
    std::mutex rate_limit_mutex_;
    std::unordered_map<std::string, Common::RateLimiter> rate_limiters_;
  };

} // namespace Rpc