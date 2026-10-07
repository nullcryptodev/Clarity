// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "HttpServer.h"

#include "HttpConnection.h"
#include "JsonRpcDispatcher.h"

#include "Logging/ILogger.h"
#include "Logging/LoggerRef.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

namespace Rpc
{

  namespace
  {
    // Set SO_REUSEADDR so a quick restart doesn't fail on TIME_WAIT.
    void setReuseAddr(int fd)
    {
      int one = 1;
      ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }

    std::string formatSockaddr(const sockaddr_storage &ss)
    {
      char buf[INET6_ADDRSTRLEN] = {0};
      if (ss.ss_family == AF_INET)
      {
        const auto *s4 = reinterpret_cast<const sockaddr_in *>(&ss);
        ::inet_ntop(AF_INET, &s4->sin_addr, buf, sizeof(buf));
      }
      else if (ss.ss_family == AF_INET6)
      {
        const auto *s6 = reinterpret_cast<const sockaddr_in6 *>(&ss);
        ::inet_ntop(AF_INET6, &s6->sin6_addr, buf, sizeof(buf));
      }
      return buf;
    }
  } // anonymous namespace

  //  Construction

  HttpServer::HttpServer(const RpcConfig &config,
                         JsonRpcDispatcher &dispatcher,
                         Logging::ILogger &logger)
      : config_(config),
        dispatcher_(dispatcher),
        logger_(logger),
        log_(std::make_unique<Logging::LoggerRef>(logger, "RPC")),
        pool_(config.worker_threads, config.max_queued_connections)
  {
  }

  HttpServer::~HttpServer()
  {
    stop();
  }

  //  Start / stop

  void HttpServer::start()
  {
    if (listen_fd_ >= 0)
      return; // already started

    // Resolve the bind address. We support IPv4 and IPv6 literals
    // (validated at config time).
    sockaddr_storage addr{};
    socklen_t addr_len = 0;

    if (config_.bind_address.find(':') != std::string::npos)
    {
      // IPv6 literal.
      auto *s6 = reinterpret_cast<sockaddr_in6 *>(&addr);
      s6->sin6_family = AF_INET6;
      s6->sin6_port = htons(config_.port);
      if (::inet_pton(AF_INET6, config_.bind_address.c_str(),
                      &s6->sin6_addr) != 1)
      {
        throw std::runtime_error(
            "rpc: inet_pton failed for bind_address " + config_.bind_address);
      }
      addr_len = sizeof(sockaddr_in6);
    }
    else
    {
      auto *s4 = reinterpret_cast<sockaddr_in *>(&addr);
      s4->sin_family = AF_INET;
      s4->sin_port = htons(config_.port);
      if (::inet_pton(AF_INET, config_.bind_address.c_str(),
                      &s4->sin_addr) != 1)
      {
        throw std::runtime_error(
            "rpc: inet_pton failed for bind_address " + config_.bind_address);
      }
      addr_len = sizeof(sockaddr_in);
    }

    // ---- Socket ----
    int family = (addr.ss_family == AF_INET6) ? AF_INET6 : AF_INET;
    listen_fd_ = ::socket(family, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
    {
      throw std::runtime_error(
          std::string("rpc: socket() failed: ") + std::strerror(errno));
    }

    setReuseAddr(listen_fd_);

    if (::bind(listen_fd_, reinterpret_cast<sockaddr *>(&addr), addr_len) < 0)
    {
      int saved = errno;
      ::close(listen_fd_);
      listen_fd_ = -1;
      throw std::runtime_error(
          std::string("rpc: bind() failed on ") + config_.bind_address +
          ":" + std::to_string(config_.port) + ": " +
          std::strerror(saved));
    }

    if (::listen(listen_fd_, 128) < 0)
    {
      int saved = errno;
      ::close(listen_fd_);
      listen_fd_ = -1;
      throw std::runtime_error(
          std::string("rpc: listen() failed: ") + std::strerror(saved));
    }

    // Discover the actual port if we bound to :0.
    {
      sockaddr_storage bound{};
      socklen_t blen = sizeof(bound);
      if (::getsockname(listen_fd_,
                        reinterpret_cast<sockaddr *>(&bound),
                        &blen) == 0)
      {
        if (bound.ss_family == AF_INET)
        {
          listening_port_ = ntohs(
              reinterpret_cast<sockaddr_in *>(&bound)->sin_port);
        }
        else
        {
          listening_port_ = ntohs(
              reinterpret_cast<sockaddr_in6 *>(&bound)->sin6_port);
        }
      }
      else
      {
        listening_port_ = config_.port;
      }
    }

    (*log_)(Logging::DEBUGGING)
        << "RPC listening on " << config_.bind_address << ":"
        << listening_port_ << " (" << pool_.threadCount() << " workers)";

    stopping_.store(false);
    accept_thread_ = std::thread([this]
                                 { acceptLoop(); });
  }

  void HttpServer::stop()
  {
    bool expected = false;
    if (!stopping_.compare_exchange_strong(expected, true))
      return;

    // Close the listening socket first. This causes accept() to
    // return an error, which wakes the accept thread and lets it
    // exit.
    if (listen_fd_ >= 0)
    {
      ::shutdown(listen_fd_, SHUT_RDWR);
      ::close(listen_fd_);
      listen_fd_ = -1;
    }

    if (accept_thread_.joinable())
      accept_thread_.join();

    // Drain workers. Workers finish their current connection,
    // then exit. Jobs still in the queue are dropped — their
    // sockets get closed by their HttpConnection destructors when
    // the queue is destroyed.
    pool_.stop();

    (*log_)(Logging::INFO) << "RPC stopped";
  }

  //  Accept loop

  void HttpServer::acceptLoop()
  {
    while (!stopping_.load())
    {
      sockaddr_storage client_addr{};
      socklen_t client_len = sizeof(client_addr);

      int client_fd = ::accept(
          listen_fd_,
          reinterpret_cast<sockaddr *>(&client_addr),
          &client_len);

      if (client_fd < 0)
      {
        if (errno == EINTR)
          continue;
        if (stopping_.load())
          break;
        // Transient errors shouldn't kill the loop.
        if (errno == ECONNABORTED || errno == EAGAIN || errno == EWOULDBLOCK)
          continue;

        (*log_)(Logging::WARNING)
            << "accept() failed: " << std::strerror(errno);
        break;
      }

      std::string remote_ip = formatSockaddr(client_addr);

      // Rate limit before enqueuing. A rate-limited client must not
      // occupy a worker slot or a queue slot — the queue is bounded
      // and workers are expensive.
      if (!allowRequest(remote_ip))
      {
        static const char response[] =
            "HTTP/1.1 429 Too Many Requests\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 16\r\n"
            "Connection: close\r\n"
            "Retry-After: 1\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            "rate limit hit\r\n"
            "\r\n";

        ::send(client_fd, response, sizeof(response) - 1, MSG_NOSIGNAL);
        ::close(client_fd);

        (*log_)(Logging::WARNING)
            << "rate-limited connection from " << remote_ip;
        continue;
      }

      // Disable Nagle: RPC requests are single round-trips, no
      // benefit to coalescing.
      int one = 1;
      ::setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

      // Enqueue for a worker. If the queue is full, refuse.
      bool accepted = pool_.submit(
          [this, client_fd, remote_ip = std::move(remote_ip)]()
          {
            handleConnection(client_fd, remote_ip);
          });

      if (!accepted)
      {
        // Queue full or pool stopping. Send a minimal 503 and close.
        static const char response[] =
            "HTTP/1.1 503 Service Unavailable\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 21\r\n"
            "Connection: close\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "\r\n"
            "server overloaded\r\n"
            "\r\n";

        // Best-effort write; ignore failures.
        ::send(client_fd, response, sizeof(response) - 1, MSG_NOSIGNAL);
        ::close(client_fd);

        (*log_)(Logging::WARNING)
            << "rejected connection from " << remote_ip
            << " (queue full)";
      }
    }
  }

  void HttpServer::handleConnection(int client_fd, std::string remote_ip)
  {
    active_.fetch_add(1);

    try
    {
      HttpConnection conn(client_fd, config_, dispatcher_, std::move(remote_ip));
      // HttpConnection's destructor closes client_fd, so we don't
      // double-close here.
      conn.run();
    }
    catch (...)
    {
      // HttpConnection::run() is documented as noexcept, but if
      // anything escapes anyway, close the fd and move on.
      ::close(client_fd);
    }

    active_.fetch_sub(1);
  }

  bool HttpServer::allowRequest(const std::string &ip)
  {
    // Config convention: both zero = disabled. If either is non-zero,
    // validateConfig already enforced burst >= per_second.
    const bool disabled = (config_.rate_limit_burst == 0 &&
                           config_.rate_limit_per_second == 0);
    if (disabled)
      return true;

    // The lock covers both the map lookup AND the tryConsume() call.
    // That's deliberate: RateLimiter is not thread-safe by design, and
    // this mutex is the single point where per-IP buckets are
    // serialized. If this lock ever moves (e.g. per-bucket locks for
    // scalability), RateLimiter must be made thread-safe at the same
    // time. See Common/RateLimiter.h for the ownership contract.
    std::lock_guard<std::mutex> lock(rate_limit_mutex_);

    auto it = rate_limiters_.find(ip);
    if (it == rate_limiters_.end())
    {
      if (rate_limiters_.size() >= MAX_RATE_LIMIT_ENTRIES)
      {
        // Cheap defense: drop everything rather than grow without
        // bound. An attacker with many source IPs will reset
        // legitimate clients' buckets, but the alternative is
        // unbounded memory. See the header comment.
        rate_limiters_.clear();
      }

      auto [inserted, _] = rate_limiters_.emplace(
          ip,
          Common::RateLimiter(config_.rate_limit_burst,
                              config_.rate_limit_per_second));
      it = inserted;
    }

    return it->second.tryConsume();
  }
} // namespace Rpc