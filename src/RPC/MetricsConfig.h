// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string>

namespace Rpc
{
  inline constexpr uint16_t DEFAULT_METRICS_PORT = 9100;
  inline constexpr const char *DEFAULT_METRICS_BIND = "127.0.0.1";

  //  MetricsConfig
  //
  //  Configuration for the Prometheus metrics endpoint. Structurally
  //  similar to RpcConfig but deliberately separate: the two
  //  endpoints have different audiences (metrics scrapers versus
  //  application clients) and different safe defaults. In
  //  particular:
  //
  //    * Metrics binds to loopback by default. RPC also binds to
  //      loopback by default, but an operator who exposes their
  //      RPC node publicly will usually *not* want to expose the
  //      metrics endpoint — and this config lets them make that
  //      choice independently.
  //
  //    * Metrics has rate limiting disabled by default. A
  //      Prometheus scraper polls every 15 seconds; rate limiting
  //      a trusted scraper is pure friction.
  //
  //    * Metrics has no admin token. The endpoint is read-only and
  //      exposes no control surface, so there is nothing to gate.
  //      An operator who wants to restrict access does so at the
  //      firewall or by binding to a private interface.
  struct MetricsConfig
  {
    // ---- Master switch ----
    bool enabled{true};

    // ---- Binding ----
    std::string bind_address{DEFAULT_METRICS_BIND};
    uint16_t port{DEFAULT_METRICS_PORT};

    // ---- Concurrency ----
    //
    // One worker is almost always enough. A scrape is a single
    // request every 15 seconds; even a 100-node cluster polling
    // in lockstep doesn't need more than one worker. Bump this
    // only if you observe scrapes queuing.
    uint32_t worker_threads{1};

    uint32_t max_queued_connections{16};

    // ---- Request limits ----
    //
    // Metrics requests are GET, no body, tiny headers. 64 KiB is
    // generous and still bounds the read loop.
    uint32_t max_request_bytes{64 * 1024};

    // ---- Socket timeout ----
    //
    // Short. A scrape is a single small write; a stalled client
    // should not hold a worker for long.
    uint32_t socket_timeout_seconds{5};

    // ---- Rate limiting ----
    //
    // Disabled by default. See the class comment.
    uint32_t rate_limit_burst{0};
    uint32_t rate_limit_per_second{0};

    // ---- Optional metric groups ----
    //
    // The per-validator block (see the metrics spec, §4.8) adds
    // ~6 new time series per active validator. On a 100-validator
    // chain that's 600 series per node, which is fine for a
    // monitoring stack but wasteful for an operator who just wants
    // to watch their own node. Default off.
    //
    // The other blocks (node, consensus, P2P, mempool, storage,
    // rewards) are always on — their cardinality is fixed and small.
    bool include_validator_metrics{false};
  };

  void validateMetricsConfig(const MetricsConfig &config);

} // namespace Rpc