// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <chrono>
#include <string>

#include "IHttpHandler.h"
#include "MetricsConfig.h"

namespace Node
{
  class Node;
}

namespace Rpc
{
  //  MetricsHandler
  //
  //  Serves the Prometheus text exposition format at /metrics. Reads
  //  from the Node's public accessors on the RPC worker thread — it
  //  never touches the P2P event loop, never blocks on a subsystem
  //  lock held by the event loop, and never posts.
  //
  //  Thread safety: IHttpHandler contract — handle() may be called
  //  concurrently from multiple worker threads. The Node accessors
  //  it reads are all already thread-safe (Node::status() takes a
  //  short lock; Mempool::stats() reads atomics; P2PManager::snapshot()
  //  reads counters written only by the event loop and is documented
  //  as safe to call from any thread; the StateDB table counts go
  //  through the existing DB read path, which is what every RPC
  //  method uses).
  //
  //  The handler holds a `started_at_` time point captured at
  //  construction, so `clrty_uptime_seconds` reports wall-clock
  //  since the node's metrics endpoint came up. It is set once and
  //  never mutated, so reading it from any thread is safe.
  class MetricsHandler : public IHttpHandler
  {
  public:
    MetricsHandler(Node::Node &node, const MetricsConfig &config);

    ~MetricsHandler() override = default;

    MetricsHandler(const MetricsHandler &) = delete;
    MetricsHandler &operator=(const MetricsHandler &) = delete;

    HttpResponse handle(const HttpRequest &request) override;

    // Build the exposition text. Public so tests can call it
    // directly without going through the HTTP layer.
    std::string render();

  private:
    // Append "# HELP name text" and "# TYPE name type" lines to
    // `out`. Every metric must be preceded by both, exactly once,
    // before any sample of that metric.
    void beginMetric(std::string &out,
                     const std::string &name,
                     const std::string &type,
                     const std::string &help);

    // Append "name value\n" — unlabelled sample.
    void emitGauge(std::string &out,
                   const std::string &name,
                   uint64_t value);

    void emitGauge(std::string &out,
                   const std::string &name,
                   int64_t value);

    // Append "name{label="value"} value\n" — labelled sample. The
    // caller is responsible for escaping the label value; the
    // helpers in this file's translation unit handle that.
    void emitGauge(std::string &out,
                   const std::string &name,
                   const std::string &label,
                   const std::string &label_value,
                   uint64_t value);

    Node::Node &node_;
    const MetricsConfig &config_;
    std::chrono::steady_clock::time_point started_at_;
  };

} // namespace Rpc