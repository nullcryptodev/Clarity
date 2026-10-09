// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>

#include "Config.h"
#include "MetricsConfig.h"

namespace Logging
{
  class ILogger;
}

namespace Node
{
  class Node;
}

namespace Rpc
{
  class JsonRpcDispatcher;
  class HttpServer;
  class MetricsHandler;

  //  RpcServer
  //
  //  Top-level HTTP object. Owns the JSON-RPC dispatcher, the RPC
  //  HTTP server, the metrics handler, and the metrics HTTP server.
  //  Holds a reference to the Node and reads through its public API.
  //
  //  Lifecycle:
  //
  //    Node::Node node(config, logger);
  //    node.start();
  //
  //    Rpc::RpcServer rpc(node, rpc_config, metrics_config, logger);
  //    rpc.start();       // binds both ports, returns
  //
  //    node.run();        // blocks in P2P event loop
  //
  //    rpc.stop();        // drains, joins
  //    node.stop();
  //
  //  Threading:
  //    - start() and stop() are safe from any thread.
  //    - stop() is idempotent.
  //    - The destructor calls stop() if not already stopped.
  //
  //  The two servers are independent: either can be disabled in its
  //  config without affecting the other, and the failure of one to
  //  bind does not prevent the other from starting — but start()
  //  does propagate the first bind failure it sees, so a partial
  //  start is never silently ignored. See start() for the exact
  //  sequencing.

  class RpcServer
  {
  public:
    RpcServer(Node::Node &node,
              const RpcConfig &config,
              const MetricsConfig &metrics_config,
              Logging::ILogger &logger);

    ~RpcServer();

    RpcServer(const RpcServer &) = delete;
    RpcServer &operator=(const RpcServer &) = delete;

    // Bind and start serving. Throws std::runtime_error if a bind
    // fails. A disabled config for either server is a no-op for that
    // server. If the RPC bind succeeds and the metrics bind fails,
    // the RPC server is stopped before the exception propagates, so
    // the object is left in a fully stopped state.
    void start();

    // Stop serving and join both servers. Bounded by each server's
    // socket_timeout_seconds plus a small grace period. Idempotent.
    void stop();

    // The actual port the RPC server bound to. Useful when the
    // config specifies port 0 (kernel-assigned).
    uint16_t listeningPort() const noexcept;

    // The actual port the metrics server bound to, or 0 if metrics
    // is disabled or not started.
    uint16_t metricsListeningPort() const noexcept;

    bool isRunning() const noexcept;

  private:
    Node::Node &node_;
    const RpcConfig &config_;
    const MetricsConfig &metrics_config_;
    Logging::ILogger &logger_;

    std::unique_ptr<JsonRpcDispatcher> dispatcher_;
    std::unique_ptr<HttpServer> http_;

    std::unique_ptr<MetricsHandler> metrics_handler_;
    std::unique_ptr<HttpServer> metrics_http_;

    bool started_{false};
  };

} // namespace Rpc