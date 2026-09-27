// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <memory>

#include "Config.h"

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

  //  RpcServer
  //
  //  Top-level RPC object. Owns the dispatcher and the HTTP server.
  //  Holds a reference to the Node and reads through its public API.
  //
  //  Lifecycle:
  //
  //    Node::Node node(config, logger);
  //    node.start();
  //
  //    Rpc::RpcServer rpc(node, rpc_config, logger);
  //    rpc.start();       // binds, spawns threads, returns
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

  class RpcServer
  {
  public:
    RpcServer(Node::Node &node,
              const RpcConfig &config,
              Logging::ILogger &logger);

    ~RpcServer();

    RpcServer(const RpcServer &) = delete;
    RpcServer &operator=(const RpcServer &) = delete;

    // Bind and start serving. Throws std::runtime_error if the bind
    // fails. No-op if the config has enabled=false.
    void start();

    // Stop serving and join. Bounded by socket_timeout_seconds plus a
    // small grace period. Idempotent.
    void stop();

    // The actual port we bound to. Useful when the config specifies
    // port 0 (kernel-assigned).
    uint16_t listeningPort() const noexcept;

    bool isRunning() const noexcept;

  private:
    Node::Node &node_;
    const RpcConfig &config_;
    Logging::ILogger &logger_;

    std::unique_ptr<JsonRpcDispatcher> dispatcher_;
    std::unique_ptr<HttpServer> http_;

    bool started_{false};
  };

} // namespace Rpc