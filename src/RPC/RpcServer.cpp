// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "RpcServer.h"

#include "HttpServer.h"
#include "JsonRpcDispatcher.h"
#include "MetricsHandler.h"

#include "Logging/ILogger.h"
#include "Node/Node.h"

namespace Rpc
{

  RpcServer::RpcServer(Node::Node &node,
                       const RpcConfig &config,
                       const MetricsConfig &metrics_config,
                       Logging::ILogger &logger)
      : node_(node),
        config_(config),
        metrics_config_(metrics_config),
        logger_(logger)
  {
  }

  RpcServer::~RpcServer()
  {
    stop();
  }

  void RpcServer::start()
  {
    if (started_)
      return;

    // Validate both configs up front, even though the daemon
    // validates them too. If RpcServer is constructed by a test with
    // a bad config, the failure should be local and clear.
    //
    // validateConfig is a no-op when config_.enabled is false, so
    // we can call it unconditionally.
    validateConfig(config_);
    validateMetricsConfig(metrics_config_);

    // ---- RPC server ----

    if (config_.enabled)
    {
      dispatcher_ = std::make_unique<JsonRpcDispatcher>(node_, config_);
      http_ = std::make_unique<HttpServer>(
          httpServerConfigFrom(config_),
          *dispatcher_,
          logger_);

      try
      {
        http_->start();
      }
      catch (...)
      {
        // Bind failed. Roll back: destroy the half-constructed
        // objects and re-throw. The destructor of HttpServer is
        // safe to call on a server that failed to start (stop() is
        // idempotent and the socket is already closed).
        http_.reset();
        dispatcher_.reset();
        throw;
      }
    }

    // ---- Metrics server ----
    //
    // If the metrics bind fails after the RPC bind succeeded, we
    // must stop the RPC server before propagating. Otherwise the
    // object would be left "started_" but with a listening socket
    // that no one will ever stop — which is worse than failing
    // cleanly.

    if (metrics_config_.enabled)
    {
      metrics_handler_ = std::make_unique<MetricsHandler>(node_, metrics_config_);
      metrics_http_ = std::make_unique<HttpServer>(
          httpServerConfigFrom(metrics_config_),
          *metrics_handler_,
          logger_);

      try
      {
        metrics_http_->start();
      }
      catch (...)
      {
        // Metrics failed. Roll back both: the metrics objects
        // (nothing to stop, start() threw before the accept thread
        // was launched) and the RPC server (which did start and
        // must be stopped).
        metrics_http_.reset();
        metrics_handler_.reset();

        if (http_)
        {
          http_->stop();
          http_.reset();
        }
        dispatcher_.reset();

        throw;
      }
    }

    started_ = true;
  }

  void RpcServer::stop()
  {
    if (!started_)
      return;

    // Stop metrics first. It's the more recent addition and the one
    // least likely to be holding important work; stopping it first
    // means its workers finish before we start tearing down the RPC
    // side, which in turn means any log line about the RPC shutdown
    // is the last thing written.
    if (metrics_http_)
    {
      metrics_http_->stop();
      metrics_http_.reset();
    }
    metrics_handler_.reset();

    if (http_)
    {
      http_->stop();
      http_.reset();
    }
    dispatcher_.reset();

    started_ = false;
  }

  uint16_t RpcServer::listeningPort() const noexcept
  {
    return http_ ? http_->listeningPort() : 0;
  }

  uint16_t RpcServer::metricsListeningPort() const noexcept
  {
    return metrics_http_ ? metrics_http_->listeningPort() : 0;
  }

  bool RpcServer::isRunning() const noexcept
  {
    return started_ && http_ != nullptr;
  }

} // namespace Rpc