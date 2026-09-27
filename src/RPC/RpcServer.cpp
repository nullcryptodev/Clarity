// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "RpcServer.h"

#include "HttpServer.h"
#include "JsonRpcDispatcher.h"

#include "Logging/ILogger.h"
#include "Node/Node.h"

namespace Rpc
{

  RpcServer::RpcServer(Node::Node &node,
                       const RpcConfig &config,
                       Logging::ILogger &logger)
      : node_(node),
        config_(config),
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

    if (!config_.enabled)
    {
      started_ = true;
      return;
    }

    // Validate the config here too, even though Daemon::validateConfig
    // already does. If RpcServer is constructed by a test with a
    // bad config, we want the failure to be local and clear.
    validateConfig(config_);

    dispatcher_ = std::make_unique<JsonRpcDispatcher>(node_, config_);
    http_ = std::make_unique<HttpServer>(config_, *dispatcher_, logger_);
    http_->start();

    started_ = true;
  }

  void RpcServer::stop()
  {
    if (!started_)
      return;

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

  bool RpcServer::isRunning() const noexcept
  {
    return started_ && http_ != nullptr;
  }

} // namespace Rpc