// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Args.h"

#include "Logging/ConsoleLogger.h"
#include "Logging/FileLogger.h"
#include "Node/Node.h"
#include "RPC/RpcServer.h"

#include <atomic>
#include <cstdio>
#include <exception>
#include <memory>
#include <mdbx.h>

namespace
{
  Logging::Level parseLogLevel(const std::string &s)
  {
    if (s == "debug")
      return Logging::DEBUGGING;
    if (s == "info")
      return Logging::INFO;
    if (s == "warn")
      return Logging::WARNING;
    if (s == "error")
      return Logging::ERROR;
    throw std::runtime_error("unknown log level: " + s);
  }
} // anonymous namespace

int main(int argc, char **argv)
{
  // Parse arguments
  Daemon::Args args;
  try
  {
    args = Daemon::parseArgs(argc, argv);
  }
  catch (const std::exception &e)
  {
    std::fprintf(stderr, "error: %s\n", e.what());
    std::fprintf(stderr, "run '%s --help' for usage\n", argv[0]);
    return 1;
  }

  if (args.show_help)
  {
    Daemon::printHelp(argv[0]);
    return 0;
  }
  if (args.show_version)
  {
    Daemon::printVersion();
    return 0;
  }

  // Validate all three configs before doing anything expensive. A
  // bad --rpc-port or --metrics-port should fail here, not on the
  // first request or the first scrape.
  try
  {
    Node::validateConfig(args.node);
    Rpc::validateConfig(args.rpc);
    Rpc::validateMetricsConfig(args.metrics);
  }
  catch (const std::exception &e)
  {
    std::fprintf(stderr, "configuration error: %s\n", e.what());
    return 1;
  }

  if (args.print_config)
  {
    Daemon::printConfig(args);
    return 0;
  }

  // Set up logging
  auto level = parseLogLevel(args.log_level);

  std::unique_ptr<Logging::ILogger> logger;

  if (!args.log_file.empty())
  {
    logger = std::make_unique<Logging::FileLogger>(level);
  }
  else
  {
    logger = std::make_unique<Logging::ConsoleLogger>(level);
  }

  // Banner
  Logging::LoggerRef log(*logger, "Daemon");
  log(Logging::INFO) << "▄█████ ▄▄     ▄▄▄  ▄▄▄▄  ▄▄ ▄▄▄▄▄▄ ▄▄ ▄▄ ";
  log(Logging::INFO) << "██     ██    ██▀██ ██▄█▄ ██   ██   ▀███▀ ";
  log(Logging::INFO) << "▀█████ ██▄▄▄ ██▀██ ██ ██ ██   ██     █   ";

  log(Logging::INFO) << "=================================================";
  log(Logging::INFO) << "  Clarity daemon starting";
  log(Logging::INFO) << "  network:  " << Logging::BRIGHT_GREEN << Node::networkName(args.node.network);
  log(Logging::INFO) << "  data dir: " << Logging::BRIGHT_GREEN << args.node.data_dir;
  log(Logging::INFO) << "  rpc:      "
                     << Logging::BRIGHT_GREEN << (args.rpc.enabled ? "enabled" : "disabled");
  log(Logging::INFO) << "  metrics:  "
                     << Logging::BRIGHT_GREEN << (args.metrics.enabled ? "enabled" : "disabled");

  // Disable nonvital logs from mdbx.
  setenv("MDBX_LOG", "ERROR", 1);
  setenv("MDBX_DEBUG", "none", 1);
  mdbx_setup_debug(MDBX_LOG_ERROR, MDBX_DBG_NONE, nullptr);

  //  No std::signal handler here. The daemon installs an asio
  //  signal_set on the P2P io_context inside Node::run(). asio
  //  catches SIGINT and SIGTERM via a self-pipe and delivers the
  //  notification as an event on the io_context, so the shutdown
  //  callback runs on the event loop thread where it is safe to
  //  take locks, join threads, and call node methods.
  //
  //  Previously this file installed a std::signal handler that
  //  called g_rpc->stop() and g_node->stop() directly. That was
  //  undefined behavior: a signal can arrive while any thread holds
  //  any of the daemon's mutexes, and the handler would try to
  //  acquire the same lock, deadlocking. The asio path avoids the
  //  problem entirely and also handles rapid repeated Ctrl+C
  //  gracefully.

  // Construct and run the node
  int exit_code = 0;

  try
  {
    Node::Node node(args.node, *logger);

    node.start();

    // Construct RPC after Node has started but before Node::run().
    //
    // RPC reads through Node's public API and runs its own worker
    // threads, so it does not depend on the main thread being free.
    // Once Node::run() blocks on the P2P event loop, RPC continues
    // serving on its workers.
    //
    // RpcServer owns both the RPC endpoint and the metrics endpoint.
    // Each is independently enabled via its own config; the object
    // is only constructed if at least one of them is enabled. If
    // both are disabled, no RPC header is ever touched again.
    std::unique_ptr<Rpc::RpcServer> rpc;
    const bool any_rpc_enabled = args.rpc.enabled || args.metrics.enabled;

    if (any_rpc_enabled)
    {
      rpc = std::make_unique<Rpc::RpcServer>(node, args.rpc, args.metrics, *logger);
      rpc->start();

      if (args.rpc.enabled)
      {
        log(Logging::INFO) << "RPC listening on " << Logging::BRIGHT_GREEN
                           << args.rpc.bind_address << ":"
                           << rpc->listeningPort();
      }

      if (args.metrics.enabled)
      {
        log(Logging::INFO) << "Metrics listening on " << Logging::BRIGHT_GREEN
                           << args.metrics.bind_address << ":"
                           << rpc->metricsListeningPort();
      }
    }

    log(Logging::INFO) << "Node is running. Press Ctrl+C to stop.";

    // Block until stopped. Node::run() returns when stop() is called,
    // whether by the asio signal handler or by the admin shutdown RPC.
    node.run();

    // Stop RPC before Node finishes tearing down. This ensures no
    // handler is running against Node-owned state while Node's
    // destructor runs. Runs on the main thread, after the P2P event
    // loop has stopped, which is the safe context for the stop()
    // sequence (no signal handler involvement).
    if (rpc)
    {
      rpc->stop();
      rpc.reset();
    }

    log(Logging::INFO) << "Node stopped cleanly.";
  }
  catch (const std::exception &e)
  {
    log(Logging::ERROR) << "Fatal error: " << e.what();
    exit_code = 1;
  }

  // Cleanup
  log(Logging::INFO) << "Daemon exiting with code " << exit_code;

  return exit_code;
}