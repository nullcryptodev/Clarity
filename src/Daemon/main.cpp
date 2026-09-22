// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "Args.h"

#include "Logging/ConsoleLogger.h"
#include "Logging/FileLogger.h"
#include "Node/Node.h"

#include <atomic>
#include <csignal>
#include <cstdio>
#include <exception>
#include <memory>

namespace
{
  std::atomic<bool> g_shutdown_requested{false};
  Node::Node *g_node{nullptr};

  extern "C" void handleSignal(int /*sig*/)
  {
    g_shutdown_requested.store(true);
    if (g_node)
    {
      g_node->stop();
    }
  }

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
  // ---- Parse arguments ----
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

  // ---- Validate node config ----
  try
  {
    Node::validateConfig(args.node);
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

  // ---- Set up logging ----
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

  // ---- Banner ----
  Logging::LoggerRef log(*logger, "Daemon");
  log(Logging::INFO) << "=================================================";
  log(Logging::INFO) << "  Clarity daemon starting";
  log(Logging::INFO) << "  network:  " << Node::networkName(args.node.network);
  log(Logging::INFO) << "  data dir: " << args.node.data_dir;
  log(Logging::INFO) << "=================================================";

  // ---- Install signal handlers ----
  std::signal(SIGINT, handleSignal);
  std::signal(SIGTERM, handleSignal);

  // ---- Construct and run the node ----
  int exit_code = 0;

  try
  {
    Node::Node node(args.node, *logger);
    g_node = &node;

    node.start();

    // If a signal arrived during startup, don't bother running.
    if (g_shutdown_requested.load())
    {
      log(Logging::WARNING) << "Shutdown requested during startup";
      node.stop();
      g_node = nullptr;
      return 0;
    }

    log(Logging::INFO) << "Node is running. Press Ctrl+C to stop.";

    // Block until stopped. Node::run() returns when stop() is called.
    node.run();

    log(Logging::INFO) << "Node stopped cleanly.";
  }
  catch (const std::exception &e)
  {
    log(Logging::ERROR) << "Fatal error: " << e.what();
    exit_code = 1;
  }

  g_node = nullptr;

  // ---- Cleanup ----
  log(Logging::INFO) << "Daemon exiting with code " << exit_code;

  return exit_code;
}