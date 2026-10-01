// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <thread>

#include "Fixtures.h"
#include "Tests/Utils.h"

#include "Node/Node.h"
#include "RPC/Config.h"
#include "RPC/HttpServer.h"
#include "RPC/JsonRpcDispatcher.h"

using namespace Tests;

namespace
{
  // Send one HTTP request and return the status line.
  //
  // Uses a fresh TCP connection per request so the test can't
  // accidentally benefit from keep-alive or per-connection state.
  std::string sendOne(uint16_t port, const std::string &body)
  {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
      return "";

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (::connect(fd, reinterpret_cast<sockaddr *>(&addr),
                  sizeof(addr)) < 0)
    {
      ::close(fd);
      return "";
    }

    std::string req = body;
    ::send(fd, req.data(), req.size(), MSG_NOSIGNAL);

    char buf[512] = {0};
    ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
    ::close(fd);
    if (n <= 0)
      return "";

    std::string resp(buf, static_cast<size_t>(n));
    auto nl = resp.find("\r\n");
    return nl == std::string::npos ? resp : resp.substr(0, nl);
  }

  std::string pingRequest()
  {
    const std::string body =
        R"({"jsonrpc":"2.0","id":1,"method":"ping"})";
    return "POST / HTTP/1.1\r\n"
           "Host: 127.0.0.1\r\n"
           "Content-Type: application/json\r\n"
           "Content-Length: " +
           std::to_string(body.size()) + "\r\n"
                                         "Connection: close\r\n"
                                         "\r\n" +
           body;
  }
} // anonymous namespace

TEST(RPC_RpcRateLimit, DisabledByDefaultNoLimit)
{
  Node::NodeConfig ncfg = makeTestNodeConfig("/tmp/clrty_ratelimit_disabled");
  NoopLogger logger;
  Node::Node node(ncfg, logger);

  Rpc::RpcConfig cfg = makeTestRpcConfig();
  cfg.rate_limit_burst = 0;
  cfg.rate_limit_per_second = 0;

  Rpc::JsonRpcDispatcher dispatcher(node, cfg);
  Rpc::HttpServer server(cfg, dispatcher, logger);
  server.start();

  // Twenty requests in a row should all succeed.
  for (int i = 0; i < 20; ++i)
  {
    std::string status = sendOne(server.listeningPort(), pingRequest());
    EXPECT_EQ(status.substr(0, 7), "HTTP/1.") << "request " << i;
    EXPECT_NE(status.find("200"), std::string::npos)
        << "request " << i << " got: " << status;
  }

  server.stop();
}

TEST(RPC_RpcRateLimit, ExhaustedBurstReturns429)
{
  Node::NodeConfig ncfg = makeTestNodeConfig("/tmp/clrty_ratelimit_burst");
  NoopLogger logger;
  Node::Node node(ncfg, logger);

  Rpc::RpcConfig cfg = makeTestRpcConfig();
  cfg.rate_limit_burst = 3;
  cfg.rate_limit_per_second = 1;

  Rpc::JsonRpcDispatcher dispatcher(node, cfg);
  Rpc::HttpServer server(cfg, dispatcher, logger);
  server.start();

  int got_429 = 0;
  int got_200 = 0;
  for (int i = 0; i < 10; ++i)
  {
    std::string status = sendOne(server.listeningPort(), pingRequest());
    if (status.find("429") != std::string::npos)
      ++got_429;
    if (status.find("200") != std::string::npos)
      ++got_200;
  }

  // With burst=3 and no refill in the time it takes to run these,
  // we expect ~3 successes and ~7 rate-limited responses. Give slack
  // because refill is time-based and the box may be fast or slow.
  EXPECT_GE(got_200, 1) << "no successful requests";
  EXPECT_GE(got_429, 1) << "no rate-limited requests";

  server.stop();
}