// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <boost/asio.hpp>
#include <gtest/gtest.h>

#include "Tests/Logger.h"
#include "Tests/Fixtures.h"
#include "Tests/Utils.h"

#include "P2P/P2PManager.h"
#include "P2P/Config.h"
#include "P2P/Message.h"
#include "P2P/MessageTypes.h"

using namespace std::chrono_literals;
using namespace P2P;
using namespace Tests;

TEST_F(P2PManagerFixture, StartsAndListens)
{
  uint16_t port = pickFreePort();
  ManagerHarness h(port, "listen");

  boost::asio::io_context io;
  boost::asio::ip::tcp::socket sock(io);
  boost::system::error_code ec;
  sock.connect(boost::asio::ip::tcp::endpoint(
                   boost::asio::ip::address_v4::loopback(), port),
               ec);
  EXPECT_FALSE(ec) << "raw connect failed: " << ec.message();

  boost::system::error_code ignored;
  sock.close(ignored);
}

// =====================================================================
//  2. StopsCleanly
// =====================================================================

TEST_F(P2PManagerFixture, StopsCleanly)
{
  uint16_t port = pickFreePort();
  ManagerHarness h(port, "stop");

  auto done = std::async(std::launch::async, [&h]
                         { h.stop(); });
  EXPECT_EQ(done.wait_for(3s), std::future_status::ready)
      << "stop() did not return within 3s";

  h.stop();
}

// =====================================================================
//  3. TwoManagersHandshake
//
//  A listens, B dials A. Both onPeerConnected callbacks fire, and
//  both peers reach Established. The Established check is the
//  meaningful part: without it, a broken handshake passes silently
//  because onPeerConnected fires at TCP connect time.
// =====================================================================

TEST_F(P2PManagerFixture, TwoManagersHandshake)
{
  uint16_t port_a = pickFreePort();
  ManagerHarness a(port_a, "handshake_a");
  ManagerHarness b(0, "handshake_b");

  b.mgr().post([&b, port_a]
               { b.mgr().connectTo("127.0.0.1", port_a); });

  ASSERT_TRUE(a.waitForConnected(1, kWait))
      << "A never saw a connection";
  ASSERT_TRUE(b.waitForConnected(1, kWait))
      << "B never saw a connection";

  EXPECT_TRUE(a.waitForEstablished(1, kWait))
      << "A's peer never reached Established";
  EXPECT_TRUE(b.waitForEstablished(1, kWait))
      << "B's peer never reached Established";
}

// =====================================================================
//  4. PeerCountReflectsConnections
// =====================================================================

TEST_F(P2PManagerFixture, PeerCountReflectsConnections)
{
  uint16_t port_a = pickFreePort();
  ManagerHarness a(port_a, "count_a");
  ManagerHarness b(0, "count_b");

  b.mgr().post([&b, port_a]
               { b.mgr().connectTo("127.0.0.1", port_a); });

  ASSERT_TRUE(a.waitForConnected(1, kWait));
  ASSERT_TRUE(b.waitForConnected(1, kWait));
  ASSERT_TRUE(a.waitForEstablished(1, kWait));
  ASSERT_TRUE(b.waitForEstablished(1, kWait));

  EXPECT_EQ(a.connectedCount(), 1u);
  EXPECT_EQ(b.connectedCount(), 1u);
  EXPECT_EQ(a.disconnectedCount(), 0u);
  EXPECT_EQ(b.disconnectedCount(), 0u);
}

// =====================================================================
//  5. DisconnectFiresCallback
// =====================================================================

TEST_F(P2PManagerFixture, DisconnectFiresCallback)
{
  uint16_t port_a = pickFreePort();
  ManagerHarness a(port_a, "disc_a");
  ManagerHarness b(0, "disc_b");

  b.mgr().post([&b, port_a]
               { b.mgr().connectTo("127.0.0.1", port_a); });

  ASSERT_TRUE(a.waitForConnected(1, kWait));
  ASSERT_TRUE(b.waitForConnected(1, kWait));
  ASSERT_TRUE(a.waitForEstablished(1, kWait));
  ASSERT_TRUE(b.waitForEstablished(1, kWait));

  a.stop();

  EXPECT_TRUE(b.waitForDisconnected(1, kWait))
      << "B never saw a disconnect after A stopped";
  ASSERT_FALSE(b.disconnects().empty());
  EXPECT_FALSE(b.disconnects().front().second.empty());
}

// =====================================================================
//  6. AcceptLoopRearms
//
//  A listens, B dials, connection established, B stops. A third
//  manager C dials A on the same port. If the accept loop failed to
//  re-arm, C never connects.
// =====================================================================

TEST_F(P2PManagerFixture, AcceptLoopRearms)
{
  uint16_t port_a = pickFreePort();
  ManagerHarness a(port_a, "rearm_a");
  ManagerHarness b(0, "rearm_b");

  b.mgr().post([&b, port_a]
               { b.mgr().connectTo("127.0.0.1", port_a); });

  ASSERT_TRUE(a.waitForConnected(1, kWait));
  ASSERT_TRUE(b.waitForConnected(1, kWait));
  ASSERT_TRUE(a.waitForEstablished(1, kWait));
  ASSERT_TRUE(b.waitForEstablished(1, kWait));

  b.stop();
  ASSERT_TRUE(a.waitForDisconnected(1, kWait));

  ManagerHarness c(0, "rearm_c");
  c.mgr().post([&c, port_a]
               { c.mgr().connectTo("127.0.0.1", port_a); });

  EXPECT_TRUE(a.waitForConnected(2, kWait))
      << "A did not accept a second connection";
  EXPECT_TRUE(c.waitForConnected(1, kWait))
      << "C never connected to A";
  EXPECT_TRUE(a.waitForEstablished(1, kWait))
      << "A's second peer never reached Established";
  EXPECT_TRUE(c.waitForEstablished(1, kWait))
      << "C's peer never reached Established";
}

// =====================================================================
//  7. TwoManagersExchangeMessage
//
//  After the handshake reaches Established, broadcast a Ping from A.
//  B receives it via onMessage. The broadcast path skips non-Established
//  peers, so a broken handshake would make this test fail — which is
//  exactly what we want.
// =====================================================================

TEST_F(P2PManagerFixture, TwoManagersExchangeMessage)
{
  uint16_t port_a = pickFreePort();
  ManagerHarness a(port_a, "msg_a");
  ManagerHarness b(0, "msg_b");

  b.mgr().post([&b, port_a]
               { b.mgr().connectTo("127.0.0.1", port_a); });

  ASSERT_TRUE(a.waitForConnected(1, kWait));
  ASSERT_TRUE(b.waitForConnected(1, kWait));
  ASSERT_TRUE(a.waitForEstablished(1, kWait));

  // Tx is forwarded by Peer::processIncoming to onMessage. Ping is not —
  // Peer::handlePing consumes it internally and only replies with a Pong,
  // so it never reaches P2PManager::onMessage. The test uses Tx because
  // it exercises the same "broadcast after handshake" path without
  // relying on protocol-internal keepalive semantics.
  a.mgr().post([&a]
               { a.mgr().broadcast(Message(MessageType::Tx)); });

  ASSERT_TRUE(b.waitForMessageOfType(MessageType::Tx, 1, kWait))
      << "B never received the Tx broadcast";
}

// =====================================================================
//  8. SelfConnectionIsRejected
//
//  A dials itself. The TCP connection succeeds and onPeerConnected
//  fires, then the Version exchange reveals that the peer's network
//  nonce matches ours. P2PManager::handlePeerMessage closes the
//  peer. Both ends close; the manager's disconnect callback fires.
//
//  Note: with the Version bug fixed, both ends complete enough of
//  the handshake for the nonce to arrive. The check fires from the
//  inbound side's handleVersion → onMessage path, and the outbound
//  side sees the resulting close. Assertions are on the disconnect
//  event, not on timing of which side closes first.
// =====================================================================

TEST_F(P2PManagerFixture, SelfConnectionIsRejected)
{
  uint16_t port = pickFreePort();
  ManagerHarness a(port, "self");

  a.mgr().post([&a, port]
               { a.mgr().connectTo("127.0.0.1", port); });

  // TCP connect completes and onPeerConnected fires. Both a self-dial
  // and a normal dial produce this; the distinction is what happens
  // next.
  EXPECT_TRUE(a.waitForConnected(1, kWait))
      << "self-dial did not even connect at TCP level";

  // The nonce check should close the peer. We wait for the disconnect
  // event with a generous timeout because both ends must complete
  // enough of the handshake to exchange Version messages first.
  EXPECT_TRUE(a.waitForDisconnected(1, kWait))
      << "self-connection was not rejected";
}
