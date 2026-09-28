#pragma once

#include <gtest/gtest.h>

#include "Utils.h"

namespace Tests
{
  class P2P_ManagerFixture : public testing::Test
  {
  protected:
    static constexpr auto kWait = 2000ms;

    static bool canBindLoopback()
    {
      try
      {
        boost::asio::io_context io;
        boost::asio::ip::tcp::acceptor acc(
            io, boost::asio::ip::tcp::endpoint(
                    boost::asio::ip::tcp::v4(), 0));
        return acc.is_open();
      }
      catch (...)
      {
        return false;
      }
    }

    void SetUp() override
    {
      if (!canBindLoopback())
        GTEST_SKIP() << "loopback sockets unavailable in this environment";
    }
  };
}