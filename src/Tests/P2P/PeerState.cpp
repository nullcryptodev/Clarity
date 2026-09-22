// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "P2P/PeerState.h"

using namespace P2P;

TEST(PeerState, Names)
{
  EXPECT_EQ(peerStateName(PeerState::Connecting), "connecting");
  EXPECT_EQ(peerStateName(PeerState::Handshaking), "handshaking");
  EXPECT_EQ(peerStateName(PeerState::VerackPending), "verack-pending");
  EXPECT_EQ(peerStateName(PeerState::Established), "established");
  EXPECT_EQ(peerStateName(PeerState::Disconnecting), "disconnecting");
  EXPECT_EQ(peerStateName(PeerState::Closed), "closed");
}

TEST(PeerState, IsOperational)
{
  EXPECT_FALSE(isOperational(PeerState::Connecting));
  EXPECT_FALSE(isOperational(PeerState::Handshaking));
  EXPECT_FALSE(isOperational(PeerState::VerackPending));
  EXPECT_TRUE(isOperational(PeerState::Established));
  EXPECT_FALSE(isOperational(PeerState::Disconnecting));
  EXPECT_FALSE(isOperational(PeerState::Closed));
}

TEST(PeerState, IsTerminal)
{
  EXPECT_FALSE(isTerminal(PeerState::Connecting));
  // ============================================================================
  EXPECT_FALSE(isTerminal(PeerState::Handshaking));
  EXPECT_FALSE(isTerminal(PeerState::VerackPending));
  EXPECT_FALSE(isTerminal(PeerState::Established));
  EXPECT_FALSE(isTerminal(PeerState::Disconnecting));
  EXPECT_TRUE(isTerminal(PeerState::Closed));
}