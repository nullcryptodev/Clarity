// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>

namespace P2P
{
  struct PeerStats
  {
    // Traffic
    uint64_t bytesSent = 0;
    uint64_t bytesRecv = 0;
    uint64_t messagesSent = 0;
    uint64_t messagesRecv = 0;

    // Misbehavior
    uint32_t misbehaviors = 0;
    uint32_t lastBanReason = 0;

    // Timing (unix seconds)
    int64_t connectedAt = 0;
    int64_t lastMessageAt = 0;
    int64_t lastPingAt = 0;
    int64_t lastPongAt = 0;

    // Identity (from version message)
    uint32_t peerProtocol = 0;
    uint64_t peerBestHeight = 0;
    uint64_t peerNonce = 0;

    // Chain state
    int64_t pingTimeMs = 0;
  };

} // namespace P2P