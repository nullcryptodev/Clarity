// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "MessageTypes.h"

namespace P2P
{
  // Configuration for the entire P2P layer.
  // Set once at construction; treated as immutable afterwards.
  struct P2PConfig
  {
    // ---- Network identity ----
    uint32_t magic = MAGIC_MAINNET;
    std::string agentString = GlobalConfig::PROJECT_AGENT_STRING;
    Version protocolVersion = GlobalConfig::CURRENT_PROTOCOL_VERSION;

    // ---- Listening ----
    uint16_t listenPort = 0; // 0 = don't listen
    bool listenOnIPv6 = false;

    // ---- Peer limits ----
    size_t maxInbound = 64;
    size_t maxOutbound = 16;
    size_t maxPeers = 128;
    size_t targetOutbound = 8;

    // ---- Resource limits ----
    size_t maxSendQueueBytes = 4 * 1024 * 1024; // per peer
    size_t maxRecvBufferBytes = 1024 * 1024;    // per peer
    uint32_t maxMessageSize = MAX_MESSAGE_SIZE;

    // ---- Timeouts ----
    uint32_t connectTimeoutMs = 10'000;
    uint32_t handshakeTimeoutMs = 10'000;
    uint32_t pingIntervalMs = 30'000;
    uint32_t pongTimeoutMs = 90'000;
    uint32_t idleTimeoutMs = 180'000;

    // ---- Misbehavior ----
    uint32_t banThreshold = 100;
    uint32_t banDurationSec = 24 * 60 * 60;

    // ---- Worker pool ----
    size_t workerThreads = 1; // 0 = hardware_concurrency - 1 (aka max threads)

    // ---- Bootstrap ----
    uint16_t defaultPort = 19444;
    std::vector<std::string> dnsSeeds;
  };

} // namespace P2P