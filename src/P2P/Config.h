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

    // ---- Rate limiting ----
    //
    // Per-peer token buckets. Both zero in a pair = that bucket is
    // disabled. Mirrors the RPC config convention; the validator in
    // P2PConfig (if/when one is added) should enforce
    // burst >= refillPerSecond when either is non-zero.
    //
    // msgBucket_       — all inbound messages, consumed in
    //                    Peer::handleReadHeader before the body read.
    // consensusBucket_ — Proposal/Prevote/Precommit only, consumed
    //                    after the body read. Stricter than msgBucket_
    //                    because a non-validator flooding consensus
    //                    traffic is almost always malicious.
    uint32_t rateLimitBurst = 200;
    uint32_t rateLimitPerSecond = 50;

    uint32_t consensusRateLimitBurst = 50;
    uint32_t consensusRateLimitPerSecond = 10;

    // Node-wide aggregate token bucket. Bounds the total inbound work
    // across all peers, so a crowd of individually-polite peers cannot
    // collectively saturate the io_context thread. Charged in
    // Peer::handleReadHeader, at the same point as the per-peer
    // general bucket, using the separate aggregate cost table in
    // AggregateLimiter.cpp.
    //
    // Same disable convention: both zero = disabled. The aggregate
    // budget should be larger than any single peer's (it covers the
    // whole peer set); a reasonable default is roughly
    // maxInbound * rateLimitPerSecond / 4, rounded to taste.
    //
    // A trip here closes the offending connection but does NOT report
    // misbehavior and does NOT ban. A shared-NAT peer can trip the
    // aggregate budget through no fault of its own; per-peer trips
    // still ban, this one only sheds.
    uint32_t aggregateRateLimitBurst = 2500;
    uint32_t aggregateRateLimitPerSecond = 800;

    // ---- Session encryption ----
    //
    // Upper bound on the inbound per-direction nonce counter. A peer
    // that sends more than this many messages on a single session is
    // either broken or attacking; the connection is torn down before
    // the counter can wrap. 2^32 is far beyond any legitimate session
    // length (at 1M messages/sec, ~71 minutes of continuous traffic).
    uint64_t maxInboundNonce = 1ULL << 32;

    // ---- Worker pool ----
    size_t workerThreads = 1; // 0 = hardware_concurrency - 1 (aka max threads)

    // ---- Bootstrap ----
    uint16_t defaultPort = 19444;
    std::vector<std::string> dnsSeeds;
  };

} // namespace P2P