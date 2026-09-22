// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string_view>

#include "GlobalConfig.h"

namespace P2P
{
  // ---- Protocol constants ----

  inline constexpr uint32_t MAGIC_MAINNET = 0x54524C43; // 'CLRT' little-endian
  inline constexpr uint32_t MAGIC_TESTNET = 0x54544C43; // 'CLTT'
  inline constexpr uint32_t MAGIC_REGTEST = 0x47524C43; // 'CLRG'

  inline constexpr uint32_t MAX_MESSAGE_SIZE = 16 * 1024 * 1024; // 16 MiB

  // ---- Message types ----

  enum class MessageType : uint16_t
  {
    // Control
    Version = 0x0001,
    Verack = 0x0002,
    Ping = 0x0003,
    Pong = 0x0004,
    GetPeers = 0x0005,
    Peers = 0x0006,

    // Chain sync
    GetHeaders = 0x0010,
    Headers = 0x0011,
    GetBlocks = 0x0012,
    Blocks = 0x0013,

    // Transaction relay
    Inv = 0x0020,
    GetData = 0x0021,
    Tx = 0x0022,
    Block = 0x0023,

    // Consensus (BFT)
    Proposal = 0x0040,
    Prevote = 0x0041,
    Precommit = 0x0042,

    // Shutdown
    Disconnect = 0x00FF,
  };

  std::string_view messageTypeName(MessageType t) noexcept;

  // Helper to get the correct magic for a network.
  inline uint32_t magicForNetwork(int network)
  {
    switch (network)
    {
    case 0:
      return MAGIC_MAINNET;
    case 1:
      return MAGIC_TESTNET;
    case 2:
      return MAGIC_REGTEST;
    default:
      return MAGIC_REGTEST;
    }
  }
  
  // ---- Ban reasons (informational) ----

  enum class BanReason : uint8_t
  {
    None = 0,
    BadMagic,
    BadProtocolVersion,
    BadMessage,
    OversizeMessage,
    HandshakeTimeout,
    PingTimeout,
    SelfConnection,
    DuplicateConnection,
    InvalidSignature,
    InvalidBlock,
    Spam,
    Other,
  };

} // namespace P2P