// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <string_view>

namespace P2P
{
  enum class PeerState : uint8_t
  {
    Connecting,
    Handshaking,
    VerackPending,
    Established,
    Disconnecting,
    Closed,
  };

  std::string_view peerStateName(PeerState s) noexcept;

  inline bool isOperational(PeerState s) noexcept
  {
    return s == PeerState::Established;
  }

  inline bool isTerminal(PeerState s) noexcept
  {
    return s == PeerState::Closed;
  }

} // namespace P2P