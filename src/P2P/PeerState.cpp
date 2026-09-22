// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PeerState.h"

namespace P2P
{

std::string_view peerStateName(PeerState s) noexcept
{
  switch (s) {
    case PeerState::Connecting:    return "connecting";
    case PeerState::Handshaking:   return "handshaking";
    case PeerState::VerackPending: return "verack-pending";
    case PeerState::Established:   return "established";
    case PeerState::Disconnecting: return "disconnecting";
    case PeerState::Closed:        return "closed";
  }
  return "unknown";
}

} // namespace P2P