// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "MessageTypes.h"

namespace P2P
{

std::string_view messageTypeName(MessageType t) noexcept
{
  switch (t) {
    case MessageType::Version:    return "version";
    case MessageType::Verack:     return "verack";
    case MessageType::Ping:       return "ping";
    case MessageType::Pong:       return "pong";
    case MessageType::GetPeers:   return "getpeers";
    case MessageType::Peers:      return "peers";
    case MessageType::GetHeaders: return "getheaders";
    case MessageType::Headers:    return "headers";
    case MessageType::GetBlocks:  return "getblocks";
    case MessageType::Blocks:     return "blocks";
    case MessageType::Inv:        return "inv";
    case MessageType::GetData:    return "getdata";
    case MessageType::Tx:         return "tx";
    case MessageType::Block:      return "block";
    case MessageType::Proposal:   return "proposal";
    case MessageType::Prevote:    return "prevote";
    case MessageType::Precommit:  return "precommit";
    case MessageType::Disconnect: return "disconnect";
  }
  return "unknown";
}

} // namespace P2P