// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AggregateLimiter.h"

namespace P2P
{
  uint32_t aggregateCost(MessageType t) noexcept
  {
    switch (t)
    {
    // Expensive-to-serve request types. Compressed relative to
    // messageCost(): GetProof is 50 there, 10 here; GetHeaders and
    // GetBlocks are 20 there, 5 here. The compression is deliberate —
    // see AggregateLimiter.h.
    case MessageType::GetProof:
      return 10;
    case MessageType::GetHeaders:
    case MessageType::GetBlocks:
      return 5;

    // Response / relay types. The receiver does real work on these
    // (deserialize, verify, apply, re-broadcast), but the sender
    // already paid the request cost to trigger them.
    case MessageType::Blocks:
    case MessageType::Block:
      return 5;

    case MessageType::Proof:
    case MessageType::Tx:
      return 4;

    // Consensus types. Small messages, but a flood vector from many
    // peers. Charged here (unlike at the per-peer general bucket) so
    // the aggregate budget covers them.
    case MessageType::Proposal:
    case MessageType::Prevote:
    case MessageType::Precommit:
      return 3;

    // Cheap parse, but not free — Headers can carry up to 2000 entries.
    case MessageType::Headers:
      return 2;

    // Control and handshake messages. Charged 1 so a peer cannot use
    // them to refill the bucket faster than it drains.
    case MessageType::Version:
    case MessageType::Verack:
    case MessageType::Ping:
    case MessageType::Pong:
    case MessageType::GetPeers:
    case MessageType::Peers:
    case MessageType::Auth:
    case MessageType::AuthReady:
    case MessageType::Inv:
    case MessageType::GetData:
    case MessageType::Disconnect:
      return 1;
    }

    return 1;
  }
} // namespace P2P