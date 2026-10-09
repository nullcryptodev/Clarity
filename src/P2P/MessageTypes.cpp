// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "MessageTypes.h"

namespace P2P
{
  std::string_view messageTypeName(MessageType t) noexcept
  {
    switch (t)
    {
    case MessageType::Version:
      return "version";
    case MessageType::Verack:
      return "verack";
    case MessageType::Ping:
      return "ping";
    case MessageType::Pong:
      return "pong";
    case MessageType::GetPeers:
      return "getpeers";
    case MessageType::Peers:
      return "peers";
    case MessageType::Auth:
      return "Auth";
    case MessageType::AuthReady:
      return "authready";
    case MessageType::GetHeaders:
      return "getheaders";
    case MessageType::Headers:
      return "headers";
    case MessageType::GetBlocks:
      return "getblocks";
    case MessageType::Blocks:
      return "blocks";
    case MessageType::GetProof:
      return "getproof";
    case MessageType::Proof:
      return "proof";
    case MessageType::Inv:
      return "inv";
    case MessageType::GetData:
      return "getdata";
    case MessageType::Tx:
      return "tx";
    case MessageType::Block:
      return "block";
    case MessageType::Proposal:
      return "proposal";
    case MessageType::Prevote:
      return "prevote";
    case MessageType::Precommit:
      return "precommit";
    case MessageType::Disconnect:
      return "disconnect";
    }
    return "unknown";
  }

  uint32_t messageCost(MessageType t) noexcept
  {
    // Costs reflect the work the *receiver* does per message, relative
    // to a cheap control message. Cheap-to-send, expensive-to-serve
    // types are charged more. Consensus types are not listed — they're
    // charged only to the consensus bucket, which is checked separately.
    switch (t)
    {
    case MessageType::GetHeaders:
      return 20; // server loops up to MAX_HEADERS_PER_REQUEST (2000) getHashByHeight calls

    case MessageType::GetBlocks:
      return 20; // server loops up to MAX_BLOCKS_PER_REQUEST (128) getBlock calls, each deserializing

    case MessageType::GetProof:
      // Server walks up to 256 SMT levels, reading nodes from disk,
      // then serializes ~9 KB of proof. Same order of work as
      // GetHeaders, plus a Blake2b chain over every sibling.
      return 50;

    case MessageType::Blocks:
      return 10; // we deserialize up to 128 blocks

    case MessageType::Proof:
      // We deserialize a ~9 KB proof and re-verify it (256 Blake2b
      // hashes). Cheaper than serving one, but not cheap enough to
      // treat as a control message.
      return 5;

    case MessageType::Block:
      return 10; // we deserialize + apply one block, then re-broadcast

    case MessageType::Tx:
      return 5; // mempool add does signature verify + state view; re-broadcast to N peers

    case MessageType::Headers:
      return 1; // small, parsed cheaply

    case MessageType::Proposal:
    case MessageType::Prevote:
    case MessageType::Precommit:
      // Consensus types are not charged to this bucket; the consensus
      // bucket handles them. Return 1 as a defensive default.
      return 1;

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

    default:
      return 1;
    }
  }
} // namespace P2P