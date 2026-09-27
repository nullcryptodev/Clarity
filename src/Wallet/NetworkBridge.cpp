// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "NetworkBridge.h"

#include "Node/NodeConfig.h"

#include <cassert>

namespace Wallet
{
  // The two enums must have identical numeric values. Rather than
  // static_assert on enum values (which C++ can't do cleanly across
  // TUs), we use a runtime assertion here. Tests also cover the
  // mapping exhaustively.

  Network networkFromNode(Node::Network n) noexcept
  {
    switch (n)
    {
    case Node::Network::Mainnet:
      return Network::Mainnet;
    case Node::Network::Testnet:
      return Network::Testnet;
    case Node::Network::Regtest:
      return Network::Regtest;
    }
    assert(false && "unhandled Node::Network");
    return Network::Mainnet;
  }

  Node::Network networkToNode(Network n) noexcept
  {
    switch (n)
    {
    case Network::Mainnet:
      return Node::Network::Mainnet;
    case Network::Testnet:
      return Node::Network::Testnet;
    case Network::Regtest:
      return Node::Network::Regtest;
    }
    assert(false && "unhandled Wallet::Network");
    return Node::Network::Mainnet;
  }

} // namespace Wallet