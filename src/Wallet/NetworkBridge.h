// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include "WalletTypes.h"

// Forward-declare the Node network enum. The full definition lives in
// Node/NodeConfig.h. We only need the underlying type here so the
// conversion functions can be declared without pulling Node into
// every wallet translation unit.
//
// The two enums must have identical numeric values. This is a soft
// contract enforced by the tests, not by the compiler.

namespace Node
{
  enum class Network : uint8_t;
}

namespace Wallet
{
  // Convert between Wallet::Network and Node::Network. These are the
  // only two functions in the entire wallet module that reference the
  // Node network type. Everything else uses Wallet::Network.

  Network networkFromNode(Node::Network n) noexcept;
  Node::Network networkToNode(Network n) noexcept;

} // namespace Wallet