// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "Crypto/Types.h"

namespace State
{
  //  Proof key descriptors.
  //
  //  A light client does not know how SMT keys are derived — it knows
  //  addresses and ids. A proof request carries a typed descriptor,
  //  and the server resolves it to the same 32-byte SMT key the
  //  current-version getters use. This is what makes light-client
  //  support possible without shipping the key derivation code to the
  //  client.
  //
  //  Key byte layouts, one per type:
  //
  //    Account:       32-byte address
  //    TokenBalance:  32-byte address || 4-byte token id (LE)
  //    Validator:     8-byte validator id (LE)
  //    Global:        UTF-8 name, max 64 bytes, not null-terminated
  //    AmmPool:       8-byte pool id (LE)
  //
  //  This lives in State rather than P2P because the resolution is a
  //  state-layer concern — it calls the same Keys::* functions the
  //  current-version getters use. Both the P2P proof protocol and the
  //  RPC getProof method consume it; neither should depend on the
  //  other to reach it.

  enum class ProofKeyType : uint8_t
  {
    Account = 0,
    TokenBalance = 1,
    Validator = 2,
    Global = 3,
    AmmPool = 4,
  };

  //  Sentinel for "the version the server considers current". Chosen
  //  as UINT64_MAX so it cannot collide with any real version: heights
  //  are uint64_t but a chain never reaches 2^64 blocks, and version
  //  0 means "genesis root", which the chain does use.
  inline constexpr uint64_t PROOF_VERSION_CURRENT = UINT64_MAX;

  //  Resolve a (key_type, key_bytes) pair to the SMT key the same
  //  current-version getters use. Returns nullopt when key_bytes does
  //  not match the layout its key_type requires.
  //
  //  This is the client/server contract: both sides agree on the
  //  layouts documented on ProofKeyType, and the server resolves them
  //  via the same Keys::* functions the state layer uses.
  std::optional<Crypto::Hash> resolveProofKey(
      ProofKeyType type, const std::vector<uint8_t> &key_bytes);

} // namespace State