// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <cstdint>
#include <optional>

#include "Crypto/Types.h"
#include "HdPath.h"
#include "WalletError.h"

namespace Wallet
{
  //  SLIP-0010 — Hierarchical Deterministic Keys for Ed25519
  //
  //  BIP-32 was designed for secp256k1. Its derivation uses point
  //  arithmetic on the curve to enable "watch-only" extended public
  //  keys (xpub). Ed25519 has no such operation, so SLIP-0010
  //  specifies a separate scheme.
  //
  //  SLIP-0010 for Ed25519 uses hardened-only derivation. Non-hardened
  //  derivation is mathematically impossible because there is no
  //  public-key tweak operation. Every component in a CLRTY path is
  //  therefore hardened (see clrtyPath()).
  //
  //  The scheme is:
  //
  //    Master:
  //      I  = HMAC-SHA512(key="ed25519 seed", data=seed)
  //      IL = I[0:32]   <- the master secret key seed
  //      IR = I[32:64]  <- the chain code
  //
  //    Child (hardened only):
  //      I  = HMAC-SHA512(key=IR, data=0x00 || IL || index_be32)
  //      IL' = I[0:32]
  //      IR' = I[32:64]
  //
  //  The public key corresponding to IL is derived via Ed25519's
  //  standard "seed -> keypair" path: Crypto::derivePublicKey(IL).
  //
  //  We do not implement the extended key serialization from BIP-32
  //  (xprv/xpub). SLIP-0010 defines the format, but for a single-chain
  //  wallet with hardened-only paths, the seed plus the path is
  //  sufficient. If you ever want to export extended keys for
  //  interoperability, that's a separate addition.

  //  Extended key node
  //
  //  Holds one level of the HD tree. The 32-byte secret is the "IL"
  //  from the derivation formula. The 32-byte chain code is "IR".
  //  The depth is a diagnostic; the child number records which child
  //  index produced this node (raw, including the hardened bit).

  struct Slip10Node
  {
    Crypto::SecretKey secret{}; // IL — the key seed at this node
    Crypto::Hash chain_code{};  // IR — used as HMAC key for children
    uint32_t depth{0};
    uint32_t child_number{0}; // raw (index | hardened bit)

    bool isNull() const noexcept
    {
      return secret.isNull() && chain_code.isNull();
    }
  };

  //  Master node from a seed.
  //
  //  `seed` must be 16-64 bytes per SLIP-0010. BIP-39's PBKDF2
  //  produces 64 bytes; that is the intended input.
  //
  //  Returns std::nullopt on failure (seed length out of range,
  //  HMAC failure — neither is expected in practice).
  std::optional<Slip10Node> slip10Master(const uint8_t *seed,
                                         size_t seed_len,
                                         WalletStatus *error_out = nullptr);

  inline std::optional<Slip10Node> slip10Master(
      const std::vector<uint8_t> &seed,
      WalletStatus *error_out = nullptr)
  {
    return slip10Master(seed.data(), seed.size(), error_out);
  }

  //  Derive one child. The component must be hardened; non-hardened
  //  derivation is rejected with WalletError::InvalidPath.
  //
  //  Returns std::nullopt on failure.
  std::optional<Slip10Node> slip10DeriveChild(const Slip10Node &parent,
                                              const PathElement &element,
                                              WalletStatus *error_out = nullptr);

  //  Derive a full path from a master node.
  //
  //  All components in the path must be hardened. Paths constructed
  //  via clrtyPath() satisfy this automatically; a hand-parsed path
  //  with a non-hardened component will fail on the first such
  //  component.
  //
  //  Returns std::nullopt on the first failure.
  std::optional<Slip10Node> slip10DerivePath(const Slip10Node &master,
                                             const HdPath &path,
                                             WalletStatus *error_out = nullptr);

  //  Convenience: derive the public key at a given node.
  //
  //  This is just Crypto::derivePublicKey(node.secret). Exposed here
  //  so callers don't need to include Crypto/Ed25519.h.
  Crypto::PublicKey slip10PublicKey(const Slip10Node &node) noexcept;

  //  Zero a node's secret material. Call this after deriving and
  //  using a child node if you're not going to keep it around.
  void wipeNode(Slip10Node &node) noexcept;

} // namespace Wallet