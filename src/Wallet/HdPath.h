// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "WalletError.h"
#include "WalletTypes.h"

namespace Wallet
{
  //  HdPath — BIP-32/BIP-44/SLIP-0010 derivation path
  //
  //  A path is a sequence of 32-bit child indices, each optionally
  //  hardened. The textual form is:
  //
  //    m / 44' / 9000' / 0' / 0' / 0'
  //
  //  with ' or h marking hardened. The leading 'm' is required in
  //  canonical form. Whitespace is not permitted.
  //
  //  For CLRTY, we use five-level paths:
  //
  //    m / 44' / 9000' / account' / change' / index'
  //
  //  All components hardened. SLIP-0010 for Ed25519 requires
  //  hardened-only derivation; there is no non-hardened variant
  //  because Ed25519 has no public-key tweak operation.
  //
  //  Depth limit: BIP-32 caps at 255, but our five-level convention
  //  means paths beyond that are absurd. We cap at 16 to catch typos.

  inline constexpr uint32_t HARDENED_BIT = 0x80000000u;
  inline constexpr uint32_t MAX_INDEX = 0x7FFFFFFFu; // before hardening
  inline constexpr size_t MAX_PATH_LENGTH = 16;
  inline constexpr size_t CLRTY_PATH_LENGTH = 5; // m/44'/coin'/acct'/chg'/idx'

  // A single path component.
  struct PathElement
  {
    uint32_t index{0}; // raw index (without the hardened bit)
    bool hardened{false};

    // The 32-bit value that goes to the derivation function.
    uint32_t raw() const noexcept
    {
      return hardened ? (index | HARDENED_BIT) : index;
    }
  };

  // A full path.
  struct HdPath
  {
    std::array<PathElement, MAX_PATH_LENGTH> elements{};
    size_t length{0}; // number of valid entries in `elements`

    bool empty() const noexcept { return length == 0; }

    // Canonical string form, e.g. "m/44'/9000'/0'/0'/0'".
    // Returns "" if the path is malformed (should never happen for
    // a path constructed by this module).
    std::string toString() const;

    // Equality: same length, same elements in order.
    bool operator==(const HdPath &o) const noexcept;
    bool operator!=(const HdPath &o) const noexcept { return !(*this == o); }

    // Convenience: append a child element. Returns false if the path
    // is already at MAX_PATH_LENGTH.
    bool push(uint32_t index, bool hardened) noexcept;
  };

  //  Parsing
  //
  //  Parse a path from its textual form.
  //
  //  Accepts:
  //    - leading 'm' or 'M' (required in canonical form)
  //    - path separator '/'
  //    - hardened marker: either ' (apostrophe) or h/H
  //    - decimal indices, 0..2^31 - 1 (before hardening)
  //
  //  Rejects:
  //    - empty strings, whitespace
  //    - missing leading 'm'
  //    - empty components ("m//44'")
  //    - indices > 2^31 - 1
  //    - more than MAX_PATH_LENGTH components
  //    - trailing '/' or trailing hardened marker
  //
  //  On failure, returns std::nullopt and (if `error_out` is non-null)
  //  fills it with a WalletError code and human-readable detail.
  std::optional<HdPath> parseHdPath(std::string_view s,
                                    WalletStatus *error_out = nullptr);

  //  Construction helpers
  //
  //  The canonical CLRTY path for a given (account, change, index).
  //
  //    defaultPath(0, 0, 0) = m/44'/9000'/0'/0'/0'
  //
  //  All components hardened.
  HdPath clrtyPath(uint32_t account,
                   uint32_t change,
                   uint32_t index);

  //  The three network-agnostic components for a "receive" address
  //  at a given account and index. Same as clrtyPath(account, 0, index).
  inline HdPath receivePath(uint32_t account, uint32_t index)
  {
    return clrtyPath(account, 0, index);
  }

  //  The "change" variant. Same as clrtyPath(account, 1, index).
  inline HdPath changePath(uint32_t account, uint32_t index)
  {
    return clrtyPath(account, 1, index);
  }

  //  The validator consensus key path.
  //
  //  Derives a distinct Ed25519 keypair used for signing consensus
  //  messages. Same mnemonic as the receive address, different
  //  branch. One validator key per account.
  //
  //  By convention, the validator key lives at index 0 of the
  //  validator chain. Multiple validator keys per account would be
  //  unusual; if you ever need them, use increasing indices.
  inline HdPath validatorPath(uint32_t account, uint32_t index = 0)
  {
    return clrtyPath(account, HD_VALIDATOR_CHAIN, index);
  }

} // namespace Wallet