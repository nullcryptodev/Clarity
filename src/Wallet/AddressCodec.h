// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "Crypto/Types.h"
#include "WalletTypes.h"

namespace Wallet
{
  //  AddressCodec
  //
  //  Translates between the on-chain representation of an account
  //  (Crypto::Address, a 32-byte Ed25519 public key) and the
  //  human-readable bech32m string form.
  //
  //  The on-chain representation is unchanged. SMT keys, transaction
  //  from/to fields, and P2P messages all continue to use the raw
  //  32-byte pubkey. Bech32m is a presentation-layer encoding used by:
  //    - CLI output and input
  //    - GUI display
  //    - QR codes
  //    - Hardware wallet screens
  //
  //  Encoding is:  bech32m(HRP(network), 0x00 || pubkey_32_bytes)
  //  where 0x00 is the witness version (see ADDRESS_WITNESS_VERSION).
  //  The HRP is sourced from GlobalConfig, one per network.
  //
  //  This module never changes a signature. The witness version byte
  //  is part of the encoded string only; it is not prepended to the
  //  32-byte pubkey when the address is used on chain.

  // Encode a 32-byte address as a bech32m string for the given network.
  //
  // Returns an empty string on failure. Failure cases:
  //   - addr.isNull()
  //   - network is not recognized
  //   - the resulting string would exceed the bech32m length limit
  //     (never in practice for a 32-byte payload, but checked anyway)
  std::string encodeAddress(const Crypto::Address &addr, Network network);

  // Decode a bech32m address string for a specific network.
  //
  // Returns std::nullopt on any error:
  //   - the string is malformed (bad checksum, mixed case, etc.)
  //   - the HRP does not match the expected network
  //   - the payload is not exactly 33 bytes (1 witness + 32 pubkey)
  //   - the witness version is not ADDRESS_WITNESS_VERSION
  //   - the resulting pubkey is all zeros (null address)
  //
  // To accept an address without knowing the network in advance, use
  // decodeAddressAnyNetwork below.
  std::optional<Crypto::Address> decodeAddress(std::string_view s,
                                               Network expected_network);

  // Decode a bech32m address string without a network hint. Returns the
  // detected network along with the address. Useful for "paste an
  // address" UIs that need to report a mismatch.
  struct DecodedAddress
  {
    Crypto::Address address{};
    Network network{Network::Mainnet};
  };

  std::optional<DecodedAddress> decodeAddressAnyNetwork(std::string_view s);

  // Return true if `s` is a syntactically valid CLRTY address on any
  // known network. Does not check whether the address exists on chain.
  bool isPlausibleAddress(std::string_view s) noexcept;

} // namespace Wallet