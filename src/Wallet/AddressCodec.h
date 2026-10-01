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
  //  Bech32m address encoding and decoding. See WalletTypes.h for the
  //  HRP constants and the constexpr hrpForNetwork() lookup.

  //  ---- HRP -> Network ----
  //
  //  The reverse of hrpForNetwork. Returns std::nullopt if the HRP
  //  is not one of the three CLRTY network HRPs. Case-sensitive;
  //  bech32m requires lowercase, and callers should pass lowercase.
  std::optional<Network> networkForHrp(std::string_view hrp) noexcept;

  //  ---- Encoding ----

  //  Encode with the HRP for the given network.
  std::string encodeAddress(const Crypto::Address &addr, Network network);

  //  Encode with a caller-supplied HRP. Does not validate the HRP
  //  against the known networks. Empty HRP or null address returns
  //  an empty string.
  //
  //  This exists for callers that already have an HRP string and
  //  would otherwise have to reverse-map it to a Network.
  std::string encodeAddress(const Crypto::Address &addr,
                            std::string_view hrp);

  //  ---- Decoding ----

  std::optional<Crypto::Address> decodeAddress(std::string_view s,
                                               Network expected_network);

  struct DecodedAddress
  {
    Crypto::Address address;
    Network network{Network::Mainnet};
  };

  std::optional<DecodedAddress> decodeAddressAnyNetwork(std::string_view s);

  bool isPlausibleAddress(std::string_view s) noexcept;

} // namespace Wallet