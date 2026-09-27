// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "AddressCodec.h"

#include "Crypto/Bech32.h"

#include <array>
#include <vector>

namespace Wallet
{
  namespace
  {
    // Map an HRP back to a network, or nullopt if unknown.
    std::optional<Network> networkForHrp(std::string_view hrp) noexcept
    {
      if (hrp == hrpForNetwork(Network::Mainnet))
        return Network::Mainnet;
      if (hrp == hrpForNetwork(Network::Testnet))
        return Network::Testnet;
      if (hrp == hrpForNetwork(Network::Regtest))
        return Network::Regtest;
      return std::nullopt;
    }

    // Build the 33-byte payload: [witness_version, pubkey[32]].
    std::vector<uint8_t> buildPayload(const Crypto::Address &addr)
    {
      std::vector<uint8_t> payload;
      payload.reserve(1 + ADDRESS_PUBKEY_LENGTH);
      payload.push_back(ADDRESS_WITNESS_VERSION);
      payload.insert(payload.end(), addr.data.begin(), addr.data.end());
      return payload;
    }

    // Extract the address from a decoded payload. Returns nullopt if the
    // payload is the wrong length, has the wrong witness version, or
    // decodes to the all-zero pubkey.
    std::optional<Crypto::Address> addressFromPayload(
        const std::vector<uint8_t> &payload)
    {
      if (payload.size() != 1 + ADDRESS_PUBKEY_LENGTH)
        return std::nullopt;
      if (payload[0] != ADDRESS_WITNESS_VERSION)
        return std::nullopt;

      Crypto::Address addr;
      std::copy(payload.begin() + 1, payload.end(), addr.data.begin());

      // Reject the null address explicitly. Nothing on chain ever uses
      // the all-zero pubkey; a bech32m string that decodes to it is
      // almost certainly a copy-paste artifact or a malformed genesis
      // placeholder.
      if (addr.isNull())
        return std::nullopt;

      return addr;
    }
  } // namespace

  std::string encodeAddress(const Crypto::Address &addr, Network network)
  {
    if (addr.isNull())
      return {};

    const std::string_view hrp = hrpForNetwork(network);
    if (hrp.empty())
      return {};

    const std::vector<uint8_t> payload = buildPayload(addr);
    return Crypto::bech32Encode(hrp, payload, Crypto::Bech32Encoding::Bech32m);
  }

  std::optional<Crypto::Address> decodeAddress(std::string_view s,
                                               Network expected_network)
  {
    if (s.empty())
      return std::nullopt;

    std::vector<uint8_t> payload;
    std::string hrp;
    Crypto::Bech32Encoding encoding;

    const Crypto::Bech32Error err =
        Crypto::bech32Decode(s, payload, hrp, encoding);
    if (err != Crypto::Bech32Error::Ok)
      return std::nullopt;

    // Reject legacy Bech32 (segwit v0) addresses for CLRTY. We only
    // ever emit Bech32m.
    if (encoding != Crypto::Bech32Encoding::Bech32m)
      return std::nullopt;

    // The HRP must match the expected network.
    const std::string_view expected_hrp = hrpForNetwork(expected_network);
    if (hrp != expected_hrp)
      return std::nullopt;

    return addressFromPayload(payload);
  }

  std::optional<DecodedAddress> decodeAddressAnyNetwork(std::string_view s)
  {
    if (s.empty())
      return std::nullopt;

    std::vector<uint8_t> payload;
    std::string hrp;
    Crypto::Bech32Encoding encoding;

    const Crypto::Bech32Error err =
        Crypto::bech32Decode(s, payload, hrp, encoding);
    if (err != Crypto::Bech32Error::Ok)
      return std::nullopt;

    if (encoding != Crypto::Bech32Encoding::Bech32m)
      return std::nullopt;

    const auto net = networkForHrp(hrp);
    if (!net)
      return std::nullopt;

    const auto addr = addressFromPayload(payload);
    if (!addr)
      return std::nullopt;

    DecodedAddress result;
    result.address = *addr;
    result.network = *net;
    return result;
  }

  bool isPlausibleAddress(std::string_view s) noexcept
  {
    return decodeAddressAnyNetwork(s).has_value();
  }

} // namespace Wallet