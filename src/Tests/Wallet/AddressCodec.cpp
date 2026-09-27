// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Bech32.h"
#include "Wallet/AddressCodec.h"
#include "Wallet/WalletTypes.h"

using namespace Crypto;
using namespace Wallet;

//  AddressCodec test suite.
//
//  Address encoding is:
//    bech32m(HRP(network), 0x00 || pubkey_32_bytes)
//
//  HRP per network:
//    mainnet -> "clrty"
//    testnet -> "tclrty"
//    regtest -> "rclrty"
//
//  No external vectors needed: the format is defined by this code.

namespace
{
  // Build a deterministic 32-byte public key from a seed byte.
  // Uses a simple LCG so the keys are reproducible and distinct.
  Crypto::Address makePubkey(uint8_t seed)
  {
    Crypto::Address addr;
    uint32_t state = uint32_t(seed) * 0x9E3779B9u + 1u;
    for (size_t i = 0; i < 32; ++i)
    {
      state = state * 1103515245u + 12345u;
      addr.data[i] = uint8_t(state >> 16);
    }
    // Ensure the address is not all zeros (which would be rejected).
    if (addr.isNull())
      addr.data[0] = 0x01;
    return addr;
  }
} // namespace

//  HRP mapping

TEST(Wallet_AddressCodec, HrpForNetwork)
{
  EXPECT_EQ(hrpForNetwork(Network::Mainnet), "clrty");
  EXPECT_EQ(hrpForNetwork(Network::Testnet), "tclrty");
  EXPECT_EQ(hrpForNetwork(Network::Regtest), "rclrty");
}

//  Encode — structural properties

TEST(Wallet_AddressCodec, EncodeStartsWithHrp)
{
  const auto pk = makePubkey(1);

  const std::string mainnet = encodeAddress(pk, Network::Mainnet);
  ASSERT_FALSE(mainnet.empty());
  EXPECT_EQ(mainnet.substr(0, 6), "clrty1");

  const std::string testnet = encodeAddress(pk, Network::Testnet);
  ASSERT_FALSE(testnet.empty());
  EXPECT_EQ(testnet.substr(0, 7), "tclrty1");

  const std::string regtest = encodeAddress(pk, Network::Regtest);
  ASSERT_FALSE(regtest.empty());
  EXPECT_EQ(regtest.substr(0, 7), "rclrty1");
}

TEST(Wallet_AddressCodec, EncodeLength)
{
  const auto pk = makePubkey(1);

  // 33-byte payload → 53 5-bit chars + 6 checksum = 59 data chars.
  // Plus HRP + '1' separator.
  EXPECT_EQ(encodeAddress(pk, Network::Mainnet).size(), 65u);
  EXPECT_EQ(encodeAddress(pk, Network::Testnet).size(), 66u);
  EXPECT_EQ(encodeAddress(pk, Network::Regtest).size(), 66u);
}

TEST(Wallet_AddressCodec, EncodeSameKeyDifferentNetworks)
{
  // Same public key, different networks: strings differ in the prefix.
  const auto pk = makePubkey(1);

  const auto m = encodeAddress(pk, Network::Mainnet);
  const auto t = encodeAddress(pk, Network::Testnet);
  const auto r = encodeAddress(pk, Network::Regtest);

  EXPECT_NE(m, t);
  EXPECT_NE(m, r);
  EXPECT_NE(t, r);
}

TEST(Wallet_AddressCodec, EncodeDifferentKeysDiffer)
{
  const auto a = encodeAddress(makePubkey(1), Network::Mainnet);
  const auto b = encodeAddress(makePubkey(2), Network::Mainnet);
  const auto c = encodeAddress(makePubkey(3), Network::Mainnet);

  EXPECT_NE(a, b);
  EXPECT_NE(a, c);
  EXPECT_NE(b, c);
}

TEST(Wallet_AddressCodec, EncodeIsDeterministic)
{
  const auto pk = makePubkey(42);
  EXPECT_EQ(encodeAddress(pk, Network::Mainnet),
            encodeAddress(pk, Network::Mainnet));
}

TEST(Wallet_AddressCodec, EncodeRejectsNullAddress)
{
  Crypto::Address null_addr; // all zeros
  EXPECT_TRUE(encodeAddress(null_addr, Network::Mainnet).empty());
  EXPECT_TRUE(encodeAddress(null_addr, Network::Testnet).empty());
  EXPECT_TRUE(encodeAddress(null_addr, Network::Regtest).empty());
}

//  Decode — round trip

TEST(Wallet_AddressCodec, RoundTripAllNetworks)
{
  for (uint8_t seed : {uint8_t(1), uint8_t(2), uint8_t(42), uint8_t(255)})
  {
    const auto pk = makePubkey(seed);

    for (auto net : {Network::Mainnet, Network::Testnet, Network::Regtest})
    {
      const std::string encoded = encodeAddress(pk, net);
      ASSERT_FALSE(encoded.empty()) << "encode failed for seed " << int(seed);

      const auto decoded = decodeAddress(encoded, net);
      ASSERT_TRUE(decoded.has_value())
          << "decode failed for: " << encoded
          << " network: " << networkName(net);

      EXPECT_EQ(*decoded, pk)
          << "round trip mismatch for seed " << int(seed);
    }
  }
}

TEST(Wallet_AddressCodec, RoundTripManyRandomKeys)
{
  // 256 distinct keys, all three networks. Catches any
  // bit-level encoding bug that a handful of vectors might miss.
  for (int i = 1; i < 256; ++i)
  {
    const auto pk = makePubkey(uint8_t(i));
    for (auto net : {Network::Mainnet, Network::Testnet, Network::Regtest})
    {
      const std::string s = encodeAddress(pk, net);
      ASSERT_FALSE(s.empty());
      const auto back = decodeAddress(s, net);
      ASSERT_TRUE(back.has_value()) << "failed for i=" << i
                                    << " addr=" << s;
      EXPECT_EQ(*back, pk);
    }
  }
}

//  Decode — case handling

TEST(Wallet_AddressCodec, DecodeUppercase)
{
  const auto pk = makePubkey(1);
  const std::string encoded = encodeAddress(pk, Network::Mainnet);

  std::string upper = encoded;
  for (char &c : upper)
    if (c >= 'a' && c <= 'z')
      c = char(c - 'a' + 'A');

  const auto decoded = decodeAddress(upper, Network::Mainnet);
  ASSERT_TRUE(decoded.has_value()) << "uppercase decode failed";
  EXPECT_EQ(*decoded, pk);
}

TEST(Wallet_AddressCodec, DecodeMixedCaseRejected)
{
  const auto pk = makePubkey(1);
  const std::string encoded = encodeAddress(pk, Network::Mainnet);

  // Uppercase the first lowercase letter in the address. Not every
  // position is a letter (the address contains digits and a '1'
  // separator), so we scan for one rather than picking a fixed index.
  std::string mixed = encoded;
  bool uppercased = false;
  for (char &c : mixed)
  {
    if (c >= 'a' && c <= 'z')
    {
      c = char(c - 'a' + 'A');
      uppercased = true;
      break;
    }
  }
  ASSERT_TRUE(uppercased)
      << "test bug: address has no lowercase letters";

  EXPECT_FALSE(decodeAddress(mixed, Network::Mainnet).has_value());
}

//  Decode — network mismatch

TEST(Wallet_AddressCodec, DecodeMainnetAsTestnetRejected)
{
  const auto pk = makePubkey(1);
  const std::string mainnet = encodeAddress(pk, Network::Mainnet);
  EXPECT_FALSE(decodeAddress(mainnet, Network::Testnet).has_value());
  EXPECT_FALSE(decodeAddress(mainnet, Network::Regtest).has_value());
}

TEST(Wallet_AddressCodec, DecodeTestnetAsMainnetRejected)
{
  const auto pk = makePubkey(1);
  const std::string testnet = encodeAddress(pk, Network::Testnet);
  EXPECT_FALSE(decodeAddress(testnet, Network::Mainnet).has_value());
  EXPECT_FALSE(decodeAddress(testnet, Network::Regtest).has_value());
}

TEST(Wallet_AddressCodec, DecodeRegtestAsMainnetRejected)
{
  const auto pk = makePubkey(1);
  const std::string regtest = encodeAddress(pk, Network::Regtest);
  EXPECT_FALSE(decodeAddress(regtest, Network::Mainnet).has_value());
  EXPECT_FALSE(decodeAddress(regtest, Network::Testnet).has_value());
}

//  Decode — tampered input

TEST(Wallet_AddressCodec, DecodeTamperedDataChar)
{
  const auto pk = makePubkey(1);
  std::string s = encodeAddress(pk, Network::Mainnet);

  // Change a character in the data part to another valid bech32
  // character. This corrupts the checksum.
  size_t pos = s.find('1') + 3;
  s[pos] = (s[pos] == 'q') ? 'p' : 'q';

  EXPECT_FALSE(decodeAddress(s, Network::Mainnet).has_value());
}

TEST(Wallet_AddressCodec, DecodeTamperedChecksum)
{
  const auto pk = makePubkey(1);
  std::string s = encodeAddress(pk, Network::Mainnet);

  // Flip the last character (part of the checksum).
  s.back() = (s.back() == 'q') ? 'p' : 'q';

  EXPECT_FALSE(decodeAddress(s, Network::Mainnet).has_value());
}

TEST(Wallet_AddressCodec, DecodeTooShort)
{
  EXPECT_FALSE(decodeAddress("clrty1", Network::Mainnet).has_value());
  EXPECT_FALSE(decodeAddress("clrty1qq", Network::Mainnet).has_value());
}

TEST(Wallet_AddressCodec, DecodeEmpty)
{
  EXPECT_FALSE(decodeAddress("", Network::Mainnet).has_value());
}

TEST(Wallet_AddressCodec, DecodeNoHrp)
{
  // Just the data part, no "clrty" prefix.
  EXPECT_FALSE(decodeAddress("1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
                             Network::Mainnet)
                   .has_value());
}

//  Decode — wrong witness version
//
//  Encode a payload with witness version 1 (using Crypto::Bech32
//  directly) and verify the decoder rejects it as an address.

TEST(Wallet_AddressCodec, DecodeWrongWitnessVersion)
{
  const auto pk = makePubkey(1);

  // Manually build bech32m("clrty", 0x01 || pubkey). This bypasses
  // AddressCodec's encoding (which always uses version 0) so we can
  // test the decoder's version check.
  std::vector<uint8_t> payload;
  payload.reserve(33);
  payload.push_back(0x01); // witness version 1, NOT 0
  payload.insert(payload.end(), pk.data.begin(), pk.data.end());

  const std::string s =
      Crypto::bech32Encode("clrty", payload, Crypto::Bech32Encoding::Bech32m);
  ASSERT_FALSE(s.empty());

  EXPECT_FALSE(decodeAddress(s, Network::Mainnet).has_value());
}

//  Decode — wrong payload length
//
//  Encode payloads with extra bytes or missing bytes; both must fail
//  the 33-byte check.

TEST(Wallet_AddressCodec, DecodePayloadTooShort)
{
  // 17-byte payload: witness version + 16 bytes. Should be rejected.
  std::vector<uint8_t> payload(17, 0xAB);
  payload[0] = 0x00;

  const std::string s =
      Crypto::bech32Encode("clrty", payload, Crypto::Bech32Encoding::Bech32m);
  ASSERT_FALSE(s.empty());

  EXPECT_FALSE(decodeAddress(s, Network::Mainnet).has_value());
}

TEST(Wallet_AddressCodec, DecodePayloadTooLong)
{
  // 48-byte payload encodes to 89 chars total — fits the 90-char
  // bech32m limit but exceeds the 33-byte CLRTY address payload.
  std::vector<uint8_t> payload(48, 0xAB);
  payload[0] = 0x00;

  const std::string s =
      Crypto::bech32Encode("clrty", payload, Crypto::Bech32Encoding::Bech32m);
  ASSERT_FALSE(s.empty());

  EXPECT_FALSE(decodeAddress(s, Network::Mainnet).has_value());
}

//  Decode — null address rejection
//
//  A bech32m string that decodes to witness version 0 with an
//  all-zero pubkey must be rejected.

TEST(Wallet_AddressCodec, DecodeNullAddressRejected)
{
  std::vector<uint8_t> payload(33, 0x00); // version 0 + 32 zero bytes

  const std::string s =
      Crypto::bech32Encode("clrty", payload, Crypto::Bech32Encoding::Bech32m);
  ASSERT_FALSE(s.empty());

  EXPECT_FALSE(decodeAddress(s, Network::Mainnet).has_value());
}

//  decodeAddressAnyNetwork

TEST(Wallet_AddressCodec, DecodeAnyNetworkMainnet)
{
  const auto pk = makePubkey(1);
  const std::string s = encodeAddress(pk, Network::Mainnet);

  auto result = decodeAddressAnyNetwork(s);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->network, Network::Mainnet);
  EXPECT_EQ(result->address, pk);
}

TEST(Wallet_AddressCodec, DecodeAnyNetworkTestnet)
{
  const auto pk = makePubkey(2);
  const std::string s = encodeAddress(pk, Network::Testnet);

  auto result = decodeAddressAnyNetwork(s);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->network, Network::Testnet);
  EXPECT_EQ(result->address, pk);
}

TEST(Wallet_AddressCodec, DecodeAnyNetworkRegtest)
{
  const auto pk = makePubkey(3);
  const std::string s = encodeAddress(pk, Network::Regtest);

  auto result = decodeAddressAnyNetwork(s);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->network, Network::Regtest);
  EXPECT_EQ(result->address, pk);
}

TEST(Wallet_AddressCodec, DecodeAnyNetworkUnknownHrp)
{
  // Valid bech32m with an HRP that isn't one of ours.
  std::vector<uint8_t> payload(33, 0xAB);
  payload[0] = 0x00;

  const std::string s =
      Crypto::bech32Encode("bc", payload, Crypto::Bech32Encoding::Bech32m);
  ASSERT_FALSE(s.empty());

  EXPECT_FALSE(decodeAddressAnyNetwork(s).has_value());
}

TEST(Wallet_AddressCodec, DecodeAnyNetworkRejectsGarbage)
{
  EXPECT_FALSE(decodeAddressAnyNetwork("").has_value());
  EXPECT_FALSE(decodeAddressAnyNetwork("not an address").has_value());
  EXPECT_FALSE(decodeAddressAnyNetwork("clrty1invalid").has_value());
}

//  isPlausibleAddress

TEST(Wallet_AddressCodec, IsPlausibleAddressValid)
{
  for (auto net : {Network::Mainnet, Network::Testnet, Network::Regtest})
  {
    const auto pk = makePubkey(42);
    EXPECT_TRUE(isPlausibleAddress(encodeAddress(pk, net)));
  }
}

TEST(Wallet_AddressCodec, IsPlausibleAddressInvalid)
{
  EXPECT_FALSE(isPlausibleAddress(""));
  EXPECT_FALSE(isPlausibleAddress("hello"));
  EXPECT_FALSE(isPlausibleAddress("clrty1"));
  EXPECT_FALSE(isPlausibleAddress("0xdeadbeef"));
}

TEST(Wallet_AddressCodec, IsPlausibleAddressNullSafe)
{
  // Accepts string_view; must not crash on empty or arbitrary input.
  EXPECT_FALSE(isPlausibleAddress(std::string_view{}));
  EXPECT_FALSE(isPlausibleAddress(std::string_view{"clrty1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"}));
}

//  Failure mode: legacy Bech32 (BIP-173) rejected
//
//  A string that verifies as Bech32 (not Bech32m) but otherwise
//  looks like a valid CLRTY address must be rejected. We only ever
//  emit Bech32m.

TEST(Wallet_AddressCodec, DecodeRejectsLegacyBech32)
{
  const auto pk = makePubkey(1);

  // Manually encode with the legacy Bech32 checksum.
  std::vector<uint8_t> payload;
  payload.push_back(0x00);
  payload.insert(payload.end(), pk.data.begin(), pk.data.end());

  const std::string legacy =
      Crypto::bech32Encode("clrty", payload, Crypto::Bech32Encoding::Bech32);
  ASSERT_FALSE(legacy.empty());

  EXPECT_FALSE(decodeAddress(legacy, Network::Mainnet).has_value());
  EXPECT_FALSE(decodeAddressAnyNetwork(legacy).has_value());
}

//  Encode/decode symmetry over all HRP lengths

TEST(Wallet_AddressCodec, AllNetworksHaveDistinctHrps)
{
  const auto m = hrpForNetwork(Network::Mainnet);
  const auto t = hrpForNetwork(Network::Testnet);
  const auto r = hrpForNetwork(Network::Regtest);

  EXPECT_NE(m, t);
  EXPECT_NE(m, r);
  EXPECT_NE(t, r);
}