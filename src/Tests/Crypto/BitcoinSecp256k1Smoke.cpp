// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <secp256k1.h>

#include <array>
#include <cstdint>
#include <cstring>

namespace
{
  // A known-valid secp256k1 secret key (the BIP32 test vector 1
  // seed-derived master is not used here; this is just "the library
  // links and its core operations work end to end").
  constexpr uint8_t kSecret[32] = {
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x01,
  };
} // namespace

TEST(Crypto_BitcoinSecp256k1Smoke, ContextAndPubkeyRoundTrip)
{
  secp256k1_context *ctx =
      secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                               SECP256K1_CONTEXT_VERIFY);
  ASSERT_NE(ctx, nullptr);

  // 1. Secret key -> public key.
  secp256k1_pubkey pubkey;
  ASSERT_EQ(secp256k1_ec_pubkey_create(ctx, &pubkey, kSecret), 1);

  // 2. Serialize compressed (33 bytes) — BIP32 uses compressed
  //    pubkeys for the HMAC input and for the P2WPKH script.
  uint8_t compressed[33];
  size_t out_len = sizeof(compressed);
  ASSERT_EQ(secp256k1_ec_pubkey_serialize(
                ctx, compressed, &out_len, &pubkey,
                SECP256K1_EC_COMPRESSED),
            1);
  ASSERT_EQ(out_len, 33u);

  // 3. Parse back — BIP32 derivation re-parses the serialized
  //    parent pubkey before tweaking it.
  secp256k1_pubkey parsed;
  ASSERT_EQ(secp256k1_ec_pubkey_parse(ctx, &parsed, compressed, 33), 1);

  uint8_t compressed2[33];
  out_len = sizeof(compressed2);
  ASSERT_EQ(secp256k1_ec_pubkey_serialize(
                ctx, compressed2, &out_len, &parsed,
                SECP256K1_EC_COMPRESSED),
            1);
  ASSERT_EQ(std::memcmp(compressed, compressed2, 33), 0);

  // 4. Non-hardened child derivation: pubkey + IL*G. This is the
  //    exact core operation BIP32 needs from the public side.
  //    IL = 1 (a valid scalar, small but non-zero).
  uint8_t tweak[32] = {0};
  tweak[31] = 0x01;
  secp256k1_pubkey tweaked = parsed;
  ASSERT_EQ(secp256k1_ec_pubkey_tweak_add(ctx, &tweaked, tweak), 1);

  uint8_t compressed3[33];
  out_len = sizeof(compressed3);
  ASSERT_EQ(secp256k1_ec_pubkey_serialize(
                ctx, compressed3, &out_len, &tweaked,
                SECP256K1_EC_COMPRESSED),
            1);
  // The tweaked key must differ from the parent.
  ASSERT_NE(std::memcmp(compressed, compressed3, 33), 0);

  secp256k1_context_destroy(ctx);
}