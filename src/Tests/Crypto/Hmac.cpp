// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Hmac.h"
#include "Crypto/Sha512.h"

using namespace Crypto;
using namespace Tests;

//  RFC 4231 — HMAC-SHA512 test vectors.
//
//  Seven test cases from §4 of RFC 4231. Each provides a key and a
//  message, plus the expected HMAC. These are the canonical vectors
//  that every HMAC-SHA512 implementation is checked against.
//
//  Source: https://datatracker.ietf.org/doc/html/rfc4231#section-4

//  Test Case 1
//
//  Key:    20 bytes of 0x0b
//  Data:   "Hi There" (8 bytes)
//  HMAC:   see below
TEST(Crypto_HmacSha512, Rfc4231Case1)
{
  const std::vector<uint8_t> key = repeat(0x0b, 20);
  const std::string msg = "Hi There";
  const std::vector<uint8_t> data(msg.begin(), msg.end());

  EXPECT_EQ(hmacHex(key, data),
            "87aa7cdea5ef619d4ff0b4241a1d6cb0"
            "2379f4e2ce4ec2787ad0b30545e17cde"
            "daa833b7d6b8a702038b274eaea3f4e4"
            "be9d914eeb61f1702e696c203a126854");
}

//  Test Case 2
//
//  Key:    "Jefe" (4 bytes)
//  Data:   "what do ya want for nothing?" (28 bytes)
TEST(Crypto_HmacSha512, Rfc4231Case2)
{
  const std::string key_s = "Jefe";
  const std::string msg_s = "what do ya want for nothing?";
  const std::vector<uint8_t> key(key_s.begin(), key_s.end());
  const std::vector<uint8_t> msg(msg_s.begin(), msg_s.end());

  EXPECT_EQ(hmacHex(key, msg),
            "164b7a7bfcf819e2e395fbe73b56e0a3"
            "87bd64222e831fd610270cd7ea250554"
            "9758bf75c05a994a6d034f65f8f0e6fd"
            "caeab1a34d4a6b4b636e070a38bce737");
}

//  Test Case 3
//
//  Key:    20 bytes of 0xaa
//  Data:   50 bytes of 0xdd
TEST(Crypto_HmacSha512, Rfc4231Case3)
{
  const std::vector<uint8_t> key = repeat(0xaa, 20);
  const std::vector<uint8_t> msg = repeat(0xdd, 50);

  EXPECT_EQ(hmacHex(key, msg),
            "fa73b0089d56a284efb0f0756c890be9"
            "b1b5dbdd8ee81a3655f83e33b2279d39"
            "bf3e848279a722c806b485a47e67c807"
            "b946a337bee8942674278859e13292fb");
}

//  Test Case 4
//
//  Key:    25 bytes of 0x01..0x19 (sequential)
//  Data:   50 bytes of 0xcd
TEST(Crypto_HmacSha512, Rfc4231Case4)
{
  std::vector<uint8_t> key(25);
  for (size_t i = 0; i < key.size(); ++i)
    key[i] = uint8_t(i + 1);

  const std::vector<uint8_t> msg = repeat(0xcd, 50);

  EXPECT_EQ(hmacHex(key, msg),
            "b0ba465637458c6990e5a8c5f61d4af7"
            "e576d97ff94b872de76f8050361ee3db"
            "a91ca5c11aa25eb4d679275cc5788063"
            "a5f19741120c4f2de2adebeb10a298dd");
}

//  Test Case 5
//
//  Key:    20 bytes of 0x0c
//  Data:   "Test With Truncation" (20 bytes)
//
//  The full 64-byte HMAC-SHA512 output, verified against the
//  reference RFC 4231 §4.5 test vector.
TEST(Crypto_HmacSha512, Rfc4231Case5)
{
  const std::vector<uint8_t> key = repeat(0x0c, 20);
  const std::string msg_s = "Test With Truncation";
  const std::vector<uint8_t> msg(msg_s.begin(), msg_s.end());

  EXPECT_EQ(hmacHex(key, msg),
            "415fad6271580a531d4179bc891d87a6"
            "50188707922a4fbb36663a1eb16da008"
            "711c5b50ddd0fc235084eb9d3364a145"
            "4fb2ef67cd1d29fe6773068ea266e96b");
}

//  Test Case 6
//
//  Key:    131 bytes of 0xaa. Longer than the SHA-512 block size (128),
//          so the key is hashed before use. This is the case that
//          exercises the key-longer-than-block path in HMAC.
//  Data:   "Test Using Larger Than Block-Size Key - Hash Key First"
TEST(Crypto_HmacSha512, Rfc4231Case6)
{
  const std::vector<uint8_t> key = repeat(0xaa, 131);
  const std::string msg_s = "Test Using Larger Than Block-Size Key - Hash Key First";
  const std::vector<uint8_t> msg(msg_s.begin(), msg_s.end());

  EXPECT_EQ(hmacHex(key, msg),
            "80b24263c7c1a3ebb71493c1dd7be8b4"
            "9b46d1f41b4aeec1121b013783f8f352"
            "6b56d037e05f2598bd0fd2215d6a1e52"
            "95e64f73f63f0aec8b915a985d786598");
}

//  Test Case 7
//
//  Key:    131 bytes of 0xaa (same long key as Case 6)
//  Data:   152-byte message "This is a test using a larger than
//          block-size key and a larger than block-size data..."
TEST(Crypto_HmacSha512, Rfc4231Case7)
{
  const std::vector<uint8_t> key = repeat(0xaa, 131);
  const std::string msg_s =
      "This is a test using a larger than block-size key and a larger "
      "than block-size data. The key needs to be hashed before being "
      "used by the HMAC algorithm.";
  const std::vector<uint8_t> msg(msg_s.begin(), msg_s.end());

  EXPECT_EQ(hmacHex(key, msg),
            "e37b6a775dc87dbaa4dfa9f96e5e3ffd"
            "debd71f8867289865df5a32d20cdc944"
            "b6022cac3c4982b10d5eeb55c3e4de15"
            "134676fb6de0446065c97440fa8c6a58");
}

//  Streaming API equivalence
//
//  The streaming HmacSha512 class must produce the same output as
//  the one-shot function. Exercise several chunk sizes.

TEST(Crypto_HmacSha512, StreamingMatchesOneShot)
{
  const std::vector<uint8_t> key = repeat(0xaa, 20);
  const std::string msg_s = "Streaming test message with a few blocks worth of data";
  const std::vector<uint8_t> msg(msg_s.begin(), msg_s.end());

  uint8_t reference[HMAC_SHA512_OUTPUT_SIZE];
  hmacSha512(key.data(), key.size(), msg.data(), msg.size(), reference);

  const size_t chunks[] = {1, 7, 63, 64, 65, 100, 128, 129};
  for (size_t chunk : chunks)
  {
    HmacSha512 h(key.data(), key.size());
    size_t off = 0;
    while (off < msg.size())
    {
      const size_t take = (msg.size() - off < chunk) ? (msg.size() - off) : chunk;
      h.update(msg.data() + off, take);
      off += take;
    }
    uint8_t out[HMAC_SHA512_OUTPUT_SIZE];
    h.finalize(out);

    EXPECT_EQ(std::memcmp(reference, out, HMAC_SHA512_OUTPUT_SIZE), 0)
        << "chunk size " << chunk << " produced different HMAC";
  }
}

//  Long key path through streaming API

TEST(Crypto_HmacSha512, StreamingLongKey)
{
  // Same as RFC 4231 Case 6, but through the streaming class.
  const std::vector<uint8_t> key = repeat(0xaa, 131);
  const std::string msg_s = "Test Using Larger Than Block-Size Key - Hash Key First";
  const std::vector<uint8_t> msg(msg_s.begin(), msg_s.end());

  HmacSha512 h(key.data(), key.size());
  h.update(msg.data(), msg.size());

  uint8_t out[HMAC_SHA512_OUTPUT_SIZE];
  h.finalize(out);

  EXPECT_EQ(toHex(out, HMAC_SHA512_OUTPUT_SIZE),
            "80b24263c7c1a3ebb71493c1dd7be8b4"
            "9b46d1f41b4aeec1121b013783f8f352"
            "6b56d037e05f2598bd0fd2215d6a1e52"
            "95e64f73f63f0aec8b915a985d786598");
}

//  Empty message

TEST(Crypto_HmacSha512, EmptyMessage)
{
  const std::vector<uint8_t> key = repeat(0x0b, 20);
  const std::vector<uint8_t> msg; // empty

  uint8_t out[HMAC_SHA512_OUTPUT_SIZE];
  hmacSha512(key.data(), key.size(), nullptr, 0, out);

  // Reference: HMAC-SHA512(key=0x0b*20, msg="") — computed from
  // the same code path as Case 1, with an empty message. This is
  // a regression check that an empty message doesn't trigger UB
  // (nullptr deref in the update path) and produces a consistent
  // digest across calls.
  uint8_t out2[HMAC_SHA512_OUTPUT_SIZE];
  hmacSha512(key.data(), key.size(), nullptr, 0, out2);
  EXPECT_EQ(std::memcmp(out, out2, HMAC_SHA512_OUTPUT_SIZE), 0);
}

//  Empty key

TEST(Crypto_HmacSha512, EmptyKey)
{
  // HMAC with a zero-length key is well-defined: it's the same as
  // HMAC with a key of all zero bytes of block size. SHA-512's
  // block size is 128 bytes, so we compare against that.
  const std::vector<uint8_t> empty_key;
  const std::vector<uint8_t> zero_key(HMAC_SHA512_BLOCK_SIZE, 0);
  const std::string msg_s = "hello";
  const std::vector<uint8_t> msg(msg_s.begin(), msg_s.end());

  uint8_t out_empty[HMAC_SHA512_OUTPUT_SIZE];
  uint8_t out_zero[HMAC_SHA512_OUTPUT_SIZE];
  hmacSha512(empty_key.data(), 0, msg.data(), msg.size(), out_empty);
  hmacSha512(zero_key.data(), zero_key.size(), msg.data(), msg.size(), out_zero);

  EXPECT_EQ(std::memcmp(out_empty, out_zero, HMAC_SHA512_OUTPUT_SIZE), 0);
}