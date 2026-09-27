// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Sha256.h"

using namespace Crypto;
using namespace Tests;

//  FIPS 180-4 / NIST SHA-256 test vectors.
//
//  Sources:
//    - FIPS 180-4 Appendix B (worked examples)
//    - NIST "SHA-256 Test Vectors" (the classic len=0, 448, 896 cases)
//    - The standard "million a" test from the original SHA-2 paper

TEST(Crypto_Sha256, Empty)
{
  uint8_t out[32];
  sha256(reinterpret_cast<const uint8_t *>(""), 0, out);

  EXPECT_EQ(toHex(out, 32),
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855");
}

TEST(Crypto_Sha256, Abc)
{
  uint8_t out[32];
  sha256(reinterpret_cast<const uint8_t *>("abc"), 3, out);

  EXPECT_EQ(toHex(out, 32),
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad");
}

TEST(Crypto_Sha256, TwoBlock)
{
  // "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  // 56 bytes. Exercises the padding case where the message plus
  // padding exactly fills one block and a second block is needed
  // for the length field.
  const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  uint8_t out[32];
  sha256(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg), out);

  EXPECT_EQ(toHex(out, 32),
            "248d6a61d20638b8e5c026930c3e6039"
            "a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Crypto_Sha256, LongMessage)
{
  // 112 bytes. Exercises three blocks.
  const char *msg =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
      "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  uint8_t out[32];
  sha256(reinterpret_cast<const uint8_t *>(msg), std::strlen(msg), out);

  EXPECT_EQ(toHex(out, 32),
            "cf5b16a778af8380036ce59e7b049237"
            "0b249b11e8f07a51afac45037afee9d1");
}

TEST(Crypto_Sha256, MillionAs)
{
  // The classic stress test: 1,000,000 'a' characters.
  // Exercises the multi-block streaming path with a large input.
  constexpr size_t N = 1000000;
  std::vector<uint8_t> buf(N, 'a');

  uint8_t out[32];
  sha256(buf.data(), buf.size(), out);

  EXPECT_EQ(toHex(out, 32),
            "cdc76e5c9914fb9281a1c7e284d73e67"
            "f1809a48a497200e046d39ccc7112cd0");
}

TEST(Crypto_Sha256, StreamingMatchesOneShot)
{
  // Verify that streaming update() in arbitrary chunk sizes produces
  // the same digest as a one-shot call.
  const char *msg =
      "The quick brown fox jumps over the lazy dog. "
      "The quick brown fox jumps over the lazy dog. "
      "The quick brown fox jumps over the lazy dog.";

  const size_t msg_len = std::strlen(msg);
  const auto *bytes = reinterpret_cast<const uint8_t *>(msg);

  uint8_t one_shot[32];
  sha256(bytes, msg_len, one_shot);

  // Chunk sizes chosen to exercise: partial blocks, full blocks,
  // and boundaries that cross block boundaries mid-message.
  const size_t chunks[] = {1, 7, 63, 64, 65, 100, 127, 128, 129};

  for (size_t chunk : chunks)
  {
    Sha256 h;
    size_t off = 0;
    while (off < msg_len)
    {
      const size_t take = (msg_len - off < chunk) ? (msg_len - off) : chunk;
      h.update(bytes + off, take);
      off += take;
    }

    uint8_t streamed[32];
    h.finalize(streamed);

    EXPECT_EQ(std::memcmp(one_shot, streamed, 32), 0)
        << "chunk size " << chunk << " produced different digest";
  }
}

TEST(Crypto_Sha256, StreamingResetAllowsReuse)
{
  // After finalize(), the hasher must be usable for a new message
  // and produce the same result as a fresh instance.
  Sha256 h;

  uint8_t first[32];
  h.update(reinterpret_cast<const uint8_t *>("abc"), 3);
  h.finalize(first);

  uint8_t second[32];
  h.update(reinterpret_cast<const uint8_t *>("abc"), 3);
  h.finalize(second);

  EXPECT_EQ(std::memcmp(first, second, 32), 0);

  uint8_t reference[32];
  sha256(reinterpret_cast<const uint8_t *>("abc"), 3, reference);
  EXPECT_EQ(std::memcmp(first, reference, 32), 0);
}

TEST(Crypto_Sha256, EmptyStreaming)
{
  // A hasher that never receives an update should produce the same
  // output as sha256 of the empty string.
  Sha256 h;
  uint8_t out[32];
  h.finalize(out);

  EXPECT_EQ(toHex(out, 32),
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855");
}