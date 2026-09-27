// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Argon2id.h"

using namespace Crypto;
using namespace Tests;

//  Argon2id test vectors.
//
//  The reference test vectors live in RFC 9106 §5.3, but that section
//  specifies inputs that include a *secret* and *associated data*.
//  Our Crypto::argon2id() API deliberately does not expose those
//  parameters as they are optional in the spec and we use the default
//  of zero-length for both. RFC 9106 does not provide a vector that
//  matches our exact API shape.
//
//  Two things we CAN verify structurally, without needing an external
//  KAT file:
//
//    1. Determinism: same inputs -> same output.
//    2. Parameter sensitivity: changing any parameter changes the
//       output.
//
//  And one we need a reference for:
//
//    3. A specific 32-byte hex output for a fixed input, used as a
//       regression guard against accidental changes to the algorithm.

//  Determinism
//
//  The same inputs must always produce the same output. This is the
//  fundamental property of a KDF, and failing this test would indicate
//  a bug in memory initialization or in the fill function.

TEST(Crypto_Argon2id, Deterministic)
{
  const auto password = testPassword();
  const auto salt = testSalt();

  Argon2Params params;
  params.m_cost_kib = 32;
  params.t_cost = 3;
  params.p_cost = 4;

  const std::string a = argon2idHex(password, salt, params);
  const std::string b = argon2idHex(password, salt, params);

  EXPECT_EQ(a, b);
}

//  Parameter sensitivity
//
//  Changing any of the three cost parameters must change the output.
//  This catches a class of bugs where a parameter is silently ignored
//  or not incorporated into the hash.

TEST(Crypto_Argon2id, MemoryCostMatters)
{
  const auto password = testPassword();
  const auto salt = testSalt();

  Argon2Params p1;
  p1.m_cost_kib = 32;
  p1.t_cost = 3;
  p1.p_cost = 4;
  Argon2Params p2;
  p2.m_cost_kib = 64;
  p2.t_cost = 3;
  p2.p_cost = 4;

  EXPECT_NE(argon2idHex(password, salt, p1),
            argon2idHex(password, salt, p2));
}

TEST(Crypto_Argon2id, TimeCostMatters)
{
  const auto password = testPassword();
  const auto salt = testSalt();

  Argon2Params p1;
  p1.m_cost_kib = 32;
  p1.t_cost = 1;
  p1.p_cost = 4;
  Argon2Params p2;
  p2.m_cost_kib = 32;
  p2.t_cost = 2;
  p2.p_cost = 4;

  EXPECT_NE(argon2idHex(password, salt, p1),
            argon2idHex(password, salt, p2));
}

TEST(Crypto_Argon2id, ParallelismMatters)
{
  const auto password = testPassword();
  const auto salt = testSalt();

  Argon2Params p1;
  p1.m_cost_kib = 32;
  p1.t_cost = 3;
  p1.p_cost = 1;
  Argon2Params p2;
  p2.m_cost_kib = 32;
  p2.t_cost = 3;
  p2.p_cost = 2;

  EXPECT_NE(argon2idHex(password, salt, p1),
            argon2idHex(password, salt, p2));
}

TEST(Crypto_Argon2id, SaltMatters)
{
  const auto password = testPassword();

  std::vector<uint8_t> salt_a(16, 0x02);
  std::vector<uint8_t> salt_b(16, 0x03);

  Argon2Params params;
  params.m_cost_kib = 32;
  params.t_cost = 3;
  params.p_cost = 4;

  EXPECT_NE(argon2idHex(password, salt_a, params),
            argon2idHex(password, salt_b, params));
}

TEST(Crypto_Argon2id, PasswordMatters)
{
  const auto salt = testSalt();

  std::vector<uint8_t> pwd_a(32, 0x01);
  std::vector<uint8_t> pwd_b(32, 0x02);

  Argon2Params params;
  params.m_cost_kib = 32;
  params.t_cost = 3;
  params.p_cost = 4;

  EXPECT_NE(argon2idHex(pwd_a, salt, params),
            argon2idHex(pwd_b, salt, params));
}

//  Output length
//
//  Argon2 can produce arbitrary-length output. Test a few lengths
//  from the minimum (4) up to a couple of blocks.

TEST(Crypto_Argon2id, OutputLengths)
{
  const auto password = testPassword();
  const auto salt = testSalt();

  Argon2Params params;
  params.m_cost_kib = 32;
  params.t_cost = 3;
  params.p_cost = 4;

  for (size_t len : {size_t(4), size_t(16), size_t(32), size_t(64), size_t(128)})
  {
    std::vector<uint8_t> out(len);
    const bool ok = argon2id(
        password.data(), password.size(),
        salt.data(), salt.size(),
        params,
        out.data(), out.size());
    EXPECT_TRUE(ok) << "length " << len;
  }
}

//  Prefix property for long outputs
//
//  Argon2's long-output mode (H' function) is defined as a
//  variable-length hash. For output lengths <= 64 bytes it's a
//  single Blake2b call; for longer it's iterative. The prefix
//  property does NOT hold across the 64-byte boundary (the H'
//  function is not prefix-consistent), so we only test that outputs
//  of different lengths differ, not that one is a prefix of another.

TEST(Crypto_Argon2id, DifferentLengthsDifferentOutput)
{
  const auto password = testPassword();
  const auto salt = testSalt();

  Argon2Params params;
  params.m_cost_kib = 32;
  params.t_cost = 3;
  params.p_cost = 4;

  std::vector<uint8_t> out32(32);
  std::vector<uint8_t> out64(64);
  argon2id(password.data(), password.size(),
           salt.data(), salt.size(), params,
           out32.data(), out32.size());
  argon2id(password.data(), password.size(),
           salt.data(), salt.size(), params,
           out64.data(), out64.size());

  // First 32 bytes should differ (they're not a prefix relation).
  EXPECT_NE(std::memcmp(out32.data(), out64.data(), 32), 0);
}

//  Parameter validation
//
//  Argon2Params::valid() enforces RFC 9106's constraints:
//    - m_cost >= 8
//    - m_cost >= 8 * p_cost
//    - t_cost >= 1
//    - p_cost >= 1

TEST(Crypto_Argon2Params, ValidDefaults)
{
  Argon2Params p; // 64 MiB, 3 iters, 4 lanes
  EXPECT_TRUE(p.valid());
}

TEST(Crypto_Argon2Params, RejectsTooLittleMemory)
{
  Argon2Params p;
  p.m_cost_kib = 4; // < 8
  EXPECT_FALSE(p.valid());
}

TEST(Crypto_Argon2Params, RejectsMemoryLessThanEightTimesParallelism)
{
  Argon2Params p;
  p.m_cost_kib = 32;
  p.p_cost = 5; // requires m_cost >= 40
  EXPECT_FALSE(p.valid());
}

TEST(Crypto_Argon2Params, RejectsZeroTimeCost)
{
  Argon2Params p;
  p.t_cost = 0;
  EXPECT_FALSE(p.valid());
}

TEST(Crypto_Argon2Params, RejectsZeroParallelism)
{
  Argon2Params p;
  p.p_cost = 0;
  EXPECT_FALSE(p.valid());
}

//  Invalid parameter rejection
//
//  argon2id() must return false rather than producing garbage if
//  given parameters that violate the RFC constraints.

TEST(Crypto_Argon2id, RejectsInvalidParams)
{
  const auto password = testPassword();
  const auto salt = testSalt();

  std::vector<uint8_t> out(32);

  Argon2Params bad;
  bad.m_cost_kib = 4; // < 8

  EXPECT_FALSE(argon2id(
      password.data(), password.size(),
      salt.data(), salt.size(),
      bad,
      out.data(), out.size()));
}

//  Edge case: minimum parameters
//
//  The smallest permitted configuration. Exercises the memory
//  allocation and filling code with almost no memory.

TEST(Crypto_Argon2id, MinimumParameters)
{
  const auto password = testPassword();
  const auto salt = testSalt();

  Argon2Params params;
  params.m_cost_kib = 8; // minimum: 8 KiB
  params.t_cost = 1;
  params.p_cost = 1;

  std::vector<uint8_t> out(32);
  const bool ok = argon2id(
      password.data(), password.size(),
      salt.data(), salt.size(),
      params,
      out.data(), out.size());
  EXPECT_TRUE(ok);
}

//  Edge case: short salt
//
//  RFC 9106 requires salt >= 8 bytes. Our wrapper enforces that.
//  This test verifies the enforcement.

TEST(Crypto_Argon2id, RejectsShortSalt)
{
  const auto password = testPassword();
  std::vector<uint8_t> short_salt(4, 0x02); // < 8

  Argon2Params params;
  params.m_cost_kib = 32;
  params.t_cost = 3;
  params.p_cost = 4;

  std::vector<uint8_t> out(32);
  EXPECT_FALSE(argon2id(
      password.data(), password.size(),
      short_salt.data(), short_salt.size(),
      params,
      out.data(), out.size()));
}

//  Edge case: empty password
//
//  RFC 9106 permits a zero-length password. It's not a sensible
//  choice for a wallet, but the primitive must handle it.

TEST(Crypto_Argon2id, EmptyPassword)
{
  const auto salt = testSalt();

  Argon2Params params;
  params.m_cost_kib = 32;
  params.t_cost = 3;
  params.p_cost = 4;

  std::vector<uint8_t> out(32);
  const bool ok = argon2id(
      nullptr, 0,
      salt.data(), salt.size(),
      params,
      out.data(), out.size());
  EXPECT_TRUE(ok);
}

//  Known-answer test (KAT)
//
//  This is a regression guard: a fixed input must produce a fixed
//  output. Any change to the implementation that alters the output
//  breaks this test, which is exactly what we want. It means every
//  keystore in the field would suddenly stop decrypting.
//
//  The reference output is generated once from a reference
//  implementation. Regenerate with any of the following:
//
//    Python (requires: pip install argon2-cffi):
//      from argon2.low_level import hash_secret_raw, Type
//      import binascii
//      out = hash_secret_raw(
//          secret=b'\x01' * 32,
//          salt=b'\x02' * 16,
//          time_cost=3,
//          memory_cost=32,     # KiB
//          parallelism=4,
//          hash_len=32,
//          type=Type.ID,
//      )
//      print(binascii.hexlify(out).decode())
//
//    CLI (requires: apt install argon2):
//      echo -n $'\x01%.0s' {1..32} | argon2 $'\x02%.0s' {1..16} -id -t 3 -m 5 -p 4 -l 32 -r
//      # where -m 5 means log2(32) = 5

TEST(Crypto_Argon2id, KnownAnswer)
{
  // KAT PIN — regenerated from the vendored reference implementation
  // (upstream phc-winner-argon2) using the test inputs:
  //   password = 32 × 0x01
  //   salt     = 16 × 0x02
  //   m_cost   = 32 KiB, t_cost = 3, p_cost = 4
  //   output   = 32 bytes
  //
  // Verified against:
  //   - The vendored reference C code directly
  //   - The `argon2` CLI (Ubuntu argon2 package)
  const char *expected =
      "03aab965c12001c9d7d0d2de33192c04"
      "94b684bb148196d73c1df1acaf6d0c2e";

  // If the pin is still all zeros, skip rather than fail. This lets
  // the rest of the test suite run while the KAT is being prepared.
  const bool unset = (std::strcmp(expected,
                                  "00000000000000000000000000000000"
                                  "00000000000000000000000000000000") == 0);
  if (unset)
  {
    GTEST_SKIP() << "Argon2id KAT not yet pinned; regenerate from a "
                    "reference implementation";
  }

  const auto password = testPassword();
  const auto salt = testSalt();

  Argon2Params params;
  params.m_cost_kib = 32;
  params.t_cost = 3;
  params.p_cost = 4;

  EXPECT_EQ(argon2idHex(password, salt, params), expected);
}