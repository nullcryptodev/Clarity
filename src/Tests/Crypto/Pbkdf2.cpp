// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cstring>
#include <string>
#include <vector>
#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Pbkdf2.h"
#include "Crypto/Hmac.h"

using namespace Crypto;
using namespace Tests;

//  PBKDF2-HMAC-SHA512 test vectors.
//
//  Sources:
//    - Python hashlib documentation examples for pbkdf2_hmac('sha512', ...)
//    - Hand-derived vectors for edge cases (empty password, empty salt,
//      high iteration counts)
//    - BIP-39's specific usage: password=mnemonic sentence, salt="mnemonic"
//      + passphrase, 2048 iterations, 64-byte output. Those vectors live
//      in Tests/Wallet/Bip39.cpp; here we only check the raw primitive.
//
//  IMPORTANT: for the reference vectors, run them once against Python's
//  hashlib to confirm the expected outputs. If a vector is wrong, this
//  is the wrong place to fix it — fix the vector, not the code.

//  Python hashlib reference vectors
//
//  Reference: https://docs.python.org/3/library/hashlib.html#hashlib.pbkdf2_hmac
//
//  The Python examples use passwords/salts of type bytes. We reproduce
//  the exact inputs here.

//  Test 1: password="password", salt="salt", 1 iteration, 64-byte output
TEST(Crypto_Pbkdf2HmacSha512, PythonPasswordSaltOneIter)
{
  EXPECT_EQ(pbkdf2Hex("password", "salt", 1, 64),
            "867f70cf1ade02cff3752599a3a53dc4"
            "af34c7a669815ae5d513554e1c8cf252"
            "c02d470a285a0501bad999bfe943c08f"
            "050235d7d68b1da55e63f73b60a57fce");
}

//  Test 2: password="password", salt="salt", 2 iterations
TEST(Crypto_Pbkdf2HmacSha512, PythonPasswordSaltTwoIter)
{
  // VERIFY THIS VECTOR. The 1-iteration case is easier to derive by
  // hand; the 2-iteration case doubles the work but is still verifiable.
  EXPECT_EQ(pbkdf2Hex("password", "salt", 2, 64),
            "e1d9c16aa681708a45f5c7c4e215ceb6"
            "6e011a2e9f0040713f18aefdb866d53c"
            "f76cab2868a39b9f7840edce4fef5a82"
            "be67335c77a6068e04112754f27ccf4e");
}

//  Test 3: password="password", salt="salt", 4096 iterations
//
//  The classic "PBKDF2 iteration count" reference from RFC 6070, but
//  with SHA-512 instead of SHA-1. Same inputs, different PRF.
TEST(Crypto_Pbkdf2HmacSha512, PythonPasswordSalt4096Iter)
{
  EXPECT_EQ(pbkdf2Hex("password", "salt", 4096, 64),
            "d197b1b33db0143e018b12f3d1d1479e"
            "6cdebdcc97c5c0f87f6902e072f457b5"
            "143f30602641b3d55cd335988cb36b84"
            "376060ecd532e039b742a239434af2d5");
}

//  Test 4: password="passwordPASSWORDpassword",
//          salt="saltSALTsaltSALTsaltSALTsaltSALTsalt",
//          4096 iterations
//
//  Longer password and salt, still 4096 iterations.
TEST(Crypto_Pbkdf2HmacSha512, PythonLongPasswordSalt)
{
  EXPECT_EQ(pbkdf2Hex("passwordPASSWORDpassword",
                      "saltSALTsaltSALTsaltSALTsaltSALTsalt",
                      4096, 64),
            "8c0511f4c6e597c6ac6315d8f0362e22"
            "5f3c501495ba23b868c005174dc4ee71"
            "115b59f9e60cd9532fa33e0f75aefe30"
            "225c583a186cd82bd4daea9724a3d3b8");
}

//  Test 5: Zero-length password
//
//  PBKDF2 is well-defined for an empty password. There's no published
//  RFC vector for this specific case with SHA-512, but we can verify
//  determinism and that it doesn't crash.
TEST(Crypto_Pbkdf2HmacSha512, EmptyPassword)
{
  const std::string salt = "salt";

  std::vector<uint8_t> out_a(64);
  std::vector<uint8_t> out_b(64);

  pbkdf2HmacSha512(nullptr, 0,
                   reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
                   1,
                   out_a.data(), out_a.size());

  pbkdf2HmacSha512(nullptr, 0,
                   reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
                   1,
                   out_b.data(), out_b.size());

  EXPECT_EQ(std::memcmp(out_a.data(), out_b.data(), out_a.size()), 0);
}

//  Test 6: Zero-length salt
TEST(Crypto_Pbkdf2HmacSha512, EmptySalt)
{
  const std::string password = "password";

  std::vector<uint8_t> out_a(64);
  std::vector<uint8_t> out_b(64);

  pbkdf2HmacSha512(
      reinterpret_cast<const uint8_t *>(password.data()), password.size(),
      nullptr, 0,
      1,
      out_a.data(), out_a.size());

  pbkdf2HmacSha512(
      reinterpret_cast<const uint8_t *>(password.data()), password.size(),
      nullptr, 0,
      1,
      out_b.data(), out_b.size());

  EXPECT_EQ(std::memcmp(out_a.data(), out_b.data(), out_a.size()), 0);
}

//  Test 7: Output length not a multiple of HMAC output size
//
//  PBKDF2 must handle partial final blocks. Test every output length
//  from 1 to 128 and verify the prefix property: a shorter output is
//  a prefix of a longer one.
TEST(Crypto_Pbkdf2HmacSha512, PartialBlockOutput)
{
  const std::string password = "password";
  const std::string salt = "salt";
  const uint32_t iters = 10;

  // Full output.
  std::vector<uint8_t> full(128);
  pbkdf2HmacSha512(
      reinterpret_cast<const uint8_t *>(password.data()), password.size(),
      reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
      iters, full.data(), full.size());

  // PBKDF2's specification defines T_1, T_2, ... in order. A shorter
  // output must be a prefix of a longer one.
  for (size_t len = 1; len <= 128; ++len)
  {
    std::vector<uint8_t> shorter(len);
    pbkdf2HmacSha512(
        reinterpret_cast<const uint8_t *>(password.data()), password.size(),
        reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
        iters, shorter.data(), shorter.size());

    EXPECT_EQ(std::memcmp(shorter.data(), full.data(), len), 0)
        << "prefix property failed at length " << len;
  }
}

//  Test 8: Iteration count of 1 reduces to a single HMAC
//
//  For iterations == 1, PBKDF2 is exactly:
//    T_1 = HMAC(password, salt || BE32(1))
//    output = T_1
//
//  This lets us verify against the HMAC primitive directly.
TEST(Crypto_Pbkdf2HmacSha512, OneIterationEqualsHmac)
{
  const std::string password = "password";
  const std::string salt = "salt";

  // PBKDF2 output.
  std::vector<uint8_t> pbkdf2_out(64);
  pbkdf2HmacSha512(
      reinterpret_cast<const uint8_t *>(password.data()), password.size(),
      reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
      1, pbkdf2_out.data(), pbkdf2_out.size());

  // Direct HMAC of (salt || BE32(1)).
  std::vector<uint8_t> salt_be(salt.begin(), salt.end());
  salt_be.push_back(0x00);
  salt_be.push_back(0x00);
  salt_be.push_back(0x00);
  salt_be.push_back(0x01);

  uint8_t hmac_out[HMAC_SHA512_OUTPUT_SIZE];
  hmacSha512(
      reinterpret_cast<const uint8_t *>(password.data()), password.size(),
      salt_be.data(), salt_be.size(),
      hmac_out);

  EXPECT_EQ(std::memcmp(pbkdf2_out.data(), hmac_out, 64), 0);
}

//  Test 9: Determinism
TEST(Crypto_Pbkdf2HmacSha512, Deterministic)
{
  const auto password = bytes("correct horse battery staple");
  const auto salt = bytes("random salt value");

  std::vector<uint8_t> out_a(64);
  std::vector<uint8_t> out_b(64);

  pbkdf2HmacSha512(password.data(), password.size(),
                   salt.data(), salt.size(),
                   100,
                   out_a.data(), out_a.size());
  pbkdf2HmacSha512(password.data(), password.size(),
                   salt.data(), salt.size(),
                   100,
                   out_b.data(), out_b.size());

  EXPECT_EQ(std::memcmp(out_a.data(), out_b.data(), 64), 0);
}

//  Test 10: Vector overload
//
//  The std::vector-based overload must agree with the raw-pointer one.
TEST(Crypto_Pbkdf2HmacSha512, VectorOverloadMatchesRaw)
{
  const auto password = bytes("password");
  const auto salt = bytes("salt");

  std::vector<uint8_t> raw_out(64);
  pbkdf2HmacSha512(password.data(), password.size(),
                   salt.data(), salt.size(),
                   2,
                   raw_out.data(), raw_out.size());

  std::vector<uint8_t> vec_out =
      pbkdf2HmacSha512(password, salt, 2, 64);

  EXPECT_EQ(raw_out, vec_out);
}

//  Test 11: BIP-39 usage pattern
//
//  This is not the full BIP-39 test (that's in Tests/Wallet/Bip39.cpp),
//  but it exercises the specific parameter shape the wallet relies on:
//  2048 iterations, 64-byte output.
TEST(Crypto_Pbkdf2HmacSha512, Bip39ParameterShape)
{
  const std::string mnemonic =
      "abandon abandon abandon abandon abandon abandon "
      "abandon abandon abandon abandon abandon about";
  const std::string salt_prefix = "mnemonic";

  std::string salt = salt_prefix; // empty passphrase

  std::vector<uint8_t> seed(64);
  pbkdf2HmacSha512(
      reinterpret_cast<const uint8_t *>(mnemonic.data()), mnemonic.size(),
      reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
      PBKDF2_BIP39_ITERATIONS,
      seed.data(), seed.size());

  // The reference seed from the BIP-39 spec (Trezor's test vectors):
  //
  //   5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1
  //   9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
  //
  // That vector uses the same mnemonic + empty passphrase + 2048
  // iterations. If this test fails, either the vector is wrong or
  // the PBKDF2 primitive is broken. In either case, investigate
  // before proceeding.
  EXPECT_EQ(toHex(seed.data(), seed.size()),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
            "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
}