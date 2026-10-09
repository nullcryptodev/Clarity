// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Crypto/Blake2b.h"
#include "Crypto/SessionKey.h"
#include "Crypto/X25519.h"

#include <array>
#include <cstring>

using namespace Crypto;

namespace
{
  // Convenience: build the arguments for one side of a handshake, so
  // tests don't repeat the setup. The two sides differ only in which
  // keys are "ours" and which are "theirs", and in the nonce order.
  //
  // Construction only allocates keys and fixed identity bytes. The
  // shared-secret derivation is a separate call so ASSERT_TRUE can be
  // used (macros that return on failure cannot live in a constructor).
  // Callers must invoke `derive()` before use; the returned bool is
  // for ASSERT_TRUE, not for branching.
  struct HandshakeFixture
  {
    X25519KeyPair aEph;
    X25519KeyPair bEph;
    std::array<uint8_t, 32> aIdent{};
    std::array<uint8_t, 32> bIdent{};
    uint64_t aNonce = 0x1111111111111111ULL;
    uint64_t bNonce = 0x2222222222222222ULL;

    std::array<uint8_t, 32> sharedAB{};
    std::array<uint8_t, 32> sharedBA{};

    HandshakeFixture()
    {
      aEph = generateX25519KeyPair();
      bEph = generateX25519KeyPair();

      // Fill identities with fixed bytes so the test is deterministic.
      for (size_t i = 0; i < 32; ++i)
      {
        aIdent[i] = static_cast<uint8_t>(0xA0 + i);
        bIdent[i] = static_cast<uint8_t>(0xB0 + i);
      }
    }

    // Compute both shared secrets. Returns false if either x25519 call
    // fails (all-zero output from a bad peer key — impossible with two
    // freshly generated keypairs, but the wrapper's contract requires
    // checking). Test bodies use ASSERT_TRUE(f.derive()).
    bool derive() noexcept
    {
      if (!x25519(aEph.secretKey.data(), bEph.publicKey.data(), sharedAB.data()))
        return false;
      if (!x25519(bEph.secretKey.data(), aEph.publicKey.data(), sharedBA.data()))
        return false;
      return true;
    }
  };
} // anonymous namespace

// ---------------------------------------------------------------------------
//  Symmetry: both sides derive the same key set
// ---------------------------------------------------------------------------

TEST(Crypto_SessionKey, BothSidesDeriveSameKeys)
{
  HandshakeFixture f;
  ASSERT_TRUE(f.derive());

  // A side: aNonce < bNonce, so weAreLowerNonce = true.
  const auto fromA = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce,
      f.bNonce,
      /*weAreLowerNonce=*/true);

  // B side: bNonce > aNonce, so weAreLowerNonce = false.
  const auto fromB = deriveSessionKeys(
      f.sharedBA.data(),
      f.bEph.publicKey.data(),
      f.aEph.publicKey.data(),
      f.bIdent.data(),
      f.aIdent.data(),
      f.bNonce,
      f.aNonce,
      /*weAreLowerNonce=*/false);

  EXPECT_EQ(std::memcmp(fromA.sessionKey.data(), fromB.sessionKey.data(), 32), 0);
  EXPECT_EQ(std::memcmp(fromA.lowerNonceKey.data(), fromB.lowerNonceKey.data(), 32), 0);
  EXPECT_EQ(std::memcmp(fromA.higherNonceKey.data(), fromB.higherNonceKey.data(), 32), 0);
}

TEST(Crypto_SessionKey, DirectionalKeysAreDistinct)
{
  HandshakeFixture f;

  const auto keys = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce,
      f.bNonce,
      true);

  EXPECT_NE(std::memcmp(keys.sessionKey.data(), keys.lowerNonceKey.data(), 32), 0);
  EXPECT_NE(std::memcmp(keys.sessionKey.data(), keys.higherNonceKey.data(), 32), 0);
  EXPECT_NE(std::memcmp(keys.lowerNonceKey.data(), keys.higherNonceKey.data(), 32), 0);
}

// ---------------------------------------------------------------------------
//  Selector correctness
// ---------------------------------------------------------------------------

TEST(Crypto_SessionKey, SendAndReceiveSelectorsAreInverses)
{
  // The A side's send key is the B side's receive key, and vice versa.
  // This is the property the encryption layer relies on: what A
  // encrypts with, B must be able to decrypt with.
  HandshakeFixture f;

  const auto fromA = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, true);

  const auto fromB = deriveSessionKeys(
      f.sharedBA.data(),
      f.bEph.publicKey.data(),
      f.aEph.publicKey.data(),
      f.bIdent.data(),
      f.aIdent.data(),
      f.bNonce, f.aNonce, false);

  // A sends with lowerNonceKey; B receives with its higherNonceKey.
  EXPECT_EQ(std::memcmp(fromA.forSend(true), fromB.forReceive(false), 32), 0);

  // B sends with higherNonceKey; A receives with its lowerNonceKey.
  EXPECT_EQ(std::memcmp(fromB.forSend(false), fromA.forReceive(true), 32), 0);
}

// ---------------------------------------------------------------------------
//  Sensitivity: every input affects the output
// ---------------------------------------------------------------------------

TEST(Crypto_SessionKey, ChangingSharedSecretChangesKeys)
{
  HandshakeFixture f;

  auto base = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, true);

  std::array<uint8_t, 32> tweaked = f.sharedAB;
  tweaked[0] ^= 0x01;

  auto changed = deriveSessionKeys(
      tweaked.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, true);

  EXPECT_NE(std::memcmp(base.sessionKey.data(), changed.sessionKey.data(), 32), 0);
}

TEST(Crypto_SessionKey, ChangingEitherEphemeralPubChangesKeys)
{
  HandshakeFixture f;

  auto base = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, true);

  {
    std::array<uint8_t, 32> tweaked = f.aEph.publicKey;
    tweaked[0] ^= 0x01;
    auto changed = deriveSessionKeys(
        f.sharedAB.data(),
        tweaked.data(),
        f.bEph.publicKey.data(),
        f.aIdent.data(),
        f.bIdent.data(),
        f.aNonce, f.bNonce, true);
    EXPECT_NE(std::memcmp(base.sessionKey.data(), changed.sessionKey.data(), 32), 0);
  }
  {
    std::array<uint8_t, 32> tweaked = f.bEph.publicKey;
    tweaked[0] ^= 0x01;
    auto changed = deriveSessionKeys(
        f.sharedAB.data(),
        f.aEph.publicKey.data(),
        tweaked.data(),
        f.aIdent.data(),
        f.bIdent.data(),
        f.aNonce, f.bNonce, true);
    EXPECT_NE(std::memcmp(base.sessionKey.data(), changed.sessionKey.data(), 32), 0);
  }
}

TEST(Crypto_SessionKey, ChangingEitherIdentityPubChangesKeys)
{
  HandshakeFixture f;

  auto base = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, true);

  {
    std::array<uint8_t, 32> tweaked = f.aIdent;
    tweaked[0] ^= 0x01;
    auto changed = deriveSessionKeys(
        f.sharedAB.data(),
        f.aEph.publicKey.data(),
        f.bEph.publicKey.data(),
        tweaked.data(),
        f.bIdent.data(),
        f.aNonce, f.bNonce, true);
    EXPECT_NE(std::memcmp(base.sessionKey.data(), changed.sessionKey.data(), 32), 0);
  }
  {
    std::array<uint8_t, 32> tweaked = f.bIdent;
    tweaked[0] ^= 0x01;
    auto changed = deriveSessionKeys(
        f.sharedAB.data(),
        f.aEph.publicKey.data(),
        f.bEph.publicKey.data(),
        f.aIdent.data(),
        tweaked.data(),
        f.aNonce, f.bNonce, true);
    EXPECT_NE(std::memcmp(base.sessionKey.data(), changed.sessionKey.data(), 32), 0);
  }
}

TEST(Crypto_SessionKey, ChangingEitherNonceChangesKeys)
{
  HandshakeFixture f;

  auto base = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, true);

  auto changedA = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce ^ 1, f.bNonce, true);

  auto changedB = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce ^ 1, true);

  EXPECT_NE(std::memcmp(base.sessionKey.data(), changedA.sessionKey.data(), 32), 0);
  EXPECT_NE(std::memcmp(base.sessionKey.data(), changedB.sessionKey.data(), 32), 0);
}

// ---------------------------------------------------------------------------
//  Ordering: swapping A/B without swapping the flag changes the result
// ---------------------------------------------------------------------------

TEST(Crypto_SessionKey, WrongLowerNonceFlagProducesDifferentKeys)
{
  // If a side computes the wrong `weAreLowerNonce`, the A/B ordering
  // flips and the derived keys diverge. This is the failure the
  // AuthReady key-confirmation step is designed to catch — but the
  // property starts here, and this test pins it.
  HandshakeFixture f;

  auto correct = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, /*weAreLowerNonce=*/true);

  auto wrong = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, /*weAreLowerNonce=*/false);

  EXPECT_NE(std::memcmp(correct.sessionKey.data(), wrong.sessionKey.data(), 32), 0);
}

// ---------------------------------------------------------------------------
//  Domain separation: changing the prefix would change the key
// ---------------------------------------------------------------------------

TEST(Crypto_SessionKey, SessionKeyDiffersFromBareBlake2bOfSharedSecret)
{
  // A sanity check that the domain prefix and the extra inputs are
  // doing work: the session key must not be a simple Blake2b of the
  // shared secret. If someone ever "simplifies" the KDF by dropping
  // the prefix or the identity/nonce inputs, this test will still
  // pass if the ephemeral public keys are included, but the intent is
  // to catch a KDF reduced to just the shared secret.
  HandshakeFixture f;

  auto keys = deriveSessionKeys(
      f.sharedAB.data(),
      f.aEph.publicKey.data(),
      f.bEph.publicKey.data(),
      f.aIdent.data(),
      f.bIdent.data(),
      f.aNonce, f.bNonce, true);

  std::array<uint8_t, 32> bare{};
  Crypto::blake2b(f.sharedAB.data(), f.sharedAB.size(), bare.data(), 32);

  EXPECT_NE(std::memcmp(keys.sessionKey.data(), bare.data(), 32), 0);
}