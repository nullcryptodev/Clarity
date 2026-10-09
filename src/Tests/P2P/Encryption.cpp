// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Crypto/Chacha20Poly1305.h"
#include "Crypto/SessionKey.h"
#include "Crypto/X25519.h"

#include <array>
#include <cstring>
#include <vector>

using namespace Crypto;

// ---------------------------------------------------------------------------
//  Session-key agreement through X25519
//
//  These tests exercise the (X25519, SessionKey) pair as the encryption
//  layer uses them: two sides agree on a shared secret, derive the
//  same directional keys, and can round-trip an AEAD frame.
//
//  They do NOT exercise Peer, P2PManager, or the wire — those are the
//  manager-harness tests. This file is the crypto-side unit test for
//  what the encryption handshake depends on.
// ---------------------------------------------------------------------------

namespace
{
  // A "session" between two sides: ephemeral keys, identity keys, and
  // nonces. Both sides derive the same DerivedSessionKeys. Helper
  // struct so individual tests don't repeat the setup.
  struct Handshake
  {
    X25519KeyPair aEph;
    X25519KeyPair bEph;
    std::array<uint8_t, 32> aIdent{};
    std::array<uint8_t, 32> bIdent{};
    uint64_t aNonce = 0x1111111111111111ULL;
    uint64_t bNonce = 0x2222222222222222ULL;

    std::array<uint8_t, 32> sharedAB{};
    std::array<uint8_t, 32> sharedBA{};

    DerivedSessionKeys aKeys{};
    DerivedSessionKeys bKeys{};

    Handshake()
    {
      aEph = generateX25519KeyPair();
      bEph = generateX25519KeyPair();

      for (size_t i = 0; i < 32; ++i)
      {
        aIdent[i] = static_cast<uint8_t>(0xA0 + i);
        bIdent[i] = static_cast<uint8_t>(0xB0 + i);
      }
    }

    // Derive both sides' keys. Returns false if any step fails.
    bool derive()
    {
      if (!x25519(aEph.secretKey.data(), bEph.publicKey.data(), sharedAB.data()))
        return false;
      if (!x25519(bEph.secretKey.data(), aEph.publicKey.data(), sharedBA.data()))
        return false;

      aKeys = deriveSessionKeys(
          sharedAB.data(),
          aEph.publicKey.data(),
          bEph.publicKey.data(),
          aIdent.data(),
          bIdent.data(),
          aNonce, bNonce,
          /*weAreLowerNonce=*/true);

      bKeys = deriveSessionKeys(
          sharedBA.data(),
          bEph.publicKey.data(),
          aEph.publicKey.data(),
          bIdent.data(),
          aIdent.data(),
          bNonce, aNonce,
          /*weAreLowerNonce=*/false);

      return true;
    }
  };

  // Build the AAD the Peer would build for a message.
  std::array<uint8_t, 3> buildAad(uint16_t type, uint8_t dirTag)
  {
    std::array<uint8_t, 3> aad{};
    aad[0] = static_cast<uint8_t>(type & 0xFF);
    aad[1] = static_cast<uint8_t>((type >> 8) & 0xFF);
    aad[2] = dirTag;
    return aad;
  }

  // Build the 24-byte nonce the Peer would build.
  std::array<uint8_t, AEAD_NONCE_SIZE> buildNonce(uint64_t counter)
  {
    std::array<uint8_t, AEAD_NONCE_SIZE> nonce{};
    for (int i = 0; i < 8; ++i)
      nonce[i] = static_cast<uint8_t>(counter >> (8 * i));
    // bytes 8..23 remain zero
    return nonce;
  }
} // anonymous namespace

// ---------------------------------------------------------------------------
//  Cross-side agreement
// ---------------------------------------------------------------------------

TEST(P2P_Encryption, BothSidesAgreeOnDirectionalKeys)
{
  Handshake h;
  ASSERT_TRUE(h.derive());

  // A sends with lowerNonceKey; B receives with its higherNonceKey.
  EXPECT_EQ(std::memcmp(h.aKeys.forSend(true), h.bKeys.forReceive(false), 32), 0);

  // B sends with higherNonceKey; A receives with its lowerNonceKey.
  EXPECT_EQ(std::memcmp(h.bKeys.forSend(false), h.aKeys.forReceive(true), 32), 0);
}

TEST(P2P_Encryption, DirectionalKeysAreDistinct)
{
  Handshake h;
  ASSERT_TRUE(h.derive());

  // The two directional keys differ. If they didn't, a message from
  // A to B could be reflected back B to A and decrypt successfully
  // under the same key.
  EXPECT_NE(std::memcmp(h.aKeys.lowerNonceKey.data(),
                        h.aKeys.higherNonceKey.data(), 32),
            0);
}

// ---------------------------------------------------------------------------
//  AEAD round-trip
// ---------------------------------------------------------------------------

TEST(P2P_Encryption, AeadRoundTripSucceeds)
{
  Handshake h;
  ASSERT_TRUE(h.derive());

  const std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03, 0x04, 0x05};

  // A encrypts with its send key.
  auto aad = buildAad(0x0022 /* Tx */, 0x00 /* A->B */);
  auto nonce = buildNonce(0);

  std::vector<uint8_t> ciphertext(plaintext.size());
  uint8_t mac[AEAD_MAC_SIZE];

  ASSERT_TRUE(aeadEncrypt(plaintext.data(), plaintext.size(),
                          aad.data(), aad.size(),
                          h.aKeys.forSend(true),
                          nonce.data(),
                          ciphertext.data(),
                          mac));

  // B decrypts with its receive key, same AAD, same nonce.
  std::vector<uint8_t> decrypted(plaintext.size());
  ASSERT_TRUE(aeadDecrypt(ciphertext.data(), ciphertext.size(),
                          aad.data(), aad.size(),
                          h.bKeys.forReceive(false),
                          nonce.data(),
                          mac,
                          decrypted.data()));

  EXPECT_EQ(plaintext, decrypted);
}

TEST(P2P_Encryption, WrongDirectionTagFailsDecryption)
{
  Handshake h;
  ASSERT_TRUE(h.derive());

  const std::vector<uint8_t> plaintext = {0x01, 0x02, 0x03};

  auto encryptAad = buildAad(0x0022, 0x00); // A->B
  auto decryptAad = buildAad(0x0022, 0x01); // B->A (wrong)
  auto nonce = buildNonce(0);

  std::vector<uint8_t> ciphertext(plaintext.size());
  uint8_t mac[AEAD_MAC_SIZE];
  ASSERT_TRUE(aeadEncrypt(plaintext.data(), plaintext.size(),
                          encryptAad.data(), encryptAad.size(),
                          h.aKeys.forSend(true), nonce.data(),
                          ciphertext.data(), mac));

  std::vector<uint8_t> decrypted(plaintext.size());
  EXPECT_FALSE(aeadDecrypt(ciphertext.data(), ciphertext.size(),
                           decryptAad.data(), decryptAad.size(),
                           h.bKeys.forReceive(false), nonce.data(),
                           mac, decrypted.data()))
      << "direction tag mismatch must fail authentication";
}

TEST(P2P_Encryption, WrongMessageTypeFailsDecryption)
{
  // The type is bound in the AAD. Re-framing a valid Ping as a Tx
  // must fail the tag check.
  Handshake h;
  ASSERT_TRUE(h.derive());

  const std::vector<uint8_t> plaintext = {0xAB, 0xCD};

  auto pingAad = buildAad(0x0003 /* Ping */, 0x00);
  auto txAad = buildAad(0x0022 /* Tx */, 0x00);
  auto nonce = buildNonce(0);

  std::vector<uint8_t> ciphertext(plaintext.size());
  uint8_t mac[AEAD_MAC_SIZE];
  ASSERT_TRUE(aeadEncrypt(plaintext.data(), plaintext.size(),
                          pingAad.data(), pingAad.size(),
                          h.aKeys.forSend(true), nonce.data(),
                          ciphertext.data(), mac));

  std::vector<uint8_t> decrypted(plaintext.size());
  EXPECT_FALSE(aeadDecrypt(ciphertext.data(), ciphertext.size(),
                           txAad.data(), txAad.size(),
                           h.bKeys.forReceive(false), nonce.data(),
                           mac, decrypted.data()))
      << "type substitution must fail authentication";
}

TEST(P2P_Encryption, WrongNonceFailsDecryption)
{
  Handshake h;
  ASSERT_TRUE(h.derive());

  const std::vector<uint8_t> plaintext = {0x10, 0x20};

  auto aad = buildAad(0x0003, 0x00);
  auto nonce0 = buildNonce(0);
  auto nonce1 = buildNonce(1);

  std::vector<uint8_t> ciphertext(plaintext.size());
  uint8_t mac[AEAD_MAC_SIZE];
  ASSERT_TRUE(aeadEncrypt(plaintext.data(), plaintext.size(),
                          aad.data(), aad.size(),
                          h.aKeys.forSend(true), nonce0.data(),
                          ciphertext.data(), mac));

  std::vector<uint8_t> decrypted(plaintext.size());
  EXPECT_FALSE(aeadDecrypt(ciphertext.data(), ciphertext.size(),
                           aad.data(), aad.size(),
                           h.bKeys.forReceive(false), nonce1.data(),
                           mac, decrypted.data()))
      << "nonce mismatch must fail authentication";
}

TEST(P2P_Encryption, CorruptedMacFailsDecryption)
{
  Handshake h;
  ASSERT_TRUE(h.derive());

  const std::vector<uint8_t> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};

  auto aad = buildAad(0x0003, 0x00);
  auto nonce = buildNonce(0);

  std::vector<uint8_t> ciphertext(plaintext.size());
  uint8_t mac[AEAD_MAC_SIZE];
  ASSERT_TRUE(aeadEncrypt(plaintext.data(), plaintext.size(),
                          aad.data(), aad.size(),
                          h.aKeys.forSend(true), nonce.data(),
                          ciphertext.data(), mac));

  mac[7] ^= 0x01; // flip one bit in the tag

  std::vector<uint8_t> decrypted(plaintext.size());
  EXPECT_FALSE(aeadDecrypt(ciphertext.data(), ciphertext.size(),
                           aad.data(), aad.size(),
                           h.bKeys.forReceive(false), nonce.data(),
                           mac, decrypted.data()));
}

TEST(P2P_Encryption, CorruptedCiphertextFailsDecryption)
{
  Handshake h;
  ASSERT_TRUE(h.derive());

  const std::vector<uint8_t> plaintext = {0xDE, 0xAD, 0xBE, 0xEF};

  auto aad = buildAad(0x0003, 0x00);
  auto nonce = buildNonce(0);

  std::vector<uint8_t> ciphertext(plaintext.size());
  uint8_t mac[AEAD_MAC_SIZE];
  ASSERT_TRUE(aeadEncrypt(plaintext.data(), plaintext.size(),
                          aad.data(), aad.size(),
                          h.aKeys.forSend(true), nonce.data(),
                          ciphertext.data(), mac));

  ciphertext[1] ^= 0x01; // flip one bit in the ciphertext

  std::vector<uint8_t> decrypted(plaintext.size());
  EXPECT_FALSE(aeadDecrypt(ciphertext.data(), ciphertext.size(),
                           aad.data(), aad.size(),
                           h.bKeys.forReceive(false), nonce.data(),
                           mac, decrypted.data()));
}

// ---------------------------------------------------------------------------
//  Empty plaintext (AuthReady)
// ---------------------------------------------------------------------------

TEST(P2P_Encryption, EmptyPlaintextRoundTrip)
{
  // The AuthReady carries no plaintext — just a MAC over the empty
  // string. This test pins the AEAD's behavior for that case.
  Handshake h;
  ASSERT_TRUE(h.derive());

  auto aad = buildAad(0x0008 /* AuthReady */, 0x00);
  auto nonce = buildNonce(0);

  uint8_t mac[AEAD_MAC_SIZE];
  ASSERT_TRUE(aeadEncrypt(nullptr, 0,
                          aad.data(), aad.size(),
                          h.aKeys.forSend(true), nonce.data(),
                          /*ciphertext=*/nullptr,
                          mac));

  ASSERT_TRUE(aeadDecrypt(nullptr, 0,
                          aad.data(), aad.size(),
                          h.bKeys.forReceive(false), nonce.data(),
                          mac,
                          /*plaintext=*/nullptr));
}

TEST(P2P_Encryption, EmptyPlaintextWithWrongMacFails)
{
  // Key-confirmation failure path: a MAC that doesn't verify against
  // the peer's derived key. This is what AuthReady validation looks
  // like when the two sides derive different session keys.
  Handshake h;
  ASSERT_TRUE(h.derive());

  auto aad = buildAad(0x0008, 0x00);
  auto nonce = buildNonce(0);

  uint8_t mac[AEAD_MAC_SIZE];
  ASSERT_TRUE(aeadEncrypt(nullptr, 0,
                          aad.data(), aad.size(),
                          h.aKeys.forSend(true), nonce.data(),
                          nullptr,
                          mac));

  mac[0] ^= 0xFF;

  EXPECT_FALSE(aeadDecrypt(nullptr, 0,
                           aad.data(), aad.size(),
                           h.bKeys.forReceive(false), nonce.data(),
                           mac,
                           nullptr));
}

// ---------------------------------------------------------------------------
//  Key-confirmation via AuthReady
// ---------------------------------------------------------------------------

TEST(P2P_Encryption, MismatchedSessionKeysFailAtAuthReady)
{
  // Derive keys on side A with one nonce ordering, and on side B
  // with the *opposite* ordering. The session keys diverge, and an
  // AuthReady tag produced by A does not verify on B. This is
  // exactly the failure the AuthReady step is designed to catch.
  Handshake h;
  ASSERT_TRUE(h.derive());

  // Deliberately derive side B's keys with the wrong A/B flag.
  auto wrongBKeys = deriveSessionKeys(
      h.sharedBA.data(),
      h.bEph.publicKey.data(),
      h.aEph.publicKey.data(),
      h.bIdent.data(),
      h.aIdent.data(),
      h.bNonce, h.aNonce,
      /*weAreLowerNonce=*/true); // should be false

  auto aad = buildAad(0x0008, 0x00);
  auto nonce = buildNonce(0);

  uint8_t mac[AEAD_MAC_SIZE];
  ASSERT_TRUE(aeadEncrypt(nullptr, 0,
                          aad.data(), aad.size(),
                          h.aKeys.forSend(true), nonce.data(),
                          nullptr,
                          mac));

  // Verify against the wrong key. Direction tag is for A->B, so
  // the receiver's key is wrongBKeys.forReceive(false) — but since
  // wrongBKeys was derived with the wrong flag, forReceive(false)
  // returns the wrong key, and the AEAD fails.
  EXPECT_FALSE(aeadDecrypt(nullptr, 0,
                           aad.data(), aad.size(),
                           wrongBKeys.forReceive(false), nonce.data(),
                           mac,
                           nullptr))
      << "divergent session keys must fail AuthReady validation";
}