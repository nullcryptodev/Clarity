// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Types.h"
#include "P2P/ProofMessages.h"
#include "P2P/MessageTypes.h"
#include "State/SmtProof.h"
#include "State/SparseMerkleTree.h"

using namespace P2P;
using namespace Tests;

namespace
{
  std::vector<uint8_t> addressBytes(uint8_t seed)
  {
    std::vector<uint8_t> b(32);
    for (size_t i = 0; i < 32; ++i)
      b[i] = uint8_t(seed + i);
    return b;
  }
} // anonymous namespace

// ============================================================================
//  GetProof encode/decode
// ============================================================================

TEST(P2P_ProofMessages, GetProofAccountRoundTrip)
{
  GetProofMessage original;
  original.key_type = ProofKeyType::Account;
  original.key_bytes = addressBytes(0xAA);
  original.version = 12345;

  auto encoded = serializeGetProof(original);

  GetProofMessage decoded;
  ASSERT_TRUE(deserializeGetProof(encoded.data(), encoded.size(), decoded));

  EXPECT_EQ(decoded.key_type, original.key_type);
  EXPECT_EQ(decoded.key_bytes, original.key_bytes);
  EXPECT_EQ(decoded.version, original.version);
}

TEST(P2P_ProofMessages, GetProofTokenBalanceRoundTrip)
{
  GetProofMessage original;
  original.key_type = ProofKeyType::TokenBalance;
  original.key_bytes = addressBytes(0xBB);
  original.key_bytes.insert(original.key_bytes.end(),
                            {0x2A, 0x00, 0x00, 0x00}); // token id 42 LE
  original.version = PROOF_VERSION_CURRENT;

  auto encoded = serializeGetProof(original);

  GetProofMessage decoded;
  ASSERT_TRUE(deserializeGetProof(encoded.data(), encoded.size(), decoded));

  EXPECT_EQ(decoded.key_type, ProofKeyType::TokenBalance);
  EXPECT_EQ(decoded.key_bytes, original.key_bytes);
  EXPECT_EQ(decoded.version, PROOF_VERSION_CURRENT);
}

TEST(P2P_ProofMessages, GetProofGlobalRoundTrip)
{
  GetProofMessage original;
  original.key_type = ProofKeyType::Global;
  original.key_bytes = {'a', 'c', 't', 'i', 'v', 'e', '_', 's', 'e', 't'};
  original.version = 7;

  auto encoded = serializeGetProof(original);

  GetProofMessage decoded;
  ASSERT_TRUE(deserializeGetProof(encoded.data(), encoded.size(), decoded));

  EXPECT_EQ(decoded.key_type, ProofKeyType::Global);
  EXPECT_EQ(decoded.key_bytes, original.key_bytes);
  EXPECT_EQ(decoded.version, 7u);
}

TEST(P2P_ProofMessages, GetProofRejectsTruncatedHeader)
{
  GetProofMessage m;
  m.key_type = ProofKeyType::Account;
  m.key_bytes = addressBytes(0xAA);
  m.version = 1;

  auto encoded = serializeGetProof(m);

  // Truncate to fewer than the minimum header (17 bytes).
  encoded.resize(10);

  GetProofMessage decoded;
  EXPECT_FALSE(deserializeGetProof(encoded.data(), encoded.size(), decoded));
}

TEST(P2P_ProofMessages, GetProofRejectsBadKeyType)
{
  GetProofMessage m;
  m.key_type = ProofKeyType::Account;
  m.key_bytes = addressBytes(0xAA);
  m.version = 1;

  auto encoded = serializeGetProof(m);

  // Corrupt the key_type byte to a value beyond the enum.
  encoded[0] = 0xFF;

  GetProofMessage decoded;
  EXPECT_FALSE(deserializeGetProof(encoded.data(), encoded.size(), decoded));
}

TEST(P2P_ProofMessages, GetProofRejectsOversizeKey)
{
  GetProofMessage m;
  m.key_type = ProofKeyType::Global;
  m.key_bytes = std::vector<uint8_t>(100, 0x41); // 100 > MAX_KEY_BYTES (64)
  m.version = 1;

  auto encoded = serializeGetProof(m);

  GetProofMessage decoded;
  EXPECT_FALSE(deserializeGetProof(encoded.data(), encoded.size(), decoded));
}

TEST(P2P_ProofMessages, GetProofRejectsTrailingBytes)
{
  GetProofMessage m;
  m.key_type = ProofKeyType::Account;
  m.key_bytes = addressBytes(0xAA);
  m.version = 1;

  auto encoded = serializeGetProof(m);
  encoded.push_back(0x00); // one trailing byte

  GetProofMessage decoded;
  EXPECT_FALSE(deserializeGetProof(encoded.data(), encoded.size(), decoded));
}

// ============================================================================
//  Proof encode/decode
// ============================================================================

TEST(P2P_ProofMessages, ProofOkRoundTrip)
{
  ProofMessage original;
  original.status = ProofMessage::Status::Ok;
  original.state_root.data[0] = 0x42;
  original.version = 100;
  original.proof.key.data[0] = 0x99;
  original.proof.value = std::vector<uint8_t>{1, 2, 3, 4};
  original.proof.siblings.resize(State::SparseMerkleTree::DEPTH);
  for (size_t i = 0; i < original.proof.siblings.size(); ++i)
    original.proof.siblings[i].data[0] = uint8_t(i);

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));

  EXPECT_EQ(decoded.status, ProofMessage::Status::Ok);
  EXPECT_EQ(decoded.state_root, original.state_root);
  EXPECT_EQ(decoded.version, original.version);
  EXPECT_EQ(decoded.proof.key, original.proof.key);
  ASSERT_TRUE(decoded.proof.value.has_value());
  EXPECT_EQ(*decoded.proof.value, *original.proof.value);
  EXPECT_EQ(decoded.proof.siblings, original.proof.siblings);
}

TEST(P2P_ProofMessages, ProofNonInclusionRoundTrip)
{
  ProofMessage original;
  original.status = ProofMessage::Status::Ok;
  original.proof.key.data[0] = 0xAA;
  original.proof.value.reset(); // non-inclusion
  original.proof.siblings.resize(State::SparseMerkleTree::DEPTH);

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(decoded.status, ProofMessage::Status::Ok);
  EXPECT_FALSE(decoded.proof.value.has_value());
}

TEST(P2P_ProofMessages, ProofVersionUnavailableHasNoProof)
{
  ProofMessage original;
  original.status = ProofMessage::Status::VersionUnavailable;
  original.version = 999;
  // No proof set.

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(decoded.status, ProofMessage::Status::VersionUnavailable);
  EXPECT_EQ(decoded.version, 999u);
}

TEST(P2P_ProofMessages, ProofMalformedHasNoProof)
{
  ProofMessage original;
  original.status = ProofMessage::Status::Malformed;

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(decoded.status, ProofMessage::Status::Malformed);
}

TEST(P2P_ProofMessages, ProofRejectsTrailingBytesAfterNonOkStatus)
{
  ProofMessage original;
  original.status = ProofMessage::Status::VersionUnavailable;

  auto encoded = serializeProof(original);
  encoded.push_back(0x00); // trailing byte

  ProofMessage decoded;
  EXPECT_FALSE(deserializeProof(encoded.data(), encoded.size(), decoded));
}

// ============================================================================
//  Key resolution
// ============================================================================

TEST(P2P_ProofMessages, ResolveAccountKey)
{
  std::vector<uint8_t> bytes = addressBytes(0xCC);
  auto key = resolveProofKey(ProofKeyType::Account, bytes);
  ASSERT_TRUE(key.has_value());

  Crypto::Address addr;
  std::memcpy(addr.data.data(), bytes.data(), 32);
  EXPECT_EQ(*key, State::Keys::account(addr));
}

TEST(P2P_ProofMessages, ResolveTokenBalanceKey)
{
  std::vector<uint8_t> bytes = addressBytes(0xDD);
  bytes.push_back(0x2A); // token id 42 LE
  bytes.push_back(0x00);
  bytes.push_back(0x00);
  bytes.push_back(0x00);

  auto key = resolveProofKey(ProofKeyType::TokenBalance, bytes);
  ASSERT_TRUE(key.has_value());

  Crypto::Address addr;
  std::memcpy(addr.data.data(), bytes.data(), 32);
  EXPECT_EQ(*key, State::Keys::tokenBalance(addr, 42));
}

TEST(P2P_ProofMessages, ResolveValidatorKey)
{
  std::vector<uint8_t> bytes(8);
  bytes[0] = 0x07; // validator id 7 LE

  auto key = resolveProofKey(ProofKeyType::Validator, bytes);
  ASSERT_TRUE(key.has_value());
  EXPECT_EQ(*key, State::Keys::validator(7));
}

TEST(P2P_ProofMessages, ResolveGlobalKey)
{
  std::vector<uint8_t> bytes = {'a', 'c', 't', 'i', 'v', 'e', '_', 's', 'e', 't'};
  auto key = resolveProofKey(ProofKeyType::Global, bytes);
  ASSERT_TRUE(key.has_value());
  EXPECT_EQ(*key, State::Keys::global("active_set"));
}

TEST(P2P_ProofMessages, ResolveAmmPoolKey)
{
  std::vector<uint8_t> bytes(8);
  bytes[0] = 0x03; // pool id 3 LE

  auto key = resolveProofKey(ProofKeyType::AmmPool, bytes);
  ASSERT_TRUE(key.has_value());
  EXPECT_EQ(*key, State::Keys::ammPool(3));
}

TEST(P2P_ProofMessages, ResolveRejectsWrongLength)
{
  // Account needs 32 bytes; give it 31.
  std::vector<uint8_t> short_bytes(31, 0);
  EXPECT_FALSE(resolveProofKey(ProofKeyType::Account, short_bytes).has_value());

  // Validator needs 8; give it 9.
  std::vector<uint8_t> long_bytes(9, 0);
  EXPECT_FALSE(resolveProofKey(ProofKeyType::Validator, long_bytes).has_value());

  // Global rejects empty.
  std::vector<uint8_t> empty;
  EXPECT_FALSE(resolveProofKey(ProofKeyType::Global, empty).has_value());
}

// ============================================================================
//  Framing round trip
// ============================================================================

TEST(P2P_ProofMessages, GetProofSurvivesWireFraming)
{
  GetProofMessage original;
  original.key_type = ProofKeyType::Validator;
  original.key_bytes = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  original.version = 5;

  Message wire_msg(MessageType::GetProof, serializeGetProof(original));

  Message received = roundTripThroughWire(wire_msg);
  EXPECT_EQ(received.type, MessageType::GetProof);

  GetProofMessage decoded;
  ASSERT_TRUE(deserializeGetProof(received.payload.data(),
                                  received.payload.size(),
                                  decoded));
  EXPECT_EQ(decoded.key_type, original.key_type);
  EXPECT_EQ(decoded.version, original.version);
}