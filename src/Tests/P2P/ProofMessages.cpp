// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Utils.h"

#include "Crypto/Types.h"
#include "P2P/ProofMessages.h"
#include "P2P/MessageTypes.h"
#include "State/Keys.h"
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

  //  Build a ProofSibling whose fields are internally consistent. Used
  //  by the round-trip tests to construct proofs they can serialize
  //  and decode. The prefix_bits length must equal
  //  ceil(prefix_len / 8), which is what ProofSibling::isValid()
  //  enforces and what the wire codec expects.
  State::ProofSibling makeSibling(uint16_t prefix_len, uint8_t hash_seed)
  {
    State::ProofSibling s;
    s.prefix_len = prefix_len;

    const size_t prefix_bytes = (prefix_len + 7) / 8;
    s.prefix_bits.assign(prefix_bytes, 0);
    for (size_t i = 0; i < prefix_bytes; ++i)
      s.prefix_bits[i] = uint8_t(hash_seed + i);

    for (size_t i = 0; i < 32; ++i)
      s.hash.data[i] = uint8_t(hash_seed + i);

    return s;
  }

  //  Compare two ProofSiblings field by field. vector<ProofSibling> has
  //  no operator==, so the tests use this. The alternative — adding
  //  operator== to ProofSibling — would be a production change for a
  //  test-only need, and future changes to the struct would silently
  //  affect equality semantics across the codebase.
  void expectSiblingsEqual(const std::vector<State::ProofSibling> &a,
                           const std::vector<State::ProofSibling> &b)
  {
    ASSERT_EQ(a.size(), b.size());
    for (size_t i = 0; i < a.size(); ++i)
    {
      EXPECT_EQ(a[i].prefix_len, b[i].prefix_len) << "sibling " << i;
      EXPECT_EQ(a[i].prefix_bits, b[i].prefix_bits) << "sibling " << i;
      EXPECT_EQ(a[i].hash, b[i].hash) << "sibling " << i;
    }
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

  // Truncate to fewer than the minimum header.
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
  m.key_bytes = std::vector<uint8_t>(100, 0x41); // > MAX_KEY_BYTES
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
  original.proof.terminal_kind = State::ProofTerminalKind::Inclusion;
  original.proof.value = std::vector<uint8_t>{1, 2, 3, 4};

  //  Build a small, valid sibling list. The compressed tree's proofs
  //  are variable-length; the wire codec doesn't care about the
  //  content, only that each sibling's prefix_len and prefix_bits are
  //  consistent.
  original.proof.siblings.push_back(makeSibling(0, 0x10));
  original.proof.siblings.push_back(makeSibling(5, 0x20));
  original.proof.siblings.push_back(makeSibling(16, 0x30));

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));

  EXPECT_EQ(decoded.status, ProofMessage::Status::Ok);
  EXPECT_EQ(decoded.state_root, original.state_root);
  EXPECT_EQ(decoded.version, original.version);
  EXPECT_EQ(decoded.proof.key, original.proof.key);
  EXPECT_EQ(decoded.proof.terminal_kind, original.proof.terminal_kind);
  ASSERT_TRUE(decoded.proof.value.has_value());
  EXPECT_EQ(*decoded.proof.value, *original.proof.value);
  expectSiblingsEqual(decoded.proof.siblings, original.proof.siblings);
}

TEST(P2P_ProofMessages, ProofNonInclusionDefaultRoundTrip)
{
  ProofMessage original;
  original.status = ProofMessage::Status::Ok;
  original.proof.key.data[0] = 0xAA;
  original.proof.terminal_kind = State::ProofTerminalKind::Default;
  original.proof.value.reset();
  original.proof.siblings.push_back(makeSibling(0, 0x10));
  original.proof.siblings.push_back(makeSibling(3, 0x20));

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(decoded.status, ProofMessage::Status::Ok);
  EXPECT_EQ(decoded.proof.terminal_kind,
            State::ProofTerminalKind::Default);
  EXPECT_FALSE(decoded.proof.value.has_value());
  expectSiblingsEqual(decoded.proof.siblings, original.proof.siblings);
}

TEST(P2P_ProofMessages, ProofNonInclusionDifferentLeafRoundTrip)
{
  ProofMessage original;
  original.status = ProofMessage::Status::Ok;
  original.proof.key.data[0] = 0xAA;
  original.proof.terminal_kind = State::ProofTerminalKind::DifferentLeaf;
  original.proof.value.reset();
  original.proof.divergent_leaf_key.data[0] = 0xBB;
  original.proof.divergent_leaf_value_hash.data[0] = 0xCC;
  original.proof.siblings.push_back(makeSibling(0, 0x10));

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(decoded.proof.terminal_kind,
            State::ProofTerminalKind::DifferentLeaf);
  EXPECT_EQ(decoded.proof.divergent_leaf_key,
            original.proof.divergent_leaf_key);
  EXPECT_EQ(decoded.proof.divergent_leaf_value_hash,
            original.proof.divergent_leaf_value_hash);
  expectSiblingsEqual(decoded.proof.siblings, original.proof.siblings);
}

TEST(P2P_ProofMessages, ProofNonInclusionDivergentBranchRoundTrip)
{
  ProofMessage original;
  original.status = ProofMessage::Status::Ok;
  original.proof.key.data[0] = 0xAA;
  original.proof.terminal_kind = State::ProofTerminalKind::DivergentBranch;
  original.proof.value.reset();
  original.proof.divergent_branch_prefix_len = 12;
  original.proof.divergent_branch_prefix_bits = {0xAB, 0xC0};
  original.proof.divergent_branch_left.data[0] = 0x11;
  original.proof.divergent_branch_right.data[0] = 0x22;
  original.proof.siblings.push_back(makeSibling(0, 0x10));

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(decoded.proof.terminal_kind,
            State::ProofTerminalKind::DivergentBranch);
  EXPECT_EQ(decoded.proof.divergent_branch_prefix_len,
            original.proof.divergent_branch_prefix_len);
  EXPECT_EQ(decoded.proof.divergent_branch_prefix_bits,
            original.proof.divergent_branch_prefix_bits);
  EXPECT_EQ(decoded.proof.divergent_branch_left,
            original.proof.divergent_branch_left);
  EXPECT_EQ(decoded.proof.divergent_branch_right,
            original.proof.divergent_branch_right);
  expectSiblingsEqual(decoded.proof.siblings, original.proof.siblings);
}

TEST(P2P_ProofMessages, ProofVersionUnavailableHasNoProof)
{
  ProofMessage original;
  original.status = ProofMessage::Status::VersionUnavailable;
  original.version = 999;

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(decoded.status, ProofMessage::Status::VersionUnavailable);
  EXPECT_EQ(decoded.version, 999u);
}

TEST(P2P_ProofMessages, ProofKeyNotFoundHasNoProof)
{
  ProofMessage original;
  original.status = ProofMessage::Status::KeyNotFound;
  original.version = 42;

  auto encoded = serializeProof(original);

  ProofMessage decoded;
  ASSERT_TRUE(deserializeProof(encoded.data(), encoded.size(), decoded));
  EXPECT_EQ(decoded.status, ProofMessage::Status::KeyNotFound);
  EXPECT_EQ(decoded.version, 42u);
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
  std::vector<uint8_t> short_bytes(31, 0);
  EXPECT_FALSE(resolveProofKey(ProofKeyType::Account, short_bytes).has_value());

  std::vector<uint8_t> long_bytes(9, 0);
  EXPECT_FALSE(resolveProofKey(ProofKeyType::Validator, long_bytes).has_value());

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