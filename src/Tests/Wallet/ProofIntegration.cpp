// Copyright (c) 2018-2026 Conceal Network & Conceal Devs
//
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "Tests/Temp.h"
#include "Tests/Utils.h"

#include "State/ProofKeys.h"
#include "State/SmtProof.h"
#include "State/SparseMerkleTree.h"

using namespace State;
using namespace Tests;

//  Key resolution tests. The resolver moved from P2P to State; these
//  verify the layouts match the ones the current-version getters use.

TEST(Wallet_ProofIntegration, ResolveAccountKeyMatchesKeys)
{
  std::vector<uint8_t> bytes(32);
  for (size_t i = 0; i < 32; ++i)
    bytes[i] = uint8_t(0xAA + i);

  auto key = State::resolveProofKey(ProofKeyType::Account, bytes);
  ASSERT_TRUE(key.has_value());

  Crypto::Address addr;
  std::memcpy(addr.data.data(), bytes.data(), 32);
  EXPECT_EQ(*key, State::Keys::account(addr));
}

TEST(Wallet_ProofIntegration, ResolveRejectsWrongLength)
{
  //  Account needs 32 bytes.
  std::vector<uint8_t> short_bytes(31, 0);
  EXPECT_FALSE(
      State::resolveProofKey(ProofKeyType::Account, short_bytes).has_value());

  //  Validator needs 8.
  std::vector<uint8_t> long_bytes(9, 0);
  EXPECT_FALSE(
      State::resolveProofKey(ProofKeyType::Validator, long_bytes).has_value());
}

//  End-to-end proof flow at the state layer. This is the "does the
//  protocol actually work" test: build a tree, write an account,
//  produce a proof, verify it against the root.

TEST(Wallet_ProofIntegration, ProveThenVerifyAccountAtCurrentVersion)
{
  TempDB db;
  SparseMerkleTree tree(db.db());

  Crypto::Address addr;
  addr.data[0] = 0x42;

  std::vector<uint8_t> value = {1, 2, 3, 4, 5};
  Crypto::Hash key = State::Keys::account(addr);

  tree.update(key, value, /*version=*/1);
  tree.save(1);

  auto proof = State::prove(tree, key);
  ASSERT_TRUE(proof.has_value());
  EXPECT_TRUE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(tree.root(), *proof));
}

TEST(Wallet_ProofIntegration, ProveThenVerifyAtHistoricalVersion)
{
  TempDB db;
  SparseMerkleTree tree(db.db());

  Crypto::Address addr;
  addr.data[0] = 0x77;

  Crypto::Hash key = State::Keys::account(addr);

  // Version 1: account exists with value A.
  tree.update(key, {0xAA}, /*version=*/1);
  tree.save(1);
  Crypto::Hash root_v1 = tree.root();

  // Version 2: account changes to value B.
  tree.update(key, {0xBB}, /*version=*/2);
  tree.save(2);
  Crypto::Hash root_v2 = tree.root();

  ASSERT_NE(root_v1, root_v2);

  // Prove against version 1's root.
  auto proof_v1 = State::proveAtRoot(tree, root_v1, key);
  ASSERT_TRUE(proof_v1.has_value());

  //  The proof must verify against root_v1 and fail against root_v2.
  EXPECT_TRUE(State::verifyProof(root_v1, *proof_v1));
  EXPECT_FALSE(State::verifyProof(root_v2, *proof_v1));
}

TEST(Wallet_ProofIntegration, NonInclusionProofVerifies)
{
  TempDB db;
  SparseMerkleTree tree(db.db());

  Crypto::Address addr;
  addr.data[0] = 0x99;

  Crypto::Hash key = State::Keys::account(addr);

  // Tree is empty at version 1.
  tree.save(1);
  Crypto::Hash root = tree.root();

  auto proof = State::proveAtRoot(tree, root, key);
  ASSERT_TRUE(proof.has_value());
  EXPECT_FALSE(proof->isInclusion());
  EXPECT_TRUE(State::verifyProof(root, *proof));
}